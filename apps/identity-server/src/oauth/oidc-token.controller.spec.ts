import { Logger, type INestApplication } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Test } from '@nestjs/testing';
import { createHash } from 'node:crypto';
import type { Server } from 'node:http';
import { exportJWK, generateKeyPair, jwtVerify, type CryptoKey } from 'jose';
import request from 'supertest';
import {
  afterAll,
  afterEach,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
  vi,
  type MockInstance,
} from 'vitest';
import type { Environment } from '../config/env.schema.js';
import { PrismaService } from '../prisma/prisma.service.js';
import { RedisService } from '../redis/redis.service.js';
import { SigningKeyService } from '../security/signing/signing-key.service.js';
import { AccessTokenIssuerService } from '../tokens/access-token-issuer.service.js';
import { RefreshTokenIssuerService } from '../tokens/refresh-token-issuer.service.js';
import { IdTokenIssuerService } from '../oidc/id-token-issuer.service.js';
import { IdpSessionStateService } from '../session/idp-session-state.service.js';
import { OAuthModule } from './oauth.module.js';
import { authorizationCodeStateSchema } from './authorization-code.state.js';

const subject = 'c0e21e3f-d3ee-425c-a99f-c2e7a7cab53f';
const issuerUrl = 'https://iam.example.test';
const nonceValue = ' Exact +%2F e\u0301 Nonce 💠 ';
const verifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
const challenge = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';
const kid = 'oidc-test-key';
const invalidGrant = {
  error: 'invalid_grant',
  error_description: 'Invalid authorization grant.',
};
const serverError = {
  error: 'server_error',
  error_description: 'Token request failed.',
};
const refreshToken = 'A'.repeat(43);
const oauthKeys = [
  'access_token',
  'expires_in',
  'refresh_token',
  'scope',
  'token_type',
];

describe('M7.6 POST /oauth/token conditional OIDC issuance after GETDEL + PKCE', () => {
  let app: INestApplication<Server>;
  let privateKey: CryptoKey;
  let publicKey: CryptoKey;
  let logs: MockInstance[];
  let access: MockInstance<AccessTokenIssuerService['issue']>;
  let id: MockInstance<IdTokenIssuerService['issue']>;
  let realAccess: AccessTokenIssuerService['issue'];
  let realId: IdTokenIssuerService['issue'];
  let client: {
    clientId: string;
    clientType: 'PUBLIC';
    enabled: boolean;
    accessTokenAudience: string | null;
    accessTokenTtl: number;
    refreshTokenTtl: number;
    clientSecretHash: null;
    id: string;
  };
  const order: string[] = [];
  const entries = new Map<string, string>();
  const forbidden = vi.fn(() => {
    throw new Error('Unexpected OIDC store/write/session operation.');
  });
  const findUnique = vi.fn();
  const refresh = vi.fn<RefreshTokenIssuerService['issueInitial']>();
  const getAndDelete = vi.fn<RedisService['getAndDelete']>();
  const getPrivateSigningKey = vi.fn();
  const getKeyId = vi.fn();
  const keyFor = (code: string): string =>
    'oauth:code:' + createHash('sha256').update(code).digest('hex');
  let sequence = 0;
  const fixture = (scopes = ['openid'], nonce: string | null = nonceValue) => {
    const body = {
      grant_type: 'authorization_code',
      client_id: 'student-spa',
      code: 'owned-oidc-code-' + sequence++,
      redirect_uri: 'http://localhost:3200/callback',
      code_verifier: verifier,
    };
    const state = authorizationCodeStateSchema.parse({
      clientId: body.client_id,
      userId: subject,
      sessionId: 'd4d7b5ef-d0a0-4c59-9fc4-70dd7773a9f3',
      redirectUri: body.redirect_uri,
      grantedScopes: scopes,
      codeChallenge: challenge,
      nonce,
      authTime: Date.now() - 1000,
      expiresAt: Date.now() + 120000,
    });
    const key = keyFor(body.code);
    entries.set(key, JSON.stringify(state));
    return { body, state, key };
  };
  beforeAll(async () => {
    ({ privateKey, publicKey } = await generateKeyPair('RS256', {
      modulusLength: 2048,
    }));
    const module = await Test.createTestingModule({ imports: [OAuthModule] })
      .overrideProvider(IdpSessionStateService)
      .useValue({ touch: forbidden })
      .overrideProvider(ConfigService)
      .useValue(
        new ConfigService<Environment, true>({
          ISSUER_URL: issuerUrl,
          COOKIE_NAME: 'iam.sid',
          COOKIE_SECURE: false,
        }),
      )
      .overrideProvider(PrismaService)
      .useValue({
        client: { findUnique },
        user: { findUnique: forbidden },
        credential: { findUnique: forbidden },
        session: { findFirst: forbidden },
        $transaction: forbidden,
      })
      .overrideProvider(RedisService)
      .useValue({
        getAndDelete,
        get: forbidden,
        delete: forbidden,
        setWithTtl: forbidden,
        setIfAbsentWithTtl: forbidden,
        sessionState: forbidden,
      })
      .overrideProvider(SigningKeyService)
      .useValue({
        getPrivateSigningKey,
        getKeyId,
        getPublicVerificationKey: forbidden,
        getPublicJwk: forbidden,
      })
      .overrideProvider(RefreshTokenIssuerService)
      .useValue({ issueInitial: refresh })
      .useMocker((token) =>
        token === ConfigService
          ? new ConfigService<Environment, true>({
              COOKIE_NAME: 'iam.sid',
              COOKIE_SECURE: false,
            })
          : undefined,
      )
      .compile();
    app = module.createNestApplication<INestApplication<Server>>({
      logger: false,
    });
    await app.listen(0, '127.0.0.1');
    expect(getPrivateSigningKey).not.toHaveBeenCalled();
    expect(getKeyId).not.toHaveBeenCalled();
    expect(findUnique).not.toHaveBeenCalled();
    expect(getAndDelete).not.toHaveBeenCalled();
    realAccess = app
      .get(AccessTokenIssuerService)
      .issue.bind(app.get(AccessTokenIssuerService));
    realId = app
      .get(IdTokenIssuerService)
      .issue.bind(app.get(IdTokenIssuerService));
  });
  beforeEach(() => {
    vi.clearAllMocks();
    entries.clear();
    order.length = 0;
    client = {
      id: 'fixture-client',
      clientId: 'student-spa',
      clientType: 'PUBLIC',
      enabled: true,
      clientSecretHash: null,
      accessTokenAudience: 'student-api',
      accessTokenTtl: 123,
      refreshTokenTtl: 456,
    };
    findUnique.mockImplementation(
      ({ where }: { where: { clientId: string } }) => {
        order.push('client');
        return Promise.resolve(
          where.clientId === client.clientId ? client : null,
        );
      },
    );
    getAndDelete.mockImplementation((key) => {
      order.push('consume');
      const value = entries.get(key) ?? null;
      entries.delete(key);
      return Promise.resolve(value);
    });
    getPrivateSigningKey.mockResolvedValue(privateKey);
    getKeyId.mockResolvedValue(kid);
    refresh.mockImplementation(() => {
      order.push('refresh');
      return Promise.resolve({ refreshToken });
    });
    access = vi
      .spyOn(app.get(AccessTokenIssuerService), 'issue')
      .mockImplementation(async (input) => {
        order.push('access');
        return realAccess(input);
      });
    id = vi
      .spyOn(app.get(IdTokenIssuerService), 'issue')
      .mockImplementation(async (input) => {
        order.push('id');
        return realId(input);
      });
    logs = [console, Logger, Logger.prototype].flatMap((target) =>
      ['log', 'info', 'error', 'warn', 'debug', 'verbose', 'fatal'].flatMap(
        (name) =>
          name in target
            ? [
                vi
                  .spyOn(target, name as 'log')
                  .mockImplementation(() => undefined),
              ]
            : [],
      ),
    );
  });
  afterEach(() => {
    try {
      expect(forbidden).not.toHaveBeenCalled();
      for (const log of logs) expect(log).not.toHaveBeenCalled();
    } finally {
      vi.restoreAllMocks();
    }
  });
  afterAll(async () => {
    await app.close();
  });
  const post = async (
    body: Record<string, string>,
    status: number,
    authorization?: string,
    query = '',
  ) => {
    const operation = request(app.getHttpServer())
      .post('/oauth/token' + query)
      .type('form')
      .send(new URLSearchParams(body).toString());
    if (authorization !== undefined)
      operation.set('Authorization', authorization);
    const response = await operation.expect(status);
    expect(response.headers['cache-control']).toBe('no-store');
    expect(response.headers.pragma).toBe('no-cache');
    expect(response.headers['set-cookie']).toBeUndefined();
    expect(response.headers.location).toBeUndefined();
    if (status !== 200) {
      expect(response.text.includes(body.code)).toBe(false);
      expect(response.text.includes(nonceValue)).toBe(false);
    }
    return response;
  };
  it.each([
    { scopes: ['profile'], nonce: null },
    { scopes: ['profile'], nonce: nonceValue },
    { scopes: ['OpenID'], nonce: nonceValue },
    { scopes: ['myopenid', 'openid.extra'], nonce: nonceValue },
  ])(
    'returns exact five-field OAuth-only response and never invokes ID issuer %#',
    async ({ scopes, nonce }) => {
      const { body, key, state } = fixture(scopes, nonce);
      const response = await post(
        body,
        200,
        undefined,
        '?scope=openid&nonce=caller',
      );
      expect(Object.keys(response.body as object).sort()).toEqual(oauthKeys);
      expect(id).not.toHaveBeenCalled();
      expect(access).toHaveBeenCalledOnce();
      expect(order).toEqual(['client', 'consume', 'access', 'refresh']);
      expect(refresh).toHaveBeenCalledExactlyOnceWith({
        userId: state.userId,
        clientRecordId: client.id,
        sessionId: state.sessionId,
        grantedScopes: scopes,
        ttlSeconds: 456,
      });
      expect(
        (response.body as Record<string, unknown>).refresh_token ===
          refreshToken,
      ).toBe(true);
      expect(entries.has(key)).toBe(false);
      const token = response.body as Record<string, string>;
      const { payload } = await jwtVerify(token.access_token, publicKey, {
        algorithms: ['RS256'],
        issuer: issuerUrl,
        audience: 'student-api',
      });
      expect(payload.scope).toBe(scopes.join(' '));
      expect(token.token_type).toBe('Bearer');
    },
  );
  it.each(
    [
      ['openid'],
      ['openid', 'profile', 'email'],
      ['profile', 'openid', 'openid'],
    ].map((scopes) => ({ scopes })),
  )(
    'issues exact six-field OIDC response from consumed grant %#',
    async ({ scopes }) => {
      const { body, key } = fixture(scopes);
      const response = await post(
        body,
        200,
        undefined,
        '?nonce=caller&scope=profile&sub=caller',
      );
      const tokens = response.body as Record<string, unknown>;
      expect(Object.keys(tokens).sort()).toEqual([
        'access_token',
        'expires_in',
        'id_token',
        'refresh_token',
        'scope',
        'token_type',
      ]);
      expect(tokens.token_type).toBe('Bearer');
      expect(tokens.expires_in).toBe(123);
      expect(tokens.scope).toBe(scopes.join(' '));
      expect(
        typeof tokens.access_token === 'string' &&
          typeof tokens.id_token === 'string',
      ).toBe(true);
      const jwk = await exportJWK(publicKey);
      const { createLocalJWKSet } = await import('jose');
      const jwks = createLocalJWKSet({
        keys: [{ ...jwk, kid, alg: 'RS256', use: 'sig' }],
      });
      const accessResult = await jwtVerify(
        tokens.access_token as string,
        jwks,
        { algorithms: ['RS256'], issuer: issuerUrl, audience: 'student-api' },
      );
      const identity = await jwtVerify(tokens.id_token as string, jwks, {
        algorithms: ['RS256'],
        issuer: issuerUrl,
        audience: 'student-spa',
      });
      expect(identity.protectedHeader).toEqual({ alg: 'RS256', kid });
      expect(Object.keys(identity.payload).sort()).toEqual([
        'aud',
        'exp',
        'iat',
        'iss',
        'nonce',
        'sub',
      ]);
      expect(
        identity.payload.sub === subject &&
          identity.payload.nonce === nonceValue,
      ).toBe(true);
      expect(identity.payload.aud).toBe('student-spa');
      expect(accessResult.payload.aud).toBe('student-api');
      expect(identity.payload.sub === accessResult.payload.sub).toBe(true);
      for (const payload of [identity.payload, accessResult.payload]) {
        expect(
          Number.isSafeInteger(payload.iat) &&
            Number.isSafeInteger(payload.exp) &&
            payload.exp! - payload.iat! === 123,
        ).toBe(true);
      }
      expect(id).toHaveBeenCalledExactlyOnceWith({
        subject,
        audience: body.client_id,
        nonce: nonceValue,
        ttlSeconds: 123,
      });
      expect(order).toEqual(['client', 'consume', 'access', 'id', 'refresh']);
      expect(tokens.refresh_token === refreshToken).toBe(true);
      expect(refresh).toHaveBeenCalledExactlyOnceWith({
        userId: subject,
        clientRecordId: client.id,
        sessionId: 'd4d7b5ef-d0a0-4c59-9fc4-70dd7773a9f3',
        grantedScopes: scopes,
        ttlSeconds: 456,
      });
      expect(entries.has(key)).toBe(false);
    },
  );
  it('fails closed for consumed openid/null-nonce invariant and rejects retry without restoration', async () => {
    const { body, key } = fixture(['openid'], null);
    const first = await post(body, 500);
    expect(first.body as unknown).toEqual(serverError);
    expect(access).toHaveBeenCalledOnce();
    expect(id).not.toHaveBeenCalled();
    expect(refresh).not.toHaveBeenCalled();
    expect(entries.has(key)).toBe(false);
    const retry = await post(body, 400);
    expect(retry.body as unknown).toEqual(invalidGrant);
    expect(access).toHaveBeenCalledOnce();
    expect(id).not.toHaveBeenCalled();
  });
  it.each(['claims', 'signing'])(
    'burns code on ID-token %s failure after access signing without a partial response',
    async (stage) => {
      const { body, key } = fixture();
      if (stage === 'claims')
        id.mockRejectedValueOnce(
          new Error('private-ID-token-nonce-PEM-canary'),
        );
      else
        getPrivateSigningKey
          .mockResolvedValueOnce(privateKey)
          .mockRejectedValueOnce(new Error('private-signing-path-canary'));
      const first = await post(body, 500);
      expect(first.body as unknown).toEqual(serverError);
      expect(first.text.includes('canary')).toBe(false);
      expect(access).toHaveBeenCalledOnce();
      expect(id).toHaveBeenCalledOnce();
      expect(refresh).not.toHaveBeenCalled();
      expect(entries.has(key)).toBe(false);
      const attempt = access.mock.results[0];
      if (attempt.type !== 'return')
        throw new Error('Expected completed access issuance.');
      const generated = await attempt.value;
      expect(first.text.includes(generated.accessToken)).toBe(false);
      const retry = await post(body, 400);
      expect(retry.body as unknown).toEqual(invalidGrant);
      expect(access).toHaveBeenCalledOnce();
      expect(id).toHaveBeenCalledOnce();
    },
  );
  it('never issues an ID token if access-token issuance fails after consumption', async () => {
    const { body, key } = fixture();
    access.mockRejectedValueOnce(new Error('private-access-token-canary'));
    expect((await post(body, 500)).body as unknown).toEqual(serverError);
    expect(entries.has(key)).toBe(false);
    expect(id).not.toHaveBeenCalled();
    expect(refresh).not.toHaveBeenCalled();
    expect((await post(body, 400)).body as unknown).toEqual(invalidGrant);
    expect(id).not.toHaveBeenCalled();
  });
  it.each([
    'shape',
    'client',
    'audience',
    'ttl',
    'refresh-ttl',
    'refresh-overflow',
  ])(
    'does not burn code or invoke issuers on pre-GETDEL %s failure',
    async (stage) => {
      const { body, key } = fixture();
      const before = entries.get(key);
      let status = 500;
      if (stage === 'audience') client.accessTokenAudience = null;
      if (stage === 'ttl') client.accessTokenTtl = 0;
      if (stage === 'refresh-ttl') client.refreshTokenTtl = 0;
      if (stage === 'refresh-overflow')
        client.refreshTokenTtl = Number.MAX_SAFE_INTEGER;
      if (stage === 'shape') status = 400;
      if (stage === 'client') status = 401;
      await post(
        stage === 'shape' ? { ...body, nonce: 'caller' } : body,
        status,
        stage === 'client' ? 'Basic cHVibGljOnNlY3JldA==' : undefined,
      );
      expect(entries.get(key) === before).toBe(true);
      expect(getAndDelete).not.toHaveBeenCalled();
      expect(access).not.toHaveBeenCalled();
      expect(id).not.toHaveBeenCalled();
      expect(refresh).not.toHaveBeenCalled();
      if (stage.startsWith('refresh-')) {
        client.refreshTokenTtl = 456;
        await post(body, 200);
        expect(entries.has(key)).toBe(false);
      }
    },
  );
  it.each(['binding', 'pkce', 'expiry', 'replay'])(
    'does not invoke either issuer on consumed %s failure',
    async (stage) => {
      const { body, key, state } = fixture();
      if (stage === 'binding')
        entries.set(
          key,
          JSON.stringify({ ...state, clientId: 'other-client' }),
        );
      if (stage === 'expiry')
        entries.set(key, JSON.stringify({ ...state, expiresAt: 1 }));
      if (stage === 'replay') entries.delete(key);
      const response = await post(
        stage === 'pkce' ? { ...body, code_verifier: 'x'.repeat(43) } : body,
        400,
      );
      expect(response.body as unknown).toEqual(invalidGrant);
      expect(entries.has(key)).toBe(false);
      expect(access).not.toHaveBeenCalled();
      expect(id).not.toHaveBeenCalled();
      expect(refresh).not.toHaveBeenCalled();
    },
  );
  it.each([['profile'], ['openid', 'profile']])(
    'burns code on refresh persistence failure with no partial credential response %#',
    async (...scopes: string[]) => {
      const { body, key } = fixture(scopes);
      refresh.mockRejectedValueOnce(
        new Error('private-refresh-hash-DB-canary'),
      );
      const response = await post(body, 500);
      expect(response.body as unknown).toEqual(serverError);
      expect(response.text.includes('canary')).toBe(false);
      expect(response.text.includes(refreshToken)).toBe(false);
      expect(entries.has(key)).toBe(false);
      expect(access).toHaveBeenCalledOnce();
      expect(id).toHaveBeenCalledTimes(scopes.includes('openid') ? 1 : 0);
      for (const attempt of [...access.mock.results, ...id.mock.results]) {
        if (attempt.type === 'return') {
          const generated = await attempt.value;
          const credential =
            'accessToken' in generated
              ? generated.accessToken
              : generated.idToken;
          expect(response.text.includes(credential)).toBe(false);
        }
      }
      expect(order.at(-1)).toBe(scopes.includes('openid') ? 'id' : 'access');
      expect(refresh).toHaveBeenCalledOnce();
      expect((await post(body, 400)).body as unknown).toEqual(invalidGrant);
      expect(refresh).toHaveBeenCalledOnce();
    },
  );
});
