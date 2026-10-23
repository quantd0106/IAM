import { Logger, type INestApplication } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Test } from '@nestjs/testing';
import { APP_FILTER } from '@nestjs/core';
import type { Server } from 'node:http';
import { generateKeyPair, jwtVerify, type CryptoKey } from 'jose';
import * as argon2 from 'argon2';
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
import { PrismaService } from '../prisma/prisma.service.js';
import { RedisService } from '../redis/redis.service.js';
import { SigningKeyService } from '../security/signing/signing-key.service.js';
import { AccessTokenIssuerService } from '../tokens/access-token-issuer.service.js';
import { RefreshTokenIssuerService } from '../tokens/refresh-token-issuer.service.js';
import { RefreshTokenGeneratorService } from '../tokens/refresh-token-generator.service.js';
import { IdTokenIssuerService } from '../oidc/id-token-issuer.service.js';
import { RegisterValidationFilter } from '../auth/register-validation.filter.js';
import { IdpSessionStateService } from '../session/idp-session-state.service.js';
import { OAuthModule } from './oauth.module.js';

const subject = 'c0e21e3f-d3ee-425c-a99f-c2e7a7cab53f';
const studentId = 'b2b2dbea-bc3a-42f4-8eae-2de818a4f2ea';
const bankId = 'd4d7b5ef-d0a0-4c59-9fc4-70dd7773a9f3';
const issuerUrl = 'https://iam.example.test';
const raw = 'A'.repeat(43);
const rawHash = new RefreshTokenGeneratorService().hash(raw);
const secret = ' synthetic exact e\u0301 +%2F: secret ';
const input = {
  grant_type: 'refresh_token',
  client_id: 'student-spa',
  refresh_token: raw,
};
const invalidGrant = {
  error: 'invalid_grant',
  error_description: 'Invalid refresh token.',
};
const invalidScope = {
  error: 'invalid_scope',
  error_description: 'Invalid refresh scope.',
};
const invalidClient = {
  error: 'invalid_client',
  error_description: 'Client authentication failed.',
};
const invalidRequest = {
  error: 'invalid_request',
  error_description: 'Invalid token request.',
};
const serverError = {
  error: 'server_error',
  error_description: 'Token request failed.',
};
const basic = (id = 'banking-web', value = secret) =>
  'Basic ' +
  Buffer.from(
    `${encodeURIComponent(id)}:${encodeURIComponent(value)}`,
  ).toString('base64');

describe('M8.6 HTTP dispatch: real client auth/hash/rotation/access RS256', () => {
  let app: INestApplication<Server>;
  let privateKey: CryptoKey;
  let publicKey: CryptoKey;
  let secretHash: string;
  let logs: MockInstance[];
  let access: MockInstance<AccessTokenIssuerService['issue']>;
  let hash: MockInstance<RefreshTokenGeneratorService['hash']>;
  let row: ReturnType<typeof fixture>;
  const order: string[] = [];
  const forbidden = vi.fn(() => {
    throw new Error('Unexpected code/PKCE/initial issuer/ID/session/write.');
  });
  const clientLookup = vi.fn();
  const tokenLookup = vi.fn();
  const transaction = vi.fn();
  const consume = vi.fn();
  const create = vi.fn();
  let children: Map<string, ReturnType<typeof fixture>>;
  type Client = {
    id: string;
    clientId: string;
    clientType: 'PUBLIC' | 'CONFIDENTIAL';
    enabled: boolean;
    clientSecretHash: string | null;
    accessTokenAudience: string | null;
    accessTokenTtl: number;
    refreshTokenTtl: number;
  };
  const clients = new Map<string, Client>();
  const fixture = () => ({
    id: 'e3c4a6be-e817-4a5a-a11a-298393b85243',
    familyId: 'a83b0df9-40eb-4a32-8e9c-5e5b12a731cf',
    status: 'ACTIVE',
    expiresAt: new Date(Date.now() + 120000),
    consumedAt: null as Date | null,
    revokedAt: null as Date | null,
    family: {
      id: 'a83b0df9-40eb-4a32-8e9c-5e5b12a731cf',
      userId: subject,
      clientId: studentId,
      status: 'ACTIVE',
      grantedScopes: ['openid', 'profile', 'email'] as unknown,
      reuseDetectedAt: null as Date | null,
      revokedAt: null as Date | null,
    },
  });
  let realIssue: AccessTokenIssuerService['issue'];
  beforeAll(async () => {
    ({ privateKey, publicKey } = await generateKeyPair('RS256', {
      modulusLength: 2048,
    }));
    secretHash = await argon2.hash(secret, { type: argon2.argon2id });
    const module = await Test.createTestingModule({
      imports: [OAuthModule],
      providers: [{ provide: APP_FILTER, useClass: RegisterValidationFilter }],
    })
      .overrideProvider(ConfigService)
      .useValue(
        new ConfigService({
          ISSUER_URL: issuerUrl,
          COOKIE_NAME: 'iam.sid',
          COOKIE_SECURE: false,
        }),
      )
      .overrideProvider(PrismaService)
      .useValue({
        client: { findUnique: clientLookup },
        refreshToken: {
          findUnique: forbidden,
          create: forbidden,
          update: forbidden,
          updateMany: forbidden,
        },
        refreshTokenFamily: {
          findUnique: forbidden,
          create: forbidden,
          update: forbidden,
        },
        user: { findUnique: forbidden },
        session: { findFirst: forbidden },
        $transaction: transaction,
      })
      .overrideProvider(RedisService)
      .useValue({
        getAndDelete: forbidden,
        get: forbidden,
        setWithTtl: forbidden,
        delete: forbidden,
      })
      .overrideProvider(SigningKeyService)
      .useValue({
        getPrivateSigningKey: () => Promise.resolve(privateKey),
        getKeyId: () => Promise.resolve('refresh-test-key'),
      })
      .overrideProvider(RefreshTokenIssuerService)
      .useValue({ issueInitial: forbidden })
      .overrideProvider(IdTokenIssuerService)
      .useValue({ issue: forbidden })
      .overrideProvider(IdpSessionStateService)
      .useValue({
        touch: forbidden,
        read: forbidden,
        create: forbidden,
        invalidate: forbidden,
      })
      .useMocker((token) =>
        token === ConfigService
          ? new ConfigService({
              ISSUER_URL: issuerUrl,
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
    realIssue = app
      .get(AccessTokenIssuerService)
      .issue.bind(app.get(AccessTokenIssuerService));
    expect(clientLookup).not.toHaveBeenCalled();
    expect(tokenLookup).not.toHaveBeenCalled();
  });
  beforeEach(() => {
    vi.clearAllMocks();
    row = fixture();
    children = new Map();
    transaction.mockImplementation(
      async (operation: (tx: unknown) => Promise<unknown>) => {
        order.push('transaction');
        const before = structuredClone(row);
        const savedChildren = structuredClone(children);
        try {
          const result = await operation({
            refreshToken: {
              findUnique: tokenLookup,
              updateMany: consume,
              create,
            },
          });
          order.push('commit');
          return result;
        } catch (error) {
          row = before;
          children = savedChildren;
          throw error;
        }
      },
    );
    consume.mockImplementation(
      ({
        where,
        data,
      }: {
        where: { id: string };
        data: { status: string; consumedAt: Date };
      }) => {
        order.push('consume');
        const token = [row, ...children.values()].find(
          (value) => value.id === where.id,
        );
        if (!token || token.status !== 'ACTIVE')
          return Promise.resolve({ count: 0 });
        Object.assign(token, data);
        return Promise.resolve({ count: 1 });
      },
    );
    create.mockImplementation(
      ({
        data,
      }: {
        data: {
          tokenHash: string;
          familyId: string;
          parentTokenId: string;
          status: string;
          issuedAt: Date;
          expiresAt: Date;
          consumedAt: null;
          revokedAt: null;
        };
      }) => {
        order.push('child');
        const id = '9676ec69-42ab-4a20-a6f3-9866a7e9f4b6';
        children.set(data.tokenHash, {
          ...fixture(),
          ...data,
          id,
          family: structuredClone(row.family),
        });
        return Promise.resolve({ id });
      },
    );
    order.length = 0;
    clients.clear();
    clients.set('student-spa', {
      id: studentId,
      clientId: 'student-spa',
      clientType: 'PUBLIC',
      enabled: true,
      clientSecretHash: null,
      accessTokenAudience: 'student-api',
      accessTokenTtl: 123,
      refreshTokenTtl: 0,
    });
    clients.set('banking-web', {
      id: bankId,
      clientId: 'banking-web',
      clientType: 'CONFIDENTIAL',
      enabled: true,
      clientSecretHash: secretHash,
      accessTokenAudience: 'banking-api',
      accessTokenTtl: 321,
      refreshTokenTtl: 0,
    });
    clientLookup.mockImplementation(
      ({ where }: { where: { clientId: string } }) => {
        order.push('client');
        return Promise.resolve(clients.get(where.clientId) ?? null);
      },
    );
    tokenLookup.mockImplementation(
      ({ where }: { where: { tokenHash: string } }) => {
        order.push('lookup');
        return Promise.resolve(
          where.tokenHash === rawHash
            ? row
            : (children.get(where.tokenHash) ?? null),
        );
      },
    );
    hash = vi.spyOn(app.get(RefreshTokenGeneratorService), 'hash');
    access = vi
      .spyOn(app.get(AccessTokenIssuerService), 'issue')
      .mockImplementation(async (values) => {
        order.push('access');
        return realIssue(values);
      });
    logs = [console, Logger, Logger.prototype].flatMap((target) =>
      ['log', 'info', 'warn', 'error', 'debug', 'verbose', 'fatal'].flatMap(
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
    await app?.close();
  });
  const checkHeaders = (headers: Record<string, unknown>) => {
    expect(headers['cache-control']).toBe('no-store');
    expect(headers.pragma).toBe('no-cache');
    expect(headers['content-type']).toMatch(/^application\/json/);
    expect(headers['set-cookie']).toBeUndefined();
    expect(headers.location).toBeUndefined();
  };
  const post = async (
    body: Record<string, string>,
    status: number,
    authorization?: string,
  ) => {
    const before = JSON.stringify(row);
    const operation = request(app.getHttpServer())
      .post('/oauth/token?scope=admin&client_id=caller&aud=caller')
      .type('form')
      .send(new URLSearchParams(body).toString());
    if (authorization !== undefined)
      operation.set('Authorization', authorization);
    const response = await operation.expect(status);
    checkHeaders(response.headers);
    if (status !== 200) expect(JSON.stringify(row) === before).toBe(true);
    for (const sensitive of [raw, secret, secretHash])
      expect(response.text.includes(sensitive)).toBe(false);
    if (status !== 200)
      expect(Object.keys(response.body as object).sort()).toEqual([
        'error',
        'error_description',
      ]);
    return response;
  };
  const verify = async (
    body: unknown,
    audience: string,
    ttl: number,
    scopes: string[],
  ) => {
    const tokens = body as Record<string, unknown>;
    expect(Object.keys(tokens).sort()).toEqual([
      'access_token',
      'expires_in',
      'refresh_token',
      'scope',
      'token_type',
    ]);
    expect(tokens.token_type).toBe('Bearer');
    expect(tokens.expires_in).toBe(ttl);
    expect(tokens.scope).toBe(scopes.join(' '));
    expect(
      typeof tokens.refresh_token === 'string' &&
        /^[A-Za-z0-9_-]{43}$/.test(tokens.refresh_token),
    ).toBe(true);
    expect(tokens.refresh_token !== raw).toBe(true);
    expect(typeof tokens.access_token === 'string').toBe(true);
    const { payload, protectedHeader } = await jwtVerify(
      tokens.access_token as string,
      publicKey,
      { algorithms: ['RS256'], issuer: issuerUrl, audience },
    );
    expect(protectedHeader).toEqual({ alg: 'RS256', kid: 'refresh-test-key' });
    expect(Object.keys(payload).sort()).toEqual([
      'aud',
      'exp',
      'iat',
      'iss',
      'permissions',
      'roles',
      'scope',
      'sub',
    ]);
    expect(payload.sub === subject && payload.scope === scopes.join(' ')).toBe(
      true,
    );
    expect(payload.exp! - payload.iat!).toBe(ttl);
    expect(payload.roles).toEqual([]);
    expect(payload.permissions).toEqual([]);
  };
  it.each([undefined, 'profile', 'email openid', 'openid profile email'])(
    'issues exact five-field PUBLIC response with verified snapshot/narrowed claims %#',
    async (scope) => {
      const scopes =
        scope === undefined ? ['openid', 'profile', 'email'] : scope.split(' ');
      const response = await post(
        { ...input, ...(scope === undefined ? {} : { scope }) },
        200,
      );
      await verify(response.body, 'student-api', 123, scopes);
      expect(order).toEqual([
        'client',
        'transaction',
        'lookup',
        'access',
        'consume',
        'child',
        'commit',
      ]);
      expect(hash).toHaveBeenCalledTimes(2);
      expect(hash.mock.calls[0][0] === raw).toBe(true);
      expect(access).toHaveBeenCalledExactlyOnceWith({
        subject,
        audience: 'student-api',
        scopes,
        ttlSeconds: 123,
        roles: [],
        permissions: [],
      });
      expect(row.status).toBe('CONSUMED');
      expect(row.consumedAt).toBeInstanceOf(Date);
      expect(children.size).toBe(1);
      expect(row.family.status).toBe('ACTIVE');
      expect(row.family.grantedScopes).toEqual(['openid', 'profile', 'email']);
    },
  );
  it('authenticates confidential Basic, binds internal UUID and uses its resource audience/access TTL', async () => {
    row.family.clientId = bankId;
    await verify(
      (await post({ ...input, client_id: 'banking-web' }, 200, basic())).body,
      'banking-api',
      321,
      ['openid', 'profile', 'email'],
    );
  });
  it.each([
    'wrong-secret',
    'missing',
    'wrong-id',
    'public-basic',
    'unknown',
    'disabled',
  ])('rejects %s before refresh hashing/lookup', async (kind) => {
    let body = { ...input, client_id: 'banking-web' };
    let authorization: string | undefined = basic();
    if (kind === 'wrong-secret') authorization = basic('banking-web', 'wrong');
    if (kind === 'missing') authorization = undefined;
    if (kind === 'wrong-id') authorization = basic('student-spa');
    if (kind === 'public-basic') body = { ...input };
    if (kind === 'unknown') body.client_id = 'unknown';
    if (kind === 'disabled') clients.get('banking-web')!.enabled = false;
    const response = await post(body, 401, authorization);
    expect(response.body as unknown).toEqual(invalidClient);
    expect(response.headers['www-authenticate']).toBe(
      'Basic realm="oauth/token"',
    );
    expect(hash).not.toHaveBeenCalled();
    expect(tokenLookup).not.toHaveBeenCalled();
    expect(access).not.toHaveBeenCalled();
    expect(transaction).not.toHaveBeenCalled();
  });
  it.each([
    'absent',
    'binding',
    'expired',
    'consumed',
    'revoked',
    'consumed-at',
    'revoked-at',
    'family',
    'family-revoked-at',
    'reuse-at',
    'empty-scopes',
    'malformed-scopes',
  ])(
    'returns one fixed invalid_grant for %s, without issuing or mutating',
    async (kind) => {
      if (kind === 'absent') tokenLookup.mockResolvedValueOnce(null);
      if (kind === 'binding') row.family.clientId = bankId;
      if (kind === 'expired') row.expiresAt = new Date(0);
      if (kind === 'consumed') row.status = 'CONSUMED';
      if (kind === 'revoked') row.status = 'REVOKED';
      if (kind === 'consumed-at') row.consumedAt = new Date();
      if (kind === 'revoked-at') row.revokedAt = new Date();
      if (kind === 'family') row.family.status = 'REVOKED';
      if (kind === 'family-revoked-at') row.family.revokedAt = new Date();
      if (kind === 'reuse-at') row.family.reuseDetectedAt = new Date();
      if (kind === 'empty-scopes') row.family.grantedScopes = [];
      if (kind === 'malformed-scopes')
        row.family.grantedScopes = ['profile', 'profile'];
      expect(
        (await post({ ...input, scope: '' }, 400)).body as unknown,
      ).toEqual(invalidGrant);
      expect(access).not.toHaveBeenCalled();
    },
  );
  it.each([
    'A'.repeat(42),
    raw + '\n',
    ' ' + raw,
    'A'.repeat(42) + '+',
    'A'.repeat(42) + 'é',
  ])(
    'rejects malformed scalar credential as invalid_grant after auth, before hashing/lookup %#',
    async (refresh_token) => {
      expect(
        (await post({ ...input, refresh_token }, 400)).body as unknown,
      ).toEqual(invalidGrant);
      expect(clientLookup).toHaveBeenCalledOnce();
      expect(hash).not.toHaveBeenCalled();
      expect(tokenLookup).not.toHaveBeenCalled();
    },
  );
  it.each([
    '',
    'openid admin',
    'OpenID',
    'profile profile',
    'profile  email',
    'profile\n',
  ])(
    'returns invalid_scope only after credential validation %#',
    async (scope) => {
      expect((await post({ ...input, scope }, 400)).body as unknown).toEqual(
        invalidScope,
      );
      expect(tokenLookup).toHaveBeenCalledOnce();
      expect(access).not.toHaveBeenCalled();
    },
  );
  it.each([
    'client-db',
    'audience',
    'ttl',
    'hash',
    'lookup',
    'date',
    'issuer',
    'generator',
    'consume',
    'child',
    'transaction',
  ])(
    'sanitizes %s/config/driver failure with no credential or DB mutation',
    async (stage) => {
      const native = new Error('private-refresh/hash/scopes/DB-canary', {
        cause: new Error('private'),
      });
      if (stage === 'client-db') clientLookup.mockRejectedValueOnce(native);
      if (stage === 'audience')
        clients.get('student-spa')!.accessTokenAudience = null;
      if (stage === 'ttl') clients.get('student-spa')!.accessTokenTtl = 0;
      if (stage === 'hash')
        hash.mockImplementationOnce(() => {
          throw native;
        });
      if (stage === 'lookup') tokenLookup.mockRejectedValueOnce(native);
      if (stage === 'date') row.expiresAt = new Date(NaN);
      if (stage === 'issuer') access.mockRejectedValueOnce(native);
      if (stage === 'generator')
        vi.spyOn(
          app.get(RefreshTokenGeneratorService),
          'generate',
        ).mockImplementationOnce(() => {
          throw native;
        });
      if (stage === 'consume') consume.mockRejectedValueOnce(native);
      if (stage === 'child') create.mockRejectedValueOnce(native);
      if (stage === 'transaction') transaction.mockRejectedValueOnce(native);
      const response = await post(input, 500);
      expect(response.body as unknown).toEqual(serverError);
      expect(response.text.includes('canary')).toBe(false);
      if (['client-db', 'audience', 'ttl', 'hash'].includes(stage))
        expect(tokenLookup).not.toHaveBeenCalled();
      expect(children.size).toBe(0);
    },
  );
  it('rejects RT1 replay, then rotates RT2 to RT3 without shrinking family scopes or expiry', async () => {
    const family = structuredClone(row.family);
    const expiry = row.expiresAt;
    const first = (await post({ ...input, scope: 'profile' }, 200)).body as {
      refresh_token: string;
    };
    expect((await post(input, 400)).body as unknown).toEqual(invalidGrant);
    const second = (
      await post({ ...input, refresh_token: first.refresh_token }, 200)
    ).body as { refresh_token: string };
    await verify(second, 'student-api', 123, ['openid', 'profile', 'email']);
    expect(second.refresh_token !== first.refresh_token).toBe(true);
    expect(children.size).toBe(2);
    for (const child of children.values())
      expect(child.expiresAt).toEqual(expiry);
    expect(row.family).toEqual(family);
    expect(access).toHaveBeenCalledTimes(2);
  });
  it('returns fixed invalid_grant and no replacement on conditional consume loss', async () => {
    consume.mockResolvedValueOnce({ count: 0 });
    expect((await post(input, 400)).body as unknown).toEqual(invalidGrant);
    expect(access).toHaveBeenCalledOnce();
    expect(create).not.toHaveBeenCalled();
    expect(children.size).toBe(0);
  });
  it.each([
    'code=x',
    'redirect_uri=x',
    'code_verifier=x',
    'extra=x',
    'refresh_token=x',
    'scope[]=profile',
    'scope[nested]=profile',
    'scope=a&scope=b',
    'client_id=duplicate',
  ])(
    'rejects strict/duplicate/structured form input before client lookup %#',
    async (suffix) => {
      const response = await request(app.getHttpServer())
        .post('/oauth/token')
        .type('form')
        .send(new URLSearchParams(input).toString() + '&' + suffix)
        .expect(400);
      checkHeaders(response.headers);
      expect(response.body as unknown).toEqual(invalidRequest);
      expect(clientLookup).not.toHaveBeenCalled();
      expect(tokenLookup).not.toHaveBeenCalled();
    },
  );
  it('classifies unknown grants before grant-specific shape, but known malformed refresh remains invalid_request', async () => {
    expect((await post({ grant_type: 'future' }, 400)).body as unknown).toEqual(
      {
        error: 'unsupported_grant_type',
        error_description: 'Unsupported grant type.',
      },
    );
    for (const body of [
      { grant_type: 'refresh_token' },
      { ...input, refresh_token: '' },
    ])
      expect((await post(body, 400)).body as unknown).toEqual(invalidRequest);
    expect(clientLookup).not.toHaveBeenCalled();
  });
});
