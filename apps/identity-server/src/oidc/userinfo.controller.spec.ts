import { Logger, type INestApplication } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { Test } from '@nestjs/testing';
import { generateKeyPair } from 'jose';
import type { Server } from 'node:http';
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
import { SigningKeyModule } from '../security/signing/signing-key.module.js';
import { SigningKeyService } from '../security/signing/signing-key.service.js';
import { AccessTokenClaimsService } from '../tokens/access-token-claims.service.js';
import { AccessTokenIssuerService } from '../tokens/access-token-issuer.service.js';
import { IdTokenClaimsService } from './id-token-claims.service.js';
import { IdTokenIssuerService } from './id-token-issuer.service.js';
import { UserInfoAccessTokenService } from './userinfo-access-token.service.js';
import { UserInfoController } from './userinfo.controller.js';
import { OidcModule } from './oidc.module.js';
import type { Environment } from '../config/env.schema.js';
import { PrismaModule } from '../prisma/prisma.module.js';
import { PrismaService } from '../prisma/prisma.service.js';
import { UserInfoClaimsService } from './userinfo-claims.service.js';

const subject = 'c0e21e3f-d3ee-425c-a99f-c2e7a7cab53f';
const issuerUrl = 'https://iam.example.test';
const kid = 'MiXeD-e\u0301-Key';
const username = ' MiXeD-e\u0301-username ';
const email = 'MiXeD@Example.test';
const invalidBody = {
  error: 'invalid_token',
  error_description: 'Invalid access token.',
};
const insufficientBody = {
  error: 'insufficient_scope',
  error_description: 'The access token does not grant UserInfo access.',
};

describe('GET + POST /oidc/userinfo protected resource', () => {
  let app: INestApplication<Server>;
  let logs: MockInstance[];
  let tokens: string[];
  let noOpenid: string;
  let idToken: string;
  let expired: string;
  let missingProfile: string;
  let missingOpenid: string;
  let publicKey: Awaited<ReturnType<typeof generateKeyPair>>['publicKey'];
  const config = new ConfigService<Environment, true>({
    ISSUER_URL: issuerUrl,
  });
  const getPublicVerificationKey = vi.fn();
  const getKeyId = vi.fn();
  const findUnique = vi.fn();
  const forbidden = vi.fn(() => {
    throw new Error('Unexpected UserInfo private-key/JWKS access.');
  });
  beforeAll(async () => {
    const pair = await generateKeyPair('RS256', { modulusLength: 2048 });
    publicKey = pair.publicKey;
    const fixtureKeys = {
      getPrivateSigningKey: () => Promise.resolve(pair.privateKey),
      getKeyId: () => Promise.resolve(kid),
    } as unknown as SigningKeyService;
    const issuer = new AccessTokenIssuerService(
      new AccessTokenClaimsService(config),
      fixtureKeys,
    );
    tokens = await Promise.all(
      [
        [['openid'], 'student-api'],
        [['openid', 'profile'], 'banking-api'],
        [['openid', 'email'], 'student-api'],
        [['openid', 'profile', 'email'], 'identity-server'],
        [['openid', 'banking.transactions.read'], 'banking-api'],
        [['openid', 'Profile', 'Email', 'myprofile', 'myemail'], 'student-api'],
      ].map(
        async ([scopes, audience]) =>
          (
            await issuer.issue({
              subject,
              audience: audience as string,
              scopes: scopes as string[],
              roles: ['role-not-returned'],
              permissions: ['permission-not-returned'],
              ttlSeconds: 600,
            })
          ).accessToken,
      ),
    );
    noOpenid = (
      await issuer.issue({
        subject,
        audience: 'student-api',
        scopes: ['profile'],
        roles: [],
        permissions: [],
        ttlSeconds: 600,
      })
    ).accessToken;
    [missingProfile, missingOpenid] = await Promise.all(
      [['openid', 'profile'], ['openid']].map(
        async (scopes) =>
          (
            await issuer.issue({
              subject: 'b7df50df-1558-440e-adc0-760cbdd8b240',
              audience: 'student-api',
              scopes,
              roles: [],
              permissions: [],
              ttlSeconds: 600,
            })
          ).accessToken,
      ),
    );
    idToken = (
      await new IdTokenIssuerService(
        new IdTokenClaimsService(config),
        fixtureKeys,
      ).issue({
        subject,
        audience: 'student-spa',
        nonce: 'opaque-nonce-value',
        ttlSeconds: 600,
      })
    ).idToken;
    const clock = vi.spyOn(Date, 'now').mockReturnValue(0);
    try {
      expired = (
        await issuer.issue({
          subject,
          audience: 'student-api',
          scopes: ['openid'],
          roles: [],
          permissions: [],
          ttlSeconds: 1,
        })
      ).accessToken;
    } finally {
      clock.mockRestore();
    }
    const module = await Test.createTestingModule({ imports: [OidcModule] })
      .overrideProvider(ConfigService)
      .useValue(config)
      .overrideProvider(PrismaService)
      .useValue({
        user: { findUnique },
        credential: { findMany: forbidden },
        session: { findMany: forbidden },
      })
      .overrideProvider(SigningKeyService)
      .useValue({
        getPublicVerificationKey,
        getKeyId,
        getPrivateSigningKey: forbidden,
        getPublicJwk: forbidden,
      })
      .compile();
    app = module.createNestApplication<INestApplication<Server>>({
      logger: false,
    });
    await app.listen(0, '127.0.0.1');
    expect(getPublicVerificationKey).not.toHaveBeenCalled();
    expect(getKeyId).not.toHaveBeenCalled();
  });
  beforeEach(() => {
    vi.clearAllMocks();
    getPublicVerificationKey.mockResolvedValue(publicKey);
    getKeyId.mockResolvedValue(kid);
    findUnique.mockResolvedValue({ username, email });
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
      expect(findUnique.mock.calls.length).toBeLessThanOrEqual(1);
      for (const log of logs) expect(log).not.toHaveBeenCalled();
    } finally {
      vi.restoreAllMocks();
    }
  });
  afterAll(async () => {
    await app.close();
  });
  const headers = (response: request.Response): void => {
    expect(response.headers['cache-control']).toBe('no-store');
    expect(response.headers.pragma).toBe('no-cache');
    expect(response.headers['set-cookie']).toBeUndefined();
    expect(response.headers.location).toBeUndefined();
  };

  it('adds only internal claims resolution and Prisma without Redis/global scope/exports', () => {
    expect(Reflect.getMetadata('imports', OidcModule) as unknown).toEqual([
      ConfigModule,
      SigningKeyModule,
      PrismaModule,
    ]);
    expect(
      (Reflect.getMetadata('exports', OidcModule) as unknown) ?? [],
    ).toEqual([]);
    expect(
      Reflect.getMetadata('__module:global__', OidcModule) as unknown,
    ).not.toBe(true);
    expect(Reflect.getMetadata('providers', OidcModule) as unknown).toContain(
      UserInfoAccessTokenService,
    );
    expect(Reflect.getMetadata('providers', OidcModule) as unknown).toContain(
      UserInfoClaimsService,
    );
    expect(Reflect.getMetadata('controllers', OidcModule) as unknown).toContain(
      UserInfoController,
    );
  });
  describe.each(['get', 'post'] as const)('%s', (method) => {
    it.each([0, 1, 2, 3, 4, 5])(
      'accepts real M6.7 token %# and returns only the exact scope-limited claims',
      async (index) => {
        const response = await request(app.getHttpServer())
          [method]('/oidc/userinfo')
          .set('Authorization', 'bEaReR   ' + tokens[index])
          .expect(200);
        headers(response);
        expect(response.headers['content-type']).toMatch(/^application\/json/);
        expect(response.headers['www-authenticate']).toBeUndefined();
        const expected = [
          { sub: subject },
          { sub: subject, preferred_username: username },
          { sub: subject, email },
          { sub: subject, preferred_username: username, email },
          { sub: subject },
          { sub: subject },
        ][index];
        expect(response.body as unknown).toEqual(expected);
        expect(Object.keys(response.body as object)).toEqual(
          Object.keys(expected),
        );
        if ([1, 2, 3].includes(index)) {
          expect(findUnique).toHaveBeenCalledExactlyOnceWith({
            where: { id: subject },
            select: { username: true, email: true },
          });
          expect(getKeyId.mock.invocationCallOrder[0]).toBeLessThan(
            findUnique.mock.invocationCallOrder[0],
          );
        } else expect(findUnique).not.toHaveBeenCalled();
      },
    );
    it('queries only after authentication has completely resolved with verified grants', async () => {
      const authentication = app.get(UserInfoAccessTokenService);
      const original = authentication.authenticate.bind(authentication);
      let verified = false;
      vi.spyOn(authentication, 'authenticate').mockImplementation(
        async (header) => {
          const result = await original(header);
          expect(result).toEqual({
            ok: true,
            subject,
            scopes: ['openid', 'profile', 'email'],
          });
          verified = result.ok;
          return result;
        },
      );
      findUnique.mockImplementationOnce(() => {
        expect(verified).toBe(true);
        return Promise.resolve({ username, email });
      });
      await request(app.getHttpServer())
        [method]('/oidc/userinfo')
        .set('Authorization', 'Bearer ' + tokens[3])
        .expect(200)
        .expect({ sub: subject, preferred_username: username, email });
    });
    it('maps a missing requested-claim user to the same fixed invalid_token and keeps openid-only stateless', async () => {
      findUnique.mockResolvedValue(null);
      const response = await request(app.getHttpServer())
        [method]('/oidc/userinfo')
        .set('Authorization', 'Bearer ' + missingProfile)
        .expect(401);
      headers(response);
      expect(response.body as unknown).toEqual(invalidBody);
      expect(response.headers['www-authenticate']).toBe(
        'Bearer realm="userinfo", error="invalid_token"',
      );
      expect(findUnique).toHaveBeenCalledExactlyOnceWith({
        where: { id: 'b7df50df-1558-440e-adc0-760cbdd8b240' },
        select: { username: true, email: true },
      });
      findUnique.mockClear();
      const stateless = await request(app.getHttpServer())
        [method]('/oidc/userinfo')
        .set('Authorization', 'Bearer ' + missingOpenid)
        .expect(200);
      headers(stateless);
      expect(stateless.body as unknown).toEqual({
        sub: 'b7df50df-1558-440e-adc0-760cbdd8b240',
      });
      expect(findUnique).not.toHaveBeenCalled();
    });
    it.each(['database', 'username', 'email'])(
      'sanitizes %s profile-resolution failure as server_error, not invalid_token',
      async (kind) => {
        if (kind === 'database')
          findUnique.mockRejectedValue(
            new Error('SQL-DATABASE_URL-subject-username-email-canary', {
              cause: new Error('private'),
            }),
          );
        else
          findUnique.mockResolvedValue({
            username,
            email,
            [kind]: kind === 'email' ? ' email-canary ' : '',
          });
        const response = await request(app.getHttpServer())
          [method]('/oidc/userinfo')
          .set('Authorization', 'Bearer ' + tokens[3])
          .expect(500);
        headers(response);
        expect(response.body as unknown).toEqual({
          error: 'server_error',
          error_description: 'UserInfo request failed.',
        });
        expect(response.headers['www-authenticate']).toBeUndefined();
        expect(response.text.includes('canary')).toBe(false);
        expect(findUnique).toHaveBeenCalledExactlyOnceWith({
          where: { id: subject },
          select: { username: true, email: true },
        });
      },
    );
    it('does not inspect status or lock metadata and never spreads mocked row extras', async () => {
      findUnique.mockResolvedValue({
        username,
        email,
        status: 'DISABLED',
        lockedUntil: new Date(9999999999999),
        name: 'private',
        email_verified: false,
      });
      const response = await request(app.getHttpServer())
        [method]('/oidc/userinfo')
        .set('Authorization', 'Bearer ' + tokens[3])
        .expect(200);
      headers(response);
      expect(response.body as unknown).toEqual({
        sub: subject,
        preferred_username: username,
        email,
      });
      expect(findUnique).toHaveBeenCalledExactlyOnceWith({
        where: { id: subject },
        select: { username: true, email: true },
      });
    });
    it('requires Authorization, never redirects to login or loads keys for missing credentials', async () => {
      const response = await request(app.getHttpServer())
        [method]('/oidc/userinfo')
        .expect(401);
      headers(response);
      expect(response.headers['www-authenticate']).toBe(
        'Bearer realm="userinfo"',
      );
      expect(response.text).toBe('');
      expect(getPublicVerificationKey).not.toHaveBeenCalled();
      expect(getKeyId).not.toHaveBeenCalled();
      expect(findUnique).not.toHaveBeenCalled();
    });
    it('does not authenticate using a session cookie or access_token query parameter', async () => {
      const response = await request(app.getHttpServer())
        [method]('/oidc/userinfo?access_token=' + encodeURIComponent(tokens[0]))
        .set('Cookie', 'iam.sid=' + subject)
        .expect(401);
      headers(response);
      expect(response.headers['www-authenticate']).toBe(
        'Bearer realm="userinfo"',
      );
      expect(getPublicVerificationKey).not.toHaveBeenCalled();
      expect(findUnique).not.toHaveBeenCalled();
    });
    it.each([
      'basic',
      'malformed-header',
      'malformed-jwt',
      'expired',
      'id-token',
    ])('rejects %s with one fixed invalid_token response', async (kind) => {
      const authorization =
        kind === 'basic'
          ? 'Basic cHVibGljOnNlY3JldA=='
          : kind === 'malformed-header'
            ? 'Bearer one two'
            : 'Bearer ' +
              (kind === 'expired'
                ? expired
                : kind === 'id-token'
                  ? idToken
                  : 'not.a.jwt');
      const response = await request(app.getHttpServer())
        [method]('/oidc/userinfo')
        .set('Authorization', authorization)
        .expect(401);
      headers(response);
      expect(response.body as unknown).toEqual(invalidBody);
      expect(response.headers['www-authenticate']).toBe(
        'Bearer realm="userinfo", error="invalid_token"',
      );
      expect(findUnique).not.toHaveBeenCalled();
    });
    it('rejects duplicate Authorization header lines instead of authenticating the first value', async () => {
      const response = await request(app.getHttpServer())
        [method]('/oidc/userinfo')
        .set({ Authorization: ['Bearer ' + tokens[0], 'Bearer ' + tokens[0]] })
        .expect(401);
      headers(response);
      expect(response.body as unknown).toEqual(invalidBody);
      expect(getPublicVerificationKey).not.toHaveBeenCalled();
    });
    it('returns insufficient_scope, not claims, for a valid profile-only access token', async () => {
      const response = await request(app.getHttpServer())
        [method]('/oidc/userinfo')
        .set('Authorization', 'Bearer ' + noOpenid)
        .expect(403);
      headers(response);
      expect(response.body as unknown).toEqual(insufficientBody);
      expect(findUnique).not.toHaveBeenCalled();
      expect(response.headers['www-authenticate']).toBe(
        'Bearer realm="userinfo", error="insufficient_scope", scope="openid"',
      );
    });
    it('ignores Host/Origin/forwarded headers, cookies and query claim/audience overrides', async () => {
      const response = await request(app.getHttpServer())
        [method](
          '/oidc/userinfo?sub=caller&scope=profile%20email&aud=caller&claims=email',
        )
        .set('Authorization', 'Bearer ' + tokens[0])
        .set('Host', 'caller.invalid')
        .set('Origin', 'https://caller.invalid')
        .set('X-Forwarded-Host', 'caller.invalid')
        .set('X-Forwarded-Proto', 'http')
        .set('Scope', 'profile email')
        .set('Cookie', 'iam.sid=untrusted')
        .expect(200);
      headers(response);
      expect(response.body as unknown).toEqual({ sub: subject });
      expect(findUnique).not.toHaveBeenCalled();
    });
    it.each(['config', 'key', 'kid', 'internal'])(
      'sanitizes %s operational failure as 500, not invalid_token',
      async (kind) => {
        const native = new Error('private-native-PEM-path-JWT-canary', {
          cause: new Error('private-native-canary'),
        });
        if (kind === 'config')
          vi.spyOn(config, 'getOrThrow').mockImplementation(() => {
            throw native;
          });
        if (kind === 'key') getPublicVerificationKey.mockRejectedValue(native);
        if (kind === 'kid') getKeyId.mockRejectedValue(native);
        if (kind === 'internal')
          vi.spyOn(
            app.get(UserInfoAccessTokenService),
            'authenticate',
          ).mockRejectedValue(native);
        const response = await request(app.getHttpServer())
          [method]('/oidc/userinfo')
          .set('Authorization', 'Bearer ' + tokens[0])
          .expect(500);
        headers(response);
        expect(response.body as unknown).toEqual({
          error: 'server_error',
          error_description: 'UserInfo request failed.',
        });
        expect(response.headers['www-authenticate']).toBeUndefined();
        expect(response.text.includes('canary')).toBe(false);
        expect(findUnique).not.toHaveBeenCalled();
      },
    );
  });
  it.each(['json', 'form'])(
    'does not accept POST body access_token transport (%s)',
    async (type) => {
      const input = request(app.getHttpServer()).post('/oidc/userinfo');
      const response = await (
        type === 'json'
          ? input.send({ access_token: tokens[0] })
          : input.type('form').send({ access_token: tokens[0] })
      ).expect(401);
      headers(response);
      expect(response.headers['www-authenticate']).toBe(
        'Bearer realm="userinfo"',
      );
      expect(getPublicVerificationKey).not.toHaveBeenCalled();
    },
  );
  it('does not use POST body to override the authenticated subject or scope', async () => {
    const response = await request(app.getHttpServer())
      .post('/oidc/userinfo')
      .set('Authorization', 'Bearer ' + tokens[0])
      .send({
        access_token: idToken,
        sub: 'caller',
        scope: 'profile',
        email: 'private-canary',
      })
      .expect(200);
    headers(response);
    expect(response.body as unknown).toEqual({ sub: subject });
  });
  it.each(['put', 'delete'] as const)(
    'does not add unsupported %s UserInfo semantics',
    async (method) => {
      await request(app.getHttpServer())[method]('/oidc/userinfo').expect(404);
    },
  );
});
