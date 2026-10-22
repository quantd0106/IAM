import { Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as jose from 'jose';
import {
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
import { SigningKeyService } from '../security/signing/signing-key.service.js';
import { AccessTokenClaimsService } from '../tokens/access-token-claims.service.js';
import { AccessTokenIssuerService } from '../tokens/access-token-issuer.service.js';
import { IdTokenClaimsService } from './id-token-claims.service.js';
import { IdTokenIssuerService } from './id-token-issuer.service.js';
import { UserInfoAccessTokenService } from './userinfo-access-token.service.js';

const { forbiddenImport, forbiddenIO } = vi.hoisted(() => ({
  forbiddenImport: vi.fn(() => {
    throw new Error('Unexpected UserInfo dependency.');
  }),
  forbiddenIO: vi.fn(() => {
    throw new Error('Unexpected UserInfo I/O/private-key operation.');
  }),
}));
vi.mock('../security/signing/signing-key.service.js', () => ({
  SigningKeyService: class {},
}));
vi.mock('../prisma/prisma.service.js', () => {
  forbiddenImport();
  return {};
});
vi.mock('../redis/redis.service.js', () => {
  forbiddenImport();
  return {};
});
vi.mock('jose', async (original) => {
  const actual = await original<typeof import('jose')>();
  return { ...actual, jwtVerify: vi.fn(actual.jwtVerify) };
});
vi.mock('node:fs/promises', async (original) => ({
  ...(await original<typeof import('node:fs/promises')>()),
  readFile: forbiddenIO,
  writeFile: forbiddenIO,
}));
vi.mock('node:fs', async (original) => ({
  ...(await original<typeof import('node:fs')>()),
  readFile: forbiddenIO,
  readFileSync: forbiddenIO,
  writeFile: forbiddenIO,
  writeFileSync: forbiddenIO,
}));
vi.mock('node:http', async (original) => ({
  ...(await original<typeof import('node:http')>()),
  get: forbiddenIO,
  request: forbiddenIO,
}));
vi.mock('node:https', async (original) => ({
  ...(await original<typeof import('node:https')>()),
  get: forbiddenIO,
  request: forbiddenIO,
}));
const realJose = await vi.importActual<typeof import('jose')>('jose');
const subject = 'c0e21e3f-d3ee-425c-a99f-c2e7a7cab53f';
const issuerUrl = 'https://IAM.example.test:443/issuer/';
const kid = 'MiXeD-e\u0301-Key';
const invalid = { ok: false, error: 'invalid_token' };

describe('UserInfoAccessTokenService stateless canonical access-token boundary', () => {
  let privateKey: jose.CryptoKey;
  let publicKey: jose.CryptoKey;
  let unrelated: jose.CryptoKey;
  let ec: jose.CryptoKey;
  let config: ConfigService<Environment, true>;
  let service: UserInfoAccessTokenService;
  let logs: MockInstance[];
  const getPublicVerificationKey = vi.fn<() => Promise<jose.CryptoKey>>();
  const getKeyId = vi.fn<() => Promise<string>>();
  const verificationKeys = {
    getPublicVerificationKey,
    getKeyId,
    getPrivateSigningKey: forbiddenIO,
    getPublicJwk: forbiddenIO,
  } as unknown as SigningKeyService;
  const claims = () =>
    new AccessTokenClaimsService(
      new ConfigService({ ISSUER_URL: issuerUrl }),
    ).build({
      subject,
      audience: 'student-api',
      scopes: ['openid'],
      roles: [],
      permissions: [],
      ttlSeconds: 600,
    });
  const signer = () =>
    ({
      getPrivateSigningKey: () => Promise.resolve(privateKey),
      getKeyId: () => Promise.resolve(kid),
    }) as unknown as SigningKeyService;
  const accessToken = async (
    scopes = ['openid'],
    audience = 'student-api',
  ): Promise<string> =>
    (
      await new AccessTokenIssuerService(
        new AccessTokenClaimsService(
          new ConfigService({ ISSUER_URL: issuerUrl }),
        ),
        signer(),
      ).issue({
        subject,
        audience,
        scopes,
        roles: [],
        permissions: [],
        ttlSeconds: 600,
      })
    ).accessToken;
  // Test-only JOSE signing permits malformed JSON/claims fixtures without custom crypto.
  const signed = (
    payload: unknown,
    header: jose.CompactJWSHeaderParameters = { alg: 'RS256', kid },
    key = privateKey,
  ) =>
    new jose.CompactSign(new TextEncoder().encode(JSON.stringify(payload)))
      .setProtectedHeader(header)
      .sign(key);
  beforeAll(async () => {
    ({ privateKey, publicKey } = await jose.generateKeyPair('RS256', {
      modulusLength: 2048,
    }));
    unrelated = (await jose.generateKeyPair('RS256', { modulusLength: 2048 }))
      .privateKey;
    ec = (await jose.generateKeyPair('ES256')).privateKey;
  });
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(jose.jwtVerify).mockImplementation(realJose.jwtVerify);
    getPublicVerificationKey.mockResolvedValue(publicKey);
    getKeyId.mockResolvedValue(kid);
    config = new ConfigService<Environment, true>({ ISSUER_URL: issuerUrl });
    service = new UserInfoAccessTokenService(config, verificationKeys);
    vi.spyOn(globalThis, 'fetch').mockImplementation(forbiddenIO);
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
      expect(forbiddenImport).not.toHaveBeenCalled();
      expect(forbiddenIO).not.toHaveBeenCalled();
      for (const log of logs) expect(log).not.toHaveBeenCalled();
    } finally {
      vi.restoreAllMocks();
    }
  });
  const checkInvalid = async (token: string): Promise<void> => {
    expect(await service.authenticate('Bearer ' + token)).toEqual(invalid);
  };
  const safeFailure = async (work: Promise<unknown>): Promise<void> => {
    const error: unknown = await work.catch((caught: unknown) => caught);
    expect(error).toBeInstanceOf(Error);
    expect((error as Error).message).toBe(
      'UserInfo access-token validation failed.',
    );
    expect((error as Error).cause).toBeUndefined();
    expect((error as Error).stack?.includes('private-native-canary')).toBe(
      false,
    );
  };

  it.each([
    [['openid'], 'student-api'],
    [['openid', 'profile'], 'student-api'],
    [['openid', 'email'], 'banking-api'],
    [['openid', 'profile', 'email'], 'identity-server'],
    [['profile', 'openid', 'openid'], ' opaque-e\u0301-resource '],
  ] as [string[], string][])(
    'accepts genuine M6.7 token %# under the explicit single-resource-audience policy',
    async (scopes, audience) => {
      const token = await accessToken(scopes, audience);
      const get = vi.spyOn(config, 'getOrThrow');
      expect(await service.authenticate('Bearer ' + token)).toEqual({
        ok: true,
        subject,
        scopes,
      });
      expect(get).toHaveBeenCalledExactlyOnceWith('ISSUER_URL', {
        infer: true,
      });
      expect(getPublicVerificationKey).toHaveBeenCalledExactlyOnceWith();
      expect(getKeyId).toHaveBeenCalledExactlyOnceWith();
      const call = vi.mocked(jose.jwtVerify).mock.calls[0];
      expect(call[0] === token && call[1] === publicKey).toBe(true);
      expect(call[2]).toEqual({
        algorithms: ['RS256'],
        issuer: issuerUrl,
        requiredClaims: [
          'iss',
          'sub',
          'aud',
          'iat',
          'exp',
          'scope',
          'roles',
          'permissions',
        ],
      });
    },
  );
  it.each(['bearer ', 'BEARER ', 'bEaReR   '])(
    'accepts HTTP scheme case/1*SP %# without changing the compact token',
    async (prefix) => {
      const token = await accessToken();
      expect(await service.authenticate(prefix + token)).toEqual({
        ok: true,
        subject,
        scopes: ['openid'],
      });
      expect(vi.mocked(jose.jwtVerify).mock.calls[0][0] === token).toBe(true);
    },
  );
  it('returns fresh verified scope arrays preserving order/duplicates without exposing other claims', async () => {
    const scopes = ['email', 'openid', 'profile', 'openid'];
    const token = await accessToken(scopes);
    const first = await service.authenticate('Bearer ' + token);
    const second = await service.authenticate('Bearer ' + token);
    expect(first).toEqual({ ok: true, subject, scopes });
    expect(second).toEqual(first);
    if (!first.ok || !second.ok) throw new Error('Expected verified grants.');
    expect(first.scopes).not.toBe(second.scopes);
    first.scopes.push('injected');
    expect(second.scopes).toEqual(scopes);
    expect(scopes).toEqual(['email', 'openid', 'profile', 'openid']);
  });
  it('distinguishes missing credentials before any key/config access', async () => {
    const get = vi.spyOn(config, 'getOrThrow');
    expect(await service.authenticate(undefined)).toEqual({
      ok: false,
      error: 'missing_credentials',
    });
    expect(get).not.toHaveBeenCalled();
    expect(getPublicVerificationKey).not.toHaveBeenCalled();
    expect(getKeyId).not.toHaveBeenCalled();
  });
  it.each([
    null,
    [],
    ['Bearer x'],
    {},
    1,
    '',
    'Basic abc',
    'Bearer',
    'Bearer ',
    ' Bearer x',
    'Bearer\tx',
    'Bearer "x"',
    'Bearer x y',
    'Bearer x, Bearer y',
    'Bearer x\n',
    'Bearer x\r\n',
    'Bearer x%2F',
    'Bearer x ',
  ])(
    'rejects malformed/repeated/structured Authorization %# without normalization or key access',
    async (header) => {
      expect(await service.authenticate(header)).toEqual(invalid);
      expect(getPublicVerificationKey).not.toHaveBeenCalled();
      expect(getKeyId).not.toHaveBeenCalled();
    },
  );
  it.each(['profile', 'profile email', 'OpenID', 'myopenid', 'openid.other'])(
    'requires exact tokenized openid, not scope %#',
    async (scope) => {
      expect(
        await service.authenticate(
          'Bearer ' + (await signed({ ...claims(), scope })),
        ),
      ).toEqual({ ok: false, error: 'insufficient_scope' });
    },
  );
  it('rejects the real M7.3 ID Token despite a valid shared signature/issuer/subject/expiry', async () => {
    const { idToken } = await new IdTokenIssuerService(
      new IdTokenClaimsService(new ConfigService({ ISSUER_URL: issuerUrl })),
      signer(),
    ).issue({
      subject,
      audience: 'student-spa',
      nonce: 'opaque-nonce-value',
      ttlSeconds: 600,
    });
    await checkInvalid(idToken);
  });
  it.each([
    'issuer',
    'expired',
    'missing-kid',
    'wrong-kid',
    'kid-case',
    'kid-normalization',
    'unrelated-key',
    'payload',
    'signature',
    'malformed',
  ])(
    'rejects cryptographic/issuer/header failure %# with the same result',
    async (kind) => {
      let token: string;
      if (kind === 'issuer')
        token = await signed({ ...claims(), iss: issuerUrl.toLowerCase() });
      else if (kind === 'expired')
        token = await signed({ ...claims(), iat: 0, exp: 1 });
      else if (kind === 'missing-kid')
        token = await signed(claims(), { alg: 'RS256' });
      else if (kind === 'wrong-kid')
        token = await signed(claims(), { alg: 'RS256', kid: 'wrong' });
      else if (kind === 'kid-case')
        token = await signed(claims(), {
          alg: 'RS256',
          kid: kid.toLowerCase(),
        });
      else if (kind === 'kid-normalization')
        token = await signed(claims(), {
          alg: 'RS256',
          kid: kid.normalize('NFC'),
        });
      else if (kind === 'unrelated-key')
        token = await signed(claims(), { alg: 'RS256', kid }, unrelated);
      else if (kind === 'malformed') token = 'not.a.jwt';
      else {
        const parts = (await accessToken()).split('.');
        if (kind === 'payload')
          parts[1] = Buffer.from(
            JSON.stringify({ ...claims(), sub: 'tampered' }),
          ).toString('base64url');
        else parts[2] = (parts[2][0] === 'A' ? 'B' : 'A') + parts[2].slice(1);
        token = parts.join('.');
      }
      await checkInvalid(token);
    },
  );
  it.each(['HS256', 'ES256', 'none'])(
    'rejects %s, without key-type/algorithm confusion',
    async (alg) => {
      let token: string;
      if (alg === 'HS256')
        token = await new jose.SignJWT(claims())
          .setProtectedHeader({ alg, kid })
          .sign(new Uint8Array(32).fill(7));
      else if (alg === 'ES256')
        token = await signed(claims(), { alg, kid }, ec);
      else
        token = [
          Buffer.from(JSON.stringify({ alg, kid })).toString('base64url'),
          Buffer.from(JSON.stringify(claims())).toString('base64url'),
          '',
        ].join('.');
      await checkInvalid(token);
    },
  );
  it.each(['iss', 'sub', 'aud', 'iat', 'exp', 'scope', 'roles', 'permissions'])(
    'rejects missing required access-token field %s',
    async (field) => {
      const payload: Record<string, unknown> = { ...claims() };
      delete payload[field];
      await checkInvalid(await signed(payload));
    },
  );
  it.each([
    ['sub', 'not-a-uuid'],
    ['sub', 1],
    ['aud', ''],
    ['aud', null],
    ['aud', ['student-api']],
    ['aud', 1],
    ['iat', -1],
    ['iat', 1.5],
    ['iat', '1'],
    ['iat', Number.MAX_SAFE_INTEGER + 1],
    ['exp', '9999999999'],
    ['exp', 9999999999.5],
    ['exp', Number.MAX_SAFE_INTEGER + 1],
    ['roles', null],
    ['roles', 'role'],
    ['roles', [1]],
    ['roles', ['']],
    ['permissions', 'permission'],
    ['permissions', [false]],
    ['scope', null],
    ['scope', ['openid']],
    ['scope', ''],
    ['scope', ' openid'],
    ['scope', 'openid '],
    ['scope', 'openid  email'],
    ['scope', 'openid\temail'],
    ['scope', 'openid\n'],
    ['scope', 'openid café'],
    ['scope', 'openid a"b'],
    ['scope', 'openid a\\b'],
  ])(
    'rejects malformed canonical field %# without echoing it',
    async (field, value) => {
      await checkInvalid(await signed({ ...claims(), [field]: value }));
    },
  );
  it('requires exp > iat and rejects unlisted payload fields, even when issuer-signed', async () => {
    const payload = claims();
    await checkInvalid(await signed({ ...payload, iat: payload.exp }));
    await checkInvalid(await signed({ ...payload, iat: payload.exp + 1 }));
    await checkInvalid(
      await signed({ ...payload, email: 'private-native-canary' }),
    );
    await checkInvalid(await signed(['not', 'a', 'claims object']));
  });
  it('does not follow token-supplied jku/JWK URLs or access private/JWKS capabilities', async () => {
    expect(
      await service.authenticate(
        'Bearer ' +
          (await signed(claims(), {
            alg: 'RS256',
            kid,
            jku: 'https://private-native-canary.invalid/jwks',
          })),
      ),
    ).toEqual({ ok: true, subject, scopes: ['openid'] });
  });
  it.each(['config', 'config-shape', 'public-key', 'kid', 'unexpected-verify'])(
    'treats %s operational failure as sanitized internal error, never invalid credentials',
    async (stage) => {
      const native = new Error('private-native-canary', {
        cause: new Error('private-native-canary'),
      });
      if (stage === 'config')
        vi.spyOn(config, 'getOrThrow').mockImplementation(() => {
          throw native;
        });
      if (stage === 'config-shape')
        vi.spyOn(config, 'getOrThrow').mockReturnValue([]);
      if (stage === 'public-key')
        getPublicVerificationKey.mockRejectedValue(native);
      if (stage === 'kid') getKeyId.mockRejectedValue(native);
      if (stage === 'unexpected-verify')
        vi.mocked(jose.jwtVerify).mockRejectedValue(native);
      await safeFailure(service.authenticate('Bearer synthetic-canary'));
    },
  );
});
