import { Logger } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { Test } from '@nestjs/testing';
import { generateKeyPair, jwtVerify, SignJWT, type CryptoKey } from 'jose';
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
import { SigningKeyModule } from '../security/signing/signing-key.module.js';
import { SigningKeyService } from '../security/signing/signing-key.service.js';
import {
  AccessTokenClaimsService,
  type AccessTokenClaimsInput,
} from './access-token-claims.service.js';
import { AccessTokenIssuerService } from './access-token-issuer.service.js';
import { TokensModule } from './tokens.module.js';
import { RefreshTokenGeneratorService } from './refresh-token-generator.service.js';
import { RefreshTokenIssuerService } from './refresh-token-issuer.service.js';
import { RefreshTokenGrantService } from './refresh-token-grant.service.js';
import { PrismaModule } from '../prisma/prisma.module.js';
import { PrismaService } from '../prisma/prisma.service.js';

const input: AccessTokenClaimsInput = {
  subject: 'c0e21e3f-d3ee-425c-a99f-c2e7a7cab53f',
  audience: ' exact e\u0301 API ',
  scopes: ['profile', 'openid', 'profile'],
  roles: [],
  permissions: [],
  ttlSeconds: 321,
};

describe('M6.7 issuer combines unchanged claims + keys through JOSE', () => {
  let privateKey: CryptoKey;
  let publicKey: CryptoKey;
  let unrelated: CryptoKey;
  let logs: MockInstance[];
  const claims = new AccessTokenClaimsService(
    new ConfigService({ ISSUER_URL: 'http://localhost:3000' }),
  );
  const getPrivateSigningKey = vi.fn<() => Promise<CryptoKey>>();
  const getKeyId = vi.fn<() => Promise<string>>();
  const issuer = new AccessTokenIssuerService(claims, {
    getPrivateSigningKey,
    getKeyId,
  } as unknown as SigningKeyService);
  beforeAll(async () => {
    ({ privateKey, publicKey } = await generateKeyPair('RS256', {
      modulusLength: 2048,
    }));
    unrelated = (await generateKeyPair('RS256', { modulusLength: 2048 }))
      .privateKey;
  });
  beforeEach(() => {
    vi.clearAllMocks();
    getPrivateSigningKey.mockResolvedValue(privateKey);
    getKeyId.mockResolvedValue('test-kid');
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
      for (const log of logs) expect(log).not.toHaveBeenCalled();
    } finally {
      vi.restoreAllMocks();
    }
  });
  it('verifies signature and exact header/payload, returns only safe metadata and uses one issuance clock', async () => {
    const now = Date.now();
    const clock = vi.spyOn(Date, 'now').mockReturnValue(now);
    const build = vi.spyOn(claims, 'build');
    const token = await issuer.issue(input);
    expect(clock).toHaveBeenCalledOnce();
    expect(build).toHaveBeenCalledExactlyOnceWith(input);
    expect(Object.keys(token).sort()).toEqual([
      'accessToken',
      'expiresIn',
      'scope',
    ]);
    const { payload, protectedHeader } = await jwtVerify(
      token.accessToken,
      publicKey,
      {
        algorithms: ['RS256'],
        issuer: 'http://localhost:3000',
        audience: input.audience,
      },
    );
    expect(protectedHeader).toEqual({ alg: 'RS256', kid: 'test-kid' });
    expect(payload).toEqual({
      iss: 'http://localhost:3000',
      sub: input.subject,
      aud: input.audience,
      iat: Math.floor(now / 1000),
      exp: Math.floor(now / 1000) + 321,
      scope: 'profile openid profile',
      roles: [],
      permissions: [],
    });
    expect(token.expiresIn).toBe(321);
    expect(token.scope).toBe(payload.scope);
    expect(build.mock.invocationCallOrder[0]).toBeLessThan(
      getPrivateSigningKey.mock.invocationCallOrder[0],
    );
  });
  it('rejects changed payload/signature and a token signed by an unrelated key', async () => {
    const { accessToken } = await issuer.issue(input);
    const [header, body, signature] = accessToken.split('.') as [
      string,
      string,
      string,
    ];
    const altered = Buffer.from(
      JSON.stringify({
        ...(JSON.parse(Buffer.from(body, 'base64url').toString()) as object),
        aud: 'wrong-api',
      }),
    ).toString('base64url');
    const changedSignature =
      (signature[0] === 'A' ? 'B' : 'A') + signature.slice(1);
    const other = await new SignJWT(claims.build(input))
      .setProtectedHeader({ alg: 'RS256', kid: 'test-kid' })
      .sign(unrelated);
    for (const candidate of [
      `${header}.${altered}.${signature}`,
      `${header}.${body}.${changedSignature}`,
      other,
    ]) {
      // Boolean assertion prevents compact tokens from appearing in assertion output.
      const rejected = await jwtVerify(candidate, publicKey, {
        algorithms: ['RS256'],
      }).then(
        () => false,
        () => true,
      );
      expect(rejected).toBe(true);
    }
  });
  it.each(['claims', 'key', 'kid', 'sign'])(
    'sanitizes %s failure without native causes',
    async (stage) => {
      const cause = new Error('private key PEM path native details');
      if (stage === 'claims')
        vi.spyOn(claims, 'build').mockImplementation(() => {
          throw cause;
        });
      if (stage === 'key') getPrivateSigningKey.mockRejectedValue(cause);
      if (stage === 'kid') getKeyId.mockRejectedValue(cause);
      if (stage === 'sign') getPrivateSigningKey.mockResolvedValue(publicKey);
      const error: unknown = await issuer
        .issue(input)
        .catch((value: unknown) => value);
      expect(error).toBeInstanceOf(Error);
      expect((error as Error).message).toBe('Access token issuance failed.');
      expect((error as Error).cause).toBeUndefined();
    },
  );
  it('exports focused claims/issuer providers, without controllers, global scope or eager key access', async () => {
    expect(Reflect.getMetadata('imports', TokensModule) as unknown).toEqual([
      ConfigModule,
      SigningKeyModule,
      PrismaModule,
    ]);
    expect(Reflect.getMetadata('providers', TokensModule) as unknown).toEqual([
      AccessTokenClaimsService,
      AccessTokenIssuerService,
      RefreshTokenGeneratorService,
      RefreshTokenIssuerService,
      RefreshTokenGrantService,
    ]);
    expect(Reflect.getMetadata('exports', TokensModule) as unknown).toEqual([
      AccessTokenClaimsService,
      AccessTokenIssuerService,
      RefreshTokenGeneratorService,
      RefreshTokenIssuerService,
      RefreshTokenGrantService,
    ]);
    expect(
      (Reflect.getMetadata('controllers', TokensModule) as unknown) ?? [],
    ).toEqual([]);
    expect(
      Reflect.getMetadata('__module:global__', TokensModule) as unknown,
    ).not.toBe(true);
    const generate = vi.spyOn(
      RefreshTokenGeneratorService.prototype,
      'generate',
    );
    const hash = vi.spyOn(RefreshTokenGeneratorService.prototype, 'hash');
    const transaction = vi.fn();
    const module = await Test.createTestingModule({ imports: [TokensModule] })
      .overrideProvider(ConfigService)
      .useValue(new ConfigService({}))
      .overrideProvider(SigningKeyService)
      .useValue({ getPrivateSigningKey, getKeyId })
      .overrideProvider(PrismaService)
      .useValue({ $transaction: transaction })
      .compile();
    try {
      for (const log of logs) log.mockClear();
      expect(module.get(AccessTokenIssuerService)).toBeInstanceOf(
        AccessTokenIssuerService,
      );
      expect(getPrivateSigningKey).not.toHaveBeenCalled();
      expect(getKeyId).not.toHaveBeenCalled();
      expect(module.get(RefreshTokenGeneratorService)).toBeInstanceOf(
        RefreshTokenGeneratorService,
      );
      expect(generate).not.toHaveBeenCalled();
      expect(hash).not.toHaveBeenCalled();
      expect(module.get(RefreshTokenIssuerService)).toBeInstanceOf(
        RefreshTokenIssuerService,
      );
      expect(transaction).not.toHaveBeenCalled();
    } finally {
      await module.close();
    }
  });
});
