import { Logger } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { Test } from '@nestjs/testing';
import { generateKeyPairSync } from 'node:crypto';
import { mkdtemp, realpath, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, dirname, join } from 'node:path';
import {
  generateKeyPair,
  importJWK,
  jwtVerify,
  SignJWT,
  type CryptoKey,
} from 'jose';
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
import { authorizationCodeStateSchema } from '../oauth/authorization-code.state.js';
import { DiscoveryController } from './discovery.controller.js';
import { DiscoveryService } from './discovery.service.js';
import { JwksController } from './jwks.controller.js';
import { JwksService } from './jwks.service.js';
import {
  IdTokenClaimsService,
  type IdTokenClaimsInput,
} from './id-token-claims.service.js';
import { IdTokenIssuerService } from './id-token-issuer.service.js';
import { OidcModule } from './oidc.module.js';
import { UserInfoClaimsService } from './userinfo-claims.service.js';
import { PrismaModule } from '../prisma/prisma.module.js';
import { PrismaService } from '../prisma/prisma.service.js';
import { UserInfoAccessTokenService } from './userinfo-access-token.service.js';
import { UserInfoController } from './userinfo.controller.js';

const input: IdTokenClaimsInput = {
  subject: 'c0e21e3f-d3ee-425c-a99f-c2e7a7cab53f',
  audience: 'student-spa',
  nonce: 'opaque-nonce-value',
  ttlSeconds: 600,
};
const issuerUrl = 'https://IAM.example.test:443/issuer/';
const kid = ' MiXeD-e\u0301-Key ';

describe('IdTokenIssuerService internal RS256/JWKS capability', () => {
  let directory: string;
  let keys: SigningKeyService;
  let unrelatedPublicKey: CryptoKey;
  let claims: IdTokenClaimsService;
  let issuer: IdTokenIssuerService;
  let logs: MockInstance[];
  beforeAll(async () => {
    directory = await mkdtemp(join(await realpath(tmpdir()), 'iam-m73-owned-'));
    const pair = generateKeyPairSync('rsa', {
      modulusLength: 2048,
      privateKeyEncoding: { format: 'pem', type: 'pkcs8' },
      publicKeyEncoding: { format: 'pem', type: 'spki' },
    });
    const privatePath = join(directory, 'private.pem');
    const publicPath = join(directory, 'public.pem');
    await Promise.all([
      writeFile(privatePath, pair.privateKey, { mode: 0o600 }),
      writeFile(publicPath, pair.publicKey, { mode: 0o644 }),
    ]);
    // Real M6.5 loading/pair validation: no alternate ID-token key/cache path.
    keys = new SigningKeyService(
      new ConfigService({
        JWT_PRIVATE_KEY_PATH: privatePath,
        JWT_PUBLIC_KEY_PATH: publicPath,
        JWT_KEY_ID: kid,
      }),
    );
    unrelatedPublicKey = (
      await generateKeyPair('RS256', { modulusLength: 2048 })
    ).publicKey;
  }, 30000);
  afterAll(async () => {
    // Resolve and bound only the owned temporary fixture before recursive cleanup.
    const target = await realpath(directory);
    expect(dirname(target)).toBe(await realpath(tmpdir()));
    expect(basename(target).startsWith('iam-m73-owned-')).toBe(true);
    await rm(target, { recursive: true, force: true });
  });
  beforeEach(() => {
    vi.clearAllMocks();
    claims = new IdTokenClaimsService(
      new ConfigService({ ISSUER_URL: issuerUrl }),
    );
    issuer = new IdTokenIssuerService(claims, keys);
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
  const verificationOptions = {
    algorithms: ['RS256'],
    issuer: issuerUrl,
    audience: 'student-spa',
  };

  it('signs exactly six claims with alg/kid only, one clock and the same M6.5/M7.2 JWKS public key', async () => {
    const now = Date.now();
    const clock = vi.spyOn(Date, 'now').mockReturnValue(now);
    const build = vi.spyOn(claims, 'build');
    const privateKey = vi.spyOn(keys, 'getPrivateSigningKey');
    const getKid = vi.spyOn(keys, 'getKeyId');
    const result = await issuer.issue(input);
    expect(Object.keys(result)).toEqual(['idToken']);
    expect(
      typeof result.idToken === 'string' &&
        result.idToken.split('.').length === 3,
    ).toBe(true);
    expect(clock).toHaveBeenCalledOnce();
    expect(build).toHaveBeenCalledExactlyOnceWith(input);
    expect(privateKey).toHaveBeenCalledExactlyOnceWith();
    expect(getKid).toHaveBeenCalledExactlyOnceWith();
    expect(build.mock.invocationCallOrder[0]).toBeLessThan(
      privateKey.mock.invocationCallOrder[0],
    );
    expect(privateKey.mock.invocationCallOrder[0]).toBeLessThan(
      getKid.mock.invocationCallOrder[0],
    );
    const document = await new JwksService(keys).build();
    const jwkKey = await importJWK(document.keys[0], 'RS256');
    for (const publicKey of [jwkKey, await keys.getPublicVerificationKey()]) {
      const { payload, protectedHeader } = await jwtVerify(
        result.idToken,
        publicKey,
        verificationOptions,
      );
      expect(protectedHeader).toEqual({ alg: 'RS256', kid });
      expect(protectedHeader.kid).toBe(await keys.getKeyId());
      expect(protectedHeader.kid).toBe(document.keys[0].kid);
      expect(Object.keys(payload).sort()).toEqual([
        'aud',
        'exp',
        'iat',
        'iss',
        'nonce',
        'sub',
      ]);
      expect(payload).toEqual({
        iss: issuerUrl,
        sub: input.subject,
        aud: 'student-spa',
        iat: Math.floor(now / 1000),
        exp: Math.floor(now / 1000) + 600,
        nonce: 'opaque-nonce-value',
      });
      expect(payload.aud).not.toBe('student-api');
      expect(payload.exp! - payload.iat!).toBe(600);
    }
  });
  it('preserves opaque client_id and nonce values in the signed payload without normalization', async () => {
    const audience = ' OAuth-e\u0301-Client ';
    const nonce = ' Nonce +%2F e\u0301💠 ';
    const { idToken } = await issuer.issue({
      ...input,
      audience,
      nonce,
      ttlSeconds: 37,
    });
    const verified = await jwtVerify(
      idToken,
      await keys.getPublicVerificationKey(),
      {
        ...verificationOptions,
        audience,
      },
    );
    expect(verified.payload.aud).toBe(audience);
    expect(verified.payload.nonce).toBe(nonce);
    expect(verified.payload.exp! - verified.payload.iat!).toBe(37);
  });
  it('demonstrates explicit userId/clientId/nonce mapping from validated grant state without coupling the builder to it', async () => {
    const state = authorizationCodeStateSchema.parse({
      userId: input.subject,
      clientId: 'student-spa',
      redirectUri: 'http://localhost:3200/callback',
      grantedScopes: ['openid'],
      codeChallenge: null,
      nonce: input.nonce,
      authTime: Date.now() - 1000,
      expiresAt: Date.now() + 120000,
    });
    // Future integration must supply these values explicitly; no code/store access here.
    const { idToken } = await issuer.issue({
      subject: state.userId,
      audience: state.clientId,
      nonce: state.nonce!,
      ttlSeconds: 600,
    });
    const { payload } = await jwtVerify(
      idToken,
      await keys.getPublicVerificationKey(),
      verificationOptions,
    );
    expect(payload.sub).toBe(state.userId);
    expect(payload.aud).toBe(state.clientId);
    expect(payload.nonce).toBe(state.nonce);
    expect(payload).not.toHaveProperty('auth_time');
  });
  it('rejects tampered payload/signature and an unrelated verification key', async () => {
    const { idToken } = await issuer.issue(input);
    const [header, body, signature] = idToken.split('.') as [
      string,
      string,
      string,
    ];
    const altered = Buffer.from(
      JSON.stringify({
        ...(JSON.parse(Buffer.from(body, 'base64url').toString()) as object),
        nonce: 'tampered',
      }),
    ).toString('base64url');
    const changedSignature =
      (signature[0] === 'A' ? 'B' : 'A') + signature.slice(1);
    for (const [candidate, key] of [
      [
        `${header}.${altered}.${signature}`,
        await keys.getPublicVerificationKey(),
      ],
      [
        `${header}.${body}.${changedSignature}`,
        await keys.getPublicVerificationKey(),
      ],
      [idToken, unrelatedPublicKey],
    ] as const) {
      // Never dump compact tokens on assertion failure.
      const rejected = await jwtVerify(
        candidate,
        key,
        verificationOptions,
      ).then(
        () => false,
        () => true,
      );
      expect(rejected).toBe(true);
    }
  });
  it.each(['claims', 'key', 'kid', 'sign', 'native-sign'])(
    'sanitizes %s failure without native/private cause or sensitive logging',
    async (stage) => {
      const native = new Error('private-signing-canary', {
        cause: new Error('private-signing-canary'),
      });
      if (stage === 'claims')
        vi.spyOn(claims, 'build').mockImplementation(() => {
          throw native;
        });
      if (stage === 'key')
        vi.spyOn(keys, 'getPrivateSigningKey').mockRejectedValue(native);
      if (stage === 'kid') vi.spyOn(keys, 'getKeyId').mockRejectedValue(native);
      if (stage === 'sign')
        vi.spyOn(keys, 'getPrivateSigningKey').mockResolvedValue(
          await keys.getPublicVerificationKey(),
        );
      if (stage === 'native-sign')
        vi.spyOn(SignJWT.prototype, 'sign').mockRejectedValue(native);
      const error: unknown = await issuer
        .issue(input)
        .catch((caught: unknown) => caught);
      expect(error).toBeInstanceOf(Error);
      expect((error as Error).message).toBe('ID token issuance failed.');
      expect((error as Error).cause).toBeUndefined();
      expect(
        [
          'private-signing-canary',
          directory,
          input.subject,
          input.audience,
          input.nonce,
          kid,
        ].some((marker) => (error as Error).stack?.includes(marker)),
      ).toBe(false);
    },
  );
  it.each([undefined, null, ''])(
    'fails closed for absent/empty OIDC nonce %# before key access',
    async (nonce) => {
      const privateKey = vi.spyOn(keys, 'getPrivateSigningKey');
      const getKid = vi.spyOn(keys, 'getKeyId');
      const error: unknown = await issuer
        .issue({ ...input, nonce } as IdTokenClaimsInput)
        .catch((caught: unknown) => caught);
      expect((error as Error).message).toBe('ID token issuance failed.');
      expect((error as Error).cause).toBeUndefined();
      expect(privateKey).not.toHaveBeenCalled();
      expect(getKid).not.toHaveBeenCalled();
    },
  );
  it('exports only the ID-token issuer for M7.6 while keeping construction lazy', async () => {
    expect(Reflect.getMetadata('imports', OidcModule) as unknown).toEqual([
      ConfigModule,
      SigningKeyModule,
      PrismaModule,
    ]);
    expect(Reflect.getMetadata('providers', OidcModule) as unknown).toEqual([
      DiscoveryService,
      JwksService,
      IdTokenClaimsService,
      IdTokenIssuerService,
      UserInfoAccessTokenService,
      UserInfoClaimsService,
    ]);
    expect(Reflect.getMetadata('controllers', OidcModule) as unknown).toEqual([
      DiscoveryController,
      JwksController,
      UserInfoController,
    ]);
    expect(
      (Reflect.getMetadata('exports', OidcModule) as unknown) ?? [],
    ).toEqual([IdTokenIssuerService]);
    expect(
      Reflect.getMetadata('__module:global__', OidcModule) as unknown,
    ).not.toBe(true);
    const build = vi.spyOn(IdTokenClaimsService.prototype, 'build');
    const issue = vi.spyOn(IdTokenIssuerService.prototype, 'issue');
    const get = vi.fn(() => {
      throw new Error('Unexpected eager config access.');
    });
    const keyAccess = vi.fn(() => {
      throw new Error('Unexpected eager key access.');
    });
    const module = await Test.createTestingModule({ imports: [OidcModule] })
      .overrideProvider(PrismaService)
      .useValue({})
      .overrideProvider(ConfigService)
      .useValue({ getOrThrow: get })
      .overrideProvider(SigningKeyService)
      .useValue({
        getPrivateSigningKey: keyAccess,
        getPublicVerificationKey: keyAccess,
        getPublicJwk: keyAccess,
        getKeyId: keyAccess,
      })
      .compile();
    try {
      for (const log of logs) log.mockClear(); // Nest DI messages are not capability logs.
      expect(module.get(IdTokenIssuerService)).toBeInstanceOf(
        IdTokenIssuerService,
      );
      expect(module.get(IdTokenClaimsService)).toBeInstanceOf(
        IdTokenClaimsService,
      );
      expect(get).not.toHaveBeenCalled();
      expect(build).not.toHaveBeenCalled();
      expect(issue).not.toHaveBeenCalled();
      expect(keyAccess).not.toHaveBeenCalled();
    } finally {
      await module.close();
    }
  });
});
