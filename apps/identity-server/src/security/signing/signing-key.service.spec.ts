import { Logger } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { Test } from '@nestjs/testing';
import { generateKeyPairSync } from 'node:crypto';
import * as fs from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, dirname, join } from 'node:path';
import * as jose from 'jose';
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
import {
  validateEnvironment,
  type Environment,
} from '../../config/env.schema.js';
import { SigningKeyModule } from './signing-key.module.js';
import { SigningKeyService } from './signing-key.service.js';

vi.mock('node:fs/promises', async (original) => {
  const actual = await original<typeof import('node:fs/promises')>();
  return { ...actual, readFile: vi.fn(actual.readFile) };
});
vi.mock('jose', async (original) => {
  const actual = await original<typeof import('jose')>();
  return {
    ...actual,
    importPKCS8: vi.fn(actual.importPKCS8),
    importSPKI: vi.fn(actual.importSPKI),
    exportJWK: vi.fn(actual.exportJWK),
  };
});
const realFs =
  await vi.importActual<typeof import('node:fs/promises')>('node:fs/promises');
const realJose = await vi.importActual<typeof import('jose')>('jose');
const failure = 'Signing key initialization failed.';

describe('SigningKeyService lazy validated RS256 capability', () => {
  let directory: string;
  let privatePath: string;
  let publicPath: string;
  let pem: { privateKey: string; publicKey: string };
  let other: { privateKey: string; publicKey: string };
  let weak: { privateKey: string; publicKey: string };
  let ec: { privateKey: string; publicKey: string };
  let logs: MockInstance[];
  const rsa = (modulusLength: number) =>
    generateKeyPairSync('rsa', {
      modulusLength,
      privateKeyEncoding: { format: 'pem', type: 'pkcs8' },
      publicKeyEncoding: { format: 'pem', type: 'spki' },
    });
  const environment = (overrides: Record<string, unknown> = {}): Environment =>
    validateEnvironment({
      NODE_ENV: 'test',
      DATABASE_URL: 'postgresql://test:test@127.0.0.1:1/test',
      REDIS_URL: 'redis://127.0.0.1:1',
      ISSUER_URL: 'http://localhost:3000',
      JWT_PRIVATE_KEY_PATH: privatePath,
      JWT_PUBLIC_KEY_PATH: publicPath,
      JWT_KEY_ID: ' MiXeD-e\u0301-Key ',
      TOTP_ENCRYPTION_KEY: 'test-placeholder',
      ...overrides,
    });
  const service = (
    overrides: Record<string, unknown> = {},
  ): SigningKeyService =>
    new SigningKeyService(
      new ConfigService<Environment, true>(environment(overrides)),
    );
  const safeFailure = async (work: Promise<unknown>): Promise<void> => {
    const error: unknown = await work.catch((value: unknown) => value);
    expect(error).toBeInstanceOf(Error);
    const safe = error as Error;
    expect(safe.message).toBe(failure);
    expect(safe.cause).toBeUndefined();
    const text = safe.stack ?? safe.message;
    expect(
      [
        pem.privateKey,
        pem.publicKey,
        directory,
        privatePath,
        publicPath,
        'private-native-canary',
      ].some((value) => text.includes(value)),
    ).toBe(false);
  };
  beforeAll(async () => {
    directory = await realFs.mkdtemp(join(tmpdir(), 'iam-m65-owned-'));
    privatePath = join(directory, 'private.pem');
    publicPath = join(directory, 'public.pem');
    // Ephemeral fixtures only; no operational key is committed or reused.
    pem = rsa(2048);
    other = rsa(2048);
    weak = rsa(1024);
    ec = generateKeyPairSync('ec', {
      namedCurve: 'prime256v1',
      privateKeyEncoding: { format: 'pem', type: 'pkcs8' },
      publicKeyEncoding: { format: 'pem', type: 'spki' },
    });
    await Promise.all([
      realFs.writeFile(privatePath, pem.privateKey, { mode: 0o600 }),
      realFs.writeFile(publicPath, pem.publicKey),
    ]);
  }, 30000);
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(fs.readFile).mockImplementation(realFs.readFile);
    vi.mocked(jose.importPKCS8).mockImplementation(realJose.importPKCS8);
    vi.mocked(jose.importSPKI).mockImplementation(realJose.importSPKI);
    vi.mocked(jose.exportJWK).mockImplementation(realJose.exportJWK);
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
  afterAll(async () => {
    // Resolve and bound the exact owned directory before recursive cleanup on Windows.
    const target = await realFs.realpath(directory);
    expect(dirname(target)).toBe(await realFs.realpath(tmpdir()));
    expect(basename(target).startsWith('iam-m65-owned-')).toBe(true);
    await realFs.rm(target, { recursive: true, force: true });
  });

  it('exports one internal non-global capability without controllers or eager I/O', async () => {
    const module = await Test.createTestingModule({
      imports: [SigningKeyModule],
    })
      .overrideProvider(ConfigService)
      .useValue(new ConfigService<Environment, true>(environment()))
      .compile();
    // Nest emits benign DI startup messages; the service itself must not log.
    for (const log of logs) {
      expect(
        log.mock.calls
          .flat()
          .some(
            (value: unknown) =>
              typeof value === 'string' &&
              [pem.privateKey, pem.publicKey, directory].some((marker) =>
                value.includes(marker),
              ),
          ),
      ).toBe(false);
      log.mockClear();
    }
    try {
      expect(module.get(SigningKeyService)).toBeInstanceOf(SigningKeyService);
      expect(
        Reflect.getMetadata('imports', SigningKeyModule) as unknown,
      ).toEqual([ConfigModule]);
      expect(
        Reflect.getMetadata('exports', SigningKeyModule) as unknown,
      ).toEqual([SigningKeyService]);
      expect(
        (Reflect.getMetadata('controllers', SigningKeyModule) as unknown) ?? [],
      ).toEqual([]);
      expect(
        Reflect.getMetadata('__module:global__', SigningKeyModule) as unknown,
      ).not.toBe(true);
      expect(fs.readFile).not.toHaveBeenCalled();
      expect(jose.importPKCS8).not.toHaveBeenCalled();
      expect(jose.importSPKI).not.toHaveBeenCalled();
    } finally {
      await module.close();
    }
  });
  it('imports matching 2048-bit PKCS#8/SPKI keys for RS256, with a non-extractable private key', async () => {
    const keys = service();
    const privateKey = await keys.getPrivateSigningKey();
    const publicKey = await keys.getPublicVerificationKey();
    expect(privateKey.type).toBe('private');
    expect(privateKey.extractable).toBe(false);
    expect(privateKey.usages).toEqual(['sign']);
    expect(publicKey.type).toBe('public');
    expect(publicKey.usages).toEqual(['verify']);
    for (const key of [privateKey, publicKey])
      expect(key.algorithm).toMatchObject({
        name: 'RSASSA-PKCS1-v1_5',
        modulusLength: 2048,
        hash: { name: 'SHA-256' },
      });
    expect(jose.importPKCS8).toHaveBeenCalledTimes(1);
    expect(jose.importSPKI).toHaveBeenCalledTimes(1);
    // Assert booleans, not PEM values, so assertion failures cannot dump a private fixture.
    const privateCall = vi.mocked(jose.importPKCS8).mock.calls[0];
    expect(privateCall[0] === pem.privateKey).toBe(true);
    expect(privateCall.slice(1)).toEqual(['RS256', { extractable: false }]);
    expect(vi.mocked(jose.importSPKI).mock.calls[0].slice(1)).toEqual([
      'RS256',
      { extractable: true },
    ]);
    await expect(realJose.exportJWK(privateKey)).rejects.toThrow();
  });
  it('returns exactly public RSA JWK parameters and preserves configured kid after the existing config trim', async () => {
    const keys = service();
    const jwk = await keys.getPublicJwk();
    expect(await keys.getKeyId()).toBe('MiXeD-e\u0301-Key');
    expect(Object.keys(jwk).sort()).toEqual([
      'alg',
      'e',
      'kid',
      'kty',
      'n',
      'use',
    ]);
    expect(jwk).toMatchObject({
      kty: 'RSA',
      alg: 'RS256',
      use: 'sig',
      kid: 'MiXeD-e\u0301-Key',
    });
    expect(jwk.n).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(jwk.e).toMatch(/^[A-Za-z0-9_-]+$/);
    for (const parameter of ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k'])
      expect(jwk).not.toHaveProperty(parameter);
    expect(jose.exportJWK).toHaveBeenCalledExactlyOnceWith(
      await keys.getPublicVerificationKey(),
    );
    expect(JSON.stringify(jwk).includes('PRIVATE KEY')).toBe(false);
  });
  it('returns a defensive JWK copy', async () => {
    const keys = service();
    const first = await keys.getPublicJwk();
    const mutable = first as { kid: string; n: string };
    mutable.kid = 'changed';
    mutable.n = 'changed';
    expect(await keys.getKeyId()).toBe('MiXeD-e\u0301-Key');
    expect((await keys.getPublicJwk()).n === 'changed').toBe(false);
  });
  it('allows JOSE signing/verification of a test-only JWS payload, including JWK re-import (no JWT claims)', async () => {
    const keys = service();
    const payload = new TextEncoder().encode(
      'M6.5 ephemeral fixture, not an access token',
    );
    const jws = await new jose.CompactSign(payload)
      .setProtectedHeader({ alg: 'RS256', kid: await keys.getKeyId() })
      .sign(await keys.getPrivateSigningKey());
    for (const publicKey of [
      await keys.getPublicVerificationKey(),
      await jose.importJWK(await keys.getPublicJwk(), 'RS256'),
    ]) {
      const result = await jose.compactVerify(jws, publicKey, {
        algorithms: ['RS256'],
      });
      expect(result.payload).toEqual(payload);
      expect(result.protectedHeader).toEqual({
        alg: 'RS256',
        kid: 'MiXeD-e\u0301-Key',
      });
    }
  });
  it('shares one initialization across concurrent first getters and reuses cached material thereafter', async () => {
    const keys = service();
    const results = await Promise.all(
      Array.from({ length: 12 }, () =>
        Promise.all([
          keys.getPrivateSigningKey(),
          keys.getPublicVerificationKey(),
          keys.getPublicJwk(),
          keys.getKeyId(),
        ]),
      ),
    );
    expect(fs.readFile).toHaveBeenCalledTimes(2);
    expect(jose.importPKCS8).toHaveBeenCalledTimes(1);
    expect(jose.importSPKI).toHaveBeenCalledTimes(1);
    expect(jose.exportJWK).toHaveBeenCalledTimes(1);
    for (const result of results) {
      expect(result[0]).toBe(results[0][0]);
      expect(result[1]).toBe(results[0][1]);
    }
    vi.mocked(fs.readFile).mockRejectedValue(new Error('Unexpected reload.'));
    expect(await keys.getPrivateSigningKey()).toBe(results[0][0]);
    expect(await keys.getPublicVerificationKey()).toBe(results[0][1]);
    expect(await keys.getKeyId()).toBe(results[0][3]);
    expect(await keys.getPublicJwk()).toEqual(results[0][2]);
    expect(fs.readFile).toHaveBeenCalledTimes(2);
  });
  it.each([
    'mismatch',
    'weak',
    'ec-private',
    'ec-public',
    'bad-private',
    'bad-public',
    'pkcs1-private',
    'pkcs1-public',
    'certificate',
    'symmetric',
    'encrypted-private',
  ])('rejects %s key material with sanitized failure', async (kind) => {
    let privatePem = pem.privateKey;
    let publicPem = pem.publicKey;
    if (kind === 'mismatch') publicPem = other.publicKey;
    if (kind === 'weak') {
      privatePem = weak.privateKey;
      publicPem = weak.publicKey;
    }
    if (kind === 'ec-private') privatePem = ec.privateKey;
    if (kind === 'ec-public') publicPem = ec.publicKey;
    if (kind === 'bad-private')
      privatePem =
        '-----BEGIN PRIVATE KEY-----\nprivate-native-canary\n-----END PRIVATE KEY-----';
    if (kind === 'bad-public')
      publicPem =
        '-----BEGIN PUBLIC KEY-----\nprivate-native-canary\n-----END PUBLIC KEY-----';
    if (kind === 'pkcs1-private')
      privatePem = pem.privateKey.replaceAll('PRIVATE KEY', 'RSA PRIVATE KEY');
    if (kind === 'pkcs1-public')
      publicPem = pem.publicKey.replaceAll('PUBLIC KEY', 'RSA PUBLIC KEY');
    if (kind === 'certificate')
      publicPem = pem.publicKey.replaceAll('PUBLIC KEY', 'CERTIFICATE');
    if (kind === 'symmetric')
      privatePem = '{"kty":"oct","k":"private-native-canary"}';
    if (kind === 'encrypted-private')
      privatePem = pem.privateKey.replaceAll(
        'PRIVATE KEY',
        'ENCRYPTED PRIVATE KEY',
      );
    const privateFile = join(directory, kind + '-private.pem');
    const publicFile = join(directory, kind + '-public.pem');
    await Promise.all([
      realFs.writeFile(privateFile, privatePem, { mode: 0o600 }),
      realFs.writeFile(publicFile, publicPem),
    ]);
    await safeFailure(
      service({
        JWT_PRIVATE_KEY_PATH: privateFile,
        JWT_PUBLIC_KEY_PATH: publicFile,
      }).getPublicJwk(),
    );
  });
  it.each(['private', 'public'])(
    'rejects a missing %s file without generating replacement keys',
    async (kind) => {
      await safeFailure(
        service({
          [kind === 'private' ? 'JWT_PRIVATE_KEY_PATH' : 'JWT_PUBLIC_KEY_PATH']:
            join(directory, 'missing-' + kind + '.pem'),
        }).getPrivateSigningKey(),
      );
      expect(jose.importPKCS8).not.toHaveBeenCalled();
      expect(jose.importSPKI).not.toHaveBeenCalled();
    },
  );
  it.each(['private', 'public'])(
    'sanitizes an unreadable %s file (deterministic EACCES fixture for Windows)',
    async (kind) => {
      const native = Object.assign(
        new Error('private-native-canary ' + privatePath + pem.privateKey),
        {
          code: 'EACCES',
          path: privatePath,
          cause: new Error('private-native-canary'),
        },
      );
      if (kind === 'public')
        vi.mocked(fs.readFile).mockImplementationOnce(realFs.readFile);
      vi.mocked(fs.readFile).mockRejectedValueOnce(native);
      await safeFailure(service().getPublicVerificationKey());
    },
  );
  it.each(['private-import', 'public-import', 'export'])(
    'sanitizes unexpected %s native/JOSE errors without causes or logs',
    async (kind) => {
      const native = new Error(
        'private-native-canary ' + privatePath + pem.privateKey + pem.publicKey,
        { cause: new Error('OpenSSL private-native-canary') },
      );
      if (kind === 'private-import')
        vi.mocked(jose.importPKCS8).mockRejectedValueOnce(native);
      if (kind === 'public-import')
        vi.mocked(jose.importSPKI).mockRejectedValueOnce(native);
      if (kind === 'export')
        vi.mocked(jose.exportJWK).mockRejectedValueOnce(native);
      await safeFailure(service().getKeyId());
    },
  );
  it.each([undefined, '', '   ', 42, null])(
    'rejects invalid kid case %# before file access, even if config validation is bypassed',
    async (kid) => {
      // Isolate the service boundary: ambient shell config cannot rescue this fixture.
      const getOrThrow = vi
        .fn<(name: string) => unknown>()
        .mockReturnValue(kid);
      const config = { getOrThrow } as unknown as ConfigService<
        Environment,
        true
      >;
      await safeFailure(new SigningKeyService(config).getKeyId());
      expect(getOrThrow).toHaveBeenCalledExactlyOnceWith('JWT_KEY_ID', {
        infer: true,
      });
      expect(fs.readFile).not.toHaveBeenCalled();
    },
  );
  it('never caches partial state after a shared failure and permits a later explicit retry', async () => {
    const keys = service();
    vi.mocked(jose.importSPKI).mockRejectedValueOnce(
      new Error('private-native-canary'),
    );
    await Promise.all([
      safeFailure(keys.getPrivateSigningKey()),
      safeFailure(keys.getPublicVerificationKey()),
      safeFailure(keys.getPublicJwk()),
      safeFailure(keys.getKeyId()),
    ]);
    expect(fs.readFile).toHaveBeenCalledTimes(2);
    expect(jose.importPKCS8).toHaveBeenCalledTimes(1);
    expect(jose.importSPKI).toHaveBeenCalledTimes(1);
    expect(await keys.getKeyId()).toBe('MiXeD-e\u0301-Key');
    expect(fs.readFile).toHaveBeenCalledTimes(4);
    expect(jose.importPKCS8).toHaveBeenCalledTimes(2);
    expect(jose.importSPKI).toHaveBeenCalledTimes(2);
    expect(jose.exportJWK).toHaveBeenCalledTimes(1);
  });
});
