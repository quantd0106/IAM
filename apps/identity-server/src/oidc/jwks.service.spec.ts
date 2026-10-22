import { Logger } from '@nestjs/common';
import {
  afterEach,
  beforeEach,
  describe,
  expect,
  it,
  vi,
  type MockInstance,
} from 'vitest';
import {
  SigningKeyService,
  type PublicSigningJwk,
} from '../security/signing/signing-key.service.js';
import { JwksService } from './jwks.service.js';

const { forbiddenImport, forbiddenIO } = vi.hoisted(() => ({
  forbiddenImport: vi.fn(() => {
    throw new Error('Unexpected JWKS dependency.');
  }),
  forbiddenIO: vi.fn(() => {
    throw new Error('Unexpected direct JWKS I/O.');
  }),
}));
// The service must cross only this public capability, not its key-loading internals.
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
vi.mock('@nestjs/config', () => {
  forbiddenImport();
  return {};
});
vi.mock('jose', () => {
  forbiddenImport();
  return {};
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

const publicKey: PublicSigningJwk = Object.freeze({
  kty: 'RSA',
  kid: ' MiXeD-e\u0301-Key ',
  alg: 'RS256',
  use: 'sig',
  n: 'opaque_Modulus-unchanged',
  e: 'AQAB',
});

describe('JwksService public-only projection', () => {
  let logs: MockInstance[];
  const getPublicJwk = vi.fn<() => Promise<PublicSigningJwk>>();
  const service = new JwksService({
    getPublicJwk,
    getPrivateSigningKey: forbiddenIO,
    getPublicVerificationKey: forbiddenIO,
    getKeyId: forbiddenIO,
  } as unknown as SigningKeyService);
  beforeEach(() => {
    vi.clearAllMocks();
    getPublicJwk.mockResolvedValue(publicKey);
    vi.spyOn(globalThis, 'fetch').mockImplementation(forbiddenIO);
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
      expect(forbiddenImport).not.toHaveBeenCalled();
      expect(forbiddenIO).not.toHaveBeenCalled();
      for (const log of logs) expect(log).not.toHaveBeenCalled();
    } finally {
      vi.restoreAllMocks();
    }
  });
  it('requests only the public capability once and preserves all six values exactly', async () => {
    const document = await service.build();
    expect(getPublicJwk).toHaveBeenCalledExactlyOnceWith();
    expect(document).toEqual({ keys: [publicKey] });
    expect(Object.keys(document)).toEqual(['keys']);
    expect(document.keys).toHaveLength(1);
    expect(Object.keys(document.keys[0]).sort()).toEqual([
      'alg',
      'e',
      'kid',
      'kty',
      'n',
      'use',
    ]);
    expect(document.keys[0]).not.toBe(publicKey);
    expect(
      Reflect.getMetadata('self:paramtypes', JwksService) as unknown,
    ).toEqual([{ index: 0, param: SigningKeyService }]);
  });
  it('strips poisoned private/native/export/config properties without reading them', async () => {
    const poisoned: Record<string, unknown> = { ...publicKey };
    for (const field of [
      'd',
      'p',
      'q',
      'dp',
      'dq',
      'qi',
      'oth',
      'privateKey',
      'publicKey',
      'pem',
      'x5u',
      'x5c',
      'x5t',
      'x5t#S256',
      'key_ops',
      'JWT_PRIVATE_KEY_PATH',
      'JWT_PUBLIC_KEY_PATH',
    ])
      Object.defineProperty(poisoned, field, {
        enumerable: true,
        get: forbiddenIO,
      });
    getPublicJwk.mockResolvedValue(poisoned as PublicSigningJwk);
    const document = await service.build();
    expect(document).toEqual({ keys: [publicKey] });
    expect(Object.keys(document.keys[0]).sort()).toEqual([
      'alg',
      'e',
      'kid',
      'kty',
      'n',
      'use',
    ]);
  });
  it('creates fresh document, array and key per call, with no second cache or mutable shared state', async () => {
    const first = await service.build();
    const second = await service.build();
    expect(first).not.toBe(second);
    expect(first.keys).not.toBe(second.keys);
    expect(first.keys[0]).not.toBe(second.keys[0]);
    (first.keys[0] as unknown as Record<string, unknown>).kid = 'caller';
    first.keys.length = 0;
    first.keys = [];
    expect(await service.build()).toEqual({ keys: [publicKey] });
    expect(getPublicJwk).toHaveBeenCalledTimes(3);
  });
  it.each(['reject', 'projection'])(
    'sanitizes %s failures without native/private cause or logging',
    async (kind) => {
      const native = new Error('private-native-PEM-path-canary', {
        cause: new Error('private-native-cause'),
      });
      if (kind === 'reject') getPublicJwk.mockRejectedValue(native);
      else
        getPublicJwk.mockResolvedValue(
          Object.defineProperty({}, 'kid', {
            get: () => {
              throw native;
            },
          }) as PublicSigningJwk,
        );
      const failure: unknown = await service
        .build()
        .catch((error: unknown) => error);
      expect(failure).toBeInstanceOf(Error);
      expect((failure as Error).message).toBe('JWKS build failed.');
      expect((failure as Error).cause).toBeUndefined();
      expect((failure as Error).stack?.includes('canary')).toBe(false);
    },
  );
});
