import { Logger } from '@nestjs/common';
import { Test, type TestingModule } from '@nestjs/testing';
import { randomBytes } from 'node:crypto';
import * as argon2 from 'argon2';
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
import type { Client } from '../generated/prisma/client.js';
import { PrismaModule } from '../prisma/prisma.module.js';
import { PrismaService } from '../prisma/prisma.service.js';
import { ClientRegistryModule } from './client-registry.module.js';
import {
  ClientSecretService,
  type IssuedClientSecret,
} from './client-secret.service.js';

vi.mock('argon2', { spy: true });
vi.mock('node:crypto', { spy: true });

const failureMessage = 'Client secret issuance failed.';
type SelectedClient = Pick<Client, 'id' | 'clientType' | 'clientSecretHash'>;
type WriteInput = {
  where: {
    id: string;
    clientType: 'CONFIDENTIAL';
    clientSecretHash: string | null;
  };
  data: { clientSecretHash: string };
};
const clientRecordId = 'd82336c1-d281-48c6-981b-201b962cfa08';

function safeError(error: unknown, forbidden: string[] = []): void {
  expect(error instanceof Error).toBe(true);
  if (!(error instanceof Error)) throw new Error('Expected safe Error.');
  expect(error.message).toBe(failureMessage);
  expect(error.cause).toBeUndefined();
  expect(Object.keys(error)).toEqual([]);
  for (const value of forbidden)
    expect((error.message + (error.stack ?? '')).includes(value)).toBe(false);
}

async function failsSafely(
  operation: Promise<unknown>,
  forbidden: string[] | (() => string[]) = [],
): Promise<void> {
  let rejected = false;
  try {
    await operation;
  } catch (error) {
    rejected = true;
    safeError(error, typeof forbidden === 'function' ? forbidden() : forbidden);
  }
  // Never give Vitest a fulfilled secret object to print on unexpected success.
  expect(rejected).toBe(true);
}

describe('ClientSecretService (isolated lifecycle)', () => {
  const findUnique = vi.fn<() => Promise<SelectedClient | null>>();
  const updateMany = vi.fn<(input: WriteInput) => Promise<{ count: number }>>();
  const unexpected = vi.fn();
  let selected: SelectedClient;
  let module: TestingModule;
  let service: ClientSecretService;
  let logs: MockInstance[];
  let nativeCrypto: typeof import('node:crypto');

  beforeAll(async () => {
    nativeCrypto =
      await vi.importActual<typeof import('node:crypto')>('node:crypto');
  });
  beforeEach(async () => {
    vi.clearAllMocks();
    vi.mocked(randomBytes)
      .mockReset()
      .mockImplementation(nativeCrypto.randomBytes);
    vi.mocked(argon2.hash)
      .mockReset()
      .mockResolvedValue('unit-only encoded hash marker');
    findUnique.mockReset();
    updateMany.mockReset().mockResolvedValue({ count: 1 });
    selected = {
      id: clientRecordId,
      clientType: 'CONFIDENTIAL',
      clientSecretHash: null,
    };
    findUnique.mockImplementation(() => Promise.resolve({ ...selected }));
    module = await Test.createTestingModule({
      imports: [ClientRegistryModule],
      providers: [
        {
          provide: 'trusted-client-secret-consumer',
          inject: [ClientSecretService],
          useFactory: (capability: ClientSecretService): ClientSecretService =>
            capability,
        },
      ],
    })
      .overrideProvider(PrismaService)
      .useValue({
        client: {
          findUnique,
          updateMany,
          create: unexpected,
          update: unexpected,
        },
        $transaction: unexpected,
      })
      .compile();
    service = module.get<ClientSecretService>('trusted-client-secret-consumer');
    logs = [
      vi.spyOn(console, 'log').mockImplementation(() => undefined),
      vi.spyOn(console, 'info').mockImplementation(() => undefined),
      vi.spyOn(console, 'warn').mockImplementation(() => undefined),
      vi.spyOn(console, 'error').mockImplementation(() => undefined),
      vi.spyOn(console, 'debug').mockImplementation(() => undefined),
      vi.spyOn(Logger.prototype, 'log').mockImplementation(() => undefined),
      vi.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined),
      vi.spyOn(Logger.prototype, 'error').mockImplementation(() => undefined),
      vi.spyOn(Logger.prototype, 'debug').mockImplementation(() => undefined),
      vi.spyOn(Logger.prototype, 'verbose').mockImplementation(() => undefined),
      vi.spyOn(Logger.prototype, 'fatal').mockImplementation(() => undefined),
    ];
  });
  afterEach(async () => {
    try {
      expect(unexpected.mock.calls.length).toBe(0);
      for (const log of logs) expect(log.mock.calls.length).toBe(0);
    } finally {
      await module.close();
      vi.restoreAllMocks();
    }
  });

  it('exports one injectable capability through a Prisma-only module with no controller', () => {
    expect(service).toBeInstanceOf(ClientSecretService);
    expect(
      Reflect.getMetadata('imports', ClientRegistryModule) as unknown,
    ).toEqual([PrismaModule]);
    expect(
      (Reflect.getMetadata('controllers', ClientRegistryModule) as unknown) ??
        [],
    ).toEqual([]);
  });

  it('uses 32 secure random bytes/base64url, Argon2id, then persists only the hash before returning only raw', async () => {
    const result = await service.issueSecret(clientRecordId);
    expect(Object.keys(result)).toEqual(['clientSecret']);
    expect(typeof result.clientSecret).toBe('string');
    expect(result.clientSecret.length).toBe(43);
    expect(/^[A-Za-z0-9_-]+$/.test(result.clientSecret)).toBe(true);
    expect(Buffer.from(result.clientSecret, 'base64url').length).toBe(32);
    expect(randomBytes).toHaveBeenCalledExactlyOnceWith(32);
    const generated: unknown = vi.mocked(randomBytes).mock.results[0].value;
    expect(Buffer.isBuffer(generated)).toBe(true);
    if (!Buffer.isBuffer(generated)) throw new Error('Expected random bytes.');
    expect(generated.toString('base64url') === result.clientSecret).toBe(true);
    expect(findUnique).toHaveBeenCalledExactlyOnceWith({
      where: { id: clientRecordId },
      select: { id: true, clientType: true, clientSecretHash: true },
    });
    expect(
      vi.mocked(argon2.hash).mock.calls[0][0] === result.clientSecret,
    ).toBe(true);
    expect(vi.mocked(argon2.hash).mock.calls[0][1]).toEqual({
      type: argon2.argon2id,
    });
    expect(updateMany).toHaveBeenCalledExactlyOnceWith({
      where: {
        id: clientRecordId,
        clientType: 'CONFIDENTIAL',
        clientSecretHash: null,
      },
      data: { clientSecretHash: 'unit-only encoded hash marker' },
    });
    expect(
      updateMany.mock.calls[0][0].data.clientSecretHash === result.clientSecret,
    ).toBe(false);
    expect(
      JSON.stringify(updateMany.mock.calls).includes(result.clientSecret),
    ).toBe(false);
    expect(findUnique.mock.invocationCallOrder[0]).toBeLessThan(
      vi.mocked(randomBytes).mock.invocationCallOrder[0],
    );
    expect(vi.mocked(randomBytes).mock.invocationCallOrder[0]).toBeLessThan(
      vi.mocked(argon2.hash).mock.invocationCallOrder[0],
    );
    expect(vi.mocked(argon2.hash).mock.invocationCallOrder[0]).toBeLessThan(
      updateMany.mock.invocationCallOrder[0],
    );
  });

  it('does not fulfill while the CAS persistence is still pending', async () => {
    let enter!: () => void;
    let complete!: (value: { count: number }) => void;
    const entered = new Promise<void>((resolve) => {
      enter = resolve;
    });
    updateMany.mockImplementationOnce(() => {
      enter();
      return new Promise((resolve) => {
        complete = resolve;
      });
    });
    let returned = false;
    const pending = service.issueSecret(clientRecordId).then((result) => {
      returned = true;
      return Object.keys(result);
    });
    await entered;
    try {
      expect(returned).toBe(false);
    } finally {
      complete({ count: 1 });
    }
    expect(await pending).toEqual(['clientSecret']);
  });

  it.each([
    '',
    ' ',
    'oauth-client-id',
    'not-a-uuid',
    ` ${clientRecordId}`,
    `${clientRecordId} `,
  ])(
    'rejects invalid internal UUID input before stores or crypto (case %#)',
    async (input) => {
      await failsSafely(service.issueSecret(input));
      expect(findUnique.mock.calls.length).toBe(0);
      expect(vi.mocked(randomBytes).mock.calls.length).toBe(0);
      expect(vi.mocked(argon2.hash).mock.calls.length).toBe(0);
      expect(updateMany.mock.calls.length).toBe(0);
    },
  );
  it('queries uppercase UUID unchanged, but uses the canonical fetched internal id for CAS', async () => {
    await service.issueSecret(clientRecordId.toUpperCase());
    expect(findUnique).toHaveBeenCalledExactlyOnceWith({
      where: { id: clientRecordId.toUpperCase() },
      select: { id: true, clientType: true, clientSecretHash: true },
    });
    expect(updateMany.mock.calls[0][0].where.id).toBe(clientRecordId);
  });
  it('rejects unknown Client before generation, hashing or update', async () => {
    findUnique.mockResolvedValueOnce(null);
    await failsSafely(service.issueSecret(clientRecordId));
    expect(vi.mocked(randomBytes).mock.calls.length).toBe(0);
    expect(vi.mocked(argon2.hash).mock.calls.length).toBe(0);
    expect(updateMany.mock.calls.length).toBe(0);
  });
  it.each([null, 'unit-only legacy marker'])(
    'rejects PUBLIC before crypto and leaves its hash unchanged (case %#)',
    async (hash) => {
      selected = { ...selected, clientType: 'PUBLIC', clientSecretHash: hash };
      await failsSafely(service.issueSecret(clientRecordId));
      expect(selected.clientSecretHash === hash).toBe(true);
      expect(vi.mocked(randomBytes).mock.calls.length).toBe(0);
      expect(vi.mocked(argon2.hash).mock.calls.length).toBe(0);
      expect(updateMany.mock.calls.length).toBe(0);
    },
  );
  it('uses the previously observed non-NULL hash for rotation CAS', async () => {
    selected.clientSecretHash = 'unit-only previous encoded marker';
    await service.issueSecret(clientRecordId);
    expect(
      updateMany.mock.calls[0][0].where.clientSecretHash ===
        selected.clientSecretHash,
    ).toBe(true);
    expect(Object.keys(updateMany.mock.calls[0][0].data)).toEqual([
      'clientSecretHash',
    ]);
  });
  it('adds no disabled-client runtime authentication policy', async () => {
    const disabled = { ...selected, enabled: false };
    findUnique.mockResolvedValueOnce(disabled);
    expect(Object.keys(await service.issueSecret(clientRecordId))).toEqual([
      'clientSecret',
    ]);
  });
  it('sanitizes read errors without generation or mutation', async () => {
    findUnique.mockRejectedValueOnce(
      new Error('private driver cause', { cause: new Error('private cause') }),
    );
    await failsSafely(service.issueSecret(clientRecordId), [
      'private driver cause',
      'private cause',
    ]);
    expect(vi.mocked(randomBytes).mock.calls.length).toBe(0);
    expect(updateMany.mock.calls.length).toBe(0);
  });
  it('sanitizes secure-random failures without hashing or mutation', async () => {
    vi.mocked(randomBytes).mockImplementationOnce(() => {
      throw new Error('private random failure');
    });
    await failsSafely(service.issueSecret(clientRecordId), [
      'private random failure',
    ]);
    expect(vi.mocked(argon2.hash).mock.calls.length).toBe(0);
    expect(updateMany.mock.calls.length).toBe(0);
  });
  it('sanitizes hashing failure containing the candidate; does not update or return raw', async () => {
    let candidate = '';
    vi.mocked(argon2.hash).mockImplementationOnce((raw) => {
      candidate = String(raw);
      return Promise.reject(
        new Error(candidate, { cause: new Error(candidate) }),
      );
    });
    await failsSafely(service.issueSecret(clientRecordId), () => [candidate]);
    expect(candidate.length).toBe(43);
    expect(updateMany.mock.calls.length).toBe(0);
  });
  it('sanitizes persistence failure containing the hash; never returns a secret', async () => {
    updateMany.mockImplementationOnce((input) =>
      Promise.reject(
        new Error(input.data.clientSecretHash, {
          cause: new Error('private driver cause'),
        }),
      ),
    );
    await failsSafely(service.issueSecret(clientRecordId), [
      'unit-only encoded hash marker',
      'private driver cause',
    ]);
    expect(updateMany.mock.calls.length).toBe(1);
  });
  it.each([0, 2])(
    'rejects CAS count %s without retry or a successful candidate result',
    async (count) => {
      updateMany.mockResolvedValueOnce({ count });
      await failsSafely(service.issueSecret(clientRecordId));
      expect(findUnique.mock.calls.length).toBe(1);
      expect(vi.mocked(argon2.hash).mock.calls.length).toBe(1);
      expect(updateMany.mock.calls.length).toBe(1);
    },
  );
  it('includes CONFIDENTIAL type in CAS, failing closed on a concurrent class change', async () => {
    updateMany.mockResolvedValueOnce({ count: 0 });
    await failsSafely(service.issueSecret(clientRecordId));
    expect(updateMany.mock.calls[0][0].where.clientType).toBe('CONFIDENTIAL');
    expect(Object.keys(updateMany.mock.calls[0][0].data)).toEqual([
      'clientSecretHash',
    ]);
  });
  it('has no retrieval/verification API or retained raw-secret field', async () => {
    await service.issueSecret(clientRecordId);
    expect(Object.getOwnPropertyNames(ClientSecretService.prototype)).toEqual([
      'constructor',
      'issueSecret',
    ]);
    expect(Object.keys(service)).toEqual(['prisma']);
  });
  it('deterministically returns one CAS winner and one safe loser from the same snapshot', async () => {
    let release!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    let reads = 0;
    let stored: string | null = null;
    const candidates = new Map<string, string>();
    findUnique.mockImplementation(async () => {
      const snapshot = { ...selected, clientSecretHash: stored };
      if (++reads === 2) release();
      await gate;
      return snapshot;
    });
    vi.mocked(argon2.hash).mockImplementation((raw) => {
      const marker = `unit-only candidate hash marker ${candidates.size}`;
      candidates.set(String(raw), marker);
      return Promise.resolve(marker);
    });
    updateMany.mockImplementation((input) => {
      if (stored !== input.where.clientSecretHash)
        return Promise.resolve({ count: 0 });
      stored = input.data.clientSecretHash;
      return Promise.resolve({ count: 1 });
    });
    const results = await Promise.allSettled([
      service.issueSecret(clientRecordId),
      service.issueSecret(clientRecordId),
    ]);
    const winners = results.filter((result) => result.status === 'fulfilled');
    const losers = results.filter((result) => result.status === 'rejected');
    expect(winners.length).toBe(1);
    expect(losers.length).toBe(1);
    expect(stored === candidates.get(winners[0].value.clientSecret)).toBe(true);
    safeError(losers[0].reason, [...candidates.keys(), ...candidates.values()]);
    expect(findUnique.mock.calls.length).toBe(2);
    expect(updateMany.mock.calls.length).toBe(2);
  });
});

describe('ClientSecretService (real Argon2id, isolated persistence)', () => {
  let issued: IssuedClientSecret;
  let rotated: IssuedClientSecret;
  let firstHash: string;
  let secondHash: string;
  let nativeArgon2: typeof import('argon2');
  beforeAll(async () => {
    nativeArgon2 = await vi.importActual<typeof import('argon2')>('argon2');
    const nativeCrypto =
      await vi.importActual<typeof import('node:crypto')>('node:crypto');
    vi.mocked(argon2.hash).mockReset().mockImplementation(nativeArgon2.hash);
    vi.mocked(randomBytes)
      .mockReset()
      .mockImplementation(nativeCrypto.randomBytes);
    let stored: string | null = null;
    const service = new ClientSecretService({
      client: {
        findUnique: () =>
          Promise.resolve({
            id: clientRecordId,
            clientType: 'CONFIDENTIAL',
            clientSecretHash: stored,
          }),
        updateMany: (input: WriteInput) => {
          if (input.where.clientSecretHash !== stored)
            return Promise.resolve({ count: 0 });
          stored = input.data.clientSecretHash;
          return Promise.resolve({ count: 1 });
        },
      },
    } as unknown as PrismaService);
    issued = await service.issueSecret(clientRecordId);
    firstHash = String(stored);
    rotated = await service.issueSecret(clientRecordId);
    secondHash = String(stored);
  }, 30000);
  it('issues a non-empty 32-byte/base64url value and stores an encoded Argon2id hash, not raw', () => {
    expect(issued.clientSecret.length).toBe(43);
    expect(Buffer.from(issued.clientSecret, 'base64url').length).toBe(32);
    expect(firstHash.startsWith('$argon2id$')).toBe(true);
    expect(firstHash === issued.clientSecret).toBe(false);
    expect(nativeArgon2.needsRehash(firstHash)).toBe(false);
  });
  it('verifies the issued raw against the persisted hash in test code only', async () => {
    expect(await nativeArgon2.verify(firstHash, issued.clientSecret)).toBe(
      true,
    );
  });
  it('rotation returns a different raw value and replaces the encoded hash', () => {
    expect(rotated.clientSecret !== issued.clientSecret).toBe(true);
    expect(secondHash !== firstHash).toBe(true);
    expect(secondHash.startsWith('$argon2id$')).toBe(true);
    expect(secondHash === rotated.clientSecret).toBe(false);
  });
  it('new hash verifies new raw and rejects old raw', async () => {
    expect(await nativeArgon2.verify(secondHash, rotated.clientSecret)).toBe(
      true,
    );
    expect(await nativeArgon2.verify(secondHash, issued.clientSecret)).toBe(
      false,
    );
  });
  it('both successful results expose only clientSecret, never the persisted hash', () => {
    expect(Object.keys(issued)).toEqual(['clientSecret']);
    expect(Object.keys(rotated)).toEqual(['clientSecret']);
    expect(JSON.stringify(issued).includes(firstHash)).toBe(false);
    expect(JSON.stringify(rotated).includes(secondHash)).toBe(false);
  });
});
