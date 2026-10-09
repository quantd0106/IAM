import { beforeEach, describe, expect, it, vi } from 'vitest';
import { runSeed } from './seed.runner.js';

const mocks = vi.hoisted(() => ({
  adapter: vi.fn<(options: unknown) => void>(),
  client: vi.fn<(options: unknown) => void>(),
  connect: vi.fn<() => Promise<void>>(),
  query: vi.fn<(sql: TemplateStringsArray) => Promise<unknown[]>>(),
  disconnect: vi.fn<() => Promise<void>>(),
}));

vi.mock('@prisma/adapter-pg', () => ({
  PrismaPg: class {
    constructor(options: unknown) {
      mocks.adapter(options);
    }
  },
}));

vi.mock('../src/generated/prisma/client.js', () => ({
  PrismaClient: class {
    constructor(options: unknown) {
      mocks.client(options);
    }
    readonly $connect = mocks.connect;
    readonly $queryRaw = mocks.query;
    readonly $disconnect = mocks.disconnect;
  },
}));

describe('seed runner (no PostgreSQL required)', () => {
  const url = 'postgresql://test:test@localhost:5432/test';

  beforeEach(() => {
    vi.resetAllMocks();
    mocks.connect.mockResolvedValue(undefined);
    mocks.query.mockResolvedValue([{ '?column?': 1 }]);
    mocks.disconnect.mockResolvedValue(undefined);
  });

  it.each([undefined, '', '   '])(
    'rejects missing/blank DATABASE_URL before creating a client: %s',
    async (value) => {
      await expect(runSeed(value)).rejects.toThrow('DATABASE_URL is required.');
      expect(mocks.adapter).not.toHaveBeenCalled();
      expect(mocks.client).not.toHaveBeenCalled();
    },
  );

  it('connects, checks fixed SQL, applies zero datasets and disconnects in order', async () => {
    await expect(runSeed(url)).resolves.toBe(0);
    expect(mocks.adapter).toHaveBeenCalledWith({
      connectionString: url,
      connectionTimeoutMillis: 5000,
    });
    expect(mocks.client).toHaveBeenCalledOnce();
    expect(mocks.client.mock.calls[0]?.[0]).toHaveProperty('adapter');
    expect(mocks.connect).toHaveBeenCalledOnce();
    expect(mocks.query).toHaveBeenCalledOnce();
    expect(mocks.query.mock.calls[0]?.[0]).toEqual(['SELECT 1']);
    expect(mocks.disconnect).toHaveBeenCalledOnce();
    expect(mocks.connect.mock.invocationCallOrder[0]).toBeLessThan(
      mocks.query.mock.invocationCallOrder[0],
    );
    expect(mocks.query.mock.invocationCallOrder[0]).toBeLessThan(
      mocks.disconnect.mock.invocationCallOrder[0],
    );
  });

  it('disconnects and propagates connection failure without querying', async () => {
    const failure = new Error('connection failure');
    mocks.connect.mockRejectedValue(failure);
    await expect(runSeed(url)).rejects.toBe(failure);
    expect(mocks.query).not.toHaveBeenCalled();
    expect(mocks.disconnect).toHaveBeenCalledOnce();
  });

  it('disconnects and propagates query failure', async () => {
    const failure = new Error('query failure');
    mocks.query.mockRejectedValue(failure);
    await expect(runSeed(url)).rejects.toBe(failure);
    expect(mocks.disconnect).toHaveBeenCalledOnce();
  });

  it('does not report success when disconnect fails', async () => {
    const failure = new Error('disconnect failure');
    mocks.disconnect.mockRejectedValue(failure);
    await expect(runSeed(url)).rejects.toBe(failure);
  });
});
