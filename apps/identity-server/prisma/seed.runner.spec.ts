import {
  afterEach,
  beforeEach,
  describe,
  expect,
  it,
  vi,
  type MockInstance,
} from 'vitest';
import type {
  Client,
  ClientRedirectUri,
  ClientScope,
  Prisma,
  Scope,
} from '../src/generated/prisma/client.js';
import { runSeed } from './seed.runner.js';

type State = {
  clients: Client[];
  scopes: Scope[];
  redirects: ClientRedirectUri[];
  assignments: ClientScope[];
};
type CanonicalClient = Pick<Client, 'name' | 'clientType' | 'enabled'> & {
  clientSecretHash?: null;
};
const mocks = vi.hoisted(() => ({
  adapter: vi.fn<(options: unknown) => void>(),
  client: vi.fn<(options: unknown) => void>(),
  connect: vi.fn<() => Promise<void>>(),
  query: vi.fn<(sql: TemplateStringsArray) => Promise<unknown[]>>(),
  disconnect: vi.fn<() => Promise<void>>(),
  transaction:
    vi.fn<
      (
        apply: (tx: Prisma.TransactionClient) => Promise<number>,
      ) => Promise<number>
    >(),
  secretBoundary: vi.fn<(tx: unknown) => void>(),
  issue: vi.fn<(id: string) => Promise<unknown>>(),
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
    readonly $transaction = mocks.transaction;
  },
}));
vi.mock('../src/client-registry/client-secret.service.js', () => ({
  ClientSecretService: class {
    constructor(tx: unknown) {
      mocks.secretBoundary(tx);
    }
    readonly issueSecret = mocks.issue;
  },
}));

describe('seed runner (isolated transactional persistence)', () => {
  const url = 'postgresql://test:test@localhost:5432/test';
  let state: State;
  let nextId: number;
  const id = (): string =>
    `00000000-0000-4000-8000-${String(++nextId).padStart(12, '0')}`;
  const tx = {
    scope: {
      upsert: vi.fn((input: { where: { name: string }; update: object }) => {
        expect(input.update).toEqual({});
        let row = state.scopes.find((scope) => scope.name === input.where.name);
        if (!row) {
          row = { id: id(), name: input.where.name };
          state.scopes.push(row);
        }
        return Promise.resolve({ id: row.id });
      }),
    },
    client: {
      upsert: vi.fn(
        (input: {
          where: { clientId: string };
          create: CanonicalClient & { clientId: string };
          update: CanonicalClient;
        }) => {
          let row = state.clients.find(
            (client) => client.clientId === input.where.clientId,
          );
          if (!row) {
            row = {
              id: id(),
              clientSecretHash: null,
              accessTokenTtl: 600,
              refreshTokenTtl: 2592000,
              ...input.create,
            };
            state.clients.push(row);
          } else Object.assign(row, input.update);
          return Promise.resolve({
            id: row.id,
            clientSecretHash: row.clientSecretHash,
          });
        },
      ),
    },
    clientRedirectUri: {
      deleteMany: vi.fn(
        (input: {
          where: { clientId: string; redirectUri: { not: string } };
        }) => {
          state.redirects = state.redirects.filter(
            (row) =>
              row.clientId !== input.where.clientId ||
              row.redirectUri === input.where.redirectUri.not,
          );
          return Promise.resolve({ count: 0 });
        },
      ),
      upsert: vi.fn(
        (input: { create: Omit<ClientRedirectUri, 'id'>; update: object }) => {
          expect(input.update).toEqual({});
          let row = state.redirects.find(
            (row) =>
              row.clientId === input.create.clientId &&
              row.redirectUri === input.create.redirectUri,
          );
          if (!row) {
            row = { id: id(), ...input.create };
            state.redirects.push(row);
          }
          return Promise.resolve(row);
        },
      ),
    },
    clientScope: {
      deleteMany: vi.fn(
        (input: {
          where: { clientId: string; scopeId: { notIn: string[] } };
        }) => {
          state.assignments = state.assignments.filter(
            (row) =>
              row.clientId !== input.where.clientId ||
              input.where.scopeId.notIn.includes(row.scopeId),
          );
          return Promise.resolve({ count: 0 });
        },
      ),
      upsert: vi.fn((input: { create: ClientScope; update: object }) => {
        expect(input.update).toEqual({});
        if (
          !state.assignments.some(
            (row) =>
              row.clientId === input.create.clientId &&
              row.scopeId === input.create.scopeId,
          )
        )
          state.assignments.push(input.create);
        return Promise.resolve(input.create);
      }),
    },
  };
  let logs: MockInstance[];
  beforeEach(() => {
    vi.resetAllMocks();
    state = { clients: [], scopes: [], redirects: [], assignments: [] };
    nextId = 0;
    mocks.connect.mockResolvedValue(undefined);
    mocks.query.mockResolvedValue([{ '?column?': 1 }]);
    mocks.disconnect.mockResolvedValue(undefined);
    mocks.transaction.mockImplementation(async (apply) => {
      const before = structuredClone(state);
      try {
        return await apply(tx as unknown as Prisma.TransactionClient);
      } catch (error) {
        state = before;
        throw error;
      }
    });
    mocks.issue.mockImplementation((clientId) => {
      const client = state.clients.find((row) => row.id === clientId);
      if (
        !client ||
        client.clientType !== 'CONFIDENTIAL' ||
        client.clientSecretHash !== null
      )
        throw new Error('Unexpected secret issuance.');
      client.clientSecretHash = `unit-only encoded marker ${clientId}`;
      // Discard the one-time result, without reading/outputting plaintext.
      return Promise.resolve(
        Object.defineProperty({}, 'clientSecret', {
          get() {
            throw new Error('Seed must not read plaintext.');
          },
        }),
      );
    });
    logs = (['log', 'info', 'warn', 'error', 'debug'] as const).map((method) =>
      vi.spyOn(console, method).mockImplementation(() => undefined),
    );
  });
  afterEach(() => {
    try {
      for (const log of logs) expect(log.mock.calls.length).toBe(0);
    } finally {
      vi.restoreAllMocks();
    }
  });
  it.each([undefined, '', '   '])(
    'rejects missing/blank DATABASE_URL before construction (%#)',
    async (value) => {
      await expect(runSeed(value)).rejects.toThrow('DATABASE_URL is required.');
      expect(mocks.adapter).not.toHaveBeenCalled();
      expect(mocks.client).not.toHaveBeenCalled();
    },
  );
  it('connects, checks SELECT 1, commits one logical dataset, then disconnects', async () => {
    await expect(runSeed(` ${url} `)).resolves.toBe(1);
    expect(mocks.adapter).toHaveBeenCalledWith({
      connectionString: url,
      connectionTimeoutMillis: 5000,
    });
    expect(mocks.client).toHaveBeenCalledOnce();
    expect(mocks.query.mock.calls[0][0]).toEqual(['SELECT 1']);
    expect(mocks.connect.mock.invocationCallOrder[0]).toBeLessThan(
      mocks.query.mock.invocationCallOrder[0],
    );
    expect(mocks.query.mock.invocationCallOrder[0]).toBeLessThan(
      mocks.transaction.mock.invocationCallOrder[0],
    );
    expect(mocks.transaction.mock.invocationCallOrder[0]).toBeLessThan(
      mocks.disconnect.mock.invocationCallOrder[0],
    );
    expect(mocks.disconnect).toHaveBeenCalledOnce();
    expect(mocks.secretBoundary).toHaveBeenCalledWith(tx);
  });
  it('creates exact clients, defaults, redirects, four scopes and 3/4/3 assignments', async () => {
    await runSeed(url);
    expect(
      state.clients.map(
        ({
          clientId,
          name,
          clientType,
          enabled,
          accessTokenTtl,
          refreshTokenTtl,
        }) => ({
          clientId,
          name,
          clientType,
          enabled,
          accessTokenTtl,
          refreshTokenTtl,
        }),
      ),
    ).toEqual([
      {
        clientId: 'student-spa',
        name: 'Student SPA',
        clientType: 'PUBLIC',
        enabled: true,
        accessTokenTtl: 600,
        refreshTokenTtl: 2592000,
      },
      {
        clientId: 'banking-web',
        name: 'Banking Web / BFF',
        clientType: 'CONFIDENTIAL',
        enabled: true,
        accessTokenTtl: 600,
        refreshTokenTtl: 2592000,
      },
      {
        clientId: 'admin-portal',
        name: 'Admin Portal / BFF',
        clientType: 'CONFIDENTIAL',
        enabled: true,
        accessTokenTtl: 600,
        refreshTokenTtl: 2592000,
      },
    ]);
    expect(state.scopes.map((row) => row.name)).toEqual([
      'openid',
      'profile',
      'email',
      'banking.transactions.read',
    ]);
    expect(state.redirects.map((row) => row.redirectUri)).toEqual([
      'http://localhost:3200/callback',
      'http://localhost:3100/auth/callback',
      'http://localhost:3300/auth/callback',
    ]);
    expect(state.clients[0].clientSecretHash === null).toBe(true);
    expect(mocks.issue.mock.calls.map(([id]) => id)).toEqual(
      state.clients.slice(1).map((row) => row.id),
    );
    for (const client of state.clients) {
      const names = state.assignments
        .filter((row) => row.clientId === client.id)
        .map(
          (row) => state.scopes.find((scope) => scope.id === row.scopeId)?.name,
        );
      expect(names).toEqual(
        client.clientId === 'banking-web'
          ? ['openid', 'profile', 'email', 'banking.transactions.read']
          : ['openid', 'profile', 'email'],
      );
    }
  });
  it('returns one dataset on rerun without duplicates, ID changes or secret rotation', async () => {
    await runSeed(url);
    const first = JSON.stringify(state);
    await expect(runSeed(url)).resolves.toBe(1);
    expect(JSON.stringify(state) === first).toBe(true);
    expect(mocks.issue.mock.calls.length).toBe(2);
  });
  it('converges only canonical registrations, preserves TTLs and unrelated exact text', async () => {
    await runSeed(url);
    const student = state.clients[0];
    student.name = 'outdated';
    student.enabled = false;
    student.clientType = 'CONFIDENTIAL';
    student.clientSecretHash = 'unit-only invalid public marker';
    student.accessTokenTtl = 123;
    student.refreshTokenTtl = 456;
    const unrelated: Client = {
      ...student,
      id: id(),
      clientId: ' Student-SPA ',
      name: ' keep exact ',
      enabled: false,
    };
    const scope = { id: id(), name: ' OpenID ' };
    const unrelatedRedirect = {
      id: id(),
      clientId: unrelated.id,
      redirectUri: ' https://EXAMPLE.test/callback ',
    };
    const unrelatedLink = { clientId: unrelated.id, scopeId: scope.id };
    state.clients.push(unrelated);
    state.scopes.push(scope);
    state.redirects.push(unrelatedRedirect, {
      id: id(),
      clientId: student.id,
      redirectUri: 'http://localhost:3200/Callback',
    });
    state.assignments.push(unrelatedLink, {
      clientId: student.id,
      scopeId: scope.id,
    });
    const preserved = JSON.stringify({
      unrelated,
      scope,
      unrelatedRedirect,
      unrelatedLink,
    });
    await runSeed(url);
    expect(student.name).toBe('Student SPA');
    expect(student.enabled).toBe(true);
    expect(student.clientType).toBe('PUBLIC');
    expect(student.clientSecretHash === null).toBe(true);
    expect([student.accessTokenTtl, student.refreshTokenTtl]).toEqual([
      123, 456,
    ]);
    expect(
      JSON.stringify({
        unrelated: state.clients.at(-1),
        scope: state.scopes.at(-1),
        unrelatedRedirect: state.redirects.at(-1),
        unrelatedLink: state.assignments.at(-1),
      }) === preserved,
    ).toBe(true);
    expect(
      state.redirects
        .filter((row) => row.clientId === student.id)
        .map((row) => row.redirectUri),
    ).toEqual(['http://localhost:3200/callback']);
    expect(
      state.assignments.filter((row) => row.clientId === student.id).length,
    ).toBe(3);
    expect(mocks.issue.mock.calls.length).toBe(2);
  });
  it('provisions only the NULL confidential hash on a partial rerun', async () => {
    await runSeed(url);
    state.clients[2].clientSecretHash = null;
    mocks.issue.mockClear();
    await runSeed(url);
    expect(mocks.issue).toHaveBeenCalledExactlyOnceWith(state.clients[2].id);
  });
  it('rolls the dataset back on secret failure and sanitizes the cause', async () => {
    mocks.issue.mockRejectedValueOnce(new Error(url));
    await expect(runSeed(url)).rejects.toThrow(/^Seed failed\.$/);
    expect(state).toEqual({
      clients: [],
      scopes: [],
      redirects: [],
      assignments: [],
    });
    expect(mocks.disconnect).toHaveBeenCalledOnce();
  });
  it('rolls back a later relation-write failure', async () => {
    tx.clientScope.upsert.mockRejectedValueOnce(new Error(url));
    await expect(runSeed(url)).rejects.toThrow(/^Seed failed\.$/);
    expect(
      state.clients.length +
        state.scopes.length +
        state.redirects.length +
        state.assignments.length,
    ).toBe(0);
  });
  it.each(['connect', 'query', 'transaction'] as const)(
    'sanitizes %s failures and disconnects',
    async (operation) => {
      mocks[operation].mockRejectedValueOnce(new Error(url));
      await expect(runSeed(url)).rejects.toThrow(/^Seed failed\.$/);
      expect(mocks.disconnect).toHaveBeenCalledOnce();
      if (operation === 'connect') expect(mocks.query).not.toHaveBeenCalled();
      if (operation !== 'transaction')
        expect(mocks.transaction).not.toHaveBeenCalled();
    },
  );
  it('does not report success when disconnect fails', async () => {
    mocks.disconnect.mockRejectedValueOnce(new Error(url));
    await expect(runSeed(url)).rejects.toThrow(/^Seed failed\.$/);
  });
  it.each(['adapter', 'client'] as const)(
    'sanitizes %s constructor failures',
    async (operation) => {
      mocks[operation].mockImplementationOnce(() => {
        throw new Error(url);
      });
      await expect(runSeed(url)).rejects.toThrow(/^Seed failed\.$/);
      expect(mocks.connect).not.toHaveBeenCalled();
      expect(mocks.disconnect).not.toHaveBeenCalled();
    },
  );
  it('does not attach driver causes or private URL values to seed errors', async () => {
    mocks.query.mockRejectedValueOnce(
      new Error(url, { cause: new Error(url) }),
    );
    try {
      await runSeed(url);
      throw new Error('Unexpected seed success.');
    } catch (error) {
      expect(error instanceof Error).toBe(true);
      if (!(error instanceof Error)) expect.fail('Expected sanitized Error.');
      expect(error.message).toBe('Seed failed.');
      expect(error.cause).toBeUndefined();
      expect((error.stack ?? '').includes(url)).toBe(false);
    }
  });
});
