import { Logger } from '@nestjs/common';
import { Test, type TestingModule } from '@nestjs/testing';
import {
  afterEach,
  beforeEach,
  describe,
  expect,
  it,
  vi,
  type MockInstance,
} from 'vitest';
import type { Prisma } from '../generated/prisma/client.js';
import { PrismaService } from '../prisma/prisma.service.js';
import { ClientRegistryModule } from './client-registry.module.js';
import { ScopeLookupService } from './scope-lookup.service.js';

const studentId = 'd82336c1-d281-48c6-981b-201b962cfa08';
const bankingId = 'a82336c1-d281-48c6-981b-201b962cfa08';
const adminId = 'b82336c1-d281-48c6-981b-201b962cfa08';
describe('ScopeLookupService', () => {
  const findMany =
    vi.fn<
      (
        input: Prisma.ClientScopeFindManyArgs,
      ) => Promise<{ scope: { name: string } }[]>
    >();
  const unexpected = vi.fn(() => {
    throw new Error('Unexpected scope lookup side effect.');
  });
  const mutations = {
    create: unexpected,
    createMany: unexpected,
    update: unexpected,
    updateMany: unexpected,
    upsert: unexpected,
    delete: unexpected,
    deleteMany: unexpected,
  };
  let module: TestingModule;
  let service: ScopeLookupService;
  let names: Map<string, string[]>;
  let logs: MockInstance[];
  beforeEach(async () => {
    vi.clearAllMocks();
    names = new Map([
      [studentId, ['openid', 'profile', 'email']],
      [bankingId, ['profile', 'banking.transactions.read', 'openid', 'email']],
      [adminId, ['email', 'profile', 'openid']],
    ]);
    findMany.mockReset().mockImplementation((input) => {
      const clientId = input.where?.clientId;
      if (typeof clientId !== 'string')
        throw new Error('Expected exact internal client identifier.');
      return Promise.resolve(
        (names.get(clientId) ?? []).map((name) => ({ scope: { name } })),
      );
    });
    module = await Test.createTestingModule({
      imports: [ClientRegistryModule],
      providers: [
        {
          provide: 'scope-consumer',
          inject: [ScopeLookupService],
          useFactory: (scopes: ScopeLookupService) => scopes,
        },
      ],
    })
      .overrideProvider(PrismaService)
      .useValue({
        clientScope: { findMany, ...mutations },
        client: { findUnique: unexpected, ...mutations },
        scope: { findMany: unexpected, ...mutations },
        clientRedirectUri: mutations,
        $transaction: unexpected,
        $queryRaw: unexpected,
        $executeRaw: unexpected,
        $queryRawUnsafe: unexpected,
        $executeRawUnsafe: unexpected,
        $connect: unexpected,
        $disconnect: unexpected,
      })
      .compile();
    service = module.get<ScopeLookupService>('scope-consumer');
    logs = [
      ...(['log', 'info', 'warn', 'error', 'debug'] as const).map((method) =>
        vi.spyOn(console, method).mockImplementation(() => undefined),
      ),
      ...(['log', 'warn', 'error', 'debug', 'verbose', 'fatal'] as const).map(
        (method) =>
          vi
            .spyOn(Logger.prototype, method)
            .mockImplementation(() => undefined),
      ),
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
  it.each([
    ['student-spa', studentId, ['email', 'openid', 'profile']],
    [
      'banking-web',
      bankingId,
      ['banking.transactions.read', 'email', 'openid', 'profile'],
    ],
    ['admin-portal', adminId, ['email', 'openid', 'profile']],
  ] as const)(
    'returns exactly assigned canonical names for %s via internal UUID',
    async (_clientId, id, expected) => {
      const result = await service.getAllowedScopeNames(id);
      expect(result).toEqual(expected);
      expect(new Set(result).size).toBe(result.length);
      expect(findMany).toHaveBeenCalledExactlyOnceWith({
        where: { clientId: id },
        select: { scope: { select: { name: true } } },
      });
      expect(result.every((value) => typeof value === 'string')).toBe(true);
    },
  );
  it('sorts exact strings by code units and removes only exact duplicates, without mutating the source', async () => {
    const exact = [
      'read',
      'Read',
      ' read ',
      'caf\u00e9',
      'cafe\u0301',
      'read:detail',
      'read write',
      '',
      'profile',
      'read',
    ];
    names.set(studentId, exact);
    expect(await service.getAllowedScopeNames(studentId)).toEqual(
      [...new Set(exact)].sort(),
    );
    expect(exact).toEqual([
      'read',
      'Read',
      ' read ',
      'caf\u00e9',
      'cafe\u0301',
      'read:detail',
      'read write',
      '',
      'profile',
      'read',
    ]);
  });
  it('is deterministic for differently ordered assignments', async () => {
    names.set(studentId, ['profile', 'openid', 'email']);
    const first = await service.getAllowedScopeNames(studentId);
    names.set(studentId, ['email', 'profile', 'openid']);
    expect(await service.getAllowedScopeNames(studentId)).toEqual(first);
  });
  it('does not invent OIDC defaults or add resource scopes', async () => {
    names.set(studentId, ['custom.scope']);
    expect(await service.getAllowedScopeNames(studentId)).toEqual([
      'custom.scope',
    ]);
    names.set(studentId, []);
    expect(await service.getAllowedScopeNames(studentId)).toEqual([]);
  });
  it('returns [] for a valid unassigned/unknown UUID without an extra Client lookup', async () => {
    expect(
      await service.getAllowedScopeNames(
        'c82336c1-d281-48c6-981b-201b962cfa08',
      ),
    ).toEqual([]);
    expect(findMany).toHaveBeenCalledOnce();
  });
  it.each([
    '',
    ' ',
    'student-spa',
    'not-a-uuid',
    ` ${studentId}`,
    `${studentId} `,
    studentId.replaceAll('-', ''),
  ])(
    'rejects malformed internal IDs before querying (case %#)',
    async (value) => {
      await expect(service.getAllowedScopeNames(value)).rejects.toThrow(
        /^Invalid client record identifier\.$/,
      );
      expect(findMany).not.toHaveBeenCalled();
    },
  );
  it('validates uppercase UUID without changing the query string', async () => {
    const uppercase = studentId.toUpperCase();
    await service.getAllowedScopeNames(uppercase);
    expect(findMany.mock.calls[0][0].where).toEqual({ clientId: uppercase });
  });
  it.each(['async', 'sync'])(
    'sanitizes %s Prisma failures without attaching identifiers or driver causes',
    async (mode) => {
      const failure = new Error(`private SQL ${studentId}`, {
        cause: new Error('private driver detail'),
      });
      if (mode === 'async') findMany.mockRejectedValueOnce(failure);
      else
        findMany.mockImplementationOnce(() => {
          throw failure;
        });
      let rejected = false;
      try {
        await service.getAllowedScopeNames(studentId);
      } catch (error) {
        rejected = true;
        expect(error instanceof Error).toBe(true);
        if (!(error instanceof Error)) expect.fail('Expected sanitized Error.');
        expect(error.message).toBe('Scope lookup failed.');
        expect(error.cause).toBeUndefined();
        expect(Object.keys(error)).toEqual([]);
        for (const value of [studentId, 'private SQL', 'private driver detail'])
          expect((error.message + (error.stack ?? '')).includes(value)).toBe(
            false,
          );
      }
      expect(rejected).toBe(true);
    },
  );
  it('reads again after assignments change; returned arrays are independent and uncached', async () => {
    const first = await service.getAllowedScopeNames(studentId);
    first.push('caller-only');
    names.set(studentId, ['updated.scope']);
    expect(await service.getAllowedScopeNames(studentId)).toEqual([
      'updated.scope',
    ]);
    expect(findMany.mock.calls.length).toBe(2);
  });
});
