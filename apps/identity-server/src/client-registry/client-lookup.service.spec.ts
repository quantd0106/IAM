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
import type { ClientType, Prisma } from '../generated/prisma/client.js';
import { PrismaModule } from '../prisma/prisma.module.js';
import { PrismaService } from '../prisma/prisma.service.js';
import { ClientRegistryModule } from './client-registry.module.js';
import { ClientSecretService } from './client-secret.service.js';
import {
  ClientLookupService,
  type EnabledClient,
} from './client-lookup.service.js';
import { ScopeLookupService } from './scope-lookup.service.js';

type SelectedClient = Omit<EnabledClient, 'redirectUris'> & {
  enabled: boolean;
  redirectUris: { redirectUri: string }[];
};
const recordId = 'd82336c1-d281-48c6-981b-201b962cfa08';

describe('ClientLookupService', () => {
  const findUnique =
    vi.fn<
      (input: Prisma.ClientFindUniqueArgs) => Promise<SelectedClient | null>
    >();
  const unexpected = vi.fn(() => {
    throw new Error('Unexpected lookup side effect.');
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
  let selected: SelectedClient;
  let module: TestingModule;
  let service: ClientLookupService;
  let logs: MockInstance[];
  beforeEach(async () => {
    vi.clearAllMocks();
    selected = {
      id: recordId,
      clientId: 'student-spa',
      name: 'Student SPA',
      clientType: 'PUBLIC',
      enabled: true,
      accessTokenTtl: 600,
      refreshTokenTtl: 2592000,
      redirectUris: [{ redirectUri: 'http://localhost:3200/callback' }],
    };
    findUnique
      .mockReset()
      .mockImplementation((input) =>
        Promise.resolve(
          input.where.clientId === selected.clientId ? selected : null,
        ),
      );
    module = await Test.createTestingModule({
      imports: [ClientRegistryModule],
      providers: [
        {
          provide: 'registry-consumer',
          inject: [
            ClientLookupService,
            ScopeLookupService,
            ClientSecretService,
          ],
          useFactory: (
            clients: ClientLookupService,
            scopes: ScopeLookupService,
            secrets: ClientSecretService,
          ) => ({ clients, scopes, secrets }),
        },
      ],
    })
      .overrideProvider(PrismaService)
      .useValue({
        client: { findUnique, findFirst: unexpected, ...mutations },
        clientScope: { findMany: unexpected, ...mutations },
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
    service = module.get<{ clients: ClientLookupService }>(
      'registry-consumer',
    ).clients;
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

  it('exports all three capabilities from a non-global Prisma-only module without controllers', () => {
    const consumer = module.get<{
      clients: ClientLookupService;
      scopes: ScopeLookupService;
      secrets: ClientSecretService;
    }>('registry-consumer');
    expect(consumer.clients).toBeInstanceOf(ClientLookupService);
    expect(consumer.scopes).toBeInstanceOf(ScopeLookupService);
    expect(consumer.secrets).toBeInstanceOf(ClientSecretService);
    expect(
      Reflect.getMetadata('imports', ClientRegistryModule) as unknown,
    ).toEqual([PrismaModule]);
    expect(
      Reflect.getMetadata('exports', ClientRegistryModule) as unknown,
    ).toEqual([ClientSecretService, ClientLookupService, ScopeLookupService]);
    expect(
      (Reflect.getMetadata('controllers', ClientRegistryModule) as unknown) ??
        [],
    ).toEqual([]);
    expect(
      Reflect.getMetadata('__module:global__', ClientRegistryModule) as unknown,
    ).not.toBe(true);
  });
  it.each(['PUBLIC', 'CONFIDENTIAL'] satisfies ClientType[])(
    'resolves enabled %s metadata using only the exact unique clientId',
    async (type) => {
      selected.clientType = type;
      const result = await service.requireEnabledClient('student-spa');
      expect(result).toEqual({
        id: recordId,
        clientId: 'student-spa',
        name: 'Student SPA',
        clientType: type,
        accessTokenTtl: 600,
        refreshTokenTtl: 2592000,
        redirectUris: ['http://localhost:3200/callback'],
      });
      expect(findUnique).toHaveBeenCalledExactlyOnceWith({
        where: { clientId: 'student-spa' },
        select: {
          id: true,
          clientId: true,
          name: true,
          clientType: true,
          enabled: true,
          accessTokenTtl: true,
          refreshTokenTtl: true,
          redirectUris: { select: { redirectUri: true } },
        },
      });
    },
  );
  it('never selects, reads or exposes a secret hash, enabled flag or extra delegate property', async () => {
    Object.defineProperty(selected, 'clientSecretHash', {
      enumerable: true,
      get() {
        throw new Error('Secret property must not be read.');
      },
    });
    const result = await service.requireEnabledClient('student-spa');
    expect(Object.keys(result).sort()).toEqual([
      'accessTokenTtl',
      'clientId',
      'clientType',
      'id',
      'name',
      'redirectUris',
      'refreshTokenTtl',
    ]);
    expect(Object.hasOwn(result, 'clientSecretHash')).toBe(false);
    expect(
      Object.hasOwn(
        findUnique.mock.calls[0][0].select ?? {},
        'clientSecretHash',
      ),
    ).toBe(false);
  });
  it('returns exact opaque URI strings, ordered without validating or normalizing them', async () => {
    const uris = [
      'https://example.test/call%62ack?b=2&a=1',
      ' https://EXAMPLE.test/callback ',
      'https://example.test/*',
      'https://example.test/caf\u00e9',
      'https://example.test/cafe\u0301',
    ];
    selected.redirectUris = uris.map((redirectUri) => ({ redirectUri }));
    expect(
      (await service.requireEnabledClient('student-spa')).redirectUris,
    ).toEqual([...uris].sort());
    expect(selected.redirectUris.map((row) => row.redirectUri)).toEqual(uris);
  });
  it('returns no registrations when an enabled client has zero redirects', async () => {
    selected.redirectUris = [];
    expect(
      (await service.requireEnabledClient('student-spa')).redirectUris,
    ).toEqual([]);
  });
  it('preserves explicit name and TTL values rather than supplying defaults', async () => {
    selected.name = ' Exact Name ';
    selected.accessTokenTtl = 123;
    selected.refreshTokenTtl = 456;
    const result = await service.requireEnabledClient('student-spa');
    expect([
      result.name,
      result.accessTokenTtl,
      result.refreshTokenTtl,
    ]).toEqual([' Exact Name ', 123, 456]);
  });
  it.each([
    'Student-spa',
    'student-spa ',
    ' student-spa',
    'STUDENT-SPA',
    'student-spa-extra',
    'prefix-student-spa',
    'student-*',
    'student-%',
    recordId,
    'unknown-client',
  ])(
    'rejects non-matching OAuth identifier without fallback (case %#)',
    async (input) => {
      await expect(service.requireEnabledClient(input)).rejects.toThrow(
        /^Client unavailable\.$/,
      );
      expect(findUnique.mock.calls[0][0].where).toEqual({ clientId: input });
      expect(findUnique).toHaveBeenCalledOnce();
    },
  );
  it.each(['', ' ', ' Exact-Client ', 'caf\u00e9', 'cafe\u0301'])(
    'does not introduce identifier syntax/normalization policy (case %#)',
    async (input) => {
      selected.clientId = input;
      expect((await service.requireEnabledClient(input)).clientId).toBe(input);
      expect(findUnique.mock.calls[0][0].where).toEqual({ clientId: input });
    },
  );
  it('uses the same safe rejection for an unknown and a disabled client, without mutation', async () => {
    await expect(
      service.requireEnabledClient('unknown-client'),
    ).rejects.toThrow(/^Client unavailable\.$/);
    selected.enabled = false;
    await expect(service.requireEnabledClient('student-spa')).rejects.toThrow(
      /^Client unavailable\.$/,
    );
    expect(selected.enabled).toBe(false);
    expect(findUnique.mock.calls.length).toBe(2);
  });
  it.each(['async', 'sync'])(
    'sanitizes %s Prisma failures without identifiers, SQL or causes',
    async (mode) => {
      const failure = new Error('private SQL student-spa', {
        cause: new Error('private driver detail'),
      });
      if (mode === 'async') findUnique.mockRejectedValueOnce(failure);
      else
        findUnique.mockImplementationOnce(() => {
          throw failure;
        });
      let rejected = false;
      try {
        await service.requireEnabledClient('student-spa');
      } catch (error) {
        rejected = true;
        expect(error instanceof Error).toBe(true);
        if (!(error instanceof Error)) expect.fail('Expected sanitized Error.');
        expect(error.message).toBe('Client lookup failed.');
        expect(error.cause).toBeUndefined();
        expect(Object.keys(error)).toEqual([]);
        for (const value of [
          'private SQL',
          'private driver detail',
          'student-spa',
        ])
          expect((error.message + (error.stack ?? '')).includes(value)).toBe(
            false,
          );
      }
      expect(rejected).toBe(true);
    },
  );
  it('queries on every call without caching or retaining returned arrays', async () => {
    const first = await service.requireEnabledClient('student-spa');
    first.redirectUris.push('https://caller.example.test/only');
    expect(
      (await service.requireEnabledClient('student-spa')).redirectUris,
    ).toEqual(['http://localhost:3200/callback']);
    selected.enabled = false;
    await expect(service.requireEnabledClient('student-spa')).rejects.toThrow(
      /^Client unavailable\.$/,
    );
    expect(findUnique.mock.calls.length).toBe(3);
  });
});
