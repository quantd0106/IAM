import { Logger, type INestApplication } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Test } from '@nestjs/testing';
import type { Server } from 'node:http';
import request from 'supertest';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { Environment } from '../config/env.schema.js';
import { PrismaService } from '../prisma/prisma.service.js';
import { RedisService } from '../redis/redis.service.js';
import { IdpSessionStateService } from '../session/idp-session-state.service.js';
import { AdminSessionRevocationService } from './admin-session-revocation.service.js';
import { AuthModule } from './auth.module.js';
import { IdpLogoutService } from './idp-logout.service.js';

const target = 'c0e21e3f-d3ee-425c-a99f-c2e7a7cab53f';
const otherUser = '511f14a5-a49c-4f3b-b93b-56eaf3a5ae2b';
const ids = [
  '030f78ab-1e02-4e9e-8fcd-d9dd1451b5de',
  '227a22b1-b3c2-4b26-9c3d-e581c7c8f698',
  '9d3d959a-c65b-4ffc-8086-ad563e59f198',
];
const foreignId = 'd0cfc4e3-1c40-4c7e-b522-5d8b740b68f8';
const historicalId = '98aa3cfb-2c2e-4aa6-9f02-031148a50be9';
const lateId = '693ab9f0-d412-4459-845e-7ee3667326a6';
type Discovery = {
  where: { userId: string; status: 'ACTIVE' };
  select: { id: true };
  orderBy: { id: 'asc' };
};
const query: Discovery = {
  where: { userId: target, status: 'ACTIVE' },
  select: { id: true },
  orderBy: { id: 'asc' },
};

describe('AdminSessionRevocationService (internal orchestration)', () => {
  const findMany = vi.fn<(input: Discovery) => Promise<{ id: string }[]>>();
  const logout = vi.fn<IdpLogoutService['logout']>();
  const service = new AdminSessionRevocationService(
    { session: { findMany } } as unknown as PrismaService,
    { logout } as unknown as IdpLogoutService,
  );
  beforeEach(() => {
    vi.resetAllMocks();
    findMany.mockResolvedValue(ids.map((id) => ({ id })));
    logout.mockResolvedValue(undefined);
  });
  afterEach(() => vi.restoreAllMocks());

  it('selects only target ACTIVE IDs in deterministic order and returns void', async () => {
    expect(await service.revokeUserSessions(target)).toBeUndefined();
    expect(findMany).toHaveBeenCalledExactlyOnceWith(query);
    expect(logout.mock.calls).toEqual(ids.map((id) => [id]));
  });
  it.each(['unknown', 'known empty'])(
    'treats %s target with no ACTIVE rows as identical success',
    async () => {
      findMany.mockResolvedValue([]);
      await expect(service.revokeUserSessions(target)).resolves.toBeUndefined();
      expect(findMany).toHaveBeenCalledExactlyOnceWith(query);
      expect(logout).not.toHaveBeenCalled();
    },
  );
  it.each([
    '',
    'invalid',
    ' ' + target,
    target + ' ',
    'user:' + target,
    'session:' + target,
    '{' + target + '}',
    '"' + target + '"',
    '123',
    target + '\n',
    target + ':suffix',
    undefined,
    null,
    123,
    {},
  ])(
    'rejects malformed target before stores without normalization (case %#)',
    async (input) => {
      await expect(service.revokeUserSessions(input as string)).rejects.toEqual(
        new Error('Admin session revocation failed.'),
      );
      expect(findMany).not.toHaveBeenCalled();
      expect(logout).not.toHaveBeenCalled();
    },
  );
  it('does not begin revocation until the discovery snapshot resolves', async () => {
    let resolve!: (rows: { id: string }[]) => void;
    findMany.mockReturnValue(
      new Promise((done) => {
        resolve = done;
      }),
    );
    const pending = service.revokeUserSessions(target);
    expect(logout).not.toHaveBeenCalled();
    resolve(ids.map((id) => ({ id })));
    await pending;
  });
  it('awaits each logout before starting the next and before returning success', async () => {
    const finishes: (() => void)[] = [];
    logout.mockImplementation(
      () =>
        new Promise<void>((resolve) => {
          finishes.push(resolve);
        }),
    );
    let completed = false;
    const pending = service.revokeUserSessions(target).then(() => {
      completed = true;
    });
    await vi.waitFor(() => expect(logout.mock.calls).toEqual([[ids[0]]]));
    expect(completed).toBe(false);
    finishes[0]();
    await vi.waitFor(() =>
      expect(logout.mock.calls).toEqual([[ids[0]], [ids[1]]]),
    );
    expect(completed).toBe(false);
    finishes[1]();
    await vi.waitFor(() =>
      expect(logout.mock.calls).toEqual(ids.map((id) => [id])),
    );
    expect(completed).toBe(false);
    finishes[2]();
    await pending;
    expect(completed).toBe(true);
  });
  it.each(['discovery', 'second logout'])(
    'sanitizes %s failure, drops causes and stops without compensation or logging',
    async (stage) => {
      const spies = (
        ['error', 'log', 'warn', 'debug', 'verbose', 'fatal'] as const
      ).map((method) => vi.spyOn(Logger.prototype, method));
      const consoles = (['log', 'error', 'warn', 'info', 'debug'] as const).map(
        (method) => vi.spyOn(console, method),
      );
      const privateMessage =
        'postgresql://user:password@host/db session:' +
        ids[1] +
        ' target=' +
        target;
      const error = new Error(privateMessage, {
        cause: new Error('private cause'),
      });
      if (stage === 'discovery') findMany.mockRejectedValue(error);
      else logout.mockResolvedValueOnce(undefined).mockRejectedValueOnce(error);
      const caught: unknown = await service
        .revokeUserSessions(target)
        .catch((error: unknown) => error);
      expect(caught).toEqual(new Error('Admin session revocation failed.'));
      expect(caught).not.toHaveProperty('cause');
      expect((caught as Error).stack).not.toContain(privateMessage);
      expect(logout.mock.calls).toEqual(
        stage === 'discovery' ? [] : [[ids[0]], [ids[1]]],
      );
      for (const spy of [...spies, ...consoles])
        expect(spy).not.toHaveBeenCalled();
    },
  );
  it('logs no target/session identifiers on success or empty discovery', async () => {
    const spies = (
      ['error', 'log', 'warn', 'debug', 'verbose', 'fatal'] as const
    ).map((method) => vi.spyOn(Logger.prototype, method));
    const consoles = (['log', 'error', 'warn', 'info', 'debug'] as const).map(
      (method) => vi.spyOn(console, method),
    );
    await service.revokeUserSessions(target);
    findMany.mockResolvedValue([]);
    await service.revokeUserSessions(target);
    for (const spy of [...spies, ...consoles])
      expect(spy).not.toHaveBeenCalled();
  });
});

describe('Admin revocation composed with real IdpLogoutService and modeled stores', () => {
  type Row = {
    id: string;
    userId: string;
    status: 'ACTIVE' | 'REVOKED';
    createdAt: number;
    lastActivityAt: number;
    expiresAt: number;
    ipAddress: null;
    userAgent: null;
  };
  const rows = new Map<string, Row>();
  const runtime = new Set<string>();
  const deleted: { id: string; present: boolean }[] = [];
  const states = {
    invalidate: vi.fn<IdpSessionStateService['invalidate']>(),
    read: vi.fn(),
    touch: vi.fn(),
    create: vi.fn(),
  };
  const findMany = vi.fn<(input: Discovery) => Promise<{ id: string }[]>>();
  const updateMany =
    vi.fn<
      (input: {
        where: { id: string; status: 'ACTIVE' };
        data: { status: 'REVOKED' };
      }) => Promise<{ count: number }>
    >();
  const userLookup = vi.fn();
  const userUpdate = vi.fn();
  const credentialUpdate = vi.fn();
  const prisma = {
    session: { findMany, updateMany },
    user: { findUnique: userLookup, update: userUpdate },
    credential: { update: credentialUpdate },
  } as unknown as PrismaService;
  const logout = new IdpLogoutService(
    states as unknown as IdpSessionStateService,
    prisma,
  );
  const service = new AdminSessionRevocationService(prisma, logout);
  const addRow = (
    id: string,
    userId = target,
    status: Row['status'] = 'ACTIVE',
  ): void => {
    rows.set(id, {
      id,
      userId,
      status,
      createdAt: 1,
      lastActivityAt: 2,
      expiresAt: 3,
      ipAddress: null,
      userAgent: null,
    });
    runtime.add(id);
  };
  const completed = (): void => {
    for (const id of ids) {
      expect(rows.get(id)?.status).toBe('REVOKED');
      expect(runtime.has(id)).toBe(false);
    }
    expect(states.read).not.toHaveBeenCalled();
    expect(states.touch).not.toHaveBeenCalled();
    expect(states.create).not.toHaveBeenCalled();
    expect(userLookup).not.toHaveBeenCalled();
    expect(userUpdate).not.toHaveBeenCalled();
    expect(credentialUpdate).not.toHaveBeenCalled();
  };
  beforeEach(() => {
    vi.resetAllMocks();
    rows.clear();
    runtime.clear();
    deleted.length = 0;
    for (const id of ids) addRow(id);
    addRow(foreignId, otherUser);
    addRow(historicalId, target, 'REVOKED');
    findMany.mockImplementation(({ where }) =>
      Promise.resolve(
        [...rows.values()]
          .filter(
            (row) => row.userId === where.userId && row.status === where.status,
          )
          .sort((a, b) => a.id.localeCompare(b.id))
          .map(({ id }) => ({ id })),
      ),
    );
    states.invalidate.mockImplementation((id) => {
      deleted.push({ id, present: runtime.delete(id) });
      return Promise.resolve();
    });
    updateMany.mockImplementation(({ where }) => {
      const row = rows.get(where.id);
      const count = row?.status === where.status ? 1 : 0;
      if (row && count) row.status = 'REVOKED';
      return Promise.resolve({ count });
    });
  });
  afterEach(() => vi.restoreAllMocks());
  it('revokes only target ACTIVE rows, including expired/missing runtime, without touching history or other user', async () => {
    runtime.delete(ids[1]);
    const before = [...rows.values()].map((row) => ({ ...row }));
    await service.revokeUserSessions(target);
    completed();
    expect(deleted).toEqual(ids.map((id) => ({ id, present: id !== ids[1] })));
    expect(rows.size).toBe(5);
    for (const row of before)
      expect(rows.get(row.id)).toEqual({
        ...row,
        status: ids.includes(row.id) ? 'REVOKED' : row.status,
      });
    expect(runtime.has(foreignId)).toBe(true);
    expect(runtime.has(historicalId)).toBe(true);
  });
  it('retains S1 revoke, S2 Redis-deleted/DB-ACTIVE and S3 untouched, then rediscovers S2/S3 for retry', async () => {
    const update = updateMany.getMockImplementation()!;
    let fail = true;
    updateMany.mockImplementation((input) => {
      if (fail && input.where.id === ids[1])
        return Promise.reject(new Error('private cause'));
      return update(input);
    });
    await expect(service.revokeUserSessions(target)).rejects.toEqual(
      new Error('Admin session revocation failed.'),
    );
    expect(rows.get(ids[0])?.status).toBe('REVOKED');
    expect(runtime.has(ids[0])).toBe(false);
    expect(rows.get(ids[1])?.status).toBe('ACTIVE');
    expect(runtime.has(ids[1])).toBe(false);
    expect(rows.get(ids[2])?.status).toBe('ACTIVE');
    expect(runtime.has(ids[2])).toBe(true);
    expect(deleted.map(({ id }) => id)).toEqual(ids.slice(0, 2));
    fail = false;
    await service.revokeUserSessions(target);
    completed();
    expect(deleted).toEqual([
      { id: ids[0], present: true },
      { id: ids[1], present: true },
      { id: ids[1], present: false },
      { id: ids[2], present: true },
    ]);
    await service.revokeUserSessions(target);
    expect(deleted).toHaveLength(4);
    expect(rows.size).toBe(5);
  });
  it('supports two concurrent privileged revocations with no new row or runtime resurrection', async () => {
    await Promise.all([
      service.revokeUserSessions(target),
      service.revokeUserSessions(target),
    ]);
    completed();
    expect(rows.size).toBe(5);
    expect(rows.get(foreignId)?.status).toBe('ACTIVE');
    expect(runtime.has(foreignId)).toBe(true);
  });
  it('supports concurrent user logout through the same primitive', async () => {
    await Promise.all([
      service.revokeUserSessions(target),
      logout.logout(ids[1]),
    ]);
    completed();
    expect(rows.size).toBe(5);
  });
  it('does not revoke a new session created after discovery or disable its user', async () => {
    const invalidate = states.invalidate.getMockImplementation()!;
    states.invalidate.mockImplementation((id) => {
      if (id === ids[0]) addRow(lateId);
      return invalidate(id);
    });
    await service.revokeUserSessions(target);
    completed();
    expect(rows.get(lateId)?.status).toBe('ACTIVE');
    expect(runtime.has(lateId)).toBe(true);
    expect(rows.size).toBe(6);
  });
});

describe('Internal module boundary and unchanged HTTP ownership', () => {
  afterEach(() => vi.restoreAllMocks());
  it('exports the injectable capability only through DI, with no admin routes or own-session bypass', async () => {
    const now = Date.now();
    const state = {
      userId: target,
      authTime: now,
      mfaLevel: 'password',
      createdAt: now,
      lastActivityAt: now,
      absoluteExpiresAt: now + 28800000,
    };
    const currentRow = {
      id: ids[0],
      userId: target,
      status: 'ACTIVE',
      createdAt: new Date(now),
      expiresAt: new Date(state.absoluteExpiresAt),
      ipAddress: null,
      userAgent: null,
    };
    const findFirst = vi
      .fn<
        (input: {
          where: { id: string; userId: string };
        }) => Promise<typeof currentRow | null>
      >()
      .mockImplementation(({ where }) =>
        Promise.resolve(
          where.id === ids[0] && where.userId === target ? currentRow : null,
        ),
      );
    const findMany = vi.fn().mockResolvedValue([]);
    const logout = vi.fn<IdpLogoutService['logout']>();
    const states = {
      touch: vi.fn().mockResolvedValue(state),
      read: vi.fn(),
      invalidate: vi.fn(),
    };
    const config = new ConfigService<Environment, true>({
      LOGIN_MAX_FAILURES: 5,
      LOGIN_LOCK_SECONDS: 900,
      PASSWORD_RESET_TTL_SECONDS: 900,
      SESSION_IDLE_TTL_SECONDS: 1800,
      SESSION_ABSOLUTE_TTL_SECONDS: 28800,
      COOKIE_NAME: 'iam.sid',
      COOKIE_SECURE: false,
    });
    const consumer = Symbol('trusted-internal-test-consumer');
    const module = await Test.createTestingModule({
      imports: [AuthModule],
      providers: [
        {
          provide: consumer,
          inject: [AdminSessionRevocationService],
          useFactory: (service: AdminSessionRevocationService) => service,
        },
      ],
    })
      .overrideProvider(PrismaService)
      .useValue({ session: { findFirst, findMany } })
      .overrideProvider(RedisService)
      .useValue({})
      .overrideProvider(IdpSessionStateService)
      .useValue(states)
      .overrideProvider(IdpLogoutService)
      .useValue({ logout })
      .useMocker((token) => (token === ConfigService ? config : undefined))
      .compile();
    const app: INestApplication<Server> = module.createNestApplication<
      INestApplication<Server>
    >({ logger: false });
    const service = module.get<AdminSessionRevocationService>(consumer);
    const revoke = vi.spyOn(service, 'revokeUserSessions');
    try {
      await app.init();
      expect(service).toBeInstanceOf(AdminSessionRevocationService);
      await service.revokeUserSessions(target);
      expect(findMany).toHaveBeenCalledExactlyOnceWith(query);
      revoke.mockClear();
      findMany.mockClear();
      for (const [method, path] of [
        ['DELETE', '/admin/users/' + otherUser + '/sessions'],
        ['POST', '/admin/users/' + otherUser + '/revoke-sessions'],
        ['DELETE', '/management/users/' + otherUser + '/sessions'],
        ['POST', '/auth/admin/revoke-sessions'],
      ]) {
        const pending =
          method === 'POST'
            ? request(app.getHttpServer()).post(path)
            : request(app.getHttpServer()).delete(path);
        await pending
          .set('Cookie', 'iam.sid=' + ids[0])
          .send({ userId: otherUser })
          .expect(404);
      }
      const response = await request(app.getHttpServer())
        .delete('/auth/sessions/' + foreignId)
        .query({ userId: otherUser })
        .set('Cookie', 'iam.sid=' + ids[0])
        .send({ userId: otherUser })
        .expect(404);
      expect(response.body as unknown).toEqual({
        statusCode: 404,
        error: 'Not Found',
        message: 'Session not found.',
      });
      expect(findFirst.mock.calls[1][0].where).toEqual({
        id: foreignId,
        userId: target,
      });
      expect(logout).not.toHaveBeenCalled();
      expect(states.invalidate).not.toHaveBeenCalled();
      expect(revoke).not.toHaveBeenCalled();
      expect(findMany).not.toHaveBeenCalled();
    } finally {
      await app.close();
    }
  });
});
