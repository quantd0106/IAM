import { Logger } from '@nestjs/common';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { PrismaService } from '../prisma/prisma.service.js';
import { IdpSessionStateService } from '../session/idp-session-state.service.js';
import type { IdpSessionState } from '../session/idp-session-state.js';
import { IdpLogoutService } from './idp-logout.service.js';
import { IdpOwnSessionService } from './idp-own-session.service.js';

const currentId = '9d3d959a-c65b-4ffc-8086-ad563e59f198';
const targetId = '227a22b1-b3c2-4b26-9c3d-e581c7c8f698';
const foreignId = 'd0cfc4e3-1c40-4c7e-b522-5d8b740b68f8';
const userId = 'c0e21e3f-d3ee-425c-a99f-c2e7a7cab53f';
const otherUserId = '511f14a5-a49c-4f3b-b93b-56eaf3a5ae2b';
const missingId = '98aa3cfb-2c2e-4aa6-9f02-031148a50be9';
const now = 1767225600000;
const select = {
  id: true,
  userId: true,
  status: true,
  createdAt: true,
  expiresAt: true,
  ipAddress: true,
  userAgent: true,
};
const row = (id = currentId, owner = userId) => ({
  id,
  userId: owner,
  status: 'ACTIVE' as 'ACTIVE' | 'REVOKED',
  createdAt: new Date(now - 5000),
  expiresAt: new Date(now + 28800000),
  lastActivityAt: new Date(now - 5000),
  ipAddress: null as string | null,
  userAgent: null as string | null,
});
const runtime = (owner = userId): IdpSessionState => ({
  userId: owner,
  authTime: now - 5000,
  mfaLevel: 'password',
  createdAt: now - 5000,
  lastActivityAt: now - 1000,
  absoluteExpiresAt: now + 28800000,
});
type Row = ReturnType<typeof row>;
type Lookup = {
  where: {
    id: string;
    userId: string;
    status?: 'ACTIVE';
    expiresAt?: { gt: Date };
  };
  select: object;
};
type List = {
  where: { userId: string; status: 'ACTIVE'; expiresAt: { gt: Date } };
  select: object;
  orderBy: { createdAt?: 'desc'; id?: 'desc' }[];
};

describe('IdpOwnSessionService', () => {
  const states = {
    touch: vi.fn<IdpSessionStateService['touch']>(),
    read: vi.fn<IdpSessionStateService['read']>(),
    invalidate: vi.fn(),
    create: vi.fn(),
  };
  const logout = { logout: vi.fn<IdpLogoutService['logout']>() };
  const findFirst = vi.fn<(input: Lookup) => Promise<Row | null>>();
  const findMany = vi.fn<(input: List) => Promise<Row[]>>();
  const updateMany = vi.fn();
  let rows: Row[];
  const service = new IdpOwnSessionService(
    states as unknown as IdpSessionStateService,
    {
      session: { findFirst, findMany, updateMany },
    } as unknown as PrismaService,
    logout as unknown as IdpLogoutService,
  );
  beforeEach(() => {
    vi.resetAllMocks();
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(now);
    rows = [row(), row(targetId), row(foreignId, otherUserId)];
    states.touch.mockResolvedValue({ ...runtime(), lastActivityAt: now });
    states.read.mockImplementation((id) =>
      Promise.resolve(id === foreignId ? runtime(otherUserId) : runtime()),
    );
    findFirst.mockImplementation(({ where }) =>
      Promise.resolve(
        rows.find(
          (r) =>
            r.id === where.id &&
            r.userId === where.userId &&
            (where.status === undefined || r.status === where.status) &&
            (where.expiresAt === undefined || r.expiresAt > where.expiresAt.gt),
        ) ?? null,
      ),
    );
    findMany.mockImplementation(({ where }) =>
      Promise.resolve(
        rows
          .filter(
            (r) =>
              r.userId === where.userId &&
              r.status === where.status &&
              r.expiresAt > where.expiresAt.gt,
          )
          .sort(
            (a, b) =>
              b.createdAt.getTime() - a.createdAt.getTime() ||
              b.id.localeCompare(a.id),
          ),
      ),
    );
    logout.logout.mockResolvedValue(undefined);
  });
  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  it('touches once, verifies matching live persistent current row, then lists only the trusted subject', async () => {
    const result = await service.list(currentId);
    expect(result.ok).toBe(true);
    expect(states.touch).toHaveBeenCalledExactlyOnceWith(currentId);
    expect(findFirst).toHaveBeenCalledExactlyOnceWith({
      where: {
        id: currentId,
        userId,
        status: 'ACTIVE',
        expiresAt: { gt: new Date(now) },
      },
      select,
    });
    expect(findMany).toHaveBeenCalledExactlyOnceWith({
      where: { userId, status: 'ACTIVE', expiresAt: { gt: new Date(now) } },
      select,
      orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
    });
    expect(states.touch.mock.invocationCallOrder[0]).toBeLessThan(
      findFirst.mock.invocationCallOrder[0],
    );
    expect(states.read).toHaveBeenCalledExactlyOnceWith(targetId);
    expect(updateMany).not.toHaveBeenCalled();
    expect(states.invalidate).not.toHaveBeenCalled();
    expect(states.create).not.toHaveBeenCalled();
    expect(logout.logout).not.toHaveBeenCalled();
    if (!result.ok) throw new Error('Expected authenticated list.');
    expect(result.sessions).toEqual([
      {
        id: currentId,
        createdAt: row().createdAt.toISOString(),
        lastActivityAt: new Date(now).toISOString(),
        expiresAt: row().expiresAt.toISOString(),
        ipAddress: null,
        userAgent: null,
        current: true,
      },
      {
        id: targetId,
        createdAt: row().createdAt.toISOString(),
        lastActivityAt: new Date(runtime().lastActivityAt).toISOString(),
        expiresAt: row().expiresAt.toISOString(),
        ipAddress: null,
        userAgent: null,
        current: false,
      },
    ]);
    expect(result.sessions.filter((s) => s.current)).toHaveLength(1);
  });

  it.each(['', 'invalid', 'session:' + currentId])(
    'rejects invalid current identifier without stores (case %#)',
    async (id) => {
      expect(await service.list(id)).toEqual({
        ok: false,
        reason: 'UNAUTHENTICATED',
      });
      expect(states.touch).not.toHaveBeenCalled();
      expect(findFirst).not.toHaveBeenCalled();
    },
  );
  it('treats absent/expired/malformed runtime as unauthenticated without DB lookup', async () => {
    states.touch.mockResolvedValue(null);
    expect(await service.list(currentId)).toEqual({
      ok: false,
      reason: 'UNAUTHENTICATED',
    });
    expect(findFirst).not.toHaveBeenCalled();
    expect(findMany).not.toHaveBeenCalled();
  });
  it.each([
    null,
    { ...row(), status: 'REVOKED' as const },
    { ...row(), userId: otherUserId },
    { ...row(), id: targetId },
    { ...row(), expiresAt: new Date(now) },
    { ...row(), expiresAt: new Date(now - 1) },
    { ...row(), createdAt: new Date(now - 5001) },
    { ...row(), expiresAt: new Date(now + 28800001) },
  ])(
    'fails closed on current persistent absence/mismatch/revocation/expiry case %#',
    async (current) => {
      findFirst.mockResolvedValueOnce(current);
      expect(await service.list(currentId)).toEqual({
        ok: false,
        reason: 'UNAUTHENTICATED',
      });
      expect(findMany).not.toHaveBeenCalled();
      expect(updateMany).not.toHaveBeenCalled();
      expect(logout.logout).not.toHaveBeenCalled();
    },
  );

  it('filters foreign, revoked and expired rows defensively without reading their runtime', async () => {
    findMany.mockResolvedValue([
      row(foreignId, otherUserId),
      { ...row(targetId), status: 'REVOKED' },
      { ...row(missingId), expiresAt: new Date(now) },
      row(),
    ]);
    expect(await service.list(currentId)).toMatchObject({
      ok: true,
      sessions: [{ id: currentId }],
    });
    expect(states.read).not.toHaveBeenCalled();
    expect(updateMany).not.toHaveBeenCalled();
  });
  it.each([
    null,
    { ...runtime(), userId: otherUserId },
    { ...runtime(), createdAt: now - 5001 },
    { ...runtime(), absoluteExpiresAt: now + 28800001 },
  ])(
    'excludes runtime-missing/corrupt/wrong-user/incoherent candidate case %#',
    async (state) => {
      states.read.mockResolvedValue(state);
      expect(await service.list(currentId)).toMatchObject({
        ok: true,
        sessions: [{ id: currentId }],
      });
      expect(states.touch).toHaveBeenCalledExactlyOnceWith(currentId);
      expect(updateMany).not.toHaveBeenCalled();
    },
  );
  it('projects nullable metadata without returning DB/user/runtime extra fields', async () => {
    rows[1].ipAddress = '192.0.2.1';
    rows[1].userAgent = 'test browser';
    const result = await service.list(currentId);
    if (!result.ok) throw new Error('Expected list.');
    expect(result.sessions[1].ipAddress).toBe('192.0.2.1');
    expect(result.sessions[1].userAgent).toBe('test browser');
    for (const session of result.sessions)
      expect(Object.keys(session).sort()).toEqual(
        [
          'id',
          'createdAt',
          'lastActivityAt',
          'expiresAt',
          'ipAddress',
          'userAgent',
          'current',
        ].sort(),
      );
  });
  it('uses createdAt DESC then ID DESC, not database return order assumptions', async () => {
    rows[1].createdAt = new Date(now - 4000);
    states.read.mockResolvedValue({ ...runtime(), createdAt: now - 4000 });
    const result = await service.list(currentId);
    if (!result.ok) throw new Error('Expected list.');
    expect(result.sessions.map((s) => s.id)).toEqual([targetId, currentId]);
    expect(findMany.mock.calls[0][0].orderBy).toEqual([
      { createdAt: 'desc' },
      { id: 'desc' },
    ]);
  });
  it('never returns a list silently missing the authenticated current session', async () => {
    findMany.mockResolvedValue([row(targetId)]);
    await expect(service.list(currentId)).rejects.toEqual(
      new Error('IdP own-session management failed.'),
    );
  });
  it('does not return a partial list after a genuine candidate Redis failure', async () => {
    states.read.mockRejectedValue(new Error('private runtime details'));
    await expect(service.list(currentId)).rejects.toEqual(
      new Error('IdP own-session management failed.'),
    );
  });

  it.each(['ACTIVE', 'REVOKED'] as const)(
    'proves ownership before reusing logout for an owned %s target',
    async (status) => {
      rows[1].status = status;
      expect(await service.revoke(currentId, targetId)).toEqual({
        ok: true,
        current: false,
      });
      expect(findFirst.mock.calls[1]).toEqual([
        { where: { id: targetId, userId }, select: { id: true, userId: true } },
      ]);
      expect(findFirst.mock.invocationCallOrder[1]).toBeLessThan(
        logout.logout.mock.invocationCallOrder[0],
      );
      expect(logout.logout).toHaveBeenCalledExactlyOnceWith(targetId);
      expect(states.read).not.toHaveBeenCalled();
      expect(states.invalidate).not.toHaveBeenCalled();
      expect(updateMany).not.toHaveBeenCalled();
    },
  );
  it.each([missingId, foreignId])(
    'returns indistinguishable NOT_FOUND without target invalidation (case %#)',
    async (target) => {
      expect(await service.revoke(currentId, target)).toEqual({
        ok: false,
        reason: 'NOT_FOUND',
      });
      expect(findFirst.mock.calls[1][0].where).toEqual({ id: target, userId });
      expect(logout.logout).not.toHaveBeenCalled();
      expect(states.invalidate).not.toHaveBeenCalled();
      expect(states.read).not.toHaveBeenCalled();
    },
  );
  it('does not trust an unexpectedly foreign ownership lookup result', async () => {
    findFirst
      .mockResolvedValueOnce(row())
      .mockResolvedValueOnce(row(foreignId, otherUserId));
    expect(await service.revoke(currentId, foreignId)).toEqual({
      ok: false,
      reason: 'NOT_FOUND',
    });
    expect(logout.logout).not.toHaveBeenCalled();
  });
  it('reports current-target success only after logout completes', async () => {
    let finish!: () => void;
    logout.logout.mockReturnValue(
      new Promise<void>((resolve) => {
        finish = resolve;
      }),
    );
    let completed = false;
    const pending = service.revoke(currentId, currentId).then((result) => {
      completed = true;
      return result;
    });
    await vi.waitFor(() => expect(logout.logout).toHaveBeenCalledOnce());
    expect(completed).toBe(false);
    finish();
    expect(await pending).toEqual({ ok: true, current: true });
  });
  it('uses the proven canonical UUID for an equivalent uppercase target spelling', async () => {
    findFirst.mockResolvedValueOnce(row()).mockResolvedValueOnce(row());
    expect(await service.revoke(currentId, currentId.toUpperCase())).toEqual({
      ok: true,
      current: true,
    });
    expect(logout.logout).toHaveBeenCalledExactlyOnceWith(currentId);
  });
  it.each(['invalid', '', '{' + targetId + '}', targetId + ':suffix'])(
    'rejects invalid target before authentication/touch or DB (case %#)',
    async (target) => {
      expect(await service.revoke(currentId, target)).toEqual({
        ok: false,
        reason: 'INVALID_IDENTIFIER',
      });
      expect(states.touch).not.toHaveBeenCalled();
      expect(findFirst).not.toHaveBeenCalled();
      expect(logout.logout).not.toHaveBeenCalled();
    },
  );
  it('does not perform ownership lookup when current session cannot authenticate', async () => {
    states.touch.mockResolvedValue(null);
    expect(await service.revoke(currentId, targetId)).toEqual({
      ok: false,
      reason: 'UNAUTHENTICATED',
    });
    expect(findFirst).not.toHaveBeenCalled();
    expect(logout.logout).not.toHaveBeenCalled();
  });
  it.each(['other', 'self'])(
    'allows concurrent %s revoke after both requests authenticate, without new runtime/DB writes',
    async (kind) => {
      const target = kind === 'self' ? currentId : targetId;
      expect(
        await Promise.all([
          service.revoke(currentId, target),
          service.revoke(currentId, target),
        ]),
      ).toEqual([
        { ok: true, current: kind === 'self' },
        { ok: true, current: kind === 'self' },
      ]);
      expect(logout.logout.mock.calls).toEqual([[target], [target]]);
      expect(states.create).not.toHaveBeenCalled();
      expect(updateMany).not.toHaveBeenCalled();
    },
  );

  it.each([
    'touch',
    'current DB',
    'list DB',
    'list Redis',
    'ownership DB',
    'logout',
  ])(
    'sanitizes %s operational errors without secrets, cause or logs',
    async (stage) => {
      const spies = (
        ['error', 'log', 'warn', 'debug', 'verbose', 'fatal'] as const
      ).map((method) => vi.spyOn(Logger.prototype, method));
      const consoles = (['log', 'error', 'warn', 'info', 'debug'] as const).map(
        (method) => vi.spyOn(console, method),
      );
      const privateMessage = 'private URL/session:' + currentId;
      const error = new Error(privateMessage, {
        cause: new Error('private cause'),
      });
      if (stage === 'touch') states.touch.mockRejectedValue(error);
      if (stage === 'current DB') findFirst.mockRejectedValue(error);
      if (stage === 'list DB') findMany.mockRejectedValue(error);
      if (stage === 'list Redis') states.read.mockRejectedValue(error);
      if (stage === 'ownership DB')
        findFirst.mockResolvedValueOnce(row()).mockRejectedValueOnce(error);
      if (stage === 'logout') logout.logout.mockRejectedValue(error);
      const caught: unknown = await (
        stage === 'ownership DB' || stage === 'logout'
          ? service.revoke(currentId, targetId)
          : service.list(currentId)
      ).catch((error: unknown) => error);
      expect(caught).toEqual(new Error('IdP own-session management failed.'));
      expect(caught).not.toHaveProperty('cause');
      expect((caught as Error).stack).not.toContain(privateMessage);
      for (const spy of [...spies, ...consoles])
        expect(spy).not.toHaveBeenCalled();
    },
  );
  it('does not log authenticated list, own revoke or failed ownership', async () => {
    const spies = (
      ['error', 'log', 'warn', 'debug', 'verbose', 'fatal'] as const
    ).map((method) => vi.spyOn(Logger.prototype, method));
    const consoles = (['log', 'error', 'warn', 'info', 'debug'] as const).map(
      (method) => vi.spyOn(console, method),
    );
    await service.list(currentId);
    await service.revoke(currentId, targetId);
    await service.revoke(currentId, foreignId);
    for (const spy of [...spies, ...consoles])
      expect(spy).not.toHaveBeenCalled();
  });
});
