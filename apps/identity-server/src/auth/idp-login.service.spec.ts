import { Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { Environment } from '../config/env.schema.js';
import { PrismaService } from '../prisma/prisma.service.js';
import { IdpSessionStateService } from '../session/idp-session-state.service.js';
import { IdpLoginService } from './idp-login.service.js';
import {
  LoginAttemptService,
  type LoginAttemptResult,
} from './login-attempt.service.js';

type SessionData = {
  userId: string;
  status: 'ACTIVE';
  createdAt: Date;
  lastActivityAt: Date;
  expiresAt: Date;
};
type CreateInput = { data: SessionData; select: { id: true } };
describe('IdpLoginService (isolated orchestration)', () => {
  const now = 1767225600000;
  const sessionId = '9d3d959a-c65b-4ffc-8086-ad563e59f198';
  const secondId = '227a22b1-b3c2-4b26-9c3d-e581c7c8f698';
  const user = {
    id: 'c0e21e3f-d3ee-425c-a99f-c2e7a7cab53f',
    email: 'unit@example.invalid',
    username: 'unit',
  };
  const identifier = {
    type: 'email' as const,
    value: ' opaque-e\u0301@example.invalid ',
  };
  const password = ' opaque e\u0301 password ';
  const attempts = { attempt: vi.fn<LoginAttemptService['attempt']>() };
  const create = vi.fn<(input: CreateInput) => Promise<{ id: string }>>();
  const state = { create: vi.fn<IdpSessionStateService['create']>() };
  const transaction =
    vi.fn<
      (
        callback: (tx: {
          session: { create: typeof create };
        }) => Promise<string>,
      ) => Promise<string>
    >();
  const committed = new Set<string>();
  let rollbacks = 0;
  let service: IdpLoginService;
  const configure = (seconds = 28800): IdpLoginService =>
    new IdpLoginService(
      attempts as unknown as LoginAttemptService,
      { $transaction: transaction } as unknown as PrismaService,
      state as unknown as IdpSessionStateService,
      new ConfigService<Environment, true>({
        SESSION_ABSOLUTE_TTL_SECONDS: seconds,
      }),
    );
  beforeEach(() => {
    vi.resetAllMocks();
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(now);
    committed.clear();
    rollbacks = 0;
    attempts.attempt.mockResolvedValue({ ok: true, user });
    create.mockResolvedValue({ id: sessionId });
    state.create.mockResolvedValue(undefined);
    transaction.mockImplementation(async (callback) => {
      try {
        const id = await callback({ session: { create } });
        committed.add(id);
        return id;
      } catch (error) {
        rollbacks++;
        throw error;
      }
    });
    service = configure();
  });
  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  it('uses one authentication attempt, one time decision and the DB-generated UUID in both stores', async () => {
    expect(await service.login(identifier, password)).toEqual({
      ok: true,
      sessionId,
    });
    expect(attempts.attempt).toHaveBeenCalledExactlyOnceWith(
      identifier,
      password,
    );
    expect(transaction).toHaveBeenCalledOnce();
    expect(create).toHaveBeenCalledExactlyOnceWith({
      data: {
        userId: user.id,
        status: 'ACTIVE',
        createdAt: new Date(now),
        lastActivityAt: new Date(now),
        expiresAt: new Date(now + 28800000),
      },
      select: { id: true },
    });
    expect(state.create).toHaveBeenCalledExactlyOnceWith(sessionId, {
      userId: user.id,
      authTime: now,
      mfaLevel: 'password',
      createdAt: now,
      lastActivityAt: now,
      absoluteExpiresAt: now + 28800000,
    });
    expect(committed.size).toBe(1);
    expect(create.mock.invocationCallOrder[0]).toBeLessThan(
      state.create.mock.invocationCallOrder[0],
    );
  });

  it.each(['INVALID_CREDENTIALS', 'DISABLED', 'LOCKED'] as const)(
    'projects %s to a generic failure without starting any session persistence',
    async (reason) => {
      attempts.attempt.mockResolvedValue({ ok: false, reason });
      expect(await service.login(identifier, password)).toEqual({ ok: false });
      expect(transaction).not.toHaveBeenCalled();
      expect(create).not.toHaveBeenCalled();
      expect(state.create).not.toHaveBeenCalled();
    },
  );
  it('uses configured absolute lifetime, not the default literal', async () => {
    service = configure(17);
    await service.login(identifier, password);
    expect(create.mock.calls[0]?.[0].data.expiresAt.getTime()).toBe(
      now + 17000,
    );
    expect(state.create.mock.calls[0]?.[1].absoluteExpiresAt).toBe(now + 17000);
  });
  it.each([
    0,
    -1,
    NaN,
    Infinity,
    Number.MAX_SAFE_INTEGER,
    Math.floor(Number.MAX_SAFE_INTEGER / 1000),
    8640000000001,
  ])(
    'rejects unsafe arithmetic/Date range before persistence (case %#)',
    async (seconds) => {
      await expect(
        configure(seconds).login(identifier, password),
      ).rejects.toEqual(new Error('IdP login failed.'));
      expect(transaction).not.toHaveBeenCalled();
      expect(state.create).not.toHaveBeenCalled();
    },
  );
  it.each([-1, NaN, Infinity, Number.MAX_SAFE_INTEGER])(
    'rejects an invalid chosen timestamp before persistence (case %#)',
    async (time) => {
      vi.spyOn(Date, 'now').mockReturnValue(time);
      await expect(service.login(identifier, password)).rejects.toEqual(
        new Error('IdP login failed.'),
      );
      expect(transaction).not.toHaveBeenCalled();
    },
  );
  it('waits for credential authentication/reset before starting the transaction', async () => {
    let resolve!: (result: LoginAttemptResult) => void;
    attempts.attempt.mockReturnValue(
      new Promise((done) => {
        resolve = done;
      }),
    );
    const pending = service.login(identifier, password);
    await Promise.resolve();
    expect(transaction).not.toHaveBeenCalled();
    resolve({ ok: true, user });
    await pending;
  });
  it('waits for Redis state and then final commit before reporting success', async () => {
    let resolveState!: () => void;
    let resolveCommit!: () => void;
    const redisPending = new Promise<void>((done) => {
      resolveState = done;
    });
    const commitPending = new Promise<void>((done) => {
      resolveCommit = done;
    });
    state.create.mockReturnValue(redisPending);
    transaction.mockImplementation(async (callback) => {
      const id = await callback({ session: { create } });
      await commitPending;
      committed.add(id);
      return id;
    });
    let finished = false;
    const pending = service.login(identifier, password).then((result) => {
      finished = true;
      return result;
    });
    await vi.waitFor(() => expect(state.create).toHaveBeenCalledOnce());
    expect(finished).toBe(false);
    expect(committed.size).toBe(0);
    resolveState();
    await Promise.resolve();
    expect(finished).toBe(false);
    resolveCommit();
    expect(await pending).toEqual({ ok: true, sessionId });
  });
  it('rolls back the transaction with zero committed sessions after Redis failure', async () => {
    state.create.mockRejectedValue(
      new Error('private Redis key/URL/state', {
        cause: new Error('private cause'),
      }),
    );
    await expect(service.login(identifier, password)).rejects.toEqual(
      new Error('IdP login failed.'),
    );
    expect(create).toHaveBeenCalledOnce();
    expect(rollbacks).toBe(1);
    expect(committed.size).toBe(0);
  });
  it('never creates Redis state after PostgreSQL Session create fails', async () => {
    create.mockRejectedValue(new Error('private PostgreSQL URL/query'));
    await expect(service.login(identifier, password)).rejects.toEqual(
      new Error('IdP login failed.'),
    );
    expect(state.create).not.toHaveBeenCalled();
    expect(committed.size).toBe(0);
  });
  it('returns no success after final commit failure and adds no deletion/revocation API', async () => {
    transaction.mockImplementation(async (callback) => {
      await callback({ session: { create } });
      throw new Error('private commit failure');
    });
    await expect(service.login(identifier, password)).rejects.toEqual(
      new Error('IdP login failed.'),
    );
    expect(state.create).toHaveBeenCalledOnce();
    expect(committed.size).toBe(0);
  });
  it('sanitizes an operational authentication error without starting persistence', async () => {
    attempts.attempt.mockRejectedValue(
      new Error('private password/driver/cause'),
    );
    await expect(service.login(identifier, password)).rejects.toEqual(
      new Error('IdP login failed.'),
    );
    expect(transaction).not.toHaveBeenCalled();
  });
  it('allows two independent concurrent logins with distinct DB IDs', async () => {
    create
      .mockResolvedValueOnce({ id: sessionId })
      .mockResolvedValueOnce({ id: secondId });
    const results = await Promise.all([
      service.login(identifier, password),
      service.login(identifier, password),
    ]);
    expect(results).toEqual([
      { ok: true, sessionId },
      { ok: true, sessionId: secondId },
    ]);
    expect(committed.size).toBe(2);
    expect(state.create.mock.calls.map(([id]) => id).sort()).toEqual(
      [sessionId, secondId].sort(),
    );
  });
  it('does not log credentials, authentication results or session identifiers', async () => {
    const spies = (
      ['error', 'log', 'warn', 'debug', 'verbose', 'fatal'] as const
    ).map((method) => vi.spyOn(Logger.prototype, method));
    const consoles = (['log', 'error', 'warn', 'info', 'debug'] as const).map(
      (method) => vi.spyOn(console, method),
    );
    await service.login(identifier, password);
    state.create.mockRejectedValue(new Error('private state'));
    await expect(service.login(identifier, password)).rejects.toThrow(
      'IdP login failed.',
    );
    for (const spy of [...spies, ...consoles])
      expect(spy).not.toHaveBeenCalled();
  });
});
