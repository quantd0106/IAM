import { Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Test, type TestingModule } from '@nestjs/testing';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { Environment } from '../config/env.schema.js';
import { PrismaService } from '../prisma/prisma.service.js';
import { RedisService } from '../redis/redis.service.js';
import { LoginAttemptService } from './login-attempt.service.js';
import {
  LoginValidationService,
  type LoginValidationResult,
} from './login-validation.service.js';

describe('LoginAttemptService (isolated unit)', () => {
  const now = new Date('2026-01-01T00:00:00Z');
  const user = {
    id: 'test-user-uuid',
    email: 'unit@example.invalid',
    username: 'unit',
  };
  const identifier = { type: 'email' as const, value: user.email };
  const rawPassword = ' opaque test-only input ';
  const key = `rate:${user.id}:login-failure`;
  const failed: LoginValidationResult = {
    ok: false,
    reason: 'INVALID_CREDENTIALS',
    subjectUserId: user.id,
  };
  const validate = vi.fn<() => Promise<LoginValidationResult>>();
  const reset = vi.fn<(key: string) => Promise<number>>();
  const increment = vi.fn<(key: string, seconds: number) => Promise<number>>();
  const updateMany = vi.fn<() => Promise<{ count: number }>>();
  let module: TestingModule;
  let service: LoginAttemptService;

  async function configure(maxFailures = 5, lockSeconds = 900): Promise<void> {
    module = await Test.createTestingModule({
      providers: [
        LoginAttemptService,
        { provide: LoginValidationService, useValue: { validate } },
        {
          provide: RedisService,
          useValue: { delete: reset, incrementWithTtl: increment },
        },
        { provide: PrismaService, useValue: { user: { updateMany } } },
        {
          provide: ConfigService,
          useValue: new ConfigService<Environment, true>({
            LOGIN_MAX_FAILURES: maxFailures,
            LOGIN_LOCK_SECONDS: lockSeconds,
          }),
        },
      ],
    }).compile();
    service = module.get(LoginAttemptService);
  }

  beforeEach(async () => {
    vi.resetAllMocks();
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(now);
    validate.mockResolvedValue(failed);
    reset.mockResolvedValue(1);
    increment.mockResolvedValue(1);
    updateMany.mockResolvedValue({ count: 1 });
    await configure();
  });
  afterEach(async () => {
    await module.close();
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  it.each([0, 1])(
    'resets before returning safe success, including DEL=%i',
    async (deleted) => {
      validate.mockResolvedValue({ ok: true, user });
      reset.mockResolvedValue(deleted);
      expect(await service.attempt(identifier, rawPassword)).toEqual({
        ok: true,
        user,
      });
      expect(validate).toHaveBeenCalledExactlyOnceWith(identifier, rawPassword);
      expect(reset).toHaveBeenCalledExactlyOnceWith(key);
      expect(increment).not.toHaveBeenCalled();
      expect(updateMany).not.toHaveBeenCalled();
    },
  );

  it('does not return success until Redis DEL has completed', async () => {
    validate.mockResolvedValue({ ok: true, user });
    let resolveReset!: (value: number) => void;
    const resetPromise = new Promise<number>((resolve) => {
      resolveReset = resolve;
    });
    reset.mockReturnValue(resetPromise);
    let finished = false;
    const pending = service.attempt(identifier, rawPassword).then((result) => {
      finished = true;
      return result;
    });
    await Promise.resolve();
    expect(reset).toHaveBeenCalledWith(key);
    expect(finished).toBe(false);
    resolveReset(0);
    expect(await pending).toEqual({ ok: true, user });
  });

  it('fails closed when resetting failure state fails', async () => {
    validate.mockResolvedValue({ ok: true, user });
    reset.mockRejectedValue(new Error('test-only private key/URL marker'));
    await expect(service.attempt(identifier, rawPassword)).rejects.toEqual(
      new Error('Login attempt failed.'),
    );
    expect(increment).not.toHaveBeenCalled();
    expect(updateMany).not.toHaveBeenCalled();
  });

  it.each(['unknown User', 'missing Credential'])(
    'creates no counter for %s without a subject UUID',
    async () => {
      validate.mockResolvedValue({ ok: false, reason: 'INVALID_CREDENTIALS' });
      expect(await service.attempt(identifier, rawPassword)).toEqual({
        ok: false,
        reason: 'INVALID_CREDENTIALS',
      });
      expect(increment).not.toHaveBeenCalled();
      expect(reset).not.toHaveBeenCalled();
      expect(updateMany).not.toHaveBeenCalled();
    },
  );

  it.each([1, 4])(
    'increments failure #%i without DB lock or counter deletion',
    async (count) => {
      increment.mockResolvedValue(count);
      expect(await service.attempt(identifier, rawPassword)).toEqual({
        ok: false,
        reason: 'INVALID_CREDENTIALS',
      });
      expect(increment).toHaveBeenCalledExactlyOnceWith(key, 900);
      expect(updateMany).not.toHaveBeenCalled();
      expect(reset).not.toHaveBeenCalled();
    },
  );

  it.each([5, 6])(
    'conditionally establishes the lock at count %i and keeps the counter',
    async (count) => {
      increment.mockResolvedValue(count);
      if (count > 5) updateMany.mockResolvedValue({ count: 0 });
      expect(await service.attempt(identifier, rawPassword)).toEqual({
        ok: false,
        reason: 'LOCKED',
      });
      expect(updateMany).toHaveBeenCalledExactlyOnceWith({
        where: {
          id: user.id,
          OR: [{ lockedUntil: null }, { lockedUntil: { lte: now } }],
        },
        data: { lockedUntil: new Date(now.getTime() + 900000) },
      });
      expect(reset).not.toHaveBeenCalled();
    },
  );

  it.each(['DISABLED', 'LOCKED'] as const)(
    'does not touch Redis/DB for already %s',
    async (reason) => {
      validate.mockResolvedValue({ ok: false, reason });
      expect(await service.attempt(identifier, rawPassword)).toEqual({
        ok: false,
        reason,
      });
      expect(increment).not.toHaveBeenCalled();
      expect(reset).not.toHaveBeenCalled();
      expect(updateMany).not.toHaveBeenCalled();
    },
  );

  it('fails closed when atomic increment fails, without writing a lock', async () => {
    increment.mockRejectedValue(new Error('test-only private key/URL marker'));
    await expect(service.attempt(identifier, rawPassword)).rejects.toEqual(
      new Error('Login attempt failed.'),
    );
    expect(updateMany).not.toHaveBeenCalled();
    expect(reset).not.toHaveBeenCalled();
  });

  it('fails closed when lock persistence fails, without deleting the threshold counter', async () => {
    increment.mockResolvedValue(5);
    updateMany.mockRejectedValue(new Error('test-only private Prisma details'));
    await expect(service.attempt(identifier, rawPassword)).rejects.toEqual(
      new Error('Login attempt failed.'),
    );
    expect(reset).not.toHaveBeenCalled();
  });

  it('consumes subjectUserId internally and projects only the safe principal', async () => {
    expect(await service.attempt(identifier, rawPassword)).toEqual({
      ok: false,
      reason: 'INVALID_CREDENTIALS',
    });
    validate.mockResolvedValue({
      ok: true,
      user: { ...user, credential: {}, passwordHash: 'private test marker' },
    } as LoginValidationResult);
    const result = await service.attempt(identifier, rawPassword);
    expect(result).toEqual({ ok: true, user });
    if (!result.ok) throw new Error('Expected success.');
    expect(Object.keys(result.user).sort()).toEqual([
      'email',
      'id',
      'username',
    ]);
  });

  it('uses ConfigService values, not canonical literals in policy logic', async () => {
    await module.close();
    await configure(2, 17);
    increment.mockResolvedValue(2);
    expect(await service.attempt(identifier, rawPassword)).toEqual({
      ok: false,
      reason: 'LOCKED',
    });
    expect(increment).toHaveBeenCalledExactlyOnceWith(key, 17);
    expect(updateMany).toHaveBeenCalledWith({
      where: {
        id: user.id,
        OR: [{ lockedUntil: null }, { lockedUntil: { lte: now } }],
      },
      data: { lockedUntil: new Date(now.getTime() + 17000) },
    });
  });

  it('preserves sanitized validation failures and does not touch state', async () => {
    const error = new Error('Password verification failed.');
    validate.mockRejectedValue(error);
    await expect(service.attempt(identifier, rawPassword)).rejects.toBe(error);
    expect(increment).not.toHaveBeenCalled();
    expect(reset).not.toHaveBeenCalled();
    expect(updateMany).not.toHaveBeenCalled();
  });

  it('does not log passwords/hashes/identifiers or premature login/account audit events', async () => {
    const spies = [
      vi.spyOn(console, 'log'),
      vi.spyOn(console, 'info'),
      vi.spyOn(console, 'warn'),
      vi.spyOn(console, 'error'),
      vi.spyOn(console, 'debug'),
      vi.spyOn(Logger.prototype, 'log'),
      vi.spyOn(Logger.prototype, 'error'),
      vi.spyOn(Logger.prototype, 'warn'),
      vi.spyOn(Logger.prototype, 'debug'),
      vi.spyOn(Logger.prototype, 'verbose'),
      vi.spyOn(Logger.prototype, 'fatal'),
    ];
    try {
      await service.attempt(identifier, rawPassword);
      increment.mockResolvedValue(5);
      await service.attempt(identifier, rawPassword);
      updateMany.mockRejectedValue(new Error('test-only private DB marker'));
      await expect(service.attempt(identifier, rawPassword)).rejects.toThrow(
        'Login attempt failed.',
      );
      increment.mockRejectedValue(new Error('test-only private Redis marker'));
      await expect(service.attempt(identifier, rawPassword)).rejects.toThrow(
        'Login attempt failed.',
      );
      validate.mockResolvedValue({ ok: true, user });
      await service.attempt(identifier, rawPassword);
      reset.mockRejectedValue(new Error('test-only private reset marker'));
      await expect(service.attempt(identifier, rawPassword)).rejects.toThrow(
        'Login attempt failed.',
      );
      for (const spy of spies) expect(spy).not.toHaveBeenCalled();
    } finally {
      for (const spy of spies) spy.mockRestore();
    }
  });
});
