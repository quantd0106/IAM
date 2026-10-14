import { Logger } from '@nestjs/common';
import { Test, type TestingModule } from '@nestjs/testing';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { Credential, User } from '../generated/prisma/client.js';
import { PrismaService } from '../prisma/prisma.service.js';
import { RedisService } from '../redis/redis.service.js';
import { ConfigService } from '@nestjs/config';
import { PasswordService } from '../security/password/password.service.js';
import { AuthModule } from './auth.module.js';
import {
  LoginValidationService,
  type LoginIdentifier,
} from './login-validation.service.js';

type SelectedUser = Pick<
  User,
  'id' | 'email' | 'username' | 'status' | 'lockedUntil'
> & {
  credential: Pick<Credential, 'passwordHash'> | null;
};

describe('LoginValidationService (isolated unit)', () => {
  const now = new Date('2026-01-01T00:00:00Z');
  const rawPassword = ' opaque e\u0301 test-only input ';
  const hash = 'test-only encoded marker';
  const user: SelectedUser = {
    id: 'test-user-id',
    email: 'MixedCase@example.invalid',
    username: 'MixedCase',
    status: 'ACTIVE',
    lockedUntil: null,
    credential: { passwordHash: hash },
  };
  const selectedFields = {
    id: true,
    email: true,
    username: true,
    status: true,
    lockedUntil: true,
    credential: { select: { passwordHash: true } },
  };
  const findUnique = vi.fn<() => Promise<SelectedUser | null>>();
  const verify = vi.fn<(encoded: string, raw: string) => Promise<boolean>>();
  const writeMethods = {
    create: vi.fn(),
    createMany: vi.fn(),
    update: vi.fn(),
    updateMany: vi.fn(),
    upsert: vi.fn(),
    delete: vi.fn(),
    deleteMany: vi.fn(),
  };
  const transact = vi.fn();
  const executeRaw = vi.fn();
  const hashPassword = vi.fn();
  let module: TestingModule;
  let service: LoginValidationService;

  beforeEach(async () => {
    vi.resetAllMocks();
    // Fake only Date; Nest's real timers and HTTP/server lifecycle remain intact.
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(now);
    findUnique.mockResolvedValue(user);
    verify.mockResolvedValue(true);
    module = await Test.createTestingModule({ imports: [AuthModule] })
      .overrideProvider(RedisService)
      .useValue({})
      .overrideProvider(PrismaService)
      .useValue({
        user: { findUnique, ...writeMethods },
        credential: { ...writeMethods },
        $transaction: transact,
        $executeRaw: executeRaw,
        $executeRawUnsafe: executeRaw,
      })
      .overrideProvider(PasswordService)
      .useValue({ verify, hash: hashPassword })
      .useMocker((token) =>
        token === ConfigService
          ? new ConfigService({
              LOGIN_MAX_FAILURES: 5,
              LOGIN_LOCK_SECONDS: 900,
              PASSWORD_RESET_TTL_SECONDS: 900,
              SESSION_IDLE_TTL_SECONDS: 1800,
              SESSION_ABSOLUTE_TTL_SECONDS: 28800,
              COOKIE_NAME: 'iam.sid',
              COOKIE_SECURE: false,
            })
          : undefined,
      )
      .compile();
    service = module.get(LoginValidationService);
  });

  afterEach(async () => {
    try {
      for (const method of Object.values(writeMethods))
        expect(method).not.toHaveBeenCalled();
      expect(transact).not.toHaveBeenCalled();
      expect(executeRaw).not.toHaveBeenCalled();
      expect(hashPassword).not.toHaveBeenCalled();
    } finally {
      await module.close();
      vi.useRealTimers();
      vi.restoreAllMocks();
    }
  });

  it.each(['email', 'username'] as const)(
    'is wired into AuthModule and performs an exact %s unique lookup with minimal fields',
    async (type) => {
      const value = user[type];
      const result = await service.validate({ type, value }, rawPassword);
      expect(service).toBeInstanceOf(LoginValidationService);
      expect(findUnique).toHaveBeenCalledExactlyOnceWith({
        where: { [type]: value },
        select: selectedFields,
      });
      expect(verify).toHaveBeenCalledExactlyOnceWith(hash, rawPassword);
      expect(result).toEqual({
        ok: true,
        user: { id: user.id, email: user.email, username: user.username },
      });
    },
  );

  it.each(['email', 'username'] as const)(
    'does not trim/casefold/normalize the %s identifier',
    async (type) => {
      const value = ' MixedCase-e\u0301@example.invalid ';
      await service.validate({ type, value }, rawPassword);
      expect(findUnique).toHaveBeenCalledExactlyOnceWith({
        where: { [type]: value },
        select: selectedFields,
      });
    },
  );

  it('keeps email and username namespaces distinct even when values collide', async () => {
    const value = 'collision@example.invalid';
    findUnique
      .mockResolvedValueOnce({ ...user, id: 'email-user-id', email: value })
      .mockResolvedValueOnce({
        ...user,
        id: 'username-user-id',
        username: value,
      });
    const emailResult = await service.validate(
      { type: 'email', value },
      rawPassword,
    );
    const usernameResult = await service.validate(
      { type: 'username', value },
      rawPassword,
    );
    expect(findUnique).toHaveBeenNthCalledWith(1, {
      where: { email: value },
      select: selectedFields,
    });
    expect(findUnique).toHaveBeenNthCalledWith(2, {
      where: { username: value },
      select: selectedFields,
    });
    expect(emailResult.ok && emailResult.user.id).toBe('email-user-id');
    expect(usernameResult.ok && usernameResult.user.id).toBe(
      'username-user-id',
    );
  });

  it.each(['email', 'username'] as const)(
    'rejects unknown %s without password work',
    async (type) => {
      findUnique.mockResolvedValue(null);
      expect(
        await service.validate({ type, value: 'unknown' }, rawPassword),
      ).toEqual({ ok: false, reason: 'INVALID_CREDENTIALS' });
      expect(verify).not.toHaveBeenCalled();
    },
  );

  it('rejects a User without Credential without repairing it', async () => {
    findUnique.mockResolvedValue({ ...user, credential: null });
    expect(
      await service.validate({ type: 'email', value: user.email }, rawPassword),
    ).toEqual({ ok: false, reason: 'INVALID_CREDENTIALS' });
    expect(verify).not.toHaveBeenCalled();
  });

  it('rejects an incorrect password with only the internal User UUID context', async () => {
    verify.mockResolvedValue(false);
    expect(
      await service.validate({ type: 'email', value: user.email }, rawPassword),
    ).toEqual({
      ok: false,
      reason: 'INVALID_CREDENTIALS',
      subjectUserId: user.id,
    });
    expect(verify).toHaveBeenCalledExactlyOnceWith(hash, rawPassword);
  });

  it.each([null, new Date(now.getTime() + 60000)])(
    'rejects DISABLED before verifying or evaluating a lock (case %#)',
    async (lockedUntil) => {
      findUnique.mockResolvedValue({
        ...user,
        status: 'DISABLED',
        lockedUntil,
      });
      expect(
        await service.validate(
          { type: 'email', value: user.email },
          rawPassword,
        ),
      ).toEqual({ ok: false, reason: 'DISABLED' });
      expect(verify).not.toHaveBeenCalled();
    },
  );

  it('rejects a future lock before password verification, without changing it', async () => {
    const lockedUser = { ...user, lockedUntil: new Date(now.getTime() + 1) };
    findUnique.mockResolvedValue(lockedUser);
    expect(
      await service.validate(
        { type: 'username', value: user.username },
        rawPassword,
      ),
    ).toEqual({ ok: false, reason: 'LOCKED' });
    expect(verify).not.toHaveBeenCalled();
    expect(lockedUser.lockedUntil.getTime()).toBe(now.getTime() + 1);
  });

  it.each([null, new Date(now.getTime() - 1), now])(
    'continues verification for null/expired/equal-time locks without clearing them (case %#)',
    async (lockedUntil) => {
      const unlockedUser = { ...user, lockedUntil };
      findUnique.mockResolvedValue(unlockedUser);
      const result = await service.validate(
        { type: 'email', value: user.email },
        rawPassword,
      );
      expect(result.ok).toBe(true);
      expect(verify).toHaveBeenCalledExactlyOnceWith(hash, rawPassword);
      expect(unlockedUser.lockedUntil).toBe(lockedUntil);
    },
  );

  it('projects exactly the safe principal even if persistence returns extra fields', async () => {
    findUnique.mockResolvedValue({
      ...user,
      password: rawPassword,
      salt: 'test-only salt marker',
    } as SelectedUser);
    const result = await service.validate(
      { type: 'email', value: user.email },
      rawPassword,
    );
    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error('Expected validation success.');
    expect(Object.keys(result).sort()).toEqual(['ok', 'user']);
    expect(Object.keys(result.user).sort()).toEqual([
      'email',
      'id',
      'username',
    ]);
  });

  it('preserves the sanitized PasswordService failure instead of reporting invalid credentials', async () => {
    const failure = new Error('Password verification failed.');
    verify.mockRejectedValue(failure);
    await expect(
      service.validate({ type: 'email', value: user.email }, rawPassword),
    ).rejects.toBe(failure);
  });

  it('sanitizes a lookup failure without passing driver details or verifying a password', async () => {
    findUnique.mockRejectedValue(
      new Error('test-only private query/identifier marker'),
    );
    await expect(
      service.validate({ type: 'email', value: user.email }, rawPassword),
    ).rejects.toEqual(new Error('Login validation lookup failed.'));
    expect(verify).not.toHaveBeenCalled();
  });

  it('does not log identifiers, passwords, hashes or login events', async () => {
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
    const identifier: LoginIdentifier = { type: 'email', value: user.email };
    try {
      await service.validate(identifier, rawPassword);
      verify.mockResolvedValue(false);
      await service.validate(identifier, rawPassword);
      verify.mockRejectedValue(new Error('Password verification failed.'));
      await expect(service.validate(identifier, rawPassword)).rejects.toThrow(
        'Password verification failed.',
      );
      findUnique.mockResolvedValue(null);
      await service.validate(identifier, rawPassword);
      findUnique.mockResolvedValue({ ...user, credential: null });
      await service.validate(identifier, rawPassword);
      findUnique.mockResolvedValue({ ...user, status: 'DISABLED' });
      await service.validate(identifier, rawPassword);
      findUnique.mockResolvedValue({
        ...user,
        lockedUntil: new Date(now.getTime() + 1),
      });
      await service.validate(identifier, rawPassword);
      findUnique.mockRejectedValue(
        new Error('test-only private driver marker'),
      );
      await expect(service.validate(identifier, rawPassword)).rejects.toThrow(
        'Login validation lookup failed.',
      );
      for (const spy of spies) expect(spy).not.toHaveBeenCalled();
    } finally {
      for (const spy of spies) spy.mockRestore();
    }
  });
});
