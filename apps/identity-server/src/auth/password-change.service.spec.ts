import { Logger } from '@nestjs/common';
import { Test, type TestingModule } from '@nestjs/testing';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { PrismaService } from '../prisma/prisma.service.js';
import { PasswordService } from '../security/password/password.service.js';
import { PasswordChangeService } from './password-change.service.js';

describe('PasswordChangeService (isolated unit)', () => {
  const now = new Date('2026-01-01T00:00:00Z');
  const userId = 'test-subject-uuid';
  const currentPassword = ' opaque e\u0301 test-only current input ';
  const newPassword = ' different e\u0301 test-only new input ';
  const oldHash = 'test-only old encoded marker';
  const newHash = 'test-only new encoded marker';
  const findUnique = vi.fn<() => Promise<{ passwordHash: string } | null>>();
  const verify = vi.fn<(hash: string, raw: string) => Promise<boolean>>();
  const hash = vi.fn<(raw: string) => Promise<string>>();
  const updateMany = vi.fn<() => Promise<{ count: number }>>();
  const unexpectedWrite = vi.fn();
  const transaction = vi.fn();
  let module: TestingModule;
  let service: PasswordChangeService;
  let log: ReturnType<typeof vi.spyOn>;
  let updated: boolean;

  beforeEach(async () => {
    vi.resetAllMocks();
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(now);
    updated = false;
    findUnique.mockResolvedValue({ passwordHash: oldHash });
    verify.mockResolvedValue(true);
    hash.mockResolvedValue(newHash);
    updateMany.mockImplementation(() => {
      updated = true;
      return Promise.resolve({ count: 1 });
    });
    module = await Test.createTestingModule({
      providers: [
        PasswordChangeService,
        {
          provide: PrismaService,
          useValue: {
            credential: {
              findUnique,
              updateMany,
              update: unexpectedWrite,
              create: unexpectedWrite,
            },
            user: { update: unexpectedWrite, updateMany: unexpectedWrite },
            $transaction: transaction,
          },
        },
        { provide: PasswordService, useValue: { verify, hash } },
      ],
    }).compile();
    service = module.get(PasswordChangeService);
    log = vi.spyOn(Logger.prototype, 'log').mockImplementation(() => {
      expect(updated).toBe(true);
    });
  });
  afterEach(async () => {
    try {
      expect(unexpectedWrite).not.toHaveBeenCalled();
      expect(transaction).not.toHaveBeenCalled();
    } finally {
      await module.close();
      vi.useRealTimers();
      vi.restoreAllMocks();
    }
  });

  it('verifies before hashing, uses one CAS update with explicit timestamp, then emits one safe event', async () => {
    expect(
      await service.changePassword(userId, currentPassword, newPassword),
    ).toEqual({ ok: true });
    expect(findUnique).toHaveBeenCalledExactlyOnceWith({
      where: { userId },
      select: { passwordHash: true },
    });
    expect(verify).toHaveBeenCalledExactlyOnceWith(oldHash, currentPassword);
    expect(hash).toHaveBeenCalledExactlyOnceWith(newPassword);
    expect(verify.mock.invocationCallOrder[0]).toBeLessThan(
      hash.mock.invocationCallOrder[0],
    );
    expect(hash.mock.invocationCallOrder[0]).toBeLessThan(
      updateMany.mock.invocationCallOrder[0],
    );
    expect(updateMany).toHaveBeenCalledExactlyOnceWith({
      where: { userId, passwordHash: oldHash },
      data: { passwordHash: newHash, passwordUpdatedAt: now },
    });
    expect(log).toHaveBeenCalledExactlyOnceWith({
      event: 'PASSWORD_CHANGED',
      userId,
    });
  });

  it('returns a generic failure for missing Credential without repairing or doing crypto work', async () => {
    findUnique.mockResolvedValue(null);
    expect(
      await service.changePassword(userId, currentPassword, newPassword),
    ).toEqual({ ok: false, reason: 'INVALID_CURRENT_PASSWORD' });
    expect(verify).not.toHaveBeenCalled();
    expect(hash).not.toHaveBeenCalled();
    expect(updateMany).not.toHaveBeenCalled();
    expect(log).not.toHaveBeenCalled();
  });

  it('rejects a wrong current password without hashing, persistence or audit', async () => {
    verify.mockResolvedValue(false);
    expect(
      await service.changePassword(userId, currentPassword, newPassword),
    ).toEqual({ ok: false, reason: 'INVALID_CURRENT_PASSWORD' });
    expect(hash).not.toHaveBeenCalled();
    expect(updateMany).not.toHaveBeenCalled();
    expect(log).not.toHaveBeenCalled();
  });

  it('rejects an unchanged password only after the current password verifies', async () => {
    expect(
      await service.changePassword(userId, currentPassword, currentPassword),
    ).toEqual({ ok: false, reason: 'PASSWORD_UNCHANGED' });
    expect(verify).toHaveBeenCalledExactlyOnceWith(oldHash, currentPassword);
    expect(hash).not.toHaveBeenCalled();
    expect(updateMany).not.toHaveBeenCalled();
    expect(log).not.toHaveBeenCalled();
  });

  it('does not report PASSWORD_UNCHANGED instead of a wrong current-password failure', async () => {
    verify.mockResolvedValue(false);
    expect(
      await service.changePassword(userId, currentPassword, currentPassword),
    ).toEqual({ ok: false, reason: 'INVALID_CURRENT_PASSWORD' });
    expect(hash).not.toHaveBeenCalled();
    expect(updateMany).not.toHaveBeenCalled();
    expect(log).not.toHaveBeenCalled();
  });

  it('loses stale CAS safely without retrying, overwriting or emitting audit', async () => {
    updateMany.mockResolvedValue({ count: 0 });
    expect(
      await service.changePassword(userId, currentPassword, newPassword),
    ).toEqual({ ok: false, reason: 'INVALID_CURRENT_PASSWORD' });
    expect(findUnique).toHaveBeenCalledOnce();
    expect(hash).toHaveBeenCalledOnce();
    expect(updateMany).toHaveBeenCalledOnce();
    expect(log).not.toHaveBeenCalled();
  });

  it('preserves a sanitized verify/internal malformed-hash failure', async () => {
    const failure = new Error('Password verification failed.');
    verify.mockRejectedValue(failure);
    await expect(
      service.changePassword(userId, currentPassword, newPassword),
    ).rejects.toBe(failure);
    expect(hash).not.toHaveBeenCalled();
    expect(updateMany).not.toHaveBeenCalled();
    expect(log).not.toHaveBeenCalled();
  });

  it('propagates safe hashing failure without writing or emitting audit', async () => {
    const failure = new Error('Password hashing failed.');
    hash.mockRejectedValue(failure);
    await expect(
      service.changePassword(userId, currentPassword, newPassword),
    ).rejects.toBe(failure);
    expect(updateMany).not.toHaveBeenCalled();
    expect(log).not.toHaveBeenCalled();
  });

  it('sanitizes Prisma lookup failures without crypto work or audit', async () => {
    findUnique.mockRejectedValue(
      new Error('test-only private query/hash/input marker'),
    );
    await expect(
      service.changePassword(userId, currentPassword, newPassword),
    ).rejects.toEqual(new Error('Password change failed.'));
    expect(verify).not.toHaveBeenCalled();
    expect(hash).not.toHaveBeenCalled();
    expect(updateMany).not.toHaveBeenCalled();
    expect(log).not.toHaveBeenCalled();
  });

  it('sanitizes Prisma write failures without forwarding causes or emitting audit', async () => {
    updateMany.mockRejectedValue(
      new Error('test-only private query/hash/input marker'),
    );
    await expect(
      service.changePassword(userId, currentPassword, newPassword),
    ).rejects.toEqual(new Error('Password change failed.'));
    expect(log).not.toHaveBeenCalled();
  });

  it('does not report success or audit for an unexpected update count', async () => {
    updateMany.mockResolvedValue({ count: 2 });
    await expect(
      service.changePassword(userId, currentPassword, newPassword),
    ).rejects.toEqual(new Error('Password change failed.'));
    expect(log).not.toHaveBeenCalled();
  });

  it.each([
    ['', currentPassword, newPassword],
    [userId, '', newPassword],
    [userId, currentPassword, ''],
    [null, currentPassword, newPassword],
    [userId, 123, newPassword],
    [userId, currentPassword, undefined],
  ])(
    'rejects non-string/empty primitive input case %# before accessing persistence',
    async (subject, current, next) => {
      await expect(
        service.changePassword(
          subject as string,
          current as string,
          next as string,
        ),
      ).rejects.toThrow(
        'Password change input must contain non-empty strings.',
      );
      expect(findUnique).not.toHaveBeenCalled();
      expect(verify).not.toHaveBeenCalled();
      expect(hash).not.toHaveBeenCalled();
      expect(updateMany).not.toHaveBeenCalled();
      expect(log).not.toHaveBeenCalled();
    },
  );

  it.each([
    [' ', '  '],
    [' e\u0301 ', ' \u00e9 '],
    ['a', 'b'],
  ])(
    'preserves opaque input and adds no password policy (case %#)',
    async (current, next) => {
      expect(await service.changePassword(userId, current, next)).toEqual({
        ok: true,
      });
      expect(verify).toHaveBeenCalledExactlyOnceWith(oldHash, current);
      expect(hash).toHaveBeenCalledExactlyOnceWith(next);
    },
  );

  it('returns only {ok:true} even if persistence supplies additional sensitive fields', async () => {
    findUnique.mockResolvedValue({
      passwordHash: oldHash,
      currentPassword,
      credential: {},
      salt: 'test-only marker',
    } as { passwordHash: string });
    const result = await service.changePassword(
      userId,
      currentPassword,
      newPassword,
    );
    expect(Object.keys(result)).toEqual(['ok']);
    expect(log).toHaveBeenCalledExactlyOnceWith({
      event: 'PASSWORD_CHANGED',
      userId,
    });
  });

  it('logs only the safe audit payload and no password/hash/driver details', async () => {
    const spies = [
      vi.spyOn(console, 'log'),
      vi.spyOn(console, 'info'),
      vi.spyOn(console, 'warn'),
      vi.spyOn(console, 'error'),
      vi.spyOn(console, 'debug'),
      vi.spyOn(Logger.prototype, 'error'),
      vi.spyOn(Logger.prototype, 'warn'),
      vi.spyOn(Logger.prototype, 'debug'),
      vi.spyOn(Logger.prototype, 'verbose'),
      vi.spyOn(Logger.prototype, 'fatal'),
    ];
    try {
      await service.changePassword(userId, currentPassword, newPassword);
      expect(log).toHaveBeenCalledExactlyOnceWith({
        event: 'PASSWORD_CHANGED',
        userId,
      });
      findUnique.mockRejectedValue(
        new Error('test-only private driver details'),
      );
      await expect(
        service.changePassword(userId, currentPassword, newPassword),
      ).rejects.toThrow('Password change failed.');
      expect(log).toHaveBeenCalledOnce();
      for (const spy of spies) expect(spy).not.toHaveBeenCalled();
    } finally {
      for (const spy of spies) spy.mockRestore();
    }
  });
});
