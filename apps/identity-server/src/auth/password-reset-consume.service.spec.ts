import { Logger } from '@nestjs/common';
import { Test, type TestingModule } from '@nestjs/testing';
import { createHash } from 'node:crypto';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { PrismaService } from '../prisma/prisma.service.js';
import { RedisService } from '../redis/redis.service.js';
import { PasswordService } from '../security/password/password.service.js';
import { PasswordResetConsumeService } from './password-reset-consume.service.js';

describe('PasswordResetConsumeService (isolated unit)', () => {
  const now = new Date('2026-01-01T00:00:00Z');
  const userId = '00000000-0000-4000-8000-000000000001';
  const state = JSON.stringify({ userId });
  const rawToken = ' test-only opaque MixedCase e\u0301 token ';
  const newPassword = ' test-only opaque \u00e9 password ';
  const passwordHash = 'test-only encoded password marker';
  const key = 'pwdreset:' + createHash('sha256').update(rawToken).digest('hex');
  const invalid = { ok: false, reason: 'INVALID_OR_EXPIRED_TOKEN' };
  const get = vi.fn<(key: string) => Promise<string | null>>();
  const getAndDelete = vi.fn<(key: string) => Promise<string | null>>();
  const hash = vi.fn<(raw: string) => Promise<string>>();
  const updateMany = vi.fn<() => Promise<{ count: number }>>();
  const unexpected = vi.fn();
  let module: TestingModule;
  let service: PasswordResetConsumeService;
  let log: ReturnType<typeof vi.spyOn>;
  let otherLogs: ReturnType<typeof vi.spyOn>[];
  let persisted: boolean;

  beforeEach(async () => {
    vi.resetAllMocks();
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(now);
    persisted = false;
    get.mockResolvedValue(state);
    getAndDelete.mockResolvedValue(state);
    hash.mockResolvedValue(passwordHash);
    updateMany.mockImplementation(() => {
      persisted = true;
      return Promise.resolve({ count: 1 });
    });
    module = await Test.createTestingModule({
      providers: [
        PasswordResetConsumeService,
        {
          provide: RedisService,
          useValue: {
            get,
            getAndDelete,
            set: unexpected,
            setWithTtl: unexpected,
            delete: unexpected,
            incrementWithTtl: unexpected,
          },
        },
        {
          provide: PrismaService,
          useValue: {
            credential: { updateMany, update: unexpected, create: unexpected },
            user: { update: unexpected, updateMany: unexpected },
            $transaction: unexpected,
          },
        },
        { provide: PasswordService, useValue: { hash, verify: unexpected } },
      ],
    }).compile();
    service = module.get(PasswordResetConsumeService);
    log = vi.spyOn(Logger.prototype, 'log').mockImplementation(() => {
      expect(persisted).toBe(true);
    });
    otherLogs = [
      vi.spyOn(Logger.prototype, 'error'),
      vi.spyOn(Logger.prototype, 'warn'),
      vi.spyOn(Logger.prototype, 'debug'),
      vi.spyOn(Logger.prototype, 'verbose'),
      vi.spyOn(Logger.prototype, 'fatal'),
      vi.spyOn(console, 'log'),
      vi.spyOn(console, 'info'),
      vi.spyOn(console, 'error'),
      vi.spyOn(console, 'warn'),
      vi.spyOn(console, 'debug'),
    ];
  });
  afterEach(async () => {
    try {
      expect(unexpected).not.toHaveBeenCalled();
      for (const spy of otherLogs) expect(spy).not.toHaveBeenCalled();
    } finally {
      await module.close();
      vi.useRealTimers();
      vi.restoreAllMocks();
    }
  });

  it('prechecks exact SHA-256 key, hashes opaque input, atomically consumes, then updates and audits', async () => {
    expect(await service.consume(rawToken, newPassword)).toEqual({ ok: true });
    expect(get.mock.calls.length).toBe(1);
    expect(get.mock.calls[0][0] === key).toBe(true);
    expect(hash).toHaveBeenCalledExactlyOnceWith(newPassword);
    expect(getAndDelete.mock.calls.length).toBe(1);
    expect(getAndDelete.mock.calls[0][0] === key).toBe(true);
    expect(get.mock.invocationCallOrder[0]).toBeLessThan(
      hash.mock.invocationCallOrder[0],
    );
    expect(hash.mock.invocationCallOrder[0]).toBeLessThan(
      getAndDelete.mock.invocationCallOrder[0],
    );
    expect(getAndDelete.mock.invocationCallOrder[0]).toBeLessThan(
      updateMany.mock.invocationCallOrder[0],
    );
    expect(updateMany).toHaveBeenCalledExactlyOnceWith({
      where: { userId },
      data: { passwordHash, passwordUpdatedAt: now },
    });
    expect(log).toHaveBeenCalledExactlyOnceWith({
      event: 'PASSWORD_RESET',
      userId,
    });
  });

  it('rejects unknown/expired token before hashing, consumption, DB or audit', async () => {
    get.mockResolvedValue(null);
    expect(await service.consume(rawToken, newPassword)).toEqual(invalid);
    expect(hash).not.toHaveBeenCalled();
    expect(getAndDelete).not.toHaveBeenCalled();
    expect(updateMany).not.toHaveBeenCalled();
    expect(log).not.toHaveBeenCalled();
  });

  it('rejects replay/race loss when GETDEL returns null, even after a successful precheck', async () => {
    getAndDelete.mockResolvedValue(null);
    expect(await service.consume(rawToken, newPassword)).toEqual(invalid);
    expect(hash).toHaveBeenCalledOnce();
    expect(updateMany).not.toHaveBeenCalled();
    expect(log).not.toHaveBeenCalled();
  });

  it('hash failure leaves token untouched and exposes only a fixed internal error', async () => {
    hash.mockRejectedValue(new Error('private ' + rawToken + newPassword));
    await expect(service.consume(rawToken, newPassword)).rejects.toEqual(
      new Error('Password reset consume failed.'),
    );
    expect(get).toHaveBeenCalledOnce();
    expect(getAndDelete).not.toHaveBeenCalled();
    expect(updateMany).not.toHaveBeenCalled();
    expect(log).not.toHaveBeenCalled();
  });

  const malformedStates = [
    '',
    'not-json',
    'null',
    '[]',
    '123',
    '"private marker"',
    '{}',
    '{"userId":""}',
    '{"userId":"   "}',
    '{"userId":123}',
    '{"userId":null}',
    '{"userId":"not-a-uuid"}',
    JSON.stringify({ userId, extra: 'private marker' }),
  ];
  it.each(malformedStates)(
    'rejects malformed preview state case %# without Argon2 or token destruction',
    async (value) => {
      get.mockResolvedValue(value);
      expect(await service.consume(rawToken, newPassword)).toEqual(invalid);
      expect(hash).not.toHaveBeenCalled();
      expect(getAndDelete).not.toHaveBeenCalled();
      expect(updateMany).not.toHaveBeenCalled();
      expect(log).not.toHaveBeenCalled();
    },
  );

  it.each([
    ...malformedStates,
    JSON.stringify({ userId: '00000000-0000-4000-8000-000000000002' }),
  ])(
    'rejects malformed/mismatched consumed state case %# without writes, audit or token restoration',
    async (value) => {
      getAndDelete.mockResolvedValue(value);
      expect(await service.consume(rawToken, newPassword)).toEqual(invalid);
      expect(getAndDelete).toHaveBeenCalledOnce();
      expect(updateMany).not.toHaveBeenCalled();
      expect(log).not.toHaveBeenCalled();
    },
  );

  it('rejects a missing Credential without creating it or restoring consumed token', async () => {
    updateMany.mockResolvedValue({ count: 0 });
    expect(await service.consume(rawToken, newPassword)).toEqual(invalid);
    expect(updateMany).toHaveBeenCalledOnce();
    expect(log).not.toHaveBeenCalled();
  });

  it.each([2, -1])(
    'rejects unexpected affected count %i with fixed error and no audit',
    async (count) => {
      updateMany.mockResolvedValue({ count });
      await expect(service.consume(rawToken, newPassword)).rejects.toEqual(
        new Error('Password reset consume failed.'),
      );
      expect(log).not.toHaveBeenCalled();
    },
  );

  it('sanitizes PostgreSQL failure after consumption without restoration or audit', async () => {
    updateMany.mockRejectedValue(
      new Error('private query ' + passwordHash + rawToken),
    );
    await expect(service.consume(rawToken, newPassword)).rejects.toEqual(
      new Error('Password reset consume failed.'),
    );
    expect(getAndDelete).toHaveBeenCalledOnce();
    expect(log).not.toHaveBeenCalled();
  });

  it('fails closed on Redis GET failure, before hashing or accessing DB', async () => {
    get.mockRejectedValue(new Error('private ' + key));
    await expect(service.consume(rawToken, newPassword)).rejects.toEqual(
      new Error('Password reset consume failed.'),
    );
    expect(hash).not.toHaveBeenCalled();
    expect(getAndDelete).not.toHaveBeenCalled();
    expect(updateMany).not.toHaveBeenCalled();
    expect(log).not.toHaveBeenCalled();
  });

  it('fails closed on GETDEL failure without DB write or audit', async () => {
    getAndDelete.mockRejectedValue(new Error('private ' + key + rawToken));
    await expect(service.consume(rawToken, newPassword)).rejects.toEqual(
      new Error('Password reset consume failed.'),
    );
    expect(updateMany).not.toHaveBeenCalled();
    expect(log).not.toHaveBeenCalled();
  });

  it.each([' ', ' e\u0301 ', ' \u00e9 ', 'a'])(
    'preserves password whitespace/Unicode and adds no reuse/history policy (case %#)',
    async (password) => {
      await service.consume(rawToken, password);
      expect(hash).toHaveBeenCalledExactlyOnceWith(password);
    },
  );

  it('allows exactly one mocked atomic claimant even when both requests passed precheck and hashing', async () => {
    let release!: () => void;
    const bothHashing = new Promise<void>((resolve) => {
      release = resolve;
    });
    let hashing = 0;
    hash.mockImplementation(async () => {
      if (++hashing === 2) release();
      await bothHashing;
      return passwordHash;
    });
    let available = true;
    getAndDelete.mockImplementation(() => {
      const result = available ? state : null;
      available = false;
      return Promise.resolve(result);
    });
    const results = await Promise.all([
      service.consume(rawToken, 'candidate A'),
      service.consume(rawToken, 'candidate B'),
    ]);
    expect(results.filter((result) => result.ok)).toHaveLength(1);
    expect(results.filter((result) => !result.ok)).toEqual([invalid]);
    expect(hash).toHaveBeenCalledTimes(2);
    expect(getAndDelete).toHaveBeenCalledTimes(2);
    expect(updateMany).toHaveBeenCalledOnce();
    expect(log).toHaveBeenCalledExactlyOnceWith({
      event: 'PASSWORD_RESET',
      userId,
    });
  });

  it('returns only safe result fields even if persistence supplies extra sensitive data', async () => {
    updateMany.mockImplementation(() => {
      persisted = true;
      return Promise.resolve({ count: 1, passwordHash, userId });
    });
    expect(await service.consume(rawToken, newPassword)).toEqual({ ok: true });
    expect(log).toHaveBeenCalledExactlyOnceWith({
      event: 'PASSWORD_RESET',
      userId,
    });
  });
});
