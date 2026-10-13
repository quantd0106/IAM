import { Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Test, type TestingModule } from '@nestjs/testing';
import { createHash } from 'node:crypto';
import {
  afterEach,
  beforeEach,
  describe,
  expect,
  it,
  vi,
  type MockInstance,
} from 'vitest';
import type { Environment } from '../config/env.schema.js';
import type { UserStatus } from '../generated/prisma/client.js';
import { PrismaService } from '../prisma/prisma.service.js';
import { buildRedisKey } from '../redis/redis-key.js';
import { RedisService } from '../redis/redis.service.js';
import {
  PASSWORD_RESET_DELIVERY,
  noOpPasswordResetDelivery,
  type PasswordResetDelivery,
} from './password-reset-delivery.js';
import { PasswordResetRequestService } from './password-reset-request.service.js';

type SelectedUser = {
  id: string;
  status: UserStatus;
  credential: { id: string } | null;
  lockedUntil?: Date;
};

describe('PasswordResetRequestService (isolated unit)', () => {
  const email = 'MixedCase@example.invalid';
  const user: SelectedUser = {
    id: 'test-user-uuid',
    status: 'ACTIVE',
    credential: { id: 'test-credential-uuid' },
  };
  const findUnique = vi.fn<() => Promise<SelectedUser | null>>();
  const setWithTtl =
    vi.fn<(key: string, value: string, ttl: number) => Promise<void>>();
  const deliver = vi.fn<PasswordResetDelivery['deliver']>();
  const unexpected = vi.fn();
  let module: TestingModule;
  let service: PasswordResetRequestService;
  let error: MockInstance<Logger['error']>;
  let otherLogs: ReturnType<typeof vi.spyOn>[];

  beforeEach(async () => {
    vi.resetAllMocks();
    findUnique.mockResolvedValue(user);
    setWithTtl.mockResolvedValue(undefined);
    deliver.mockResolvedValue(undefined);
    module = await Test.createTestingModule({
      providers: [
        PasswordResetRequestService,
        {
          provide: PrismaService,
          useValue: {
            user: { findUnique, update: unexpected, updateMany: unexpected },
            credential: { update: unexpected, updateMany: unexpected },
            $transaction: unexpected,
          },
        },
        {
          provide: RedisService,
          useValue: {
            setWithTtl,
            set: unexpected,
            delete: unexpected,
            incrementWithTtl: unexpected,
          },
        },
        {
          provide: ConfigService,
          useValue: new ConfigService<Environment, true>({
            PASSWORD_RESET_TTL_SECONDS: 73,
          }),
        },
        { provide: PASSWORD_RESET_DELIVERY, useValue: { deliver } },
      ],
    }).compile();
    service = module.get(PasswordResetRequestService);
    error = vi
      .spyOn(Logger.prototype, 'error')
      .mockImplementation(() => undefined);
    otherLogs = [
      vi.spyOn(Logger.prototype, 'log'),
      vi.spyOn(Logger.prototype, 'warn'),
      vi.spyOn(Logger.prototype, 'debug'),
      vi.spyOn(Logger.prototype, 'verbose'),
      vi.spyOn(Logger.prototype, 'fatal'),
      vi.spyOn(console, 'log'),
      vi.spyOn(console, 'info'),
      vi.spyOn(console, 'warn'),
      vi.spyOn(console, 'error'),
      vi.spyOn(console, 'debug'),
    ];
  });
  afterEach(async () => {
    try {
      expect(unexpected).not.toHaveBeenCalled();
      for (const log of otherLogs) expect(log).not.toHaveBeenCalled();
      // Fixed messages only: never dump generated tokens/hashes even on failure.
      expect(
        error.mock.calls.every(
          (args: unknown[]) =>
            args.length === 1 &&
            args[0] === 'Password reset request processing failed.',
        ),
      ).toBe(true);
    } finally {
      await module.close();
      vi.restoreAllMocks();
    }
  });

  it('generates a 32-byte base64url secret, stores only hash/userId with configured TTL, then delivers', async () => {
    expect(await service.request(email)).toBeUndefined();
    expect(findUnique).toHaveBeenCalledExactlyOnceWith({
      where: { email },
      select: { id: true, status: true, credential: { select: { id: true } } },
    });
    expect(setWithTtl.mock.calls.length).toBe(1);
    expect(deliver.mock.calls.length).toBe(1);
    const input = deliver.mock.calls[0][0];
    const [key, value, ttl] = setWithTtl.mock.calls[0];
    const digest = createHash('sha256').update(input.token).digest('hex');
    expect(input.email).toBe(email);
    expect(input.token.length).toBe(43);
    expect(/^[A-Za-z0-9_-]+$/.test(input.token)).toBe(true);
    expect(Buffer.from(input.token, 'base64url').length).toBe(32);
    expect(/^[a-f0-9]{64}$/.test(digest)).toBe(true);
    expect(key === buildRedisKey('pwdreset', digest)).toBe(true);
    expect(/^pwdreset:[a-f0-9]{64}$/.test(key)).toBe(true);
    expect(key.includes(input.token) || value.includes(input.token)).toBe(
      false,
    );
    expect(JSON.parse(value) as unknown).toEqual({ userId: user.id });
    expect(ttl).toBe(73);
    expect(error).not.toHaveBeenCalled();
  });

  it('waits for successful Redis persistence before invoking delivery', async () => {
    let resolveStore!: () => void;
    setWithTtl.mockReturnValue(
      new Promise<void>((resolve) => {
        resolveStore = resolve;
      }),
    );
    const pending = service.request(email);
    await Promise.resolve();
    expect(setWithTtl.mock.calls.length).toBe(1);
    expect(deliver.mock.calls.length).toBe(0);
    resolveStore();
    await pending;
    expect(deliver.mock.calls.length).toBe(1);
  });

  it.each([
    null,
    { ...user, status: 'DISABLED' as const },
    { ...user, credential: null },
  ])(
    'reveals nothing and does no Redis/delivery work for ineligible case %#',
    async (account) => {
      findUnique.mockResolvedValue(account);
      expect(await service.request(email)).toBeUndefined();
      expect(setWithTtl.mock.calls.length).toBe(0);
      expect(deliver.mock.calls.length).toBe(0);
      expect(error).not.toHaveBeenCalled();
    },
  );

  it('allows recovery for an ACTIVE locked account without mutating lock/counter', async () => {
    const lockedUntil = new Date(Date.now() + 60000);
    const locked = { ...user, lockedUntil };
    findUnique.mockResolvedValue(locked);
    await service.request(email);
    expect(deliver.mock.calls.length).toBe(1);
    expect(locked.lockedUntil).toBe(lockedUntil);
  });

  it('preserves exact email identity without service-level casefold/normalization', async () => {
    await service.request(' MixedCase@example.invalid ');
    expect(findUnique).toHaveBeenCalledWith({
      where: { email: ' MixedCase@example.invalid ' },
      select: { id: true, status: true, credential: { select: { id: true } } },
    });
  });

  it('suppresses lookup failure and never exposes driver details or writes state', async () => {
    findUnique.mockRejectedValue(new Error('private query/email/URL marker'));
    expect(await service.request(email)).toBeUndefined();
    expect(setWithTtl.mock.calls.length).toBe(0);
    expect(deliver.mock.calls.length).toBe(0);
    expect(error).toHaveBeenCalledOnce();
  });

  it('does not deliver after Redis failure and never propagates secret-bearing errors', async () => {
    setWithTtl.mockImplementation((key) =>
      Promise.reject(new Error(`private ${email} ${key}`)),
    );
    expect(await service.request(email)).toBeUndefined();
    expect(deliver.mock.calls.length).toBe(0);
    expect(error).toHaveBeenCalledOnce();
  });

  it('suppresses delivery failure with fixed logging and no rollback/password mutation', async () => {
    deliver.mockImplementation(({ token }) =>
      Promise.reject(new Error(`private ${email} ${token}`)),
    );
    expect(await service.request(email)).toBeUndefined();
    expect(setWithTtl.mock.calls.length).toBe(1);
    expect(deliver.mock.calls.length).toBe(1);
    expect(error).toHaveBeenCalledOnce();
  });

  it('creates independent random tokens/hashes for two requests without a user index', async () => {
    await service.request(email);
    await service.request(email);
    expect(setWithTtl.mock.calls.length).toBe(2);
    expect(deliver.mock.calls.length).toBe(2);
    expect(
      deliver.mock.calls[0][0].token !== deliver.mock.calls[1][0].token,
    ).toBe(true);
    expect(setWithTtl.mock.calls[0][0] !== setWithTtl.mock.calls[1][0]).toBe(
      true,
    );
    expect(
      setWithTtl.mock.calls.every(([key]) =>
        /^pwdreset:[a-f0-9]{64}$/.test(key),
      ),
    ).toBe(true);
  });

  it('keeps the default delivery placeholder silent and returns no token', async () => {
    expect(
      await noOpPasswordResetDelivery.deliver({
        email,
        token: 'test-only canary',
      }),
    ).toBeUndefined();
    expect(error).not.toHaveBeenCalled();
  });
});
