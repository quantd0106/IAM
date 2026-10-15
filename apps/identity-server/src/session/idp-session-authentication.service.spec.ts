import { ConfigService } from '@nestjs/config';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { PrismaService } from '../prisma/prisma.service.js';
import type { Environment } from '../config/env.schema.js';
import { IdpSessionCookieService } from './idp-session-cookie.service.js';
import type { IdpSessionStateService } from './idp-session-state.service.js';
import type { IdpSessionState } from './idp-session-state.js';
import {
  IdpSessionAuthenticationService,
  sessionAuthenticationSelect,
} from './idp-session-authentication.service.js';

const id = '9d3d959a-c65b-4ffc-8086-ad563e59f198';
const userId = 'c0e21e3f-d3ee-425c-a99f-c2e7a7cab53f';
const other = '511f14a5-a49c-4f3b-b93b-56eaf3a5ae2b';
const now = 1900000000000;
const original: IdpSessionState = {
  userId,
  authTime: now - 5000,
  mfaLevel: 'password',
  createdAt: now - 5000,
  lastActivityAt: now,
  absoluteExpiresAt: now + 60000,
};
const row = () => ({
  id,
  userId,
  status: 'ACTIVE' as 'ACTIVE' | 'REVOKED',
  createdAt: new Date(original.createdAt),
  expiresAt: new Date(original.absoluteExpiresAt),
  ipAddress: null,
  userAgent: null,
});

describe('IdpSessionAuthenticationService shared M3.6/M5.4 authority', () => {
  const touch = vi.fn<IdpSessionStateService['touch']>();
  const findFirst = vi.fn<() => Promise<ReturnType<typeof row> | null>>();
  const unexpected = vi.fn(() => {
    throw new Error('Unexpected session write.');
  });
  const cookies = new IdpSessionCookieService(
    new ConfigService<Environment, true>({
      COOKIE_NAME: 'configured.sid',
      COOKIE_SECURE: false,
    }),
  );
  const service = new IdpSessionAuthenticationService(
    { touch },
    {
      session: {
        findFirst,
        create: unexpected,
        updateMany: unexpected,
        deleteMany: unexpected,
      },
    } as unknown as PrismaService,
    cookies,
  );
  beforeEach(() => {
    vi.resetAllMocks();
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(now);
    touch.mockResolvedValue(structuredClone(original));
    findFirst.mockResolvedValue(row());
  });
  afterEach(() => {
    expect(unexpected).not.toHaveBeenCalled();
    vi.useRealTimers();
    vi.restoreAllMocks();
  });
  it('parses configured cookie, touches once, then requires coherent live persistent state', async () => {
    const result = await service.authenticate(`configured.sid=${id}`);
    expect(result).toEqual({
      sessionId: id,
      userId,
      authTime: original.authTime,
      mfaLevel: 'password',
      state: original,
      now: new Date(now),
    });
    expect(touch).toHaveBeenCalledExactlyOnceWith(id);
    expect(findFirst).toHaveBeenCalledExactlyOnceWith({
      where: { id, userId, status: 'ACTIVE', expiresAt: { gt: new Date(now) } },
      select: sessionAuthenticationSelect,
    });
    expect(touch.mock.invocationCallOrder[0]).toBeLessThan(
      findFirst.mock.invocationCallOrder[0],
    );
  });
  it.each([
    undefined,
    '',
    'configured.sid=invalid',
    `configured.sid=${id}; configured.sid=${id}`,
    `iam.sid=${id}`,
    `sessionId=${id}`,
    `configured.sid=%39${id.slice(1)}`,
  ])(
    'rejects absent/malformed/duplicate/unconfigured cookies before stores (%#)',
    async (header) => {
      expect(await service.authenticate(header)).toBeNull();
      expect(touch).not.toHaveBeenCalled();
      expect(findFirst).not.toHaveBeenCalled();
    },
  );
  it('does not authenticate a recognized UUID without runtime state', async () => {
    touch.mockResolvedValue(null);
    expect(await service.authenticate(`configured.sid=${id}`)).toBeNull();
    expect(findFirst).not.toHaveBeenCalled();
  });
  it.each([
    null,
    { ...row(), id: other },
    { ...row(), userId: other },
    { ...row(), status: 'REVOKED' as const },
    { ...row(), expiresAt: new Date(now) },
    { ...row(), expiresAt: new Date(now - 1) },
    { ...row(), createdAt: new Date(original.createdAt - 1) },
    { ...row(), expiresAt: new Date(original.absoluteExpiresAt + 1) },
  ])(
    'does not authenticate persistent absence/revocation/expiry/identity/timestamp mismatch (%#)',
    async (persistent) => {
      findFirst.mockResolvedValue(persistent);
      expect(await service.authenticate(`configured.sid=${id}`)).toBeNull();
    },
  );
  it.each(['Redis', 'Prisma'])(
    'sanitizes %s operational failure, never treating outage as logout',
    async (stage) => {
      const logs = (['log', 'info', 'error', 'warn', 'debug'] as const).map(
        (method) => vi.spyOn(console, method),
      );
      const error = new Error(`private SQL/cookie/session:${id}`, {
        cause: new Error('private driver cause'),
      });
      if (stage === 'Redis') touch.mockRejectedValue(error);
      else findFirst.mockRejectedValue(error);
      const caught: unknown = await service
        .authenticate(`configured.sid=${id}`)
        .catch((value: unknown) => value);
      expect(caught).toEqual(new Error('IdP session authentication failed.'));
      expect(caught).not.toHaveProperty('cause');
      expect((caught as Error).stack).not.toContain(id);
      for (const log of logs) expect(log).not.toHaveBeenCalled();
    },
  );
});
