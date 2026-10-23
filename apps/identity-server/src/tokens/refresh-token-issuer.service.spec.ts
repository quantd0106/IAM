import { Logger } from '@nestjs/common';
import {
  afterEach,
  beforeEach,
  describe,
  expect,
  it,
  vi,
  type MockInstance,
} from 'vitest';
import type { PrismaService } from '../prisma/prisma.service.js';
import {
  RefreshTokenIssuerService,
  type InitialRefreshTokenInput,
} from './refresh-token-issuer.service.js';

const input: InitialRefreshTokenInput = {
  userId: 'c0e21e3f-d3ee-425c-a99f-c2e7a7cab53f',
  clientRecordId: 'b2b2dbea-bc3a-42f4-8eae-2de818a4f2ea',
  sessionId: 'd4d7b5ef-d0a0-4c59-9fc4-70dd7773a9f3',
  grantedScopes: ['profile', 'Scope:Exact', 'openid'],
  ttlSeconds: 456,
};
const now = 1800000000123;
const rawToken = 'A'.repeat(43);
const tokenHash = 'b'.repeat(64);

describe('M8.4 initial refresh issuer: one atomic family + root, hash only', () => {
  const familyCreate = vi.fn();
  const tokenCreate = vi.fn();
  const tx = {
    refreshTokenFamily: { create: familyCreate },
    refreshToken: { create: tokenCreate },
  };
  let committed: boolean;
  const transaction = vi.fn(
    async (operation: (client: typeof tx) => Promise<void>) => {
      await operation(tx);
      committed = true;
    },
  );
  const generate = vi.fn();
  const issuer = new RefreshTokenIssuerService(
    { $transaction: transaction } as unknown as Pick<
      PrismaService,
      '$transaction'
    >,
    { generate },
  );
  let logs: MockInstance[];
  beforeEach(() => {
    vi.clearAllMocks();
    committed = false;
    vi.spyOn(Date, 'now').mockReturnValue(now);
    familyCreate.mockResolvedValue({ id: 'owned-family' });
    tokenCreate.mockResolvedValue({ id: 'owned-root' });
    generate.mockReturnValue({ rawToken, tokenHash });
    logs = [console, Logger, Logger.prototype].flatMap((target) =>
      ['log', 'info', 'error', 'warn', 'debug', 'verbose', 'fatal'].flatMap(
        (name) =>
          name in target
            ? [
                vi
                  .spyOn(target, name as 'log')
                  .mockImplementation(() => undefined),
              ]
            : [],
      ),
    );
  });
  afterEach(() => {
    try {
      for (const log of logs) expect(log).not.toHaveBeenCalled();
    } finally {
      vi.restoreAllMocks();
    }
  });
  const sanitized = async (candidate: InitialRefreshTokenInput = input) => {
    const error: unknown = await issuer
      .issueInitial(candidate)
      .catch((value: unknown) => value);
    expect(error).toBeInstanceOf(Error);
    expect((error as Error).message).toBe('Refresh token issuance failed.');
    expect((error as Error).cause).toBeUndefined();
    expect(Object.keys(error as object)).toEqual([]);
    expect(committed).toBe(false);
  };
  it('creates the exact bound ACTIVE family then ACTIVE parentless root from one instant and returns raw only after commit', async () => {
    const result = await issuer.issueInitial(input);
    expect(committed).toBe(true);
    expect(Object.keys(result)).toEqual(['refreshToken']);
    expect(result.refreshToken === rawToken).toBe(true);
    expect(generate).toHaveBeenCalledOnce();
    expect(transaction).toHaveBeenCalledOnce();
    expect(Date.now).toHaveBeenCalledOnce();
    expect(familyCreate).toHaveBeenCalledExactlyOnceWith({
      data: {
        userId: input.userId,
        clientId: input.clientRecordId,
        sessionId: input.sessionId,
        grantedScopes: input.grantedScopes,
        status: 'ACTIVE',
        reuseDetectedAt: null,
        revokedAt: null,
        createdAt: new Date(now),
      },
      select: { id: true },
    });
    expect(tokenCreate).toHaveBeenCalledExactlyOnceWith({
      data: {
        familyId: 'owned-family',
        tokenHash,
        parentTokenId: null,
        status: 'ACTIVE',
        issuedAt: new Date(now),
        expiresAt: new Date(now + input.ttlSeconds * 1000),
        consumedAt: null,
        revokedAt: null,
      },
      select: { id: true },
    });
    expect(familyCreate.mock.invocationCallOrder[0]).toBeLessThan(
      tokenCreate.mock.invocationCallOrder[0],
    );
    const family = familyCreate.mock.calls[0][0] as {
      data: { grantedScopes: string[] };
    };
    expect(family.data.grantedScopes).not.toBe(input.grantedScopes);
    expect(
      JSON.stringify([
        familyCreate.mock.calls,
        tokenCreate.mock.calls,
      ]).includes(rawToken),
    ).toBe(false);
  });
  it.each(['family', 'token', 'unique', 'transaction', 'generator'])(
    'sanitizes %s failure, never retries, and never delivers a partial credential',
    async (stage) => {
      const native = new Error('private DB credential/hash/UUID/scopes', {
        cause: new Error('private'),
      });
      if (stage === 'family') familyCreate.mockRejectedValueOnce(native);
      if (stage === 'token' || stage === 'unique')
        tokenCreate.mockRejectedValueOnce(native);
      if (stage === 'transaction') transaction.mockRejectedValueOnce(native);
      if (stage === 'generator')
        generate.mockImplementationOnce(() => {
          throw native;
        });
      await sanitized();
      expect(generate).toHaveBeenCalledOnce();
      expect(transaction).toHaveBeenCalledTimes(stage === 'generator' ? 0 : 1);
      if (stage === 'family') expect(tokenCreate).not.toHaveBeenCalled();
    },
  );
  it.each([
    { userId: 'not-uuid' },
    { clientRecordId: 'student-spa' },
    { sessionId: null },
    { sessionId: undefined },
    { sessionId: 'invalid' },
    { grantedScopes: [] },
    { grantedScopes: ['profile', 'profile'] },
    { grantedScopes: [' profile'] },
    { grantedScopes: ['two scopes'] },
    { grantedScopes: ['é'] },
    { grantedScopes: ['a\\b'] },
    { grantedScopes: ['a"b'] },
    { grantedScopes: 'profile' },
    ...[
      null,
      undefined,
      '600',
      0,
      -1,
      1.5,
      NaN,
      Infinity,
      Number.MAX_SAFE_INTEGER,
    ].map((ttlSeconds) => ({ ttlSeconds })),
  ])(
    'rejects malformed trusted input before generator/transaction %#',
    async (change) => {
      await sanitized({ ...input, ...change } as InitialRefreshTokenInput);
      expect(generate).not.toHaveBeenCalled();
      expect(transaction).not.toHaveBeenCalled();
    },
  );
  it.each([-1, NaN, Infinity, 1.5, Number.MAX_SAFE_INTEGER, 8640000000000000])(
    'rejects invalid clock/addition/date overflow before credentials or writes %#',
    async (instant) => {
      vi.mocked(Date.now).mockReturnValue(instant);
      await sanitized();
      expect(generate).not.toHaveBeenCalled();
      expect(transaction).not.toHaveBeenCalled();
    },
  );
  it('does not deliver the raw value while the transaction is pending', async () => {
    let release!: () => void;
    tokenCreate.mockImplementationOnce(
      () =>
        new Promise((resolve) => {
          release = () => resolve({ id: 'owned-root' });
        }),
    );
    let delivered = false;
    const pending = issuer.issueInitial(input).then((value) => {
      delivered = true;
      return value;
    });
    await vi.waitFor(() => expect(tokenCreate).toHaveBeenCalledOnce());
    expect(delivered).toBe(false);
    release();
    await pending;
    expect(delivered && committed).toBe(true);
  });
});
