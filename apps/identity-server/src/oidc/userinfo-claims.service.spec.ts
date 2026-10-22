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
import { PrismaService } from '../prisma/prisma.service.js';
import {
  UserInfoClaimsService,
  type UserInfoClaimsInput,
} from './userinfo-claims.service.js';

const forbidden = vi.hoisted(() =>
  vi.fn(() => {
    throw new Error('Unexpected mapping dependency.');
  }),
);
vi.mock('../redis/redis.service.js', () => {
  forbidden();
  return {};
});
vi.mock('../prisma/prisma.service.js', () => ({ PrismaService: class {} }));

const subject = 'c0e21e3f-d3ee-425c-a99f-c2e7a7cab53f';
const username = '  MiXeD-e\u0301-user  ';
const email = 'MiXeD.User@Example.test';

describe('UserInfoClaimsService scope-limited read-only mapping', () => {
  const findUnique = vi.fn();
  const noOtherAccess = new Proxy({}, { get: forbidden });
  const prisma = {
    user: { findUnique },
    credential: noOtherAccess,
    session: noOtherAccess,
    client: noOtherAccess,
    $transaction: forbidden,
  } as unknown as PrismaService;
  const service = new UserInfoClaimsService(prisma);
  let logs: MockInstance[];
  beforeEach(() => {
    vi.clearAllMocks();
    findUnique.mockResolvedValue({ username, email });
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
      expect(forbidden).not.toHaveBeenCalled();
      for (const log of logs) expect(log).not.toHaveBeenCalled();
    } finally {
      vi.restoreAllMocks();
    }
  });
  const query = (): void => {
    expect(findUnique).toHaveBeenCalledExactlyOnceWith({
      where: { id: subject },
      select: { username: true, email: true },
    });
  };
  it.each(
    [
      [],
      ['openid'],
      ['openid', 'banking.transactions.read'],
      [
        'openid',
        'Profile',
        'Email',
        'myprofile',
        'myemail',
        'profile.read',
        'email.read',
      ],
    ].map((scopes) => ({ scopes })),
  )(
    'returns only sub without any database access for grants %#',
    async ({ scopes }) => {
      expect(await service.resolve({ subject, scopes })).toEqual({
        ok: true,
        claims: { sub: subject },
      });
      expect(findUnique).not.toHaveBeenCalled();
    },
  );
  it.each([
    {
      scopes: ['openid', 'profile'],
      claims: { sub: subject, preferred_username: username },
    },
    { scopes: ['openid', 'email'], claims: { sub: subject, email } },
    {
      scopes: ['openid', 'profile', 'email'],
      claims: { sub: subject, preferred_username: username, email },
    },
    {
      scopes: ['openid', 'profile', 'banking.transactions.read'],
      claims: { sub: subject, preferred_username: username },
    },
    {
      scopes: ['email', 'openid', 'profile', 'email', 'profile'],
      claims: { sub: subject, preferred_username: username, email },
    },
  ])(
    'projects exact granted claims using one minimal query %#',
    async ({ scopes, claims }) => {
      expect(await service.resolve({ subject, scopes })).toEqual({
        ok: true,
        claims,
      });
      query();
    },
  );
  it('never spreads input/array properties, persisted extras, status or metadata and returns fresh objects', async () => {
    const scopes = Object.assign(['openid', 'profile', 'email'], {
      email: 'injected',
      permissions: ['injected'],
    });
    const input = { subject, scopes, email: 'injected', sub: 'injected' };
    const row = {
      username,
      email,
      status: 'DISABLED',
      lockedUntil: new Date(9999999999999),
      passwordHash: 'private',
      name: 'private',
      email_verified: true,
    };
    findUnique.mockResolvedValue(row);
    const result = await service.resolve(input);
    expect(result).toEqual({
      ok: true,
      claims: { sub: subject, preferred_username: username, email },
    });
    query();
    if (!result.ok) throw new Error('Expected successful mapping.');
    result.claims.preferred_username = 'mutated';
    expect(await service.resolve(input)).toEqual({
      ok: true,
      claims: { sub: subject, preferred_username: username, email },
    });
    expect(scopes).toEqual(
      Object.assign(['openid', 'profile', 'email'], {
        email: 'injected',
        permissions: ['injected'],
      }),
    );
    expect(row.username).toBe(username);
  });
  it('preserves exact verified subject spelling in the lookup and response', async () => {
    const upper = subject.toUpperCase();
    expect(
      await service.resolve({ subject: upper, scopes: ['openid', 'email'] }),
    ).toEqual({ ok: true, claims: { sub: upper, email } });
    expect(findUnique).toHaveBeenCalledExactlyOnceWith({
      where: { id: upper },
      select: { username: true, email: true },
    });
  });
  it('distinguishes a missing requested-claim user from operational errors', async () => {
    findUnique.mockResolvedValue(null);
    expect(
      await service.resolve({ subject, scopes: ['openid', 'profile'] }),
    ).toEqual({ ok: false, error: 'invalid_token' });
    query();
    findUnique.mockClear();
    expect(await service.resolve({ subject, scopes: ['openid'] })).toEqual({
      ok: true,
      claims: { sub: subject },
    });
    expect(findUnique).not.toHaveBeenCalled();
  });
  it.each([
    { username: '' },
    { username: null },
    { username: 1 },
    { email: '' },
    { email: null },
    { email: 1 },
    { email: 'invalid' },
    { email: ' user@example.test ' },
  ])(
    'sanitizes malformed selected persisted values %# without repair',
    async (malformed) => {
      findUnique.mockResolvedValue({ username, email, ...malformed });
      const error: unknown = await service
        .resolve({ subject, scopes: ['openid', 'profile', 'email'] })
        .catch((caught: unknown) => caught);
      expect(error).toBeInstanceOf(Error);
      expect((error as Error).message).toBe(
        'UserInfo claims resolution failed.',
      );
      expect((error as Error).cause).toBeUndefined();
      query();
    },
  );
  it('suppresses database driver details and attached causes', async () => {
    findUnique.mockRejectedValue(
      new Error('SQL-DATABASE_URL-subject-email-canary', {
        cause: new Error('private'),
      }),
    );
    const error: unknown = await service
      .resolve({ subject, scopes: ['openid', 'email'] })
      .catch((caught: unknown) => caught);
    expect((error as Error).message).toBe('UserInfo claims resolution failed.');
    expect((error as Error).cause).toBeUndefined();
    expect((error as Error).stack).not.toContain('canary');
    query();
  });
  it.each([
    { subject: 'not-uuid', scopes: ['openid', 'profile'] },
    { subject, scopes: [{ profile: true }] },
  ])('rejects malformed internal input before querying %#', async (input) => {
    await expect(service.resolve(input as UserInfoClaimsInput)).rejects.toThrow(
      'UserInfo claims resolution failed.',
    );
    expect(findUnique).not.toHaveBeenCalled();
  });
});
