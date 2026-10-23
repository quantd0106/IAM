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
  RefreshTokenGrantService,
  type RefreshTokenGrantInput,
} from './refresh-token-grant.service.js';

const subject = 'c0e21e3f-d3ee-425c-a99f-c2e7a7cab53f';
const clientRecordId = 'b2b2dbea-bc3a-42f4-8eae-2de818a4f2ea';
const now = 1800000000123;
const raw = 'A'.repeat(42) + '_';
const digest = 'b'.repeat(64);
const input = { rawRefreshToken: raw, clientRecordId };
const fixture = () => ({
  status: 'ACTIVE',
  expiresAt: new Date(now + 1),
  consumedAt: null as Date | null,
  revokedAt: null as Date | null,
  family: {
    userId: subject,
    clientId: clientRecordId,
    status: 'ACTIVE',
    grantedScopes: ['openid', 'profile', 'email'] as unknown,
    reuseDetectedAt: null as Date | null,
    revokedAt: null as Date | null,
  },
});
const invalidGrant = { ok: false, error: 'invalid_grant' };
const invalidScope = { ok: false, error: 'invalid_scope' };

describe('M8.5 refresh grant: one hash lookup, trusted snapshot, no mutation', () => {
  const forbidden = vi.fn(() => {
    throw new Error('Unexpected I/O/write/rotation.');
  });
  const findUnique = vi.fn();
  const hash = vi.fn();
  const service = new RefreshTokenGrantService(
    {
      refreshToken: {
        findUnique,
        create: forbidden,
        update: forbidden,
        updateMany: forbidden,
        delete: forbidden,
      },
      refreshTokenFamily: {
        findUnique: forbidden,
        update: forbidden,
        create: forbidden,
      },
      session: { findUnique: forbidden },
      client: { findUnique: forbidden },
      user: { findUnique: forbidden },
      $transaction: forbidden,
    } as unknown as Pick<PrismaService, 'refreshToken'>,
    { hash },
  );
  let row: ReturnType<typeof fixture>;
  let logs: MockInstance[];
  beforeEach(() => {
    vi.clearAllMocks();
    row = fixture();
    findUnique.mockImplementation(() => Promise.resolve(row));
    hash.mockReturnValue(digest);
    vi.spyOn(Date, 'now').mockReturnValue(now);
    logs = [console, Logger, Logger.prototype].flatMap((target) =>
      ['log', 'info', 'warn', 'error', 'debug', 'verbose', 'fatal'].flatMap(
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
  it('hashes exact credential once and uses only a minimal unique hash projection', async () => {
    const result = await service.validate(input);
    expect(result).toEqual({
      ok: true,
      subject,
      scopes: ['openid', 'profile', 'email'],
    });
    expect(hash).toHaveBeenCalledOnce();
    expect(hash.mock.calls[0][0] === raw).toBe(true);
    expect(findUnique).toHaveBeenCalledOnce();
    const query = findUnique.mock.calls[0][0] as {
      where: { tokenHash: string };
      select: unknown;
    };
    expect(query.where.tokenHash === digest).toBe(true);
    expect(query.select).toEqual({
      status: true,
      expiresAt: true,
      consumedAt: true,
      revokedAt: true,
      family: {
        select: {
          userId: true,
          clientId: true,
          status: true,
          grantedScopes: true,
          reuseDetectedAt: true,
          revokedAt: true,
        },
      },
    });
    expect(JSON.stringify(query).includes(raw)).toBe(false);
    expect(hash.mock.invocationCallOrder[0]).toBeLessThan(
      findUnique.mock.invocationCallOrder[0],
    );
    expect(Date.now).toHaveBeenCalledOnce();
    expect(result.ok && result.scopes !== row.family.grantedScopes).toBe(true);
  });
  it.each([
    undefined,
    null,
    '',
    'A'.repeat(42),
    'A'.repeat(44),
    'A'.repeat(43) + '\n',
    'A'.repeat(42) + '+',
    'A'.repeat(42) + '/',
    'A'.repeat(42) + '=',
    'A'.repeat(42) + 'é',
    'A'.repeat(42) + '.',
    'A'.repeat(42) + '~',
    ' ' + raw,
    raw + ' ',
    '%41' + raw.slice(1),
    {},
    [],
  ])(
    'rejects malformed credential before hashing/lookup without normalization %#',
    async (candidate) => {
      expect(
        await service.validate({
          ...input,
          rawRefreshToken: candidate,
        } as RefreshTokenGrantInput),
      ).toEqual(invalidGrant);
      expect(hash).not.toHaveBeenCalled();
      expect(findUnique).not.toHaveBeenCalled();
    },
  );
  it('hashes distinct case-sensitive canonical strings exactly, never decoding or casefolding', async () => {
    for (const candidate of [
      'a'.repeat(43),
      'A'.repeat(43),
      '_'.repeat(43),
      '-'.repeat(43),
    ]) {
      await service.validate({ ...input, rawRefreshToken: candidate });
      expect(hash.mock.lastCall?.[0] === candidate).toBe(true);
    }
  });
  it('returns the same invalid_grant on absent credential, regardless of requested scope', async () => {
    findUnique.mockResolvedValue(null);
    expect(
      await service.validate({ ...input, requestedScope: 'invalid  scope' }),
    ).toEqual(invalidGrant);
  });
  it.each([
    { status: 'CONSUMED' },
    { status: 'REVOKED' },
    { consumedAt: new Date(now) },
    { revokedAt: new Date(now) },
    { expiresAt: new Date(now) },
    { expiresAt: new Date(now - 1) },
  ])(
    'rejects nonactive/inconsistent/expired token without repair %#',
    async (change) => {
      Object.assign(row, change);
      const before = JSON.stringify(row);
      expect(await service.validate(input)).toEqual(invalidGrant);
      expect(JSON.stringify(row) === before).toBe(true);
    },
  );
  it.each([
    { clientId: 'd4d7b5ef-d0a0-4c59-9fc4-70dd7773a9f3' },
    { status: 'REVOKED' },
    { revokedAt: new Date(now) },
    { reuseDetectedAt: new Date(now) },
  ])(
    'rejects wrong internal client or invalid family lifecycle %#',
    async (change) => {
      Object.assign(row.family, change);
      expect(await service.validate({ ...input, requestedScope: '' })).toEqual(
        invalidGrant,
      );
    },
  );
  it.each([
    undefined,
    null,
    [],
    ['profile', 'profile'],
    [''],
    ['two scopes'],
    [' profile'],
    ['é'],
    ['a\\b'],
    ['a"b'],
    'openid',
    [1],
  ])(
    'never treats missing/empty/malformed/duplicate stored scopes as defaults %#',
    async (grantedScopes) => {
      row.family.grantedScopes = grantedScopes;
      expect(await service.validate(input)).toEqual(invalidGrant);
    },
  );
  it.each([
    { requestedScope: undefined, scopes: ['openid', 'profile', 'email'] },
    { requestedScope: 'profile', scopes: ['profile'] },
    { requestedScope: 'email openid', scopes: ['email', 'openid'] },
    {
      requestedScope: 'openid profile email',
      scopes: ['openid', 'profile', 'email'],
    },
  ])(
    'preserves stored or narrowed requested scope order %#',
    async ({ requestedScope, scopes }) => {
      expect(await service.validate({ ...input, requestedScope })).toEqual({
        ok: true,
        subject,
        scopes,
      });
    },
  );
  it.each([
    '',
    'profile profile',
    ' profile',
    'profile ',
    'openid  profile',
    'profile\temail',
    'profile\n',
    'é',
    'a"b',
    'a\\b',
    'OpenID',
    'openid admin',
    'prof',
    'myopenid',
  ])(
    'rejects malformed/duplicate/nonmember requested scope only after valid grant %#',
    async (requestedScope) => {
      expect(await service.validate({ ...input, requestedScope })).toEqual(
        invalidScope,
      );
    },
  );
  it('accepts exact unusual scope tokens without case normalization, sorting or input mutation', async () => {
    row.family.grantedScopes = ['z', 'OpenID', 'a:b!~'];
    expect(
      await service.validate({ ...input, requestedScope: 'a:b!~ OpenID' }),
    ).toEqual({ ok: true, subject, scopes: ['a:b!~', 'OpenID'] });
    expect(row.family.grantedScopes).toEqual(['z', 'OpenID', 'a:b!~']);
  });
  it('permits repeated read-only use only during M8.5; returned arrays are independent', async () => {
    const before = JSON.stringify(row);
    const first = await service.validate(input);
    if (first.ok) first.scopes.reverse();
    expect(await service.validate(input)).toEqual({
      ok: true,
      subject,
      scopes: ['openid', 'profile', 'email'],
    });
    expect(JSON.stringify(row) === before).toBe(true);
  });
  it.each([
    'hash',
    'database',
    'client',
    'clock',
    'date',
    'driver',
    'family',
    'subject',
  ])(
    'sanitizes unexpected %s failure without cause or logging',
    async (stage) => {
      const native = new Error('private token/hash/DB/UUID/scopes', {
        cause: new Error('private'),
      });
      if (stage === 'hash')
        hash.mockImplementationOnce(() => {
          throw native;
        });
      if (stage === 'database') findUnique.mockRejectedValueOnce(native);
      if (stage === 'clock') vi.mocked(Date.now).mockReturnValue(NaN);
      if (stage === 'date') row.expiresAt = new Date(NaN);
      if (stage === 'driver') Object.assign(row, { expiresAt: 'not-a-Date' });
      if (stage === 'family') Object.assign(row, { family: null });
      if (stage === 'subject') row.family.userId = 'not-uuid';
      const error: unknown = await service
        .validate(
          stage === 'client'
            ? { ...input, clientRecordId: 'student-spa' }
            : input,
        )
        .catch((value: unknown) => value);
      expect(error).toBeInstanceOf(Error);
      expect((error as Error).message).toBe(
        'Refresh token grant validation failed.',
      );
      expect((error as Error).cause).toBeUndefined();
      if (stage === 'hash' || stage === 'client')
        expect(findUnique).not.toHaveBeenCalled();
    },
  );
});
