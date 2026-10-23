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
  RefreshTokenRotationService,
  type RefreshTokenRotationInput,
} from './refresh-token-rotation.service.js';

const subject = 'c0e21e3f-d3ee-425c-a99f-c2e7a7cab53f';
const clientRecordId = 'b2b2dbea-bc3a-42f4-8eae-2de818a4f2ea';
const now = 1800000000123;
const raw = 'A'.repeat(42) + '_';
const digest = 'b'.repeat(64);
const tokenId = 'e3c4a6be-e817-4a5a-a11a-298393b85243';
const familyId = 'a83b0df9-40eb-4a32-8e9c-5e5b12a731cf';
const input = {
  rawRefreshToken: raw,
  clientRecordId,
  accessTokenAudience: 'student-api',
  accessTokenTtl: 123,
};
const fixture = () => ({
  id: tokenId,
  familyId,
  status: 'ACTIVE',
  expiresAt: new Date(now + 1),
  consumedAt: null as Date | null,
  revokedAt: null as Date | null,
  family: {
    id: familyId,
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

describe('M8.6 transaction authority: validation, signing, conditional consume and child', () => {
  const forbidden = vi.fn(() => {
    throw new Error('Unexpected I/O/write/rotation.');
  });
  const findUnique = vi.fn();
  const hash = vi.fn();
  const generate = vi.fn();
  const issue = vi.fn();
  const updateMany = vi.fn();
  const create = vi.fn();
  const transaction = vi.fn();
  const service = new RefreshTokenRotationService(
    {
      refreshToken: {
        findUnique: forbidden,
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
      $transaction: transaction,
    } as unknown as Pick<PrismaService, '$transaction'>,
    { hash, generate },
    { issue },
  );
  let row: ReturnType<typeof fixture>;
  let pending: ReturnType<typeof fixture>;
  let children: unknown[];
  let pendingChildren: unknown[];
  const tx = { refreshToken: { findUnique, updateMany, create } };
  const runTransaction = async (
    operation: (value: typeof tx) => Promise<unknown>,
    failCommit = false,
  ) => {
    pending = structuredClone(row);
    pendingChildren = [...children];
    const result = await operation(tx);
    if (failCommit) throw new Error('private commit failure');
    row = pending;
    children = pendingChildren;
    return result;
  };
  let logs: MockInstance[];
  beforeEach(() => {
    vi.clearAllMocks();
    row = fixture();
    children = [];
    transaction.mockImplementation(
      (operation: (value: typeof tx) => Promise<unknown>) =>
        runTransaction(operation),
    );
    findUnique.mockImplementation(() => Promise.resolve(pending));
    generate.mockReturnValue({
      rawToken: 'C'.repeat(43),
      tokenHash: 'd'.repeat(64),
    });
    issue.mockImplementation((values: { scopes: string[] }) =>
      Promise.resolve({
        accessToken: 'signed-access',
        expiresIn: 123,
        scope: values.scopes.join(' '),
      }),
    );
    updateMany.mockImplementation(
      ({ data }: { data: { status: string; consumedAt: Date } }) => {
        Object.assign(pending, data);
        return Promise.resolve({ count: 1 });
      },
    );
    create.mockImplementation(({ data }: { data: unknown }) => {
      pendingChildren.push(data);
      return Promise.resolve({ id: tokenId });
    });
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
    const result = await service.rotate(input);
    expect(result).toEqual({
      ok: true,
      accessToken: 'signed-access',
      tokenType: 'Bearer',
      expiresIn: 123,
      scope: 'openid profile email',
      refreshToken: 'C'.repeat(43),
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
      id: true,
      familyId: true,
      status: true,
      expiresAt: true,
      consumedAt: true,
      revokedAt: true,
      family: {
        select: {
          id: true,
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
    expect(transaction).toHaveBeenCalledExactlyOnceWith(expect.any(Function), {
      isolationLevel: 'ReadCommitted',
    });
    expect(updateMany).toHaveBeenCalledExactlyOnceWith({
      where: {
        id: tokenId,
        familyId,
        status: 'ACTIVE',
        consumedAt: null,
        revokedAt: null,
        expiresAt: { gt: new Date(now) },
      },
      data: { status: 'CONSUMED', consumedAt: new Date(now) },
    });
    expect(create).toHaveBeenCalledExactlyOnceWith({
      data: {
        familyId,
        parentTokenId: tokenId,
        tokenHash: 'd'.repeat(64),
        status: 'ACTIVE',
        issuedAt: new Date(now),
        expiresAt: new Date(now + 1),
        consumedAt: null,
        revokedAt: null,
      },
      select: { id: true },
    });
    expect(row.status).toBe('CONSUMED');
    expect(row.consumedAt).toEqual(new Date(now));
    expect(issue).toHaveBeenCalledExactlyOnceWith({
      subject,
      audience: 'student-api',
      scopes: ['openid', 'profile', 'email'],
      ttlSeconds: 123,
      roles: [],
      permissions: [],
    });
    expect(generate.mock.invocationCallOrder[0]).toBeLessThan(
      issue.mock.invocationCallOrder[0],
    );
    expect(issue.mock.invocationCallOrder[0]).toBeLessThan(
      updateMany.mock.invocationCallOrder[0],
    );
    expect(updateMany.mock.invocationCallOrder[0]).toBeLessThan(
      create.mock.invocationCallOrder[0],
    );
    expect(JSON.stringify(children).includes('C'.repeat(43))).toBe(false);
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
        await service.rotate({
          ...input,
          rawRefreshToken: candidate,
        } as RefreshTokenRotationInput),
      ).toEqual(invalidGrant);
      expect(hash).not.toHaveBeenCalled();
      expect(findUnique).not.toHaveBeenCalled();
      expect(transaction).not.toHaveBeenCalled();
    },
  );
  it('hashes distinct case-sensitive canonical strings exactly, never decoding or casefolding', async () => {
    for (const candidate of [
      'a'.repeat(43),
      'A'.repeat(43),
      '_'.repeat(43),
      '-'.repeat(43),
    ]) {
      row = fixture();
      await service.rotate({ ...input, rawRefreshToken: candidate });
      expect(hash.mock.lastCall?.[0] === candidate).toBe(true);
    }
  });
  it('returns the same invalid_grant on absent credential, regardless of requested scope', async () => {
    findUnique.mockResolvedValue(null);
    expect(
      await service.rotate({ ...input, requestedScope: 'invalid  scope' }),
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
      expect(await service.rotate(input)).toEqual(invalidGrant);
      expect(updateMany).not.toHaveBeenCalled();
      expect(create).not.toHaveBeenCalled();
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
      expect(await service.rotate({ ...input, requestedScope: '' })).toEqual(
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
      expect(await service.rotate(input)).toEqual(invalidGrant);
      expect(updateMany).not.toHaveBeenCalled();
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
      const family = structuredClone(row.family);
      const result = await service.rotate({ ...input, requestedScope });
      expect(result.ok && result.scope === scopes.join(' ')).toBe(true);
      expect(
        (issue.mock.lastCall?.[0] as { scopes: string[] } | undefined)?.scopes,
      ).toEqual(scopes);
      expect(row.family).toEqual(family);
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
      expect(await service.rotate({ ...input, requestedScope })).toEqual(
        invalidScope,
      );
      expect(updateMany).not.toHaveBeenCalled();
      expect(create).not.toHaveBeenCalled();
      expect(generate).not.toHaveBeenCalled();
      expect(issue).not.toHaveBeenCalled();
    },
  );
  it('accepts exact unusual scope tokens without case normalization, sorting or input mutation', async () => {
    row.family.grantedScopes = ['z', 'OpenID', 'a:b!~'];
    expect(
      await service.rotate({ ...input, requestedScope: 'a:b!~ OpenID' }),
    ).toMatchObject({ ok: true, scope: 'a:b!~ OpenID' });
    expect(row.family.grantedScopes).toEqual(['z', 'OpenID', 'a:b!~']);
  });
  it('rejects replay without changing family or producing another child', async () => {
    const family = structuredClone(row.family);
    await service.rotate(input);
    expect(await service.rotate(input)).toEqual(invalidGrant);
    expect(children).toHaveLength(1);
    expect(row.family).toEqual(family);
    expect(updateMany).toHaveBeenCalledOnce();
  });
  it('inherits the same absolute horizon through RT2 -> RT3 and rejects equality expiry', async () => {
    const expiry = row.expiresAt;
    await service.rotate(input);
    row = {
      ...fixture(),
      id: '9676ec69-42ab-4a20-a6f3-9866a7e9f4b6',
      expiresAt: expiry,
    };
    await service.rotate({ ...input, rawRefreshToken: 'C'.repeat(43) });
    expect(children).toHaveLength(2);
    for (const child of children)
      expect((child as { expiresAt: Date }).expiresAt).toEqual(expiry);
    row = { ...fixture(), expiresAt: expiry };
    vi.mocked(Date.now).mockReturnValue(expiry.getTime());
    expect(await service.rotate(input)).toEqual(invalidGrant);
    expect(children).toHaveLength(2);
  });
  it('returns only invalid_grant on conditional consume count=0; discards transient credentials', async () => {
    updateMany.mockResolvedValueOnce({ count: 0 });
    const before = JSON.stringify(row);
    expect(await service.rotate(input)).toEqual(invalidGrant);
    expect(issue).toHaveBeenCalledOnce();
    expect(create).not.toHaveBeenCalled();
    expect(children).toEqual([]);
    expect(JSON.stringify(row)).toBe(before);
  });
  it('does not expose either credential while transaction commit is pending', async () => {
    let releaseCommit!: () => void;
    let reachedCommit!: () => void;
    const commitGate = new Promise<void>((resolve) => {
      releaseCommit = resolve;
    });
    const ready = new Promise<void>((resolve) => {
      reachedCommit = resolve;
    });
    transaction.mockImplementationOnce(
      async (operation: (value: typeof tx) => Promise<unknown>) => {
        pending = structuredClone(row);
        pendingChildren = [];
        const result = await operation(tx);
        reachedCommit();
        await commitGate;
        row = pending;
        children = pendingChildren;
        return result;
      },
    );
    let delivered = false;
    const result = service.rotate(input).then((value) => {
      delivered = true;
      return value;
    });
    await ready;
    try {
      expect(delivered).toBe(false);
      expect(row.status).toBe('ACTIVE');
      expect(children).toEqual([]);
      expect(create).toHaveBeenCalledOnce();
    } finally {
      releaseCommit();
    }
    expect((await result).ok).toBe(true);
    expect(delivered).toBe(true);
    expect(row.status).toBe('CONSUMED');
    expect(children).toHaveLength(1);
  });
  it.each([
    NaN,
    Infinity,
    -1,
    0.5,
    Number.MAX_SAFE_INTEGER + 1,
    8640000000000001,
  ])('rejects unsafe rotation clock before mutation %#', async (clock) => {
    vi.mocked(Date.now).mockReturnValue(clock);
    await expect(service.rotate(input)).rejects.toThrow(
      'Refresh token rotation failed.',
    );
    expect(updateMany).not.toHaveBeenCalled();
    expect(create).not.toHaveBeenCalled();
    expect(children).toEqual([]);
  });
  it.each([
    'generator',
    'signer',
    'consume',
    'child',
    'transaction',
    'commit',
    'count',
  ])(
    'rolls back %s failure with fixed sanitized error, no partial credentials',
    async (stage) => {
      const before = JSON.stringify(row);
      const native = new Error('private-credential-hash-SQL', {
        cause: new Error('private'),
      });
      if (stage === 'generator')
        generate.mockImplementationOnce(() => {
          throw native;
        });
      if (stage === 'signer') issue.mockRejectedValueOnce(native);
      if (stage === 'consume') updateMany.mockRejectedValueOnce(native);
      if (stage === 'child') create.mockRejectedValueOnce(native);
      if (stage === 'transaction') transaction.mockRejectedValueOnce(native);
      if (stage === 'commit')
        transaction.mockImplementationOnce(
          (operation: (value: typeof tx) => Promise<unknown>) =>
            runTransaction(operation, true),
        );
      if (stage === 'count') updateMany.mockResolvedValueOnce({ count: 2 });
      const error: unknown = await service
        .rotate(input)
        .catch((value: unknown) => value);
      expect(error).toBeInstanceOf(Error);
      expect((error as Error).message).toBe('Refresh token rotation failed.');
      expect((error as Error).cause).toBeUndefined();
      expect(JSON.stringify(row)).toBe(before);
      expect(children).toEqual([]);
    },
  );
  it.each([
    'hash',
    'database',
    'client',
    'clock',
    'date',
    'driver',
    'family',
    'subject',
    'token-id',
    'family-id',
    'family-binding',
    'requested-scope-type',
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
      if (stage === 'token-id') row.id = 'not-uuid';
      if (stage === 'family-id') row.family.id = 'not-uuid';
      if (stage === 'family-binding') row.family.id = tokenId;
      const error: unknown = await service
        .rotate(
          stage === 'requested-scope-type'
            ? ({
                ...input,
                requestedScope: [],
              } as unknown as RefreshTokenRotationInput)
            : stage === 'client'
              ? { ...input, clientRecordId: 'student-spa' }
              : input,
        )
        .catch((value: unknown) => value);
      expect(error).toBeInstanceOf(Error);
      expect((error as Error).message).toBe('Refresh token rotation failed.');
      expect((error as Error).cause).toBeUndefined();
      if (stage === 'hash' || stage === 'client')
        expect(findUnique).not.toHaveBeenCalled();
    },
  );
});
