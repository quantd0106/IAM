import { beforeEach, describe, expect, it, vi } from 'vitest';
import * as argon2 from 'argon2';
import { ClientAuthenticationService } from './client-authentication.service.js';
import type { PrismaService } from '../prisma/prisma.service.js';

vi.mock('argon2', () => ({ verify: vi.fn() }));
const hash = '$argon2id$private-hash-canary';
const secret = 'private-secret-canary';
const row = {
  id: 'private-uuid',
  clientId: 'banking-web',
  clientType: 'CONFIDENTIAL' as const,
  enabled: true,
  clientSecretHash: hash,
  accessTokenTtl: 321,
  refreshTokenTtl: 2592000,
  accessTokenAudience: ' exact-audience ',
};
const invalid = { ok: false, error: 'invalid_client' };
const basic = (id = row.clientId, value = secret): string =>
  'Basic ' +
  Buffer.from(
    `${encodeURIComponent(id)}:${encodeURIComponent(value)}`,
  ).toString('base64');

describe('ClientAuthenticationService read-only safe boundary', () => {
  const findUnique = vi.fn();
  const service = new ClientAuthenticationService({
    client: { findUnique },
  } as unknown as PrismaService);
  beforeEach(() => {
    vi.resetAllMocks();
    findUnique.mockResolvedValue(row);
    vi.mocked(argon2.verify).mockResolvedValue(true);
  });
  it('uses exact client_id, privately selects a hash and returns only safe metadata', async () => {
    const clientId = ' Banking e\u0301 %2F+ ';
    findUnique.mockResolvedValue({ ...row, clientId });
    expect(
      await service.authenticateTokenClient(clientId, basic(clientId)),
    ).toEqual({
      ok: true,
      client: {
        id: row.id,
        clientId,
        clientType: 'CONFIDENTIAL',
        accessTokenTtl: row.accessTokenTtl,
        refreshTokenTtl: row.refreshTokenTtl,
        accessTokenAudience: row.accessTokenAudience,
      },
    });
    expect(findUnique).toHaveBeenCalledExactlyOnceWith({
      where: { clientId },
      select: {
        id: true,
        clientId: true,
        clientType: true,
        enabled: true,
        clientSecretHash: true,
        accessTokenTtl: true,
        refreshTokenTtl: true,
        accessTokenAudience: true,
      },
    });
    expect(argon2.verify).toHaveBeenCalledExactlyOnceWith(hash, secret);
  });
  it('allows PUBLIC without Authorization and never reads/verifies its hash', async () => {
    findUnique.mockResolvedValue({
      ...row,
      clientType: 'PUBLIC',
      get clientSecretHash(): never {
        throw new Error('Unexpected PUBLIC hash read.');
      },
    });
    expect(
      await service.authenticateTokenClient(row.clientId, undefined),
    ).toEqual({
      ok: true,
      client: {
        id: row.id,
        clientId: row.clientId,
        clientType: 'PUBLIC',
        accessTokenTtl: row.accessTokenTtl,
        refreshTokenTtl: row.refreshTokenTtl,
        accessTokenAudience: row.accessTokenAudience,
      },
    });
    expect(argon2.verify).not.toHaveBeenCalled();
  });
  it.each([
    undefined,
    '',
    'Bearer secret',
    'Basic !!!!',
    basic('other'),
    basic('Banking-Web'),
  ])('rejects confidential auth case %# before Argon2', async (header) => {
    expect(await service.authenticateTokenClient(row.clientId, header)).toEqual(
      invalid,
    );
    expect(argon2.verify).not.toHaveBeenCalled();
  });
  it.each([
    null,
    { ...row, enabled: false },
    { ...row, clientSecretHash: null },
  ])(
    'rejects unavailable client case %# with the same classification',
    async (client) => {
      findUnique.mockResolvedValue(client);
      expect(
        await service.authenticateTokenClient(row.clientId, basic()),
      ).toEqual(invalid);
      expect(argon2.verify).not.toHaveBeenCalled();
    },
  );
  it.each(['', basic(), 'Bearer secret'])(
    'rejects any supplied PUBLIC authentication case %# without verifying',
    async (header) => {
      findUnique.mockResolvedValue({ ...row, clientType: 'PUBLIC' });
      expect(
        await service.authenticateTokenClient(row.clientId, header),
      ).toEqual(invalid);
      expect(argon2.verify).not.toHaveBeenCalled();
    },
  );
  it('classifies a false Argon2 verification as invalid_client', async () => {
    vi.mocked(argon2.verify).mockResolvedValue(false);
    expect(
      await service.authenticateTokenClient(row.clientId, basic()),
    ).toEqual(invalid);
  });
  it.each(['database', 'argon2', 'stored-hash'])(
    'sanitizes %s infrastructure errors without attaching native causes',
    async (kind) => {
      const privateError = new Error(
        `private SQL/hash/secret ${secret} ${hash}`,
      );
      if (kind === 'database') findUnique.mockRejectedValue(privateError);
      if (kind === 'argon2')
        vi.mocked(argon2.verify).mockRejectedValue(privateError);
      if (kind === 'stored-hash')
        findUnique.mockResolvedValue({
          ...row,
          clientSecretHash: 'broken-hash',
        });
      const error: unknown = await service
        .authenticateTokenClient(row.clientId, basic())
        .catch((value: unknown) => value);
      expect(error).toBeInstanceOf(Error);
      expect((error as Error).message).toBe(
        'Token client authentication failed.',
      );
      expect((error as Error).cause).toBeUndefined();
    },
  );
});
