import { Logger } from '@nestjs/common';
import * as crypto from 'node:crypto';
import {
  afterEach,
  beforeEach,
  describe,
  expect,
  it,
  vi,
  type MockInstance,
} from 'vitest';
import { AuthorizationCodeService } from './authorization-code.service.js';
import {
  authorizationCodeStateSchema,
  type AuthorizationCodeState,
} from './authorization-code.state.js';

vi.mock('node:crypto', async (original) => {
  const actual = await original<typeof import('node:crypto')>();
  return {
    ...actual,
    createHash: vi.fn(actual.createHash),
    randomBytes: vi.fn(() => {
      throw new Error('Consumption must not issue.');
    }),
  };
});
const realCrypto =
  await vi.importActual<typeof import('node:crypto')>('node:crypto');
const now = 1800000000000;
const state: AuthorizationCodeState = {
  clientId: ' exact e\u0301 CLIENT ',
  userId: 'c0e21e3f-d3ee-425c-a99f-c2e7a7cab53f',
  sessionId: 'd4d7b5ef-d0a0-4c59-9fc4-70dd7773a9f3',
  redirectUri: ' HTTPS://EXAMPLE.invalid:443/a/../%2f?b=2&a=%2520#fragment ',
  grantedScopes: ['profile', 'openid'],
  codeChallenge: 'A'.repeat(43),
  nonce: ' opaque nonce ',
  authTime: now - 60000,
  expiresAt: now + 120000,
};
const input = {
  code: ' opaque e\u0301 +%2F / CODE \t ',
  clientId: state.clientId,
  redirectUri: state.redirectUri,
};
const keyFor = (code: string): string =>
  'oauth:code:' + realCrypto.createHash('sha256').update(code).digest('hex');
const invalid = { ok: false, error: 'invalid_grant' };

describe('AuthorizationCodeService M6.2 atomic consumption', () => {
  const entries = new Map<string, string>();
  const unexpected = vi.fn(() => {
    throw new Error('Unexpected read/write/restore/lookup.');
  });
  const getAndDelete = vi.fn<(key: string) => Promise<string | null>>();
  const redis = {
    getAndDelete,
    setIfAbsentWithTtl: unexpected,
    get: unexpected,
    delete: unexpected,
    ttl: unexpected,
    set: unexpected,
    setWithTtl: unexpected,
  };
  const service = new AuthorizationCodeService(redis);
  let logs: MockInstance[];
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(crypto.createHash).mockImplementation(realCrypto.createHash);
    vi.spyOn(Date, 'now').mockReturnValue(now);
    entries.clear();
    entries.set(keyFor(input.code), JSON.stringify(state));
    getAndDelete.mockImplementation((key) => {
      const value = entries.get(key) ?? null;
      entries.delete(key);
      return Promise.resolve(value);
    });
    logs = [
      ...(['log', 'info', 'error', 'warn', 'debug'] as const).map((method) =>
        vi.spyOn(console, method).mockImplementation(() => undefined),
      ),
      ...(['log', 'error', 'warn', 'debug', 'verbose', 'fatal'] as const).map(
        (method) =>
          vi
            .spyOn(Logger.prototype, method)
            .mockImplementation(() => undefined),
      ),
    ];
  });
  afterEach(() => {
    try {
      expect(unexpected).not.toHaveBeenCalled();
      expect(crypto.randomBytes).not.toHaveBeenCalled();
      for (const log of logs) expect(log).not.toHaveBeenCalled();
    } finally {
      vi.restoreAllMocks();
    }
  });

  it('hashes exact raw text once, GETDELs one lowercase SHA-256 key and returns only validated canonical state', async () => {
    const parse = vi.spyOn(authorizationCodeStateSchema, 'parse');
    const result = await service.consume(input);
    expect(crypto.createHash).toHaveBeenCalledExactlyOnceWith('sha256');
    expect(getAndDelete).toHaveBeenCalledOnce();
    expect(getAndDelete.mock.calls[0][0] === keyFor(input.code)).toBe(true);
    expect(
      /^oauth:code:[0-9a-f]{64}$/.test(getAndDelete.mock.calls[0][0]),
    ).toBe(true);
    expect(parse).toHaveBeenCalledOnce();
    expect(
      result.ok && JSON.stringify(result.state) === JSON.stringify(state),
    ).toBe(true);
    expect(result.ok && Object.keys(result).join(',') === 'ok,state').toBe(
      true,
    );
    expect(entries.size).toBe(0);
    expect(Date.now).toHaveBeenCalledOnce();
  });

  it.each([
    (code: string) => code.trim(),
    (code: string) => code.normalize('NFC'),
    (code: string) => code.toLowerCase(),
    (code: string) => code.toUpperCase(),
    (code: string) => decodeURIComponent(code),
  ])(
    'does not normalize, casefold, trim or decode the raw code (%#)',
    async (change) => {
      expect(
        await service.consume({ ...input, code: change(input.code) }),
      ).toEqual(invalid);
      expect(entries.size).toBe(1);
      expect((await service.consume(input)).ok).toBe(true);
    },
  );

  it('allows one first consume, rejects replay and unknown code identically', async () => {
    expect((await service.consume(input)).ok).toBe(true);
    expect(await service.consume(input)).toEqual(invalid);
    expect(await service.consume({ ...input, code: 'unknown-canary' })).toEqual(
      invalid,
    );
    expect(getAndDelete).toHaveBeenCalledTimes(3);
    expect(entries.size).toBe(0);
  });

  it.each([now - 1, now, 0])(
    'burns logically expired state even when the key still exists (%#)',
    async (expiresAt) => {
      entries.set(keyFor(input.code), JSON.stringify({ ...state, expiresAt }));
      expect(await service.consume(input)).toEqual(invalid);
      expect(entries.size).toBe(0);
      expect(await service.consume(input)).toEqual(invalid);
    },
  );

  it('accepts an expiry strictly after now without mutating it', async () => {
    entries.set(
      keyFor(input.code),
      JSON.stringify({ ...state, expiresAt: now + 1 }),
    );
    const result = await service.consume(input);
    expect(result.ok && result.state.expiresAt === now + 1).toBe(true);
  });

  it.each([
    'other-client',
    state.clientId.trim(),
    state.clientId.toLowerCase(),
    state.clientId.normalize('NFC'),
    'c0e21e3f-d3ee-425c-a99f-c2e7a7cab53f',
  ])(
    'exact client mismatch burns code without registry lookup (%#)',
    async (clientId) => {
      expect(await service.consume({ ...input, clientId })).toEqual(invalid);
      expect(entries.size).toBe(0);
      expect(await service.consume(input)).toEqual(invalid);
    },
  );

  it.each([
    state.redirectUri.trim(),
    state.redirectUri.toLowerCase(),
    state.redirectUri.replace('%2f', '%2F'),
    state.redirectUri.replace('%2520', '%20'),
    state.redirectUri.replace('?b=2&a=%2520', '?a=%2520&b=2'),
    state.redirectUri.replace(':443', ''),
    state.redirectUri.replace('/a/../', '/'),
  ])(
    'exact redirect mismatch burns code; no URI normalization (%#)',
    async (redirectUri) => {
      expect(await service.consume({ ...input, redirectUri })).toEqual(invalid);
      expect(entries.size).toBe(0);
      expect(await service.consume(input)).toEqual(invalid);
    },
  );

  it.each([
    'not-json-private-canary',
    'null',
    '[]',
    '{}',
    JSON.stringify({ ...state, userId: 'private-invalid-user' }),
    JSON.stringify({ ...state, sessionId: undefined }),
    JSON.stringify({ ...state, sessionId: 'not-a-uuid' }),
    JSON.stringify({ ...state, expiresAt: 'later' }),
    JSON.stringify({ ...state, expiresAt: Number.MAX_SAFE_INTEGER + 1 }),
    JSON.stringify({ ...state, codeChallenge: 'invalid' }),
    JSON.stringify({ ...state, nonce: undefined }),
    JSON.stringify({ ...state, grantedScopes: [] }),
    JSON.stringify({ ...state, extra: 'private-extra-canary' }),
  ])(
    'fails closed on corrupted JSON/schema without restore or private error cause (%#)',
    async (serialized) => {
      entries.set(keyFor(input.code), serialized);
      const error: unknown = await service
        .consume(input)
        .catch((value: unknown) => value);
      expect(error).toEqual(
        new Error('Authorization code consumption failed.'),
      );
      expect(error).not.toHaveProperty('cause');
      expect(entries.size).toBe(0);
      expect(await service.consume(input)).toEqual(invalid);
    },
  );

  it.each([NaN, Infinity, -1, 1.5, Number.MAX_SAFE_INTEGER + 1])(
    'rejects unsafe clock after retrieval, without restoring (%#)',
    async (clock) => {
      vi.mocked(Date.now).mockReturnValue(clock);
      await expect(service.consume(input)).rejects.toEqual(
        new Error('Authorization code consumption failed.'),
      );
      expect(entries.size).toBe(0);
    },
  );

  it.each(['hash', 'Redis', 'lost-reply'] as const)(
    'sanitizes %s failures, without retry/restore',
    async (stage) => {
      const failure = new Error(
        'private raw code/hash/key/state/driver material',
        { cause: new Error('private cause') },
      );
      if (stage === 'hash')
        vi.mocked(crypto.createHash).mockImplementationOnce(() => {
          throw failure;
        });
      if (stage === 'Redis') getAndDelete.mockRejectedValueOnce(failure);
      if (stage === 'lost-reply')
        getAndDelete.mockImplementationOnce((key) => {
          entries.delete(key);
          return Promise.reject(failure);
        });
      const error: unknown = await service
        .consume(input)
        .catch((value: unknown) => value);
      expect(error).toEqual(
        new Error('Authorization code consumption failed.'),
      );
      expect(error).not.toHaveProperty('cause');
      expect(getAndDelete).toHaveBeenCalledTimes(stage === 'hash' ? 0 : 1);
      expect(entries.size).toBe(stage === 'lost-reply' ? 0 : 1);
    },
  );

  it('never reads a verifier or applies PKCE/client authentication policy', async () => {
    const supplied = { ...input };
    Object.defineProperty(supplied, 'code_verifier', { get: unexpected });
    const result = await service.consume(supplied);
    expect(
      result.ok && result.state.codeChallenge === state.codeChallenge,
    ).toBe(true);
    entries.set(
      keyFor(input.code),
      JSON.stringify({
        ...state,
        clientId: 'banking-web',
        codeChallenge: null,
      }),
    );
    expect(
      (await service.consume({ ...input, clientId: 'banking-web' })).ok,
    ).toBe(true);
    expect(crypto.createHash).toHaveBeenCalledTimes(2); // codes only, never verifiers
  });

  it('gives exactly one winner across concurrent attempts, never recreating the key', async () => {
    const results = await Promise.all(
      Array.from({ length: 12 }, () => service.consume(input)),
    );
    expect(results.filter((result) => result.ok)).toHaveLength(1);
    expect(
      results.filter(
        (result) => !result.ok && result.error === 'invalid_grant',
      ),
    ).toHaveLength(11);
    expect(getAndDelete).toHaveBeenCalledTimes(12);
    expect(entries.size).toBe(0);
  });
});
