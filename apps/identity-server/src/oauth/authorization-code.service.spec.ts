import { Logger } from '@nestjs/common';
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
import { RedisService } from '../redis/redis.service.js';
import {
  AuthorizationCodeService,
  AUTHORIZATION_CODE_TTL_SECONDS,
} from './authorization-code.service.js';
import {
  authorizationCodeStateSchema,
  type AuthorizationCodeInput,
} from './authorization-code.state.js';

const { generate } = vi.hoisted(() => ({
  generate: vi.fn<(size: number) => Buffer>(),
}));
vi.mock('node:crypto', async (importOriginal) => ({
  ...(await importOriginal<typeof import('node:crypto')>()),
  randomBytes: generate,
}));
const crypto =
  await vi.importActual<typeof import('node:crypto')>('node:crypto');

describe('AuthorizationCodeService M5.5 issue-only capability', () => {
  const reserve = vi.fn<RedisService['setIfAbsentWithTtl']>();
  const service = new AuthorizationCodeService({
    setIfAbsentWithTtl: reserve,
    getAndDelete: vi.fn(() => {
      throw new Error('Issuance must not consume.');
    }),
  });
  const now = 1800000000000;
  const input: AuthorizationCodeInput = {
    clientId: 'student-spa',
    userId: 'c0e21e3f-d3ee-425c-a99f-c2e7a7cab53f',
    sessionId: 'd4d7b5ef-d0a0-4c59-9fc4-70dd7773a9f3',
    redirectUri: 'http://localhost:3200/call%62ack?b=2&a=1',
    grantedScopes: ['profile', 'openid', 'email'],
    codeChallenge: 'A'.repeat(42) + '_',
    nonce: ' opaque\u00e9 nonce ',
    authTime: now - 123456,
  };
  let logs: MockInstance[];
  beforeEach(() => {
    vi.resetAllMocks();
    vi.spyOn(Date, 'now').mockReturnValue(now);
    generate.mockImplementation((size) => crypto.randomBytes(size));
    reserve.mockResolvedValue(true);
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
      for (const log of logs) expect(log).not.toHaveBeenCalled();
    } finally {
      vi.restoreAllMocks();
    }
  });
  it('uses real 256-bit randomness, URL-safe unpadded encoding and SHA-256 hash-at-rest only', async () => {
    const { code } = await service.issue(input);
    expect(generate).toHaveBeenCalledExactlyOnceWith(32);
    // Boolean assertions keep randomly generated bearer credentials out of failure output.
    expect(/^[A-Za-z0-9_-]{43}$/.test(code)).toBe(true);
    expect(Buffer.from(code, 'base64url').length).toBe(32);
    expect(reserve).toHaveBeenCalledOnce();
    const [key, value, ttl] = reserve.mock.calls[0];
    expect(
      key === 'oauth:code:' + createHash('sha256').update(code).digest('hex'),
    ).toBe(true);
    expect(/^oauth:code:[0-9a-f]{64}$/.test(key)).toBe(true);
    expect(key.includes(code) || value.includes(code)).toBe(false);
    expect(ttl).toBe(120);
    expect(ttl).toBe(AUTHORIZATION_CODE_TTL_SECONDS);
    expect(JSON.parse(value) as unknown).toEqual({
      ...input,
      expiresAt: now + 120000,
    });
    expect(Date.now).toHaveBeenCalledOnce();
  });
  it('produces independent raw codes and hash keys for independent issues', async () => {
    const first = await service.issue(input);
    const second = await service.issue(input);
    expect(first.code !== second.code).toBe(true);
    expect(reserve.mock.calls[0][0] !== reserve.mock.calls[1][0]).toBe(true);
    expect(generate).toHaveBeenCalledTimes(2);
  });
  it('serializes exactly nine fields including trusted sessionId, preserving exact protocol values', async () => {
    const exact = {
      ...input,
      clientId: ' exact\u00e9 ',
      grantedScopes: ['Scope', 'a:b', 'profile'],
      nonce: ' \u00e9 ',
    };
    await service.issue(exact);
    const serialized = reserve.mock.calls[0][1];
    expect(
      serialized === JSON.stringify({ ...exact, expiresAt: now + 120000 }),
    ).toBe(true);
    expect(
      Object.keys(JSON.parse(serialized) as Record<string, unknown>),
    ).toEqual([
      'clientId',
      'userId',
      'sessionId',
      'redirectUri',
      'grantedScopes',
      'codeChallenge',
      'nonce',
      'authTime',
      'expiresAt',
    ]);
    expect(input.grantedScopes).toEqual(['profile', 'openid', 'email']);
  });
  it('represents permitted absent confidential PKCE and non-openid nonce explicitly as null', async () => {
    await service.issue({
      ...input,
      clientId: 'banking-web',
      grantedScopes: ['profile'],
      codeChallenge: null,
      nonce: null,
    });
    const stored: unknown = JSON.parse(reserve.mock.calls[0][1]);
    expect(stored).toEqual({
      ...input,
      clientId: 'banking-web',
      grantedScopes: ['profile'],
      codeChallenge: null,
      nonce: null,
      expiresAt: now + 120000,
    });
  });
  it.each([
    { clientId: '' },
    { userId: 'not-uuid' },
    { redirectUri: '' },
    { grantedScopes: [] },
    { grantedScopes: [''] },
    { grantedScopes: ['two scopes'] },
    { grantedScopes: ['\u00e9'] },
    { grantedScopes: ['a\\b'] },
    { codeChallenge: 'x' },
    { codeChallenge: 'A'.repeat(42) + '\n' },
    { codeChallenge: undefined },
    { nonce: '' },
    { nonce: undefined },
    { authTime: -1 },
    { authTime: 1.5 },
    { authTime: Number.MAX_SAFE_INTEGER + 1 },
    { authTime: NaN },
    { authTime: Infinity },
    { rawCode: 'never-store' },
    { state: 'never-store' },
    { sessionId: 'never-store' },
    { sessionId: undefined },
    { sessionId: null },
  ])(
    'rejects malformed/extra state before randomness or Redis (%#)',
    async (variation) => {
      await expect(
        service.issue({ ...input, ...variation } as AuthorizationCodeInput),
      ).rejects.toEqual(new Error('Authorization code issuance failed.'));
      expect(generate).not.toHaveBeenCalled();
      expect(reserve).not.toHaveBeenCalled();
    },
  );
  it.each([-1, NaN, Infinity, 1.5, Number.MAX_SAFE_INTEGER - 1])(
    'rejects an unsafe issue clock/expiry before Redis (%#)',
    async (instant) => {
      vi.mocked(Date.now).mockReturnValue(instant);
      await expect(service.issue(input)).rejects.toEqual(
        new Error('Authorization code issuance failed.'),
      );
      expect(generate).not.toHaveBeenCalled();
      expect(reserve).not.toHaveBeenCalled();
    },
  );
  it('requires explicit canonical fields in the strict shared state schema', () => {
    const state = { ...input, expiresAt: now + 120000 };
    expect(authorizationCodeStateSchema.safeParse(state).success).toBe(true);
    expect(
      authorizationCodeStateSchema.safeParse({
        ...state,
        state: 'not-canonical',
      }).success,
    ).toBe(false);
    expect(
      authorizationCodeStateSchema.safeParse({ ...state, expiresAt: 1.5 })
        .success,
    ).toBe(false);
  });
  it('retries a collision with fresh randomness and never deletes or overwrites the occupied entry', async () => {
    generate
      .mockReturnValueOnce(Buffer.alloc(32, 1))
      .mockReturnValueOnce(Buffer.alloc(32, 2));
    reserve.mockResolvedValueOnce(false).mockResolvedValueOnce(true);
    const result = await service.issue(input);
    expect(reserve).toHaveBeenCalledTimes(2);
    expect(generate).toHaveBeenCalledTimes(2);
    const first = reserve.mock.calls[0];
    const second = reserve.mock.calls[1];
    expect(first[0] !== second[0]).toBe(true);
    expect(
      second[0] ===
        'oauth:code:' + createHash('sha256').update(result.code).digest('hex'),
    ).toBe(true);
    expect(first[1] === second[1]).toBe(true);
    expect(first[2] === 120 && second[2] === 120).toBe(true);
    expect(Date.now).toHaveBeenCalledOnce();
  });
  it('fails safely after exactly three occupied reservations', async () => {
    reserve.mockResolvedValue(false);
    await expect(service.issue(input)).rejects.toEqual(
      new Error('Authorization code issuance failed.'),
    );
    expect(generate).toHaveBeenCalledTimes(3);
    expect(reserve).toHaveBeenCalledTimes(3);
    expect(new Set(reserve.mock.calls.map(([key]) => key)).size).toBe(3);
  });
  it.each(['crypto', 'serialization', 'Redis'] as const)(
    'drops private %s failure/cause without a success, retries or logs',
    async (stage) => {
      const failure = new Error('private raw code/hash/key/state/driver URL', {
        cause: new Error('private cause'),
      });
      if (stage === 'crypto')
        generate.mockImplementation(() => {
          throw failure;
        });
      if (stage === 'serialization')
        vi.spyOn(JSON, 'stringify').mockImplementationOnce(() => {
          throw failure;
        });
      if (stage === 'Redis') reserve.mockRejectedValue(failure);
      const error: unknown = await service
        .issue(input)
        .catch((value: unknown) => value);
      expect(error).toEqual(new Error('Authorization code issuance failed.'));
      expect(error).not.toHaveProperty('cause');
      if (stage !== 'Redis') expect(reserve).not.toHaveBeenCalled();
      else expect(reserve).toHaveBeenCalledOnce();
    },
  );
});
