import { describe, expect, it } from 'vitest';
import { requireRefreshTokenIssuance } from './refresh-token-issuance.policy.js';

describe('M8.4 trusted refresh issuance configuration before GETDEL', () => {
  it.each([1, 456, 2592000])(
    'returns the exact positive TTL %s without conversion',
    (ttl) => {
      expect(requireRefreshTokenIssuance({ refreshTokenTtl: ttl })).toEqual({
        ttlSeconds: ttl,
      });
    },
  );
  it.each([
    undefined,
    null,
    '',
    '600',
    0,
    -1,
    1.5,
    NaN,
    Infinity,
    {},
    [],
    1n,
    Number.MAX_SAFE_INTEGER,
    8640000000001,
  ])(
    'rejects missing/type/unsafe/millisecond/date overflow configuration %#',
    (ttl) => {
      expect(() =>
        requireRefreshTokenIssuance({ refreshTokenTtl: ttl } as {
          refreshTokenTtl: number;
        }),
      ).toThrow('Refresh token issuance configuration unavailable.');
    },
  );
});
