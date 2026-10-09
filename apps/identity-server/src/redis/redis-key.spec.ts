import { describe, expect, it } from 'vitest';
import { buildRedisKey } from './redis-key.js';

describe('buildRedisKey', () => {
  it('builds canonical keys without adding a hidden prefix', () => {
    expect(buildRedisKey('session', 'abc')).toBe('session:abc');
    expect(buildRedisKey('oauth:code', 'xyz')).toBe('oauth:code:xyz');
    expect(buildRedisKey('rate', 'user-1', 'login')).toBe('rate:user-1:login');
    expect(buildRedisKey('prefix')).toBe('prefix');
  });

  it.each([
    ['', 'abc'],
    ['   ', 'abc'],
    ['session', ''],
    ['session', '   '],
  ])('rejects empty prefix/segments (%s, %s)', (prefix, segment) => {
    expect(() => buildRedisKey(prefix, segment)).toThrow(
      'Redis key prefix and segments must not be empty.',
    );
  });
});
