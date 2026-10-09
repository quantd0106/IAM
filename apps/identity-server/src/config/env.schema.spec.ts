import { describe, expect, it } from 'vitest';
import { validateEnvironment } from './env.schema.js';

const required = {
  DATABASE_URL: 'postgresql://test:test@127.0.0.1:5432/test',
  REDIS_URL: 'redis://127.0.0.1:6379',
  ISSUER_URL: 'http://localhost:3000',
  JWT_PRIVATE_KEY_PATH: './test-placeholder-private.pem',
  JWT_PUBLIC_KEY_PATH: './test-placeholder-public.pem',
  JWT_KEY_ID: 'test-placeholder',
  TOTP_ENCRYPTION_KEY: 'test-only-placeholder',
};
const complete = {
  ...required,
  NODE_ENV: 'test',
  IDENTITY_SERVER_PORT: '3100',
  ACCESS_TOKEN_TTL_SECONDS: '600',
  AUTH_CODE_TTL_SECONDS: '120',
  REFRESH_TOKEN_TTL_SECONDS: '2592000',
  SESSION_IDLE_TTL_SECONDS: '1800',
  SESSION_ABSOLUTE_TTL_SECONDS: '28800',
  COOKIE_NAME: 'iam.sid',
  COOKIE_SECURE: 'false',
  LOGIN_MAX_FAILURES: '5',
  LOGIN_LOCK_SECONDS: '900',
};
const ttlNames = [
  'ACCESS_TOKEN_TTL_SECONDS',
  'AUTH_CODE_TTL_SECONDS',
  'REFRESH_TOKEN_TTL_SECONDS',
  'SESSION_IDLE_TTL_SECONDS',
  'SESSION_ABSOLUTE_TTL_SECONDS',
] as const;

describe('environment validation', () => {
  it('accepts the complete contract and returns typed integers/boolean', () => {
    const result = validateEnvironment(complete);
    expect(result).toEqual({
      ...required,
      NODE_ENV: 'test',
      IDENTITY_SERVER_PORT: 3100,
      ACCESS_TOKEN_TTL_SECONDS: 600,
      AUTH_CODE_TTL_SECONDS: 120,
      REFRESH_TOKEN_TTL_SECONDS: 2592000,
      SESSION_IDLE_TTL_SECONDS: 1800,
      SESSION_ABSOLUTE_TTL_SECONDS: 28800,
      COOKIE_NAME: 'iam.sid',
      COOKIE_SECURE: false,
      LOGIN_MAX_FAILURES: 5,
      LOGIN_LOCK_SECONDS: 900,
    });
  });

  it('uses only canonical defaults and discards unrelated environment names', () => {
    const result = validateEnvironment({
      ...required,
      PORT: '9999',
      UNRELATED: 'ignored',
    });
    expect(result).toEqual({
      ...validateEnvironment(complete),
      NODE_ENV: 'development',
      IDENTITY_SERVER_PORT: 3000,
    });
    expect(result).not.toHaveProperty('PORT');
    expect(result).not.toHaveProperty('UNRELATED');
  });

  it.each([
    '',
    '0',
    '-1',
    '65536',
    '1.5',
    '3e3',
    '0xBB8',
    '3000abc',
    ' 3000 ',
    'Infinity',
  ])('rejects malformed or out-of-range port %s', (value) => {
    expect(() =>
      validateEnvironment({ ...complete, IDENTITY_SERVER_PORT: value }),
    ).toThrow('IDENTITY_SERVER_PORT');
  });

  it.each(ttlNames)('validates positive safe seconds for %s', (name) => {
    for (const value of [
      '',
      '0',
      '-1',
      '1.5',
      '1e2',
      '10seconds',
      ' 10 ',
      '9007199254740992',
      NaN,
      Infinity,
      0,
      -1,
    ]) {
      expect(() => validateEnvironment({ ...complete, [name]: value })).toThrow(
        name,
      );
    }
    expect(validateEnvironment({ ...complete, [name]: '1' })[name]).toBe(1);
  });

  it.each(['LOGIN_MAX_FAILURES', 'LOGIN_LOCK_SECONDS'])(
    'rejects invalid positive integers for %s',
    (name) => {
      for (const value of ['0', '-1', '1.5', '1x', '9007199254740992']) {
        expect(() =>
          validateEnvironment({ ...complete, [name]: value }),
        ).toThrow(name);
      }
    },
  );

  it.each(['DATABASE_URL', 'REDIS_URL', 'ISSUER_URL'])(
    'rejects missing, blank, malformed and wrong-protocol %s',
    (name) => {
      for (const value of [
        undefined,
        '',
        '   ',
        'not-a-url',
        'file:///tmp/test',
        'redis://',
      ]) {
        expect(() =>
          validateEnvironment({ ...complete, [name]: value }),
        ).toThrow(name);
      }
    },
  );

  it('accepts supported connection URL protocols', () => {
    expect(
      validateEnvironment({
        ...complete,
        DATABASE_URL: 'postgres://localhost/test',
        REDIS_URL: 'rediss://localhost:6379',
        ISSUER_URL: 'https://example.test',
      }),
    ).toMatchObject({ REDIS_URL: 'rediss://localhost:6379' });
    expect(() =>
      validateEnvironment({
        ...complete,
        DATABASE_URL: 'https://localhost/test',
      }),
    ).toThrow('DATABASE_URL');
    expect(() =>
      validateEnvironment({ ...complete, REDIS_URL: 'http://localhost:6379' }),
    ).toThrow('REDIS_URL');
  });

  it.each([
    ['false', false],
    ['true', true],
    [false, false],
    [true, true],
  ])('parses COOKIE_SECURE %s as a real boolean', (input, expected) => {
    expect(
      validateEnvironment({ ...complete, COOKIE_SECURE: input }).COOKIE_SECURE,
    ).toBe(expected);
  });

  it.each(['', 'yes', 'no', '1', '0', 'FALSE', 'True', ' true ', 1])(
    'rejects malformed COOKIE_SECURE %s',
    (value) => {
      expect(() =>
        validateEnvironment({ ...complete, COOKIE_SECURE: value }),
      ).toThrow('COOKIE_SECURE');
    },
  );

  it('defaults production cookies to secure and requires HTTPS issuer', () => {
    const production = {
      ...required,
      NODE_ENV: 'production',
      ISSUER_URL: 'https://id.example.test',
    };
    expect(validateEnvironment(production).COOKIE_SECURE).toBe(true);
    expect(() =>
      validateEnvironment({ ...production, COOKIE_SECURE: 'false' }),
    ).toThrow('COOKIE_SECURE');
    expect(() =>
      validateEnvironment({
        ...production,
        ISSUER_URL: 'http://localhost:3000',
      }),
    ).toThrow('ISSUER_URL');
    expect(() =>
      validateEnvironment({
        ...production,
        ISSUER_URL: 'invalid-secret-bearing-url',
      }),
    ).toThrow('Invalid environment configuration: ISSUER_URL.');
  });

  it.each([
    'JWT_PRIVATE_KEY_PATH',
    'JWT_PUBLIC_KEY_PATH',
    'JWT_KEY_ID',
    'TOTP_ENCRYPTION_KEY',
  ])('rejects missing and blank sensitive configuration %s', (name) => {
    for (const value of [undefined, '', '   ']) {
      expect(() => validateEnvironment({ ...complete, [name]: value })).toThrow(
        name,
      );
    }
  });

  it('does not impose key existence or secret encoding and does not trim secret bytes', () => {
    expect(
      validateEnvironment({
        ...complete,
        TOTP_ENCRYPTION_KEY: ' arbitrary placeholder ',
      }).TOTP_ENCRYPTION_KEY,
    ).toBe(' arbitrary placeholder ');
  });

  it('reports variable names without leaking invalid input values', () => {
    const sensitiveValue = 'do-not-echo-test-marker';
    expect(() =>
      validateEnvironment({
        ...complete,
        DATABASE_URL: sensitiveValue,
        NODE_ENV: sensitiveValue,
      }),
    ).toThrow('Invalid environment configuration: NODE_ENV, DATABASE_URL.');
  });

  it.each(['', 'staging', 'Production'])(
    'rejects invalid NODE_ENV %s',
    (value) => {
      expect(() =>
        validateEnvironment({ ...complete, NODE_ENV: value }),
      ).toThrow('NODE_ENV');
    },
  );

  it.each(['', '   '])('rejects blank COOKIE_NAME %s', (value) => {
    expect(() =>
      validateEnvironment({ ...complete, COOKIE_NAME: value }),
    ).toThrow('COOKIE_NAME');
  });
});
