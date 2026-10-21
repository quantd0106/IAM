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
import { verifyTokenPkce } from './token-pkce.policy.js';

vi.mock('node:crypto', async (original) => {
  const actual = await original<typeof import('node:crypto')>();
  return {
    ...actual,
    createHash: vi.fn(actual.createHash),
    timingSafeEqual: vi.fn(actual.timingSafeEqual),
  };
});
const actual =
  await vi.importActual<typeof import('node:crypto')>('node:crypto');
// Public RFC 7636 Appendix B test vector, not a live credential.
const verifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
const challenge = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';
const challengeFor = (input: string): string =>
  actual.createHash('sha256').update(input, 'ascii').digest('base64url');

describe('M6.3 token PKCE S256 policy', () => {
  let logs: MockInstance[];
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(crypto.createHash).mockImplementation(actual.createHash);
    vi.mocked(crypto.timingSafeEqual).mockImplementation(
      actual.timingSafeEqual,
    );
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

  it('accepts the known S256 vector using ASCII SHA-256 and unpadded base64url', () => {
    expect(verifier.length).toBe(43);
    expect(verifyTokenPkce(challenge, verifier)).toBe(true);
    expect(crypto.createHash).toHaveBeenCalledExactlyOnceWith('sha256');
    expect(crypto.timingSafeEqual).toHaveBeenCalledOnce();
    const [calculated, stored] = vi.mocked(crypto.timingSafeEqual).mock
      .calls[0];
    expect(
      Buffer.isBuffer(calculated) && calculated.toString() === challenge,
    ).toBe(true);
    expect(Buffer.isBuffer(stored) && stored.toString() === challenge).toBe(
      true,
    );
    expect(calculated.byteLength).toBe(43);
    expect(Buffer.isBuffer(calculated) && calculated.includes('=')).toBe(false);
  });

  it.each([43, 44, 64, 127, 128])(
    'accepts valid RFC verifier length %i',
    (length) => {
      const input = 'Ab0-._~'.repeat(19).slice(0, length);
      expect(verifyTokenPkce(challengeFor(input), input)).toBe(true);
    },
  );

  it.each([
    undefined,
    '',
    'a',
    'A'.repeat(42),
    'A'.repeat(129),
    'A'.repeat(512),
    ...[
      ' ',
      '\t',
      '\n',
      '\r',
      '\0',
      '\x7f',
      'é',
      '\u0301',
      '💠',
      '+',
      '/',
      '=',
      '%',
      ':',
      '!',
      '\\',
    ].map((character) => 'A'.repeat(42) + character),
    ' ' + verifier,
    verifier + ' ',
    verifier + '\n',
    '%64' + verifier.slice(1),
  ])(
    'rejects missing/empty/invalid syntax without hashing, trimming or repair (%#)',
    (input) => {
      expect(verifyTokenPkce(challenge, input)).toBe(false);
      expect(crypto.createHash).not.toHaveBeenCalled();
      expect(crypto.timingSafeEqual).not.toHaveBeenCalled();
    },
  );

  it('rejects a well-shaped wrong verifier and never falls back to plain', () => {
    expect(verifyTokenPkce(challenge, 'A'.repeat(43))).toBe(false);
    expect(verifyTokenPkce(verifier, verifier)).toBe(false);
    expect(crypto.createHash).toHaveBeenCalledTimes(2);
  });

  it.each([
    challenge.toLowerCase(),
    challenge + '=',
    ' ' + challenge,
    challenge + '\n',
    challenge.slice(1),
    'É' + challenge.slice(1),
  ])(
    'compares the exact stored challenge without normalization or padding repair (%#)',
    (stored) => {
      expect(verifyTokenPkce(stored, verifier)).toBe(false);
    },
  );

  it.each([undefined, '', ' short ', verifier, 'é%2F'])(
    'does not require or inspect verifier syntax when challenge is null (%#)',
    (input) => {
      expect(verifyTokenPkce(null, input)).toBe(true);
      expect(crypto.createHash).not.toHaveBeenCalled();
      expect(crypto.timingSafeEqual).not.toHaveBeenCalled();
    },
  );

  it.each(['hash', 'compare'] as const)(
    'sanitizes %s exceptions without attaching private causes',
    (stage) => {
      const failure = new Error('private verifier/challenge/code canary', {
        cause: new Error('private cause'),
      });
      if (stage === 'hash')
        vi.mocked(crypto.createHash).mockImplementationOnce(() => {
          throw failure;
        });
      else
        vi.mocked(crypto.timingSafeEqual).mockImplementationOnce(() => {
          throw failure;
        });
      let error: unknown;
      try {
        verifyTokenPkce(challenge, verifier);
      } catch (caught) {
        error = caught;
      }
      expect(error).toEqual(new Error('PKCE verification failed.'));
      expect(error).not.toHaveProperty('cause');
    },
  );
});
