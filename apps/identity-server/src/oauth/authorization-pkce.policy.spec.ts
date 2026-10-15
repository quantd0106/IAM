import { describe, expect, it } from 'vitest';
import { validateAuthorizationPkce } from './authorization-pkce.policy.js';

// Fixed S256 example only; no verifier handling or hashing in this task.
const challenge = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';

describe.each(['PUBLIC', 'CONFIDENTIAL'] as const)(
  'authorization PKCE policy for %s',
  (clientType) => {
    it('accepts the complete exact S256 pair', () => {
      expect(validateAuthorizationPkce(clientType, challenge, 'S256')).toBe(
        true,
      );
    });
    it('accepts all allowed base64url character classes without changing inputs', () => {
      const input = Object.freeze({
        challenge: `_${challenge.slice(1)}`,
        method: 'S256',
      });
      expect(
        validateAuthorizationPkce(clientType, input.challenge, input.method),
      ).toBe(true);
      expect(input.challenge).toBe(`_${challenge.slice(1)}`);
      expect(input.method).toBe('S256');
    });
    it('rejects a lone challenge', () => {
      expect(validateAuthorizationPkce(clientType, challenge, undefined)).toBe(
        false,
      );
    });
    it('rejects a lone method', () => {
      expect(validateAuthorizationPkce(clientType, undefined, 'S256')).toBe(
        false,
      );
    });
    it.each([
      'plain',
      's256',
      ' S256',
      'S256 ',
      'S256\t',
      'S256\n',
      '',
      'unknown',
    ])('rejects non-exact method (%#)', (method) => {
      expect(validateAuthorizationPkce(clientType, challenge, method)).toBe(
        false,
      );
    });
    it.each([
      '',
      'x',
      'A'.repeat(42),
      'A'.repeat(44),
      `${challenge}=`,
      `${'A'.repeat(42)}=`,
      `${'A'.repeat(42)}+`,
      `${'A'.repeat(42)}/`,
      `${'A'.repeat(42)}.`,
      `${'A'.repeat(42)}~`,
      ` ${challenge}`,
      `${challenge} `,
      ...[
        ' ',
        '\t',
        '\n',
        '\r',
        '\u2028',
        '\u2029',
        '\u0000',
        '\u007f',
        '\u00e9',
        '\u0301',
      ].map((character) => `${'A'.repeat(42)}${character}`),
      `${'A'.repeat(40)}%2D`,
    ])(
      'rejects invalid challenge length/alphabet without repair (%#)',
      (value) => {
        expect(validateAuthorizationPkce(clientType, value, 'S256')).toBe(
          false,
        );
      },
    );
  },
);

it('requires PKCE for PUBLIC clients', () => {
  expect(validateAuthorizationPkce('PUBLIC', undefined, undefined)).toBe(false);
});
it('allows CONFIDENTIAL clients to omit both PKCE fields', () => {
  expect(validateAuthorizationPkce('CONFIDENTIAL', undefined, undefined)).toBe(
    true,
  );
});
