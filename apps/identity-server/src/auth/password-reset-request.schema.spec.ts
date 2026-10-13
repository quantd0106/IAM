import { describe, expect, it } from 'vitest';
import { passwordResetRequestSchema } from './password-reset-request.schema.js';

describe('passwordResetRequestSchema', () => {
  it('trims surrounding whitespace without changing email case', () => {
    expect(
      passwordResetRequestSchema.parse({
        email: ' MixedCase@example.invalid ',
      }),
    ).toEqual({ email: 'MixedCase@example.invalid' });
  });

  it.each([
    {},
    { email: '' },
    { email: '   ' },
    { email: 'not-an-email' },
    { email: 123 },
    { email: null },
    { email: 'user@example.invalid', token: 'test-only canary' },
    null,
    [],
    'user@example.invalid',
  ])('rejects invalid or non-strict input case %#', (input) => {
    expect(passwordResetRequestSchema.safeParse(input).success).toBe(false);
  });
});
