import { describe, expect, it } from 'vitest';
import { passwordResetConsumeSchema } from './password-reset-consume.schema.js';

describe('passwordResetConsumeSchema', () => {
  it.each([
    {
      token: ' opaque MixedCase e\u0301 ',
      newPassword: ' opaque \u00e9 password ',
    },
    { token: ' ', newPassword: ' ' },
    { token: 'a', newPassword: 'b' },
  ])(
    'preserves non-empty opaque token/password input exactly (case %#)',
    (input) => {
      expect(passwordResetConsumeSchema.parse(input)).toEqual(input);
    },
  );

  it.each([
    {},
    { token: 'test-only' },
    { newPassword: 'test-only' },
    { token: '', newPassword: 'test-only' },
    { token: 'test-only', newPassword: '' },
    { token: 123, newPassword: 'test-only' },
    { token: 'test-only', newPassword: 123 },
    { token: null, newPassword: 'test-only' },
    { token: 'test-only', newPassword: null },
    { token: 'test-only', newPassword: 'test-only', userId: 'untrusted' },
    null,
    [],
    'not-an-object',
  ])('rejects invalid or unknown-property body case %#', (input) => {
    expect(passwordResetConsumeSchema.safeParse(input).success).toBe(false);
  });
});
