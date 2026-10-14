import { describe, expect, it } from 'vitest';
import { loginSchema } from './login.schema.js';

describe('loginSchema', () => {
  const input = {
    identifier: { type: 'email', value: ' MixedCase-e\u0301@example.invalid ' },
    password: ' opaque e\u0301 password ',
  };
  it.each(['email', 'username'])(
    'preserves exact strings for explicit %s lookup',
    (type) => {
      const value = { ...input, identifier: { ...input.identifier, type } };
      expect(loginSchema.parse(value)).toEqual(value);
    },
  );
  it('accepts non-empty whitespace without inventing normalization or complexity policy', () => {
    const value = {
      identifier: { type: 'username', value: ' ' },
      password: ' ',
    };
    expect(loginSchema.parse(value)).toEqual(value);
  });
  it.each([
    {},
    { password: 'opaque' },
    { identifier: { value: 'x' }, password: 'opaque' },
    { identifier: { type: 'other', value: 'x' }, password: 'opaque' },
    { identifier: { type: 'email' }, password: 'opaque' },
    { identifier: { type: 'email', value: '' }, password: 'opaque' },
    { identifier: input.identifier },
    { ...input, password: '' },
    { ...input, password: 123 },
    { ...input, password: null },
    { ...input, identifier: null },
    { ...input, identifier: 'x' },
    { ...input, identifier: { type: 'email', value: 123 } },
    { ...input, sessionId: 'browser-selected' },
    { ...input, identifier: { ...input.identifier, extra: true } },
    [],
    null,
    'not-an-object',
  ])('rejects malformed/non-strict input case %#', (value) => {
    expect(loginSchema.safeParse(value).success).toBe(false);
  });
});
