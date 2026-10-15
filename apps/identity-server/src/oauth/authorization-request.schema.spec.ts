import { describe, expect, it } from 'vitest';
import { authorizationRequestSchema } from './authorization-request.schema.js';

const valid = {
  response_type: 'code',
  client_id: 'student-spa',
  redirect_uri: 'http://localhost:3200/callback',
  scope: 'openid profile email',
  state: ' opaque state e\u0301 ',
  nonce: ' opaque nonce \u00e9 ',
  code_challenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
  code_challenge_method: 'S256',
};
describe('authorizationRequestSchema', () => {
  it('parses scope tokens only, preserving all other decoded values and the input', () => {
    const input = Object.freeze({ ...valid });
    expect(authorizationRequestSchema.parse(input)).toEqual({
      ...valid,
      scope: ['openid', 'profile', 'email'],
    });
    expect(input.scope).toBe('openid profile email');
  });
  it('preserves scope case, token order and duplicates; does not default or calculate granted scopes', () => {
    expect(
      authorizationRequestSchema.parse({
        ...valid,
        scope: 'profile custom.scope profile OpenID',
      }).scope,
    ).toEqual(['profile', 'custom.scope', 'profile', 'OpenID']);
  });
  it('ignores unknown OAuth parameters without retaining/aliasing them', () => {
    expect(
      authorizationRequestSchema.parse({
        ...valid,
        unknown_extension: 'opaque',
        code_verifier: 'not-handled-here',
      }),
    ).toEqual({ ...valid, scope: ['openid', 'profile', 'email'] });
    const missing: Record<string, unknown> = { ...valid };
    delete missing.client_id;
    expect(
      authorizationRequestSchema.safeParse({
        ...missing,
        CLIENT_ID: 'student-spa',
      }).success,
    ).toBe(false);
  });
  it.each([
    'response_type',
    'client_id',
    'redirect_uri',
    'scope',
    'state',
  ] as const)('rejects missing/empty required %s', (field) => {
    const input: Record<string, unknown> = { ...valid };
    delete input[field];
    expect(authorizationRequestSchema.safeParse(input).success).toBe(false);
    expect(
      authorizationRequestSchema.safeParse({ ...valid, [field]: '' }).success,
    ).toBe(false);
  });
  it.each([
    'response_type',
    'client_id',
    'redirect_uri',
    'scope',
    'state',
    'nonce',
    'code_challenge',
    'code_challenge_method',
  ] as const)('rejects non-scalar %s without coercion', (field) => {
    for (const value of [null, 42, true, [], ['code'], { value: 'code' }])
      expect(
        authorizationRequestSchema.safeParse({ ...valid, [field]: value })
          .success,
      ).toBe(false);
  });
  it.each([undefined, null, [], 1, true, 'query-is-not-an-object'])(
    'rejects root query shape (%#)',
    (query) => {
      expect(authorizationRequestSchema.safeParse(query).success).toBe(false);
    },
  );
  it.each([
    '',
    ' openid',
    'openid ',
    'openid  profile',
    'openid\tprofile',
    'openid\n',
    'openid\r',
    'openid\r\nprofile',
    'openid\u2028',
    'openid\u2029',
    'open\u0000id',
    'open\u007fid',
    'profile\\email',
    'profile"email',
    'caf\u00e9',
    'cafe\u0301',
  ])(
    'rejects malformed scope grammar without trimming/normalization (%#)',
    (scope) => {
      expect(
        authorizationRequestSchema.safeParse({ ...valid, scope }).success,
      ).toBe(false);
    },
  );
  it.each(['openid', 'profile openid email', 'openid openid'])(
    'requires nonce for exact openid token (%#)',
    (scope) => {
      const input = { ...valid, nonce: undefined };
      expect(
        authorizationRequestSchema.safeParse({ ...input, scope }).success,
      ).toBe(false);
      expect(
        authorizationRequestSchema.safeParse({ ...input, scope, nonce: '' })
          .success,
      ).toBe(false);
    },
  );
  it.each([
    'OpenID',
    'OPENID',
    'openid.extra',
    'prefixopenid',
    'profile email',
  ])('does not infer openid from case/prefix/suffix (%#)', (scope) => {
    const input = { ...valid, nonce: undefined };
    expect(
      authorizationRequestSchema.safeParse({ ...input, scope }).success,
    ).toBe(true);
  });
  it('preserves whitespace state/nonce without changing their opaque M5.1 semantics', () => {
    const input = { ...valid, state: ' ', nonce: ' ' };
    expect(authorizationRequestSchema.parse(input)).toEqual({
      ...input,
      scope: ['openid', 'profile', 'email'],
    });
  });
  it.each(['plain', 's256', ' S256', 'S256 ', '', 'other'])(
    'preserves scalar PKCE method for the resolved-client policy without normalization (%#)',
    (method) => {
      expect(
        authorizationRequestSchema.safeParse({
          ...valid,
          code_challenge_method: method,
        }).success,
      ).toBe(true);
      expect(
        authorizationRequestSchema.parse({
          ...valid,
          code_challenge_method: method,
        }).code_challenge_method,
      ).toBe(method);
    },
  );
  it('leaves pair/format decisions to the PKCE policy after client resolution', () => {
    const withoutMethod = { ...valid, code_challenge_method: undefined };
    expect(authorizationRequestSchema.safeParse(withoutMethod).success).toBe(
      true,
    );
    const withoutBoth = { ...withoutMethod, code_challenge: undefined };
    expect(authorizationRequestSchema.safeParse(withoutBoth).success).toBe(
      true,
    );
    for (const code_challenge of ['', 'x', ' ', `${valid.code_challenge}=`])
      expect(
        authorizationRequestSchema.parse({ ...valid, code_challenge })
          .code_challenge,
      ).toBe(code_challenge);
  });
});
