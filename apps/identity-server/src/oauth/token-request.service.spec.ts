import { describe, expect, it } from 'vitest';
import { tokenRequestSchema } from './token-request.schema.js';
import { TokenRequestService } from './token-request.service.js';

const form = 'application/x-www-form-urlencoded';
const valid = {
  grant_type: 'authorization_code',
  client_id: 'unknown-client',
  code: 'fake-code',
  redirect_uri: 'unregistered opaque redirect',
};
const service = new TokenRequestService();
const invalid = { ok: false, error: 'invalid_request' };
const fields = [...Object.keys(valid), 'code_verifier'];

describe('M6.1 strict token request schema / no-I/O service', () => {
  it('returns only validated protocol fields; fake code/client/redirect need no lookup', () => {
    expect(service.validate(valid, form)).toEqual({ ok: true, request: valid });
    expect(
      Reflect.getMetadata('design:paramtypes', TokenRequestService) ?? [],
    ).toEqual([]);
    expect(
      Reflect.getMetadata('self:paramtypes', TokenRequestService) ?? [],
    ).toEqual([]);
  });

  it.each(Object.keys(valid))('requires nonempty %s', (field) => {
    const missing: Record<string, unknown> = { ...valid };
    delete missing[field];
    expect(service.validate(missing, form)).toEqual(invalid);
    expect(service.validate({ ...valid, [field]: '' }, form)).toEqual(invalid);
  });

  it.each(
    fields.flatMap((field) =>
      [null, 1, true, false, [], ['value'], {}, { value: 'value' }].map(
        (value) => ({ field, value }),
      ),
    ),
  )('rejects non-string $field ($value)', ({ field, value }) => {
    expect(service.validate({ ...valid, [field]: value }, form)).toEqual(
      invalid,
    );
  });

  it.each([undefined, null, true, 1, 'body', [], [valid]])(
    'rejects non-object body %j',
    (body) => {
      expect(service.validate(body, form)).toEqual(invalid);
    },
  );

  it.each(['client_secret', 'scope', 'state', 'nonce', 'extra'])(
    'rejects unknown field %s',
    (field) => {
      expect(service.validate({ ...valid, [field]: 'canary' }, form)).toEqual(
        invalid,
      );
    },
  );

  it.each([
    'Authorization_Code',
    'AUTHORIZATION_CODE',
    'authorization-code',
    ' authorization_code',
    'authorization_code ',
    'refresh_token',
  ])('dispatches exact grant, rejecting %j', (grant_type) => {
    expect(service.validate({ ...valid, grant_type }, form)).toEqual({
      ok: false,
      error: 'unsupported_grant_type',
    });
    expect(
      service.validate({ ...valid, grant_type, code: null }, form),
    ).toEqual(invalid);
  });

  it('preserves opaque whitespace, Unicode, percent encoding and URI text without policy checks', () => {
    const input = {
      grant_type: 'authorization_code',
      client_id: ' Unknown e\u0301 CLIENT \t',
      code: ' fake +%2F/💠\n',
      redirect_uri: ' HTTPS://EXAMPLE.invalid:443/a/../%2f?b=2&a=%2520#frag ',
      code_verifier: ' short e\u0301 +%2F\t ',
    };
    expect(tokenRequestSchema.parse(input)).toEqual(input);
    expect(service.validate(input, form)).toEqual({ ok: true, request: input });
    expect(service.validate({ ...valid, code_verifier: '' }, form)).toEqual(
      invalid,
    );
    expect(service.validate({ ...valid, code_verifier: ' ' }, form)).toEqual({
      ok: true,
      request: { ...valid, code_verifier: ' ' },
    });
  });

  it.each([
    undefined,
    'application/json',
    'text/plain',
    'multipart/form-data',
    'application/x-www-form-urlencoded-other',
  ])('rejects non-form media type %j even with a valid body', (type) => {
    expect(service.validate(valid, type)).toEqual(invalid);
  });

  it('accepts normal form media type parameters without modifying protocol input', () => {
    expect(
      service.validate(
        valid,
        'Application/X-WWW-Form-Urlencoded; charset=UTF-8',
      ),
    ).toEqual({ ok: true, request: valid });
  });
});
