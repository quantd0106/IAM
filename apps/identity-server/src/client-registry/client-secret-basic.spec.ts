import { describe, expect, it } from 'vitest';
import { parseClientSecretBasic } from './client-secret-basic.js';

const basic = (value: string): string =>
  'Basic ' + Buffer.from(value).toString('base64');

describe('OAuth client_secret_basic parsing', () => {
  it('accepts a case-insensitive scheme and space separator', () => {
    expect(parseClientSecretBasic(basic('banking-web:secret'))).toEqual({
      clientId: 'banking-web',
      secret: 'secret',
    });
    expect(
      parseClientSecretBasic(
        basic('admin-portal:secret').replace('Basic ', 'bAsIc   '),
      ),
    ).toEqual({
      clientId: 'admin-portal',
      secret: 'secret',
    });
  });
  it('form-decodes each component once, preserving opaque decoded values exactly', () => {
    const clientId = ' e\u0301 +%2F:/ ';
    const secret = ' \t e\u0301 +%2F:/💠 ';
    const encode = (value: string): string =>
      new URLSearchParams({ x: value }).toString().slice(2);
    expect(
      parseClientSecretBasic(basic(`${encode(clientId)}:${encode(secret)}`)),
    ).toEqual({ clientId, secret });
    expect(parseClientSecretBasic(basic('a%252Fb:s%252Be'))).toEqual({
      clientId: 'a%2Fb',
      secret: 's%2Be',
    });
  });
  it.each([
    undefined,
    '',
    'Bearer credential',
    'Basic',
    'Basic ',
    ' Basic YTpi',
    'Basic\tYTpi',
    'Basic YTpi ',
    'Basic YTpi, YTpi',
    'Basic !!!!',
    'Basic YTpi=',
    'Basic YTpi===',
    'Basic YTpi_',
    'Basic YTpiYw',
    'Basic YTpiYx==',
    'Basic YTpi\n',
    basic('no-colon'),
    basic(':secret'),
    basic('client:'),
    basic('client:%'),
    basic('client:%FF'),
    basic('client:s\necret'),
    'Basic ' + Buffer.from([0xff, 0x3a, 0x61]).toString('base64'),
  ])('rejects malformed/unsupported credentials case %#', (header) => {
    expect(parseClientSecretBasic(header)).toBeNull();
  });
});
