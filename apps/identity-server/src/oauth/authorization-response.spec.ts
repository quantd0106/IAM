import { describe, expect, it } from 'vitest';
import { buildAuthorizationSuccessLocation } from './authorization-response.js';

describe('buildAuthorizationSuccessLocation M5.6 pure textual append', () => {
  const code = 'test-code';
  const state = 'original-state';
  it.each([
    [
      'http://localhost:3200/callback',
      'http://localhost:3200/callback?code=test-code&state=original-state',
    ],
    [
      'HTTP://LOCALHOST:3200/call%62ack?tenant=a&mode=b',
      'HTTP://LOCALHOST:3200/call%62ack?tenant=a&mode=b&code=test-code&state=original-state',
    ],
    [
      'http://localhost:3200/callback?',
      'http://localhost:3200/callback?code=test-code&state=original-state',
    ],
    [
      'http://localhost:3200/callback?tenant=a&',
      'http://localhost:3200/callback?tenant=a&code=test-code&state=original-state',
    ],
    [
      'http://localhost:3200/callback#route?x=1',
      'http://localhost:3200/callback?code=test-code&state=original-state#route?x=1',
    ],
    [
      'http://localhost:3200/call%62ack?b=%2f&a=hello+world#opaque%2F?x=1#tail',
      'http://localhost:3200/call%62ack?b=%2f&a=hello+world&code=test-code&state=original-state#opaque%2F?x=1#tail',
    ],
    [
      'http://localhost:3200/callback?#',
      'http://localhost:3200/callback?code=test-code&state=original-state#',
    ],
    [
      'http://localhost:3200/call%23back',
      'http://localhost:3200/call%23back?code=test-code&state=original-state',
    ],
  ])(
    'preserves the exact URI bytes/query order/fragment (case %#)',
    (redirectUri, expected) => {
      expect(
        buildAuthorizationSuccessLocation({ redirectUri, code, state }) ===
          expected,
      ).toBe(true);
    },
  );
  it.each([
    ' &+=?/#%\r\n',
    ' Tiếng Việt / 漢字 / 🙂 ',
    'e\u0301',
    '\u00e9',
    '%252F+%20',
    '   ',
    '\u0000',
  ])(
    'round-trips reserved/control/Unicode state without mutation (case %#)',
    (original) => {
      const location = buildAuthorizationSuccessLocation({
        redirectUri: 'http://localhost:3200/callback',
        code,
        state: original,
      });
      expect(new URL(location).searchParams.get('state') === original).toBe(
        true,
      );
      expect(location.includes('\r') || location.includes('\n')).toBe(false);
      expect(location.endsWith('&state=' + encodeURIComponent(original))).toBe(
        true,
      );
    },
  );
  it('encodes only code and state as independent query components', () => {
    const specialCode = 'code?&=+#/% é';
    const location = buildAuthorizationSuccessLocation({
      redirectUri: 'http://localhost:3200/callback?tenant=a',
      code: specialCode,
      state: 'original&code=forged',
    });
    const returned = new URL(location).searchParams;
    expect(returned.getAll('code').length).toBe(1);
    expect(returned.get('code') === specialCode).toBe(true);
    expect(returned.get('state') === 'original&code=forged').toBe(true);
    expect(location.includes('code=code%3F%26%3D%2B%23%2F%25%20%C3%A9')).toBe(
      true,
    );
    expect(returned.get('tenant')).toBe('a');
  });
  it('does not replace invalid Unicode with a different state', () => {
    expect(() =>
      buildAuthorizationSuccessLocation({
        redirectUri: 'http://localhost:3200/callback',
        code,
        state: '\ud800',
      }),
    ).toThrow(URIError);
  });
});
