import { describe, expect, it } from 'vitest';
import { calculateGrantedScopes } from './authorization-scope.policy.js';

describe('calculateGrantedScopes', () => {
  it('grants exactly a requested subset, without adding allowed defaults', () => {
    expect(
      calculateGrantedScopes(['profile'], ['email', 'openid', 'profile']),
    ).toEqual({ ok: true, grantedScopes: ['profile'] });
  });
  it('accepts the full allowed set in first-request order', () => {
    expect(
      calculateGrantedScopes(
        ['openid', 'profile', 'email'],
        ['email', 'openid', 'profile'],
      ),
    ).toEqual({ ok: true, grantedScopes: ['openid', 'profile', 'email'] });
  });
  it.each([
    ['openid', 'forbidden.scope'],
    ['openid', 'definitely.unknown'],
    ['openid', 'forbidden', 'profile'],
    ['BANKING.TRANSACTIONS.READ'],
    ['OpenID'],
    ['OPENID'],
    [' openid'],
    ['openid '],
    ['%6fpenid'],
    ['openid.extra'],
    ['transaction.view'],
  ])(
    'rejects any non-exact/forbidden token, never partial success (%#)',
    (...requested) => {
      expect(
        calculateGrantedScopes(requested, [
          'openid',
          'profile',
          'banking.transactions.read',
        ]),
      ).toEqual({ ok: false });
    },
  );
  it('keeps Unicode-distinct names distinct without normalization', () => {
    expect(calculateGrantedScopes(['cafe\u0301'], ['caf\u00e9'])).toEqual({
      ok: false,
    });
    expect(calculateGrantedScopes(['caf\u00e9'], ['cafe\u0301'])).toEqual({
      ok: false,
    });
    expect(
      calculateGrantedScopes(
        ['cafe\u0301', 'caf\u00e9'],
        ['caf\u00e9', 'cafe\u0301'],
      ),
    ).toEqual({ ok: true, grantedScopes: ['cafe\u0301', 'caf\u00e9'] });
  });
  it('deduplicates both sets without rejecting duplicate allowed requests', () => {
    expect(
      calculateGrantedScopes(
        ['openid', 'profile', 'openid', 'profile'],
        ['profile', 'openid', 'openid'],
      ),
    ).toEqual({ ok: true, grantedScopes: ['openid', 'profile'] });
  });
  it('does not mutate frozen inputs and returns an independent grant array', () => {
    const requested = Object.freeze(['profile', 'openid', 'profile']);
    const allowed = Object.freeze(['email', 'openid', 'profile']);
    const result = calculateGrantedScopes(requested, allowed);
    expect(result).toEqual({ ok: true, grantedScopes: ['profile', 'openid'] });
    if (result.ok) result.grantedScopes.push('caller-only');
    expect(requested).toEqual(['profile', 'openid', 'profile']);
    expect(allowed).toEqual(['email', 'openid', 'profile']);
    expect(calculateGrantedScopes(requested, allowed)).toEqual({
      ok: true,
      grantedScopes: ['profile', 'openid'],
    });
  });
  it('is independent of allowed-set ordering', () => {
    expect(
      calculateGrantedScopes(
        ['profile', 'openid', 'profile'],
        ['openid', 'email', 'profile'],
      ),
    ).toEqual(
      calculateGrantedScopes(
        ['profile', 'openid', 'profile'],
        ['profile', 'openid', 'email'],
      ),
    );
  });
  it('rejects non-empty requested scope with an empty allowed set', () => {
    expect(calculateGrantedScopes(['openid'], [])).toEqual({ ok: false });
  });
  it('does not invent scopes for an empty mathematical request (HTTP parser still requires scope)', () => {
    expect(calculateGrantedScopes([], ['openid'])).toEqual({
      ok: true,
      grantedScopes: [],
    });
    expect(calculateGrantedScopes([], [])).toEqual({
      ok: true,
      grantedScopes: [],
    });
  });
  it('uses string membership rather than object-property authority', () => {
    expect(
      calculateGrantedScopes(['__proto__', 'constructor'], ['openid']),
    ).toEqual({ ok: false });
    expect(calculateGrantedScopes(['__proto__'], ['__proto__'])).toEqual({
      ok: true,
      grantedScopes: ['__proto__'],
    });
  });
});
