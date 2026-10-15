import { Logger } from '@nestjs/common';
import {
  afterEach,
  beforeEach,
  describe,
  expect,
  it,
  vi,
  type MockInstance,
} from 'vitest';
import {
  ClientLookupService,
  type EnabledClient,
} from '../client-registry/client-lookup.service.js';
import { ScopeLookupService } from '../client-registry/scope-lookup.service.js';
import { AuthorizationRequestService } from './authorization-request.service.js';

const query = {
  response_type: 'code',
  client_id: 'student-spa',
  redirect_uri: 'http://localhost:3200/callback',
  scope: 'openid profile email',
  state: 'opaque state',
  nonce: 'opaque nonce',
  code_challenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
  code_challenge_method: 'S256',
};
describe('AuthorizationRequestService', () => {
  const lookup = vi.fn<ClientLookupService['requireEnabledClient']>();
  const allowedLookup = vi.fn<ScopeLookupService['getAllowedScopeNames']>();
  let service: AuthorizationRequestService;
  let client: EnabledClient;
  let logs: MockInstance[];
  beforeEach(() => {
    vi.resetAllMocks();
    client = {
      id: 'd82336c1-d281-48c6-981b-201b962cfa08',
      clientId: 'student-spa',
      name: 'Student SPA',
      clientType: 'PUBLIC',
      accessTokenTtl: 600,
      refreshTokenTtl: 2592000,
      redirectUris: ['http://localhost:3200/callback'],
    };
    lookup.mockResolvedValue(client);
    allowedLookup.mockResolvedValue(['email', 'openid', 'profile']);
    service = new AuthorizationRequestService(
      { requireEnabledClient: lookup },
      { getAllowedScopeNames: allowedLookup },
    );
    logs = [
      ...(['log', 'info', 'warn', 'error', 'debug'] as const).map((method) =>
        vi.spyOn(console, method).mockImplementation(() => undefined),
      ),
      ...(['log', 'warn', 'error', 'debug', 'verbose', 'fatal'] as const).map(
        (method) =>
          vi
            .spyOn(Logger.prototype, method)
            .mockImplementation(() => undefined),
      ),
    ];
  });
  afterEach(() => {
    try {
      for (const log of logs) expect(log.mock.calls.length).toBe(0);
    } finally {
      vi.restoreAllMocks();
    }
  });
  it('uses only M4.6 exact client resolution and returns a transient typed parsed boundary', async () => {
    const result = await service.validate(query);
    expect(result).toEqual({
      ok: true,
      client,
      request: { ...query, scope: ['openid', 'profile', 'email'] },
      grantedScopes: ['openid', 'profile', 'email'],
    });
    expect(lookup).toHaveBeenCalledExactlyOnceWith('student-spa');
    expect(allowedLookup).toHaveBeenCalledExactlyOnceWith(client.id);
    expect(allowedLookup).not.toHaveBeenCalledWith(client.clientId);
    expect(lookup.mock.invocationCallOrder[0]).toBeLessThan(
      allowedLookup.mock.invocationCallOrder[0],
    );
  });
  it.each(['banking-web', 'admin-portal'])(
    'does not force PKCE for enabled confidential %s',
    async (id) => {
      client = {
        ...client,
        clientId: id,
        clientType: 'CONFIDENTIAL',
        redirectUris: [
          `http://localhost:${id === 'banking-web' ? 3100 : 3300}/auth/callback`,
        ],
      };
      lookup.mockResolvedValue(client);
      const input = {
        ...query,
        code_challenge: undefined,
        code_challenge_method: undefined,
      };
      expect(
        (
          await service.validate({
            ...input,
            client_id: id,
            redirect_uri: client.redirectUris[0],
          })
        ).ok,
      ).toBe(true);
    },
  );
  it.each(['unknown', 'disabled'])(
    'maps %s client to the same safe validation result',
    async () => {
      lookup.mockRejectedValue(new Error('Client unavailable.'));
      expect(await service.validate(query)).toEqual({
        ok: false,
        error: 'invalid_request',
      });
    },
  );
  it.each([
    'Student-spa',
    'student-spa ',
    ' student-spa',
    'caf\u00e9',
    'cafe\u0301',
  ])(
    'passes exact decoded client_id to lookup without transformation (%#)',
    async (id) => {
      lookup.mockRejectedValue(new Error('Client unavailable.'));
      await service.validate({ ...query, client_id: id });
      expect(lookup).toHaveBeenCalledExactlyOnceWith(id);
    },
  );
  it.each([
    'http://localhost:3200/callback/',
    'http://localhost:3200/Callback',
    'HTTP://LOCALHOST:3200/callback',
    'http://localhost:3200/call%62ack',
    'http://localhost:3200/callback?x=1',
    'http://localhost:3200/callback.evil',
    'http://localhost:3200/prefix/callback',
    'http://localhost:3200/*',
    'http://localhost:3200/%',
    'http://localhost:3200@evil.example/callback',
    'https://evil.example/callback',
    ' http://localhost:3200/callback',
    'http://localhost:3200/callback ',
  ])(
    'rejects unregistered URI by exact membership (%#)',
    async (redirect_uri) => {
      expect(await service.validate({ ...query, redirect_uri })).toEqual({
        ok: false,
        error: 'invalid_request',
      });
    },
  );
  it('does not normalize query ordering, encoding or Unicode in registered redirects', async () => {
    client.redirectUris = [
      'https://example.test/call%62ack?b=2&a=1',
      'https://example.test/caf\u00e9',
      'https://example.test/second',
    ];
    for (const redirect_uri of client.redirectUris)
      expect((await service.validate({ ...query, redirect_uri })).ok).toBe(
        true,
      );
    for (const redirect_uri of [
      'https://example.test/callback?b=2&a=1',
      'https://example.test/call%62ack?a=1&b=2',
      'https://example.test/cafe\u0301',
    ])
      expect((await service.validate({ ...query, redirect_uri })).ok).toBe(
        false,
      );
  });
  it('rejects when an enabled client has no redirect registrations', async () => {
    client.redirectUris = [];
    expect(await service.validate(query)).toEqual({
      ok: false,
      error: 'invalid_request',
    });
  });
  it.each(['token', 'id_token', 'code token', 'Code', ' code', 'code '])(
    'rejects unsupported response type before lookup (%#)',
    async (response_type) => {
      expect(await service.validate({ ...query, response_type })).toEqual({
        ok: false,
        error: 'unsupported_response_type',
      });
      expect(lookup).not.toHaveBeenCalled();
    },
  );
  it.each(['code_challenge', 'code_challenge_method'] as const)(
    'rejects PUBLIC missing %s',
    async (field) => {
      const input: Record<string, unknown> = { ...query };
      delete input[field];
      expect(await service.validate(input)).toEqual({
        ok: false,
        error: 'invalid_request',
      });
    },
  );
  it('permits confidential S256 PKCE but rejects a supplied challenge without S256/plain', async () => {
    client.clientType = 'CONFIDENTIAL';
    expect((await service.validate(query)).ok).toBe(true);
    const input = { ...query, code_challenge_method: undefined };
    expect((await service.validate(input)).ok).toBe(false);
    expect(
      (await service.validate({ ...query, code_challenge_method: 'plain' })).ok,
    ).toBe(false);
  });
  it.each(['PUBLIC', 'CONFIDENTIAL'] as const)(
    'enforces PKCE policy after enabled %s client resolution',
    async (clientType) => {
      client.clientType = clientType;
      for (const variation of [
        { code_challenge: undefined },
        { code_challenge_method: undefined },
        { code_challenge_method: 'plain' },
        { code_challenge_method: 's256' },
        { code_challenge_method: ' S256' },
        { code_challenge_method: 'S256 ' },
        { code_challenge: '' },
        { code_challenge: 'x' },
        { code_challenge: 'A'.repeat(42) },
        { code_challenge: 'A'.repeat(44) },
        { code_challenge: `${'A'.repeat(42)}=` },
        { code_challenge: `${'A'.repeat(42)}+` },
        { code_challenge: `${'A'.repeat(42)}/` },
        { code_challenge: `${'A'.repeat(42)}\n` },
        { code_challenge: `${'A'.repeat(42)}\u00e9` },
      ]) {
        lookup.mockClear();
        expect(await service.validate({ ...query, ...variation })).toEqual({
          ok: false,
          error: 'invalid_request',
        });
        expect(lookup).toHaveBeenCalledExactlyOnceWith(query.client_id);
      }
    },
  );
  it('does not run PKCE policy before the existing enabled-client lookup', async () => {
    lookup.mockRejectedValue(new Error('Client lookup failed.'));
    await expect(
      service.validate({ ...query, code_challenge: 'x' }),
    ).rejects.toThrow('Authorization request failed.');
  });
  it.each([
    'openid banking.transactions.read',
    'openid definitely.unknown',
    'OpenID',
    'OPENID',
    'custom.scope OpenID custom.scope',
    '%6fpenid',
  ])(
    'rejects any unassigned exact scope token, not a partial grant (%#)',
    async (scope) => {
      expect(await service.validate({ ...query, scope })).toEqual({
        ok: false,
        error: 'invalid_scope',
      });
      expect(allowedLookup).toHaveBeenCalledExactlyOnceWith(client.id);
    },
  );
  it.each(['student-spa', 'banking-web', 'admin-portal'])(
    'enforces seeded-style allowed assignments for %s, not client-type defaults',
    async (clientId) => {
      client.clientId = clientId;
      client.clientType =
        clientId === 'student-spa' ? 'PUBLIC' : 'CONFIDENTIAL';
      if (clientId === 'banking-web')
        allowedLookup.mockResolvedValue([
          'email',
          'openid',
          'profile',
          'banking.transactions.read',
        ]);
      expect(
        (await service.validate({ ...query, client_id: clientId })).ok,
      ).toBe(true);
      const result = await service.validate({
        ...query,
        client_id: clientId,
        scope: 'openid banking.transactions.read',
      });
      if (clientId === 'banking-web') {
        expect(result.ok).toBe(true);
        if (result.ok)
          expect(result.grantedScopes).toEqual([
            'openid',
            'banking.transactions.read',
          ]);
      } else expect(result).toEqual({ ok: false, error: 'invalid_scope' });
      if (clientId === 'admin-portal')
        expect(
          await service.validate({
            ...query,
            client_id: clientId,
            scope: 'banking.transactions.read',
          }),
        ).toEqual({ ok: false, error: 'invalid_scope' });
    },
  );
  it('does not case-fold an assigned banking scope', async () => {
    client.clientType = 'CONFIDENTIAL';
    allowedLookup.mockResolvedValue(['banking.transactions.read']);
    expect(
      await service.validate({ ...query, scope: 'BANKING.TRANSACTIONS.READ' }),
    ).toEqual({ ok: false, error: 'invalid_scope' });
  });
  it('preserves requested duplicates while exposing an independent deduplicated transient grant', async () => {
    const input = Object.freeze({
      ...query,
      scope: 'profile openid profile email openid',
    });
    const result = await service.validate(input);
    expect(result.ok).toBe(true);
    if (!result.ok) expect.fail('Expected valid grant.');
    expect(result.request.scope).toEqual([
      'profile',
      'openid',
      'profile',
      'email',
      'openid',
    ]);
    expect(result.grantedScopes).toEqual(['profile', 'openid', 'email']);
    result.grantedScopes.push('caller-only');
    expect(result.request.scope).toEqual([
      'profile',
      'openid',
      'profile',
      'email',
      'openid',
    ]);
    expect(input.scope).toBe('profile openid profile email openid');
    expect(Object.keys(result).sort()).toEqual([
      'client',
      'grantedScopes',
      'ok',
      'request',
    ]);
  });
  it('does not infer defaults and reads fresh assignments instead of caching grants', async () => {
    allowedLookup.mockResolvedValueOnce([]).mockResolvedValueOnce(['profile']);
    expect(await service.validate(query)).toEqual({
      ok: false,
      error: 'invalid_scope',
    });
    const result = await service.validate({
      ...query,
      scope: 'profile',
      nonce: undefined,
    });
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.grantedScopes).toEqual(['profile']);
    expect(allowedLookup).toHaveBeenCalledTimes(2);
  });
  it.each([
    { state: undefined },
    { response_type: 'token' },
    { redirect_uri: 'https://unregistered.example.invalid' },
    { code_challenge: undefined },
    { code_challenge: 'x' },
    { code_challenge_method: 'plain' },
    { nonce: undefined },
  ])(
    'never reads allowed scopes before earlier validation succeeds (%#)',
    async (variation) => {
      allowedLookup.mockRejectedValue(new Error('Must not read scopes.'));
      const result = await service.validate({ ...query, ...variation });
      expect(result.ok).toBe(false);
      expect(allowedLookup).not.toHaveBeenCalled();
    },
  );
  it.each(['Client unavailable.', 'Client lookup failed.'])(
    'does not read scopes after client lookup rejection (%#)',
    async (message) => {
      lookup.mockRejectedValue(new Error(message));
      try {
        await service.validate(query);
      } catch {
        /* fixed operational failure */
      }
      expect(allowedLookup).not.toHaveBeenCalled();
    },
  );
  it.each(['async', 'sync'])(
    'sanitizes %s scope lookup failures as server failures, not invalid_scope',
    async (mode) => {
      const privateError = new Error(
        `Scope lookup failed. private SQL ${client.id} ${query.state}`,
        { cause: new Error('private driver detail') },
      );
      if (mode === 'async') allowedLookup.mockRejectedValue(privateError);
      else
        allowedLookup.mockImplementation(() => {
          throw privateError;
        });
      let rejected = false;
      try {
        await service.validate(query);
      } catch (error) {
        rejected = true;
        expect(error instanceof Error).toBe(true);
        if (!(error instanceof Error)) expect.fail('Expected safe Error.');
        expect(error.message).toBe('Authorization request failed.');
        expect(error.cause).toBeUndefined();
        expect(Object.keys(error)).toEqual([]);
        for (const value of [
          client.id,
          query.state,
          'Scope lookup failed.',
          'private SQL',
          'private driver detail',
        ])
          expect((error.message + (error.stack ?? '')).includes(value)).toBe(
            false,
          );
      }
      expect(rejected).toBe(true);
    },
  );
  it('rejects malformed shapes before client resolution', async () => {
    expect(
      await service.validate({ ...query, redirect_uri: ['opaque-uri'] }),
    ).toEqual({ ok: false, error: 'invalid_request' });
    expect(lookup).not.toHaveBeenCalled();
  });
  it('sanitizes lookup infrastructure errors without retaining private causes', async () => {
    lookup.mockRejectedValue(
      new Error('private SQL client_id state nonce', {
        cause: new Error('private driver cause'),
      }),
    );
    try {
      await service.validate(query);
      expect.fail('Expected sanitized failure.');
    } catch (error) {
      expect(error instanceof Error).toBe(true);
      if (!(error instanceof Error)) expect.fail('Expected Error.');
      expect(error.message).toBe('Authorization request failed.');
      expect(error.cause).toBeUndefined();
      expect((error.stack ?? '').includes('private SQL')).toBe(false);
    }
  });
});
