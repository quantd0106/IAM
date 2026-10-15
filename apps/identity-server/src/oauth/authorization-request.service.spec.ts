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
    service = new AuthorizationRequestService({ requireEnabledClient: lookup });
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
    });
    expect(lookup).toHaveBeenCalledExactlyOnceWith('student-spa');
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
  it('accepts syntactically valid unregistered scopes without querying allowed scopes or granting them', async () => {
    const input = { ...query, nonce: undefined };
    const result = await service.validate({
      ...input,
      scope: 'custom.scope OpenID custom.scope',
    });
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.request.scope).toEqual([
        'custom.scope',
        'OpenID',
        'custom.scope',
      ]);
      expect(Object.keys(result).sort()).toEqual(['client', 'ok', 'request']);
    }
  });
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
