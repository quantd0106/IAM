import { Logger, type INestApplication } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import { ConfigService } from '@nestjs/config';
import type { Environment } from '../config/env.schema.js';
import { RedisService } from '../redis/redis.service.js';
import { IdpSessionStateService } from '../session/idp-session-state.service.js';
import type { IdpSessionState } from '../session/idp-session-state.js';
import { SessionAuthenticationModule } from '../session/session-authentication.module.js';
import { AuthorizationService } from './authorization.service.js';
import { AuthorizationCodeService } from './authorization-code.service.js';
import { RedisModule } from '../redis/redis.module.js';
import type { Server } from 'node:http';
import request from 'supertest';
import {
  afterAll,
  afterEach,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
  vi,
  type MockInstance,
} from 'vitest';
import type { Prisma } from '../generated/prisma/client.js';
import { PrismaService } from '../prisma/prisma.service.js';
import { ClientRegistryModule } from '../client-registry/client-registry.module.js';
import { ScopeLookupService } from '../client-registry/scope-lookup.service.js';
import { ClientSecretService } from '../client-registry/client-secret.service.js';
import { OAuthModule } from './oauth.module.js';
import { OAuthController } from './oauth.controller.js';
import { AuthorizationRequestService } from './authorization-request.service.js';

const valid = {
  response_type: 'code',
  client_id: 'student-spa',
  redirect_uri: 'http://localhost:3200/callback',
  scope: 'openid profile email',
  state: 'opaque-state-canary',
  nonce: 'opaque-nonce-canary',
  code_challenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
  code_challenge_method: 'S256',
};
const badRequest = {
  error: 'invalid_request',
  error_description: 'Invalid authorization request.',
};
const unauthenticated = {
  statusCode: 401,
  error: 'Unauthorized',
  message: 'Authentication required.',
};
const currentId = '9d3d959a-c65b-4ffc-8086-ad563e59f198';
const currentUser = 'c0e21e3f-d3ee-425c-a99f-c2e7a7cab53f';
const currentCookie = `iam.sid=${currentId}`;
const currentRow = () => ({
  id: currentId,
  userId: currentUser,
  status: 'ACTIVE' as 'ACTIVE' | 'REVOKED',
  createdAt: new Date(Date.now() - 5000),
  expiresAt: new Date(Date.now() + 60000),
  ipAddress: null,
  userAgent: null,
});
const rows = [
  {
    id: 'a82336c1-d281-48c6-981b-201b962cfa08',
    clientId: 'student-spa',
    name: 'Student SPA',
    clientType: 'PUBLIC',
    enabled: true,
    accessTokenTtl: 600,
    refreshTokenTtl: 2592000,
    redirectUris: [{ redirectUri: 'http://localhost:3200/callback' }],
  },
  {
    id: 'b82336c1-d281-48c6-981b-201b962cfa08',
    clientId: 'banking-web',
    name: 'Banking Web / BFF',
    clientType: 'CONFIDENTIAL',
    enabled: true,
    accessTokenTtl: 600,
    refreshTokenTtl: 2592000,
    redirectUris: [{ redirectUri: 'http://localhost:3100/auth/callback' }],
  },
  {
    id: 'c82336c1-d281-48c6-981b-201b962cfa08',
    clientId: 'admin-portal',
    name: 'Admin Portal / BFF',
    clientType: 'CONFIDENTIAL',
    enabled: true,
    accessTokenTtl: 600,
    refreshTokenTtl: 2592000,
    redirectUris: [{ redirectUri: 'http://localhost:3300/auth/callback' }],
  },
];

describe('GET /oauth/authorize (M5.1 HTTP boundary + real M4.6 lookup)', () => {
  const findUnique =
    vi.fn<
      (
        input: Prisma.ClientFindUniqueArgs,
      ) => Promise<(typeof rows)[number] | null>
    >();
  const findAllowed =
    vi.fn<
      (
        input: Prisma.ClientScopeFindManyArgs,
      ) => Promise<{ scope: { name: string } }[]>
    >();
  const unexpected = vi.fn(() => {
    throw new Error('Unexpected business-data side effect.');
  });
  const mutations = {
    create: unexpected,
    createMany: unexpected,
    update: unexpected,
    updateMany: unexpected,
    upsert: unexpected,
    delete: unexpected,
    deleteMany: unexpected,
  };
  let clients: typeof rows;
  let allowedNames: Map<string, string[]>;
  let app: INestApplication<Server>;
  const touch = vi.fn<IdpSessionStateService['touch']>();
  const reserve = vi.fn<RedisService['setIfAbsentWithTtl']>();
  const findSession =
    vi.fn<() => Promise<ReturnType<typeof currentRow> | null>>();
  let persistent: ReturnType<typeof currentRow>;
  let logs: MockInstance[];
  let codeWriteFailure = false;
  beforeAll(async () => {
    const module = await Test.createTestingModule({ imports: [OAuthModule] })
      .overrideProvider(PrismaService)
      .useValue({
        client: { findUnique, findFirst: unexpected, ...mutations },
        clientScope: { findMany: findAllowed, ...mutations },
        scope: { findMany: unexpected, ...mutations },
        user: { findUnique: unexpected, ...mutations },
        credential: mutations,
        session: { findMany: unexpected, findFirst: findSession, ...mutations },
        clientRedirectUri: mutations,
        $transaction: unexpected,
        $executeRaw: unexpected,
        $executeRawUnsafe: unexpected,
      })
      .overrideProvider(ClientSecretService)
      .useValue({ issueSecret: unexpected })
      .overrideProvider(RedisService)
      .useValue({ setIfAbsentWithTtl: reserve })
      .overrideProvider(IdpSessionStateService)
      .useValue({ touch })
      .useMocker((token) =>
        token === ConfigService
          ? new ConfigService<Environment, true>({
              COOKIE_NAME: 'iam.sid',
              COOKIE_SECURE: false,
            })
          : undefined,
      )
      .compile();
    app = module.createNestApplication<INestApplication<Server>>({
      logger: false,
    });
    await app.init();
  });
  beforeEach(() => {
    vi.resetAllMocks();
    reserve.mockResolvedValue(true);
    codeWriteFailure = false;
    clients = structuredClone(rows);
    persistent = currentRow();
    findSession.mockImplementation(() => Promise.resolve(persistent));
    touch.mockImplementation((id) =>
      Promise.resolve(
        id === currentId
          ? {
              userId: currentUser,
              authTime: persistent.createdAt.getTime(),
              mfaLevel: 'password',
              createdAt: persistent.createdAt.getTime(),
              lastActivityAt: Date.now(),
              absoluteExpiresAt: persistent.expiresAt.getTime(),
            }
          : null,
      ),
    );
    allowedNames = new Map(
      rows.map((row) => [
        row.id,
        [
          'openid',
          'profile',
          'email',
          ...(row.clientId === 'banking-web'
            ? ['banking.transactions.read']
            : []),
        ],
      ]),
    );
    findAllowed.mockImplementation((input) => {
      const id = input.where?.clientId;
      if (typeof id !== 'string')
        throw new Error('Expected internal client identifier.');
      return Promise.resolve(
        (allowedNames.get(id) ?? []).map((name) => ({ scope: { name } })),
      );
    });
    findUnique.mockImplementation((input) =>
      Promise.resolve(
        clients.find((row) => row.clientId === input.where.clientId) ?? null,
      ),
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
      expect(unexpected.mock.calls.length).toBe(0);
      for (const log of logs) expect(log.mock.calls.length).toBe(0);
    } finally {
      vi.restoreAllMocks();
    }
  });
  afterAll(async () => {
    await app.close();
  });
  async function call(
    query: Record<string, unknown>,
    status: number,
    body?: unknown,
    cookie: string | undefined = currentCookie,
  ) {
    const touchesBefore = touch.mock.calls.length;
    const reservationsBefore = reserve.mock.calls.length;
    const operation = request(app.getHttpServer())
      .get('/oauth/authorize')
      .query(query);
    if (cookie !== undefined) operation.set('Cookie', cookie);
    const response = await operation.expect(status);
    if (status === 400) expect(touch.mock.calls.length).toBe(touchesBefore);
    if (status === 400 || status === 401)
      expect(reserve.mock.calls.length).toBe(reservationsBefore);
    if (status === 500 && !codeWriteFailure)
      expect(reserve.mock.calls.length).toBe(reservationsBefore);
    if (status === 204)
      expect(reserve.mock.calls.length).toBe(reservationsBefore + 1);
    expect(response.headers.location).toBeUndefined();
    expect(response.headers['set-cookie']).toBeUndefined();
    expect(response.headers['cache-control']).toBe('no-store');
    if (status === 204) expect(response.text).toBe('');
    else expect(response.body as unknown).toEqual(body ?? badRequest);
    for (const value of [
      valid.state,
      valid.nonce,
      valid.code_challenge,
      valid.redirect_uri,
      valid.scope,
      currentId,
      currentUser,
      'private driver cause',
    ])
      expect(response.text.includes(value)).toBe(false);
    return response;
  }
  it('uses a non-global OAuth module with the shared central-session capability, not AuthModule or new session semantics', () => {
    expect(Reflect.getMetadata('imports', OAuthModule) as unknown).toEqual([
      ClientRegistryModule,
      SessionAuthenticationModule,
      RedisModule,
    ]);
    expect(Reflect.getMetadata('controllers', OAuthModule) as unknown).toEqual([
      OAuthController,
    ]);
    expect(Reflect.getMetadata('providers', OAuthModule) as unknown).toEqual([
      AuthorizationRequestService,
      AuthorizationService,
      AuthorizationCodeService,
    ]);
    expect(
      Reflect.getMetadata('__module:global__', OAuthModule) as unknown,
    ).not.toBe(true);
    expect(Object.keys(app.get(AuthorizationRequestService))).toEqual([
      'clients',
      'scopes',
    ]);
  });
  it('persists exactly one code after authentication but returns empty 204, never code/token/redirect/cookie', async () => {
    await call(valid, 204);
    expect(findUnique).toHaveBeenCalledOnce();
    expect(findUnique.mock.calls[0][0].where).toEqual({
      clientId: 'student-spa',
    });
    expect(findAllowed).toHaveBeenCalledExactlyOnceWith({
      where: { clientId: rows[0].id },
      select: { scope: { select: { name: true } } },
    });
    expect(reserve).toHaveBeenCalledOnce();
    expect(findSession.mock.invocationCallOrder[0]).toBeLessThan(
      reserve.mock.invocationCallOrder[0],
    );
    const stored: unknown = JSON.parse(reserve.mock.calls[0][1]);
    expect(stored).toEqual({
      clientId: valid.client_id,
      userId: currentUser,
      redirectUri: valid.redirect_uri,
      grantedScopes: ['openid', 'profile', 'email'],
      codeChallenge: valid.code_challenge,
      nonce: valid.nonce,
      authTime: persistent.createdAt.getTime(),
      expiresAt: expect.any(Number) as unknown,
    });
    expect(reserve.mock.calls[0][2]).toBe(120);
  });
  it.each(['banking-web', 'admin-portal'])(
    'accepts exact %s registration without requiring PKCE',
    async (id) => {
      const client = clients.find((row) => row.clientId === id);
      if (!client) throw new Error('Missing fixture.');
      await call(
        {
          ...valid,
          client_id: id,
          redirect_uri: client.redirectUris[0].redirectUri,
          code_challenge: undefined,
          code_challenge_method: undefined,
        },
        204,
      );
    },
  );
  it.each([
    'response_type',
    'client_id',
    'redirect_uri',
    'scope',
    'state',
  ] as const)(
    'rejects missing required %s without Location/cookie or lookup',
    async (field) => {
      const input: Record<string, unknown> = { ...valid };
      delete input[field];
      await call(input, 400);
      expect(findUnique).not.toHaveBeenCalled();
    },
  );
  it.each(['token', 'id_token', 'code token', 'Code', 'code '])(
    'returns a fixed OAuth unsupported_response_type for %s',
    async (response_type) => {
      await call({ ...valid, response_type }, 400, {
        ...badRequest,
        error: 'unsupported_response_type',
      });
      expect(findUnique).not.toHaveBeenCalled();
    },
  );
  it.each([
    'unknown-client',
    'Student-spa',
    'student-spa ',
    ' student-spa',
    'student-*',
  ])('rejects unknown/non-exact client_id (%#)', async (client_id) => {
    await call({ ...valid, client_id }, 400);
    expect(findUnique.mock.calls[0][0].where).toEqual({ clientId: client_id });
  });
  it('rejects disabled clients with the same direct error as unknown clients', async () => {
    clients[0].enabled = false;
    await call(valid, 400);
    await call({ ...valid, client_id: 'unknown-client' }, 400);
  });
  it.each([
    'http://localhost:3200/callback/',
    'http://localhost:3200/Callback',
    'http://localhost:3200/call%62ack',
    'HTTP://LOCALHOST:3200/callback',
    'http://localhost:3200/callback?x=1',
    'http://localhost:3200/callback.evil',
    'http://localhost:3200/prefix/callback',
    'http://localhost:3200/*',
    'http://localhost:3200/%',
    'http://localhost:3200@evil.example/callback',
    'https://evil.example/callback',
  ])('never redirects to invalid supplied URI (%#)', async (redirect_uri) => {
    await call({ ...valid, redirect_uri }, 400);
  });
  it('uses exactly one framework decoding step, not URL re-encoding/canonicalization', async () => {
    const registered = 'http://localhost:3200/call%62ack?b=2&a=1';
    clients[0].redirectUris = [{ redirectUri: registered }];
    await call({ ...valid, redirect_uri: registered }, 204);
    await call(
      { ...valid, redirect_uri: 'http://localhost:3200/callback?b=2&a=1' },
      400,
    );
    await call(
      { ...valid, redirect_uri: 'http://localhost:3200/call%62ack?a=1&b=2' },
      400,
    );
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
  ] as const)('rejects duplicate scalar %s query parameters', async (field) => {
    await call(
      { ...valid, [field]: ['duplicate-canary-a', 'duplicate-canary-b'] },
      400,
    );
    expect(findUnique).not.toHaveBeenCalled();
  });
  it.each(['state', 'scope', 'redirect_uri', 'client_id'])(
    'rejects object query syntax instead of coercing %s',
    async (field) => {
      await call({ ...valid, [field]: { nested: 'object-canary' } }, 400);
      expect(findUnique).not.toHaveBeenCalled();
    },
  );
  it('requires nonce for exact requested openid before scope lookup; other case tokens are not aliases', async () => {
    await call({ ...valid, nonce: undefined }, 400);
    expect(findAllowed).not.toHaveBeenCalled();
    await call(
      { ...valid, nonce: undefined, scope: 'custom.scope OpenID' },
      400,
      { ...badRequest, error: 'invalid_scope' },
    );
    await call({ ...valid, nonce: undefined, scope: 'profile' }, 204);
    allowedNames.get(rows[0].id)?.push('OpenID');
    await call({ ...valid, nonce: undefined, scope: 'OpenID' }, 204);
  });
  it.each([
    ['student-spa', 'openid banking.transactions.read'],
    ['student-spa', 'openid definitely.unknown'],
    ['student-spa', 'OpenID'],
    ['banking-web', 'BANKING.TRANSACTIONS.READ'],
    ['admin-portal', 'openid banking.transactions.read'],
    ['admin-portal', 'banking.transactions.read'],
  ])(
    'returns fixed invalid_scope for %s unassigned request (%#)',
    async (id, scope) => {
      const client = clients.find((row) => row.clientId === id);
      if (!client) throw new Error('Missing fixture.');
      await call(
        {
          ...valid,
          client_id: id,
          redirect_uri: client.redirectUris[0].redirectUri,
          scope,
        },
        400,
        { ...badRequest, error: 'invalid_scope' },
      );
      expect(findAllowed.mock.calls[0][0].where).toEqual({
        clientId: client.id,
      });
    },
  );
  it.each([
    ['student-spa', 'profile'],
    ['student-spa', 'openid profile openid email profile'],
    ['banking-web', 'openid banking.transactions.read'],
    ['banking-web', 'banking.transactions.read'],
    ['admin-portal', 'email profile'],
  ])(
    'retains interim empty 204 for %s valid subset/duplicates (%#)',
    async (id, scope) => {
      const client = clients.find((row) => row.clientId === id);
      if (!client) throw new Error('Missing fixture.');
      await call(
        {
          ...valid,
          client_id: id,
          redirect_uri: client.redirectUris[0].redirectUri,
          scope,
        },
        204,
      );
    },
  );
  it('does not fall back to default OIDC scopes when no assignments exist', async () => {
    allowedNames.set(rows[0].id, []);
    await call(valid, 400, { ...badRequest, error: 'invalid_scope' });
  });
  it.each([
    { response_type: undefined },
    { response_type: 'token' },
    { client_id: 'unknown-client' },
    { redirect_uri: 'https://unregistered.example.invalid' },
    { code_challenge: 'x' },
    { code_challenge_method: 'plain' },
  ])(
    'skips all scope queries when an earlier check fails (%#)',
    async (variation) => {
      await call({ ...valid, ...variation, scope: 'definitely.unknown' }, 400, {
        ...badRequest,
        error:
          variation.response_type === 'token'
            ? 'unsupported_response_type'
            : 'invalid_request',
      });
      expect(findAllowed).not.toHaveBeenCalled();
    },
  );
  it('does not query scopes for a disabled client', async () => {
    clients[0].enabled = false;
    await call(valid, 400);
    expect(findAllowed).not.toHaveBeenCalled();
  });
  it('maps scope-read infrastructure failure to server_error, never invalid_scope', async () => {
    findAllowed.mockRejectedValueOnce(
      new Error('private driver cause SQL scope client UUID'),
    );
    await call(valid, 500, {
      error: 'server_error',
      error_description: 'Authorization request failed.',
    });
  });
  it('sanitizes unexpected scope lookup exceptions without query or internal identifier leakage', async () => {
    vi.spyOn(
      app.get(ScopeLookupService),
      'getAllowedScopeNames',
    ).mockRejectedValueOnce(
      new Error(`${rows[0].id} ${JSON.stringify(valid)}`),
    );
    await call(valid, 500, {
      error: 'server_error',
      error_description: 'Authorization request failed.',
    });
  });
  it.each([
    { code_challenge: undefined, code_challenge_method: undefined },
    { code_challenge: undefined },
    { code_challenge: '' },
    { code_challenge_method: undefined },
    { code_challenge_method: 'plain' },
    { code_challenge_method: 's256' },
  ])(
    'enforces PUBLIC challenge/method presence and exact S256 (%#)',
    async (variation) => {
      await call({ ...valid, ...variation }, 400);
    },
  );
  it('rejects the short challenge previously allowed by the minimal M5.1 boundary', async () => {
    await call({ ...valid, code_challenge: 'x' }, 400);
  });
  it.each(['banking-web', 'admin-portal'])(
    'accepts complete S256 PKCE but rejects partial pairs for confidential %s',
    async (id) => {
      const client = clients.find((row) => row.clientId === id);
      if (!client) throw new Error('Missing fixture.');
      const query = {
        ...valid,
        client_id: id,
        redirect_uri: client.redirectUris[0].redirectUri,
      };
      await call(query, 204);
      await call({ ...query, code_challenge: undefined }, 400);
      await call({ ...query, code_challenge_method: undefined }, 400);
      await call({ ...query, code_challenge_method: 'plain' }, 400);
    },
  );
  it.each(['student-spa', 'banking-web', 'admin-portal'])(
    'rejects malformed PKCE for %s without repair, output/log leaks or side effects',
    async (id) => {
      const client = clients.find((row) => row.clientId === id);
      if (!client) throw new Error('Missing fixture.');
      const query = {
        ...valid,
        client_id: id,
        redirect_uri: client.redirectUris[0].redirectUri,
      };
      for (const code_challenge of [
        '',
        'x',
        'A'.repeat(42),
        'A'.repeat(44),
        `${valid.code_challenge}=`,
        ...[
          '=',
          '+',
          '/',
          '.',
          '~',
          ' ',
          '\t',
          '\n',
          '\r',
          '\u2028',
          '\u2029',
          '\u0000',
          '\u007f',
          '\u00e9',
        ].map((character) => `${'A'.repeat(42)}${character}`),
        `${'A'.repeat(40)}%2D`,
      ])
        await call({ ...query, code_challenge }, 400);
      for (const code_challenge_method of [
        'plain',
        's256',
        ' S256',
        'S256 ',
        'S256\n',
        '',
        'unknown',
      ])
        await call({ ...query, code_challenge_method }, 400);
    },
  );
  it('does not accept query subjects or Bearer/custom headers instead of a configured cookie', async () => {
    const response = await request(app.getHttpServer())
      .get('/oauth/authorize')
      .query({
        ...valid,
        userId: 'not-an-authority',
        unknown_extension: 'opaque',
      })
      .set('Cookie', 'iam.sid=not-a-session')
      .set('Authorization', 'Bearer not-a-token')
      .set('X-Session-Id', currentId)
      .expect(401);
    expect(response.body as unknown).toEqual(unauthenticated);
    expect(touch).not.toHaveBeenCalled();
    expect(response.headers.location).toBeUndefined();
    expect(response.headers['set-cookie']).toBeUndefined();
  });
  it.each([
    '',
    'unrelated=value',
    'iam.sid=invalid',
    `iam.sid=${currentId}; iam.sid=${currentId}`,
  ])(
    'returns indistinguishable 401 for missing/malformed/duplicate cookies (%#)',
    async (cookie) => {
      await call(valid, 401, unauthenticated, cookie);
      expect(touch).not.toHaveBeenCalled();
      expect(findSession).not.toHaveBeenCalled();
    },
  );
  it('requires authentication when the configured cookie is entirely absent', async () => {
    const response = await request(app.getHttpServer())
      .get('/oauth/authorize')
      .query(valid)
      .expect(401);
    expect(response.body as unknown).toEqual(unauthenticated);
    expect(response.headers.location).toBeUndefined();
    expect(response.headers['set-cookie']).toBeUndefined();
    expect(response.headers['cache-control']).toBe('no-store');
    expect(touch).not.toHaveBeenCalled();
  });
  it('returns 401 for a UUID with missing/expired runtime, without persistent fallback', async () => {
    touch.mockResolvedValue(null);
    await call(valid, 401, unauthenticated);
    expect(findSession).not.toHaveBeenCalled();
  });
  it.each([
    'missing',
    'revoked',
    'expired',
    'wrong user',
    'wrong id',
    'createdAt',
    'absolute expiry',
  ])(
    'returns the same 401 for persistent session failure (%#)',
    async (variation) => {
      const state: IdpSessionState = {
        userId: currentUser,
        authTime: persistent.createdAt.getTime(),
        mfaLevel: 'password',
        createdAt: persistent.createdAt.getTime(),
        lastActivityAt: Date.now(),
        absoluteExpiresAt: persistent.expiresAt.getTime(),
      };
      touch.mockResolvedValue(state);
      if (variation === 'missing') findSession.mockResolvedValue(null);
      if (variation === 'revoked') persistent.status = 'REVOKED';
      if (variation === 'expired')
        persistent.expiresAt = new Date(Date.now() - 1);
      if (variation === 'wrong user') persistent.userId = rows[0].id;
      if (variation === 'wrong id') persistent.id = rows[0].id;
      if (variation === 'createdAt')
        persistent.createdAt = new Date(state.createdAt - 1);
      if (variation === 'absolute expiry')
        persistent.expiresAt = new Date(state.absoluteExpiresAt + 1);
      await call(valid, 401, unauthenticated);
    },
  );
  it.each(['Redis', 'Prisma'])(
    'returns sanitized server_error for %s session failure, not 401',
    async (stage) => {
      const failure = new Error(
        `private driver cause ${currentId} ${currentUser}`,
        { cause: new Error('private cause') },
      );
      if (stage === 'Redis') touch.mockRejectedValue(failure);
      else findSession.mockRejectedValue(failure);
      await call(valid, 500, {
        error: 'server_error',
        error_description: 'Authorization request failed.',
      });
    },
  );
  it('touches only after client, redirect, PKCE and allowed-scope validation succeeded', async () => {
    await call({ ...valid, scope: 'unknown.scope' }, 400, {
      ...badRequest,
      error: 'invalid_scope',
    });
    expect(touch).not.toHaveBeenCalled();
    await call(valid, 204);
    expect(touch).toHaveBeenCalledExactlyOnceWith(currentId);
    expect(findAllowed.mock.invocationCallOrder[1]).toBeLessThan(
      touch.mock.invocationCallOrder[0],
    );
    expect(touch.mock.invocationCallOrder[0]).toBeLessThan(
      findSession.mock.invocationCallOrder[0],
    );
  });
  it('sanitizes Prisma/lookup errors into a fixed OAuth 500 without cause/logging', async () => {
    findUnique.mockRejectedValueOnce(
      new Error('private driver cause state nonce redirect_uri'),
    );
    await call(valid, 500, {
      error: 'server_error',
      error_description: 'Authorization request failed.',
    });
  });
  it('maps code Redis failure to the identical fixed 500, without raw code/key/state leakage', async () => {
    codeWriteFailure = true;
    reserve.mockImplementation((key, value) =>
      Promise.reject(
        new Error(`private driver cause ${key} ${value}`, {
          cause: new Error('private cause'),
        }),
      ),
    );
    await call(valid, 500, {
      error: 'server_error',
      error_description: 'Authorization request failed.',
    });
    expect(reserve).toHaveBeenCalledOnce();
  });
  it('fails closed on bounded collision exhaustion, without a success HTTP response', async () => {
    codeWriteFailure = true;
    reserve.mockResolvedValue(false);
    await call(valid, 500, {
      error: 'server_error',
      error_description: 'Authorization request failed.',
    });
    expect(reserve).toHaveBeenCalledTimes(3);
  });
  it('sanitizes unexpected validation failures without reflecting the query', async () => {
    vi.spyOn(
      app.get(AuthorizationRequestService),
      'validate',
    ).mockRejectedValueOnce(new Error(JSON.stringify(valid)));
    await call(valid, 500, {
      error: 'server_error',
      error_description: 'Authorization request failed.',
    });
  });
  it.each([
    '/oauth/token',
    '/oauth/revoke',
    '/.well-known/openid-configuration',
    '/.well-known/jwks.json',
    '/oidc/userinfo',
  ])('does not add future endpoint %s', async (path) => {
    await request(app.getHttpServer()).get(path).expect(404);
  });
});
