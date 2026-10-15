import { Logger, type INestApplication } from '@nestjs/common';
import { Test } from '@nestjs/testing';
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
  let app: INestApplication<Server>;
  let logs: MockInstance[];
  beforeAll(async () => {
    const module = await Test.createTestingModule({ imports: [OAuthModule] })
      .overrideProvider(PrismaService)
      .useValue({
        client: { findUnique, findFirst: unexpected, ...mutations },
        clientScope: { findMany: unexpected, ...mutations },
        scope: { findMany: unexpected, ...mutations },
        user: { findUnique: unexpected, ...mutations },
        credential: mutations,
        session: { findMany: unexpected, findFirst: unexpected, ...mutations },
        clientRedirectUri: mutations,
        $transaction: unexpected,
        $executeRaw: unexpected,
        $executeRawUnsafe: unexpected,
      })
      .overrideProvider(ScopeLookupService)
      .useValue({ getAllowedScopeNames: unexpected })
      .overrideProvider(ClientSecretService)
      .useValue({ issueSecret: unexpected })
      .compile();
    app = module.createNestApplication<INestApplication<Server>>({
      logger: false,
    });
    await app.init();
  });
  beforeEach(() => {
    vi.resetAllMocks();
    clients = structuredClone(rows);
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
  ) {
    const response = await request(app.getHttpServer())
      .get('/oauth/authorize')
      .query(query)
      .expect(status);
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
      'private driver cause',
    ])
      expect(response.text.includes(value)).toBe(false);
    return response;
  }
  it('uses a non-global OAuth module with only ClientRegistryModule, one controller/service and no session/Redis dependencies', () => {
    expect(Reflect.getMetadata('imports', OAuthModule) as unknown).toEqual([
      ClientRegistryModule,
    ]);
    expect(Reflect.getMetadata('controllers', OAuthModule) as unknown).toEqual([
      OAuthController,
    ]);
    expect(Reflect.getMetadata('providers', OAuthModule) as unknown).toEqual([
      AuthorizationRequestService,
    ]);
    expect(
      Reflect.getMetadata('__module:global__', OAuthModule) as unknown,
    ).not.toBe(true);
    expect(Object.keys(app.get(AuthorizationRequestService))).toEqual([
      'clients',
    ]);
  });
  it('returns interim empty 204 for Student SPA S256, never a code/token/redirect/cookie', async () => {
    await call(valid, 204);
    expect(findUnique).toHaveBeenCalledOnce();
    expect(findUnique.mock.calls[0][0].where).toEqual({
      clientId: 'student-spa',
    });
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
  it('requires nonce only for exact openid and does not consult allowed scopes', async () => {
    await call({ ...valid, nonce: undefined }, 400);
    await call(
      { ...valid, nonce: undefined, scope: 'custom.scope OpenID' },
      204,
    );
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
  it('ignores unrelated query values, incoming cookies and Bearer headers without authenticating/touching sessions', async () => {
    const response = await request(app.getHttpServer())
      .get('/oauth/authorize')
      .query({
        ...valid,
        userId: 'not-an-authority',
        unknown_extension: 'opaque',
      })
      .set('Cookie', 'iam.sid=not-a-session')
      .set('Authorization', 'Bearer not-a-token')
      .expect(204);
    expect(response.text).toBe('');
    expect(response.headers.location).toBeUndefined();
    expect(response.headers['set-cookie']).toBeUndefined();
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
