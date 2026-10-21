import { Logger, type INestApplication } from '@nestjs/common';
import { APP_FILTER } from '@nestjs/core';
import { ConfigService } from '@nestjs/config';
import { Test } from '@nestjs/testing';
import type { Server } from 'node:http';
import * as crypto from 'node:crypto';
import * as argon2 from 'argon2';
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
import { OAuthModule } from './oauth.module.js';
import { AuthorizationService } from './authorization.service.js';
import { AuthorizationRequestService } from './authorization-request.service.js';
import { PrismaService } from '../prisma/prisma.service.js';
import { RedisService } from '../redis/redis.service.js';
import { ClientLookupService } from '../client-registry/client-lookup.service.js';
import { ScopeLookupService } from '../client-registry/scope-lookup.service.js';
import { ClientSecretService } from '../client-registry/client-secret.service.js';
import { IdpSessionStateService } from '../session/idp-session-state.service.js';
import { RegisterValidationFilter } from '../auth/register-validation.filter.js';

vi.mock('argon2', async (original) => {
  const actual = await original<typeof import('argon2')>();
  return { ...actual, verify: vi.fn(actual.verify) };
});
vi.mock('node:crypto', async (original) => {
  const actual = await original<typeof import('node:crypto')>();
  return { ...actual, createHash: vi.fn(actual.createHash) };
});
const realArgon = await vi.importActual<typeof import('argon2')>('argon2');
const secret = ' opaque-secret e\u0301 +%2F:💠 ';
const verifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
const challenge = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';
const invalidClient = {
  error: 'invalid_client',
  error_description: 'Client authentication failed.',
};
const invalidGrant = {
  error: 'invalid_grant',
  error_description: 'Invalid authorization grant.',
};
const serverError = {
  error: 'server_error',
  error_description: 'Token request failed.',
};
const basic = (id: string, value = secret): string =>
  'bAsIc ' +
  Buffer.from(
    `${encodeURIComponent(id)}:${encodeURIComponent(value)}`,
  ).toString('base64');

describe('POST /oauth/token M6.4 real client authentication → GETDEL → PKCE', () => {
  let app: INestApplication<Server>;
  let hash: string;
  let logs: MockInstance[];
  const hashCode = vi.mocked(crypto.createHash);
  const unexpected = vi.fn(() => {
    throw new Error('Unexpected issuance/write/session/lookup operation.');
  });
  const entries = new Map<string, string>();
  const clients = new Map<
    string,
    {
      id: string;
      clientId: string;
      clientType: 'PUBLIC' | 'CONFIDENTIAL';
      enabled: boolean;
      clientSecretHash: string | null;
    }
  >();
  const findUnique = vi.fn();
  const getAndDelete = vi.fn<RedisService['getAndDelete']>();
  const keyFor = (code: string): string =>
    'oauth:code:' + crypto.createHash('sha256').update(code).digest('hex');
  const fixture = (
    clientId = 'banking-web',
    codeChallenge: string | null = challenge,
  ) => {
    const body = {
      grant_type: 'authorization_code',
      client_id: clientId,
      code: 'owned-code-canary',
      redirect_uri: 'http://localhost/callback',
      code_verifier: verifier,
    };
    const key = keyFor(body.code);
    entries.set(
      key,
      JSON.stringify({
        clientId,
        userId: 'c0e21e3f-d3ee-425c-a99f-c2e7a7cab53f',
        redirectUri: body.redirect_uri,
        grantedScopes: ['openid'],
        codeChallenge,
        nonce: null,
        authTime: Date.now() - 1000,
        expiresAt: Date.now() + 120000,
      }),
    );
    return { body, key };
  };
  const post = async (
    body: Record<string, string>,
    header?: string,
    status = 204,
    expected?: object,
  ) => {
    const pending = request(app.getHttpServer())
      .post('/oauth/token')
      .set('Content-Type', 'application/x-www-form-urlencoded');
    if (header !== undefined) pending.set('Authorization', header);
    const response = await pending
      .send(new URLSearchParams(body).toString())
      .expect(status);
    expect(response.headers['cache-control']).toBe('no-store');
    expect(response.headers.location).toBeUndefined();
    expect(response.headers['set-cookie']).toBeUndefined();
    expect(response.headers['www-authenticate']).toBe(
      status === 401 ? 'Basic realm="oauth/token"' : undefined,
    );
    if (status === 204) expect(response.text).toBe('');
    else expect(response.body).toEqual(expected);
    for (const value of [secret, hash, body.code, verifier, challenge].filter(
      Boolean,
    ))
      expect(response.text.includes(value)).toBe(false);
    return response;
  };
  beforeAll(async () => {
    hash = await realArgon.hash(secret, { type: realArgon.argon2id });
    const module = await Test.createTestingModule({
      imports: [OAuthModule],
      providers: [{ provide: APP_FILTER, useClass: RegisterValidationFilter }],
    })
      .overrideProvider(PrismaService)
      .useValue({
        client: { findUnique, update: unexpected, updateMany: unexpected },
        session: { findFirst: unexpected },
        $transaction: unexpected,
        $queryRaw: unexpected,
      })
      .overrideProvider(RedisService)
      .useValue({
        getAndDelete,
        get: unexpected,
        delete: unexpected,
        ttl: unexpected,
        setWithTtl: unexpected,
        setIfAbsentWithTtl: unexpected,
      })
      .overrideProvider(ClientLookupService)
      .useValue({ requireEnabledClient: unexpected })
      .overrideProvider(ScopeLookupService)
      .useValue({ getAllowedScopeNames: unexpected })
      .overrideProvider(ClientSecretService)
      .useValue({ issueSecret: unexpected })
      .overrideProvider(IdpSessionStateService)
      .useValue({ touch: unexpected })
      .overrideProvider(AuthorizationService)
      .useValue({ authorize: unexpected })
      .overrideProvider(AuthorizationRequestService)
      .useValue({ validate: unexpected })
      .useMocker((token) =>
        token === ConfigService
          ? new ConfigService({ COOKIE_NAME: 'iam.sid', COOKIE_SECURE: false })
          : undefined,
      )
      .compile();
    app = module.createNestApplication<INestApplication<Server>>({
      logger: false,
    });
    await app.listen(0, '127.0.0.1');
  });
  beforeEach(() => {
    vi.clearAllMocks();
    entries.clear();
    clients.clear();
    for (const clientId of [
      'student-spa',
      'banking-web',
      'admin-portal',
      ' opaque e\u0301 +%2F ',
    ])
      clients.set(clientId, {
        id: 'fixture-' + clientId,
        clientId,
        clientType: clientId === 'student-spa' ? 'PUBLIC' : 'CONFIDENTIAL',
        enabled: true,
        clientSecretHash: clientId === 'student-spa' ? null : hash,
      });
    findUnique.mockImplementation(
      ({ where }: { where: { clientId: string } }) =>
        Promise.resolve(clients.get(where.clientId) ?? null),
    );
    vi.mocked(argon2.verify).mockImplementation(realArgon.verify);
    getAndDelete.mockImplementation((key) => {
      const value = entries.get(key) ?? null;
      entries.delete(key);
      return Promise.resolve(value);
    });
    logs = [console, Logger, Logger.prototype].flatMap((target) =>
      ['log', 'error', 'warn', 'debug', 'verbose', 'fatal'].flatMap((name) =>
        name in target
          ? [
              vi
                .spyOn(target, name as 'log')
                .mockImplementation(() => undefined),
            ]
          : [],
      ),
    );
  });
  afterEach(() => {
    expect(unexpected).not.toHaveBeenCalled();
    for (const log of logs) expect(log).not.toHaveBeenCalled();
    vi.restoreAllMocks();
  });
  afterAll(async () => {
    await app.close();
  });

  it('allows Student SPA without Authorization or Argon2, then consumes and verifies PKCE', async () => {
    const { body, key } = fixture('student-spa');
    await post(body);
    expect(argon2.verify).not.toHaveBeenCalled();
    expect(entries.has(key)).toBe(false);
  });
  it.each(['banking-web', 'admin-portal', ' opaque e\u0301 +%2F '])(
    'authenticates %j with real Argon2id before hashing/GETDEL/PKCE',
    async (id) => {
      const { body, key } = fixture(id);
      hashCode.mockClear();
      await post(body, basic(id));
      expect(argon2.verify).toHaveBeenCalledExactlyOnceWith(hash, secret);
      const order = [
        findUnique.mock.invocationCallOrder[0],
        vi.mocked(argon2.verify).mock.invocationCallOrder[0],
        hashCode.mock.invocationCallOrder[0],
        getAndDelete.mock.invocationCallOrder[0],
        hashCode.mock.invocationCallOrder[1],
      ];
      expect(order).toEqual([...order].sort((a, b) => a - b));
      expect(entries.has(key)).toBe(false);
      await post(body, basic(id), 400, invalidGrant);
    },
  );
  it.each([
    'wrong',
    'missing',
    'malformed',
    'unsupported',
    'mismatch',
    'case',
    'normalized',
    'unknown',
    'disabled',
    'public-basic',
    'absent-hash',
  ])(
    'rejects %s auth before code hashing/GETDEL; valid retry still succeeds',
    async (kind) => {
      const id = kind === 'public-basic' ? 'student-spa' : 'banking-web';
      const { body, key } = fixture(id);
      const original = entries.get(key);
      let header: string | undefined = basic(id);
      const input = { ...body };
      if (kind === 'wrong') header = basic(id, 'wrong-secret-canary');
      if (kind === 'missing') header = undefined;
      if (kind === 'malformed') header = 'Basic !!!!';
      if (kind === 'unsupported') header = 'Bearer secret-canary';
      if (kind === 'mismatch') header = basic('admin-portal');
      if (kind === 'case') input.client_id = 'Banking-Web';
      if (kind === 'normalized') input.client_id = ' banking-web ';
      if (kind === 'unknown') input.client_id = 'unknown-client';
      if (kind === 'disabled') clients.get(id)!.enabled = false;
      if (kind === 'absent-hash') clients.get(id)!.clientSecretHash = null;
      hashCode.mockClear();
      await post(input, header, 401, invalidClient);
      expect(hashCode).not.toHaveBeenCalled();
      expect(getAndDelete).not.toHaveBeenCalled();
      expect(entries.get(key)).toBe(original);
      if (kind !== 'wrong') expect(argon2.verify).not.toHaveBeenCalled();
      clients.get(id)!.enabled = true;
      if (id !== 'student-spa') clients.get(id)!.clientSecretHash = hash;
      await post(body, id === 'student-spa' ? undefined : basic(id));
      expect(entries.has(key)).toBe(false);
    },
  );
  it.each(['database', 'argon2', 'corrupt-hash'])(
    'sanitizes %s failure, does not log/cause a code burn',
    async (kind) => {
      const { body, key } = fixture();
      const original = entries.get(key);
      const native = new Error(
        `SQL driver private ${secret} ${hash} ${body.code}`,
      );
      if (kind === 'database') findUnique.mockRejectedValueOnce(native);
      if (kind === 'argon2')
        vi.mocked(argon2.verify).mockRejectedValueOnce(native);
      if (kind === 'corrupt-hash')
        clients.get(body.client_id)!.clientSecretHash =
          '$argon2id$corrupt-private-hash';
      hashCode.mockClear();
      await post(body, basic(body.client_id), 500, serverError);
      expect(hashCode).not.toHaveBeenCalled();
      expect(getAndDelete).not.toHaveBeenCalled();
      expect(entries.get(key)).toBe(original);
    },
  );
  it('rejects shape/unsupported grants before client lookup or Argon2', async () => {
    const { body } = fixture();
    await post({ ...body, code: '' }, basic(body.client_id), 400, {
      error: 'invalid_request',
      error_description: 'Invalid token request.',
    });
    await post(
      { ...body, grant_type: 'refresh_token' },
      basic(body.client_id),
      400,
      {
        error: 'unsupported_grant_type',
        error_description: 'Unsupported grant type.',
      },
    );
    expect(findUnique).not.toHaveBeenCalled();
    expect(argon2.verify).not.toHaveBeenCalled();
    expect(getAndDelete).not.toHaveBeenCalled();
  });
  it('still burns code on failed PKCE after successful confidential auth', async () => {
    const { body, key } = fixture();
    await post(
      { ...body, code_verifier: '' },
      basic(body.client_id),
      400,
      invalidGrant,
    );
    expect(entries.has(key)).toBe(false);
    await post(body, basic(body.client_id), 400, invalidGrant);
  });
  it('allows confidential null-challenge state after valid Basic, not before authentication', async () => {
    const { body, key } = fixture('banking-web', null);
    await post(body, undefined, 401, invalidClient);
    expect(entries.has(key)).toBe(true);
    await post(
      { ...body, code_verifier: 'not-required' },
      basic(body.client_id),
    );
    expect(entries.has(key)).toBe(false);
  });
});
