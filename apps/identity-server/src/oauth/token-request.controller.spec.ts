import { Logger, type INestApplication } from '@nestjs/common';
import { APP_FILTER } from '@nestjs/core';
import { Test } from '@nestjs/testing';
import { ConfigService } from '@nestjs/config';
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
import { OAuthModule } from './oauth.module.js';
import { TokenRequestService } from './token-request.service.js';
import { AuthorizationCodeService } from './authorization-code.service.js';
import { AuthorizationService } from './authorization.service.js';
import { AuthorizationRequestService } from './authorization-request.service.js';
import { PrismaService } from '../prisma/prisma.service.js';
import { RedisService } from '../redis/redis.service.js';
import { ClientLookupService } from '../client-registry/client-lookup.service.js';
import { ScopeLookupService } from '../client-registry/scope-lookup.service.js';
import { ClientSecretService } from '../client-registry/client-secret.service.js';
import { ClientAuthenticationService } from '../client-registry/client-authentication.service.js';
import { IdpSessionStateService } from '../session/idp-session-state.service.js';
import { RegisterValidationFilter } from '../auth/register-validation.filter.js';
import * as crypto from 'node:crypto';

vi.mock('node:crypto', async (original) => {
  const actual = await original<typeof import('node:crypto')>();
  return {
    ...actual,
    createHash: vi.fn(actual.createHash),
    randomBytes: vi.fn(() => {
      throw new Error('Unexpected issuance.');
    }),
  };
});
const realCrypto =
  await vi.importActual<typeof import('node:crypto')>('node:crypto');

const valid = {
  grant_type: 'authorization_code',
  client_id: 'unknown-client',
  code: 'synthetic-code-canary',
  redirect_uri: 'unregistered opaque redirect',
};
const form = 'application/x-www-form-urlencoded';
const invalid = {
  error: 'invalid_request',
  error_description: 'Invalid token request.',
};
const unsupported = {
  error: 'unsupported_grant_type',
  error_description: 'Unsupported grant type.',
};
const invalidGrant = {
  error: 'invalid_grant',
  error_description: 'Invalid authorization grant.',
};
const serverError = {
  error: 'server_error',
  error_description: 'Token request failed.',
};
const verifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
const challenge = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';

describe('POST /oauth/token M6.1 validation + M6.2 consumption + M6.3 PKCE (real parser + OAuthModule)', () => {
  let app: INestApplication<Server>;
  let logs: MockInstance[];
  const unexpected = vi.fn(() => {
    throw new Error('Unexpected storage/authentication operation.');
  });
  const entries = new Map<string, string>();
  // Isolate the existing shape/GETDEL/PKCE regression suite; M6.4 has real-auth HTTP tests.
  const authenticateTokenClient = vi.fn((clientId: string) =>
    Promise.resolve({
      ok: true as const,
      client: { id: 'fixture-client', clientId, clientType: 'PUBLIC' as const },
    }),
  );
  const getAndDelete = vi.fn<RedisService['getAndDelete']>();
  let expectedHashes = 0;
  let expectedConsumes = 0;
  const keyFor = (code: string): string =>
    'oauth:code:' + realCrypto.createHash('sha256').update(code).digest('hex');
  function put(input = valid, overrides: Record<string, unknown> = {}): void {
    entries.set(
      keyFor(input.code),
      JSON.stringify({
        clientId: input.client_id,
        userId: 'c0e21e3f-d3ee-425c-a99f-c2e7a7cab53f',
        redirectUri: input.redirect_uri,
        grantedScopes: ['openid', 'profile'],
        codeChallenge: null,
        nonce: 'opaque-nonce',
        authTime: Date.now() - 1000,
        expiresAt: Date.now() + 120000,
        ...overrides,
      }),
    );
  }
  beforeAll(async () => {
    const module = await Test.createTestingModule({
      imports: [OAuthModule],
      providers: [{ provide: APP_FILTER, useClass: RegisterValidationFilter }],
    })
      .overrideProvider(PrismaService)
      .useValue({
        client: { findUnique: unexpected },
        session: { findFirst: unexpected },
        $transaction: unexpected,
        $queryRaw: unexpected,
      })
      .overrideProvider(RedisService)
      .useValue({
        get: unexpected,
        getAndDelete,
        delete: unexpected,
        ttl: unexpected,
        setWithTtl: unexpected,
        setIfAbsentWithTtl: unexpected,
        sessionState: unexpected,
      })
      .overrideProvider(ClientLookupService)
      .useValue({ requireEnabledClient: unexpected })
      .overrideProvider(ScopeLookupService)
      .useValue({ getAllowedScopeNames: unexpected })
      .overrideProvider(ClientSecretService)
      .useValue({ issueSecret: unexpected })
      .overrideProvider(ClientAuthenticationService)
      .useValue({ authenticateTokenClient })
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
    // Listen once so concurrent Supertest requests do not each auto-bind the same server.
    await app.listen(0, '127.0.0.1');
  });
  beforeEach(() => {
    vi.clearAllMocks();
    entries.clear();
    expectedHashes = 0;
    expectedConsumes = 0;
    vi.mocked(crypto.createHash).mockImplementation(realCrypto.createHash);
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
    expect(crypto.createHash).toHaveBeenCalledTimes(expectedHashes);
    expect(getAndDelete).toHaveBeenCalledTimes(expectedConsumes);
    expect(
      vi
        .mocked(crypto.createHash)
        .mock.calls.every(([algorithm]) => algorithm === 'sha256'),
    ).toBe(true);
    expect(crypto.randomBytes).not.toHaveBeenCalled();
    for (const log of logs) expect(log).not.toHaveBeenCalled();
    vi.restoreAllMocks();
  });
  afterAll(async () => {
    await app.close();
  });

  async function check(
    body: string,
    status = 400,
    expected = invalid,
    type = form,
    path = '/oauth/token',
  ): Promise<void> {
    const authCalls = authenticateTokenClient.mock.calls.length;
    if (status === 204 || expected === invalidGrant || status === 500) {
      expectedHashes++;
      expectedConsumes++;
    }
    const response = await request(app.getHttpServer())
      .post(path)
      .set('Content-Type', type)
      .send(body)
      .expect(status);
    expect(response.headers['cache-control']).toBe('no-store');
    expect(response.headers.location).toBeUndefined();
    expect(response.headers['set-cookie']).toBeUndefined();
    if (status === 204) expect(response.text).toBe('');
    else expect(response.body).toEqual(expected);
    if (status === 400 && (expected === invalid || expected === unsupported))
      expect(authenticateTokenClient).toHaveBeenCalledTimes(authCalls);
  }

  it('unknown fake code reaches one GETDEL then invalid_grant; verifier remains optional on matching state', async () => {
    await check(new URLSearchParams(valid).toString(), 400, invalidGrant);
    put();
    await check(new URLSearchParams(valid).toString(), 204);
    put();
    await check(
      new URLSearchParams({
        ...valid,
        code_verifier: ' short +%2F e\u0301 ',
      }).toString(),
      204,
    );
  });

  it('passes only exact framework-decoded body values, without a second decode or normalization', async () => {
    const input = {
      ...valid,
      client_id: ' UNKNOWN e\u0301 ',
      code: ' %2F+ /💠 ',
      redirect_uri: ' HTTPS://EXAMPLE.invalid/%2f?b=%2520&a=1#x ',
      code_verifier: ' +%2F e\u0301\t ',
    };
    const validate = vi.spyOn(app.get(TokenRequestService), 'validate');
    put(input);
    const consume = vi.spyOn(app.get(AuthorizationCodeService), 'consume');
    await check(new URLSearchParams(input).toString(), 204);
    expect(validate).toHaveBeenCalledExactlyOnceWith(input, form);
    expect(validate.mock.results[0].value).toEqual({
      ok: true,
      request: input,
    });
    const call = consume.mock.calls[0][0];
    expect(
      JSON.stringify(call) ===
        JSON.stringify({
          code: input.code,
          clientId: input.client_id,
          redirectUri: input.redirect_uri,
        }),
    ).toBe(true);
    expect(Object.keys(call).sort()).toEqual([
      'clientId',
      'code',
      'redirectUri',
    ]);
  });

  it.each(Object.keys(valid))(
    'rejects missing/empty/duplicate/array/object %s',
    async (field) => {
      const missing = new URLSearchParams(valid);
      missing.delete(field);
      await check(missing.toString());
      const empty = new URLSearchParams(valid);
      empty.set(field, '');
      await check(empty.toString());
      await check(`${new URLSearchParams(valid)}&${field}=duplicate-canary`);
      await check(`${missing}&${field}[]=array-canary`);
      await check(`${missing}&${field}[nested]=object-canary`);
    },
  );

  it.each([
    'code_verifier=a&code_verifier=b',
    'code_verifier[]=a',
    'code_verifier[nested]=a',
  ])('rejects ambiguous/structured optional verifier %j', async (suffix) => {
    await check(`${new URLSearchParams(valid)}&${suffix}`);
  });

  it.each([verifier, 'Ab0-._~'.repeat(19).slice(0, 128)])(
    'accepts exact 43/128-character S256 verifier only after consume (%#)',
    async (input) => {
      put(valid, {
        codeChallenge: realCrypto
          .createHash('sha256')
          .update(input, 'ascii')
          .digest('base64url'),
      });
      expectedHashes++;
      await check(
        new URLSearchParams({ ...valid, code_verifier: input }).toString(),
        204,
      );
      expect(entries.size).toBe(0);
      const hashes = vi.mocked(crypto.createHash).mock;
      expect(hashes.invocationCallOrder[0]).toBeLessThan(
        getAndDelete.mock.invocationCallOrder[0],
      );
      expect(getAndDelete.mock.invocationCallOrder[0]).toBeLessThan(
        hashes.invocationCallOrder[1],
      );
      expect(getAndDelete).toHaveBeenCalledOnce();
    },
  );

  it.each([
    undefined,
    '',
    'A'.repeat(42),
    'A'.repeat(129),
    'A'.repeat(43),
    'A'.repeat(42) + '+',
    'A'.repeat(42) + '/',
    'A'.repeat(42) + '=',
    'A'.repeat(42) + 'é',
    ' ' + verifier,
    verifier + '\n',
    '%64' + verifier.slice(1),
  ])(
    'PKCE missing/empty/malformed/wrong verifier returns identical invalid_grant and burns code (%#)',
    async (input) => {
      put(valid, { codeChallenge: challenge });
      if (
        input !== undefined &&
        input.length >= 43 &&
        input.length <= 128 &&
        !/[^A-Za-z0-9._~-]/.test(input)
      )
        expectedHashes++;
      const body = {
        ...valid,
        ...(input === undefined ? {} : { code_verifier: input }),
      };
      await check(new URLSearchParams(body).toString(), 400, invalidGrant);
      expect(entries.size).toBe(0);
      // A correct verifier cannot rescue an already-consumed grant.
      await check(
        new URLSearchParams({ ...valid, code_verifier: verifier }).toString(),
        400,
        invalidGrant,
      );
      expect(getAndDelete).toHaveBeenCalledTimes(2);
    },
  );

  it.each([undefined, '', ' malformed e\u0301 %2F+ ', verifier])(
    'null challenge requires no PKCE regardless of optional scalar verifier (%#)',
    async (input) => {
      put();
      await check(
        new URLSearchParams({
          ...valid,
          ...(input === undefined ? {} : { code_verifier: input }),
        }).toString(),
        204,
      );
    },
  );

  it('does not verify/hash PKCE when M6.2 binding has failed', async () => {
    put(valid, { codeChallenge: challenge });
    await check(
      new URLSearchParams({
        ...valid,
        client_id: 'wrong-client',
        code_verifier: verifier,
      }).toString(),
      400,
      invalidGrant,
    );
    expect(entries.size).toBe(0);
  });

  it('sanitizes a PKCE crypto failure after GETDEL and still burns the code', async () => {
    put(valid, { codeChallenge: challenge });
    vi.mocked(crypto.createHash)
      .mockImplementationOnce(realCrypto.createHash)
      .mockImplementationOnce(() => {
        throw new Error('private verifier/challenge/code canary', {
          cause: new Error('private cause'),
        });
      });
    expectedHashes++;
    await check(
      new URLSearchParams({ ...valid, code_verifier: verifier }).toString(),
      500,
      serverError,
    );
    expect(entries.size).toBe(0);
    await check(
      new URLSearchParams({ ...valid, code_verifier: verifier }).toString(),
      400,
      invalidGrant,
    );
  });

  it.each([
    'Authorization_Code',
    'AUTHORIZATION_CODE',
    'authorization-code',
    ' authorization_code',
    'authorization_code ',
    'refresh_token',
  ])(
    'rejects well-shaped unsupported grant %j without normalization',
    async (grant_type) => {
      await check(
        new URLSearchParams({ ...valid, grant_type }).toString(),
        400,
        unsupported,
      );
    },
  );

  it.each(['client_secret', 'scope', 'extra'])(
    'rejects unknown %s rather than stripping it',
    async (field) => {
      await check(`${new URLSearchParams(valid)}&${field}=sensitive-canary`);
    },
  );

  it('does not use query, arbitrary headers or cookie as body field authority', async () => {
    const response = await request(app.getHttpServer())
      .post(`/oauth/token?${new URLSearchParams(valid)}`)
      .set('Content-Type', form)
      .set('Authorization', 'Basic synthetic-client-secret')
      .set('client_id', valid.client_id)
      .set('Cookie', 'iam.sid=synthetic-cookie')
      .send('')
      .expect(400);
    expect(response.body).toEqual(invalid);
    expect(response.headers['set-cookie']).toBeUndefined();
    put();
    expectedHashes++;
    expectedConsumes++;
    await request(app.getHttpServer())
      .post('/oauth/token')
      .set('Content-Type', form)
      .set('Cookie', 'iam.sid=synthetic-cookie')
      .send(new URLSearchParams(valid).toString())
      .expect(204);
  });

  it('does not introduce GET token requests', async () => {
    await request(app.getHttpServer())
      .get('/oauth/token')
      .query(valid)
      .expect(404);
  });

  it('burns code on success/replay and exact client/redirect mismatches', async () => {
    put();
    await check(new URLSearchParams(valid).toString(), 204);
    await check(new URLSearchParams(valid).toString(), 400, invalidGrant);
    for (const change of [
      { client_id: 'other-client' },
      { redirect_uri: valid.redirect_uri + ' ' },
    ]) {
      put();
      await check(
        new URLSearchParams({ ...valid, ...change }).toString(),
        400,
        invalidGrant,
      );
      expect(entries.size).toBe(0);
      await check(new URLSearchParams(valid).toString(), 400, invalidGrant);
    }
  });

  it('burns logically expired state even with a surviving Redis key', async () => {
    put(valid, { expiresAt: Date.now() - 1 });
    await check(new URLSearchParams(valid).toString(), 400, invalidGrant);
    expect(entries.size).toBe(0);
  });

  it.each(['malformed-json', 'invalid-schema', 'Redis'] as const)(
    'sanitizes %s failure with fixed server_error and no restoration',
    async (stage) => {
      put();
      if (stage === 'malformed-json')
        entries.set(keyFor(valid.code), 'private-state-canary{');
      if (stage === 'invalid-schema')
        put(valid, { userId: 'private-user-canary' });
      if (stage === 'Redis')
        getAndDelete.mockRejectedValueOnce(
          new Error('private-driver/code/hash/key-canary', {
            cause: new Error('private cause'),
          }),
        );
      await check(new URLSearchParams(valid).toString(), 500, serverError);
      if (stage !== 'Redis') {
        expect(entries.size).toBe(0);
        await check(new URLSearchParams(valid).toString(), 400, invalidGrant);
      }
    },
  );

  it('sanitizes hashing failure before any GETDEL', async () => {
    vi.mocked(crypto.createHash).mockImplementationOnce(() => {
      throw new Error('private-hash-code-canary');
    });
    expectedHashes++;
    const response = await request(app.getHttpServer())
      .post('/oauth/token')
      .set('Content-Type', form)
      .send(new URLSearchParams(valid).toString())
      .expect(500);
    expect(response.body).toEqual(serverError);
    expect(response.headers['cache-control']).toBe('no-store');
    expect(response.headers.location).toBeUndefined();
    expect(response.headers['set-cookie']).toBeUndefined();
  });

  it('concurrent identical requests yield exactly one 204 and all others invalid_grant', async () => {
    put();
    expectedHashes += 10;
    expectedConsumes += 10;
    const responses = await Promise.all(
      Array.from({ length: 10 }, () =>
        request(app.getHttpServer())
          .post('/oauth/token')
          .set('Content-Type', form)
          .send(new URLSearchParams(valid).toString()),
      ),
    );
    expect(
      responses.filter((response) => response.status === 204),
    ).toHaveLength(1);
    expect(
      responses.filter((response) => response.status === 400),
    ).toHaveLength(9);
    for (const response of responses) {
      if (response.status === 204) expect(response.text).toBe('');
      else expect(response.body).toEqual(invalidGrant);
      expect(response.headers['cache-control']).toBe('no-store');
      expect(response.headers.location).toBeUndefined();
      expect(response.headers['set-cookie']).toBeUndefined();
    }
    expect(entries.size).toBe(0);
  });

  it.each(['/oauth/token', '/OAUTH/TOKEN/', '/oauth/token?x=1'])(
    'sanitizes pre-controller malformed JSON on %s',
    async (path) => {
      await check(
        '{"secret":"body-fragment-canary",',
        400,
        invalid,
        'application/json',
        path,
      );
    },
  );

  it('rejects JSON/plain/multipart or absent media type, even for otherwise valid input', async () => {
    await check(JSON.stringify(valid), 400, invalid, 'application/json');
    await check(
      new URLSearchParams(valid).toString(),
      400,
      invalid,
      'text/plain',
    );
    await check(
      'body-fragment-canary',
      400,
      invalid,
      'multipart/form-data; boundary=none',
    );
    await request(app.getHttpServer())
      .post('/oauth/token')
      .expect(400, invalid);
  });

  it('sanitizes form parser limits, depth, charset, encoding and oversized bodies without logging', async () => {
    await check('x=canary&'.repeat(1002));
    await check('code' + '[x]'.repeat(35) + '=body-fragment-canary');
    await check(
      'code=body-fragment-canary',
      400,
      invalid,
      `${form}; charset=unsupported-canary`,
    );
    await check('code=' + 'body-fragment-canary'.repeat(7000));
    const response = await request(app.getHttpServer())
      .post('/oauth/token')
      .set('Content-Type', form)
      .set('Content-Encoding', 'unsupported-canary')
      .send('code=body-fragment-canary')
      .expect(400);
    expect(response.body).toEqual(invalid);
    expect(response.headers['cache-control']).toBe('no-store');
  });

  it.each(['gzip', 'deflate', 'br'])(
    'sanitizes malformed %s compression before the controller',
    async (encoding) => {
      const validate = vi.spyOn(app.get(TokenRequestService), 'validate');
      const response = await request(app.getHttpServer())
        .post('/oauth/token')
        .set('Content-Type', form)
        .set('Content-Encoding', encoding)
        .send('code=body-fragment-canary')
        .expect(400);
      expect(validate).not.toHaveBeenCalled();
      expect(response.body).toEqual(invalid);
      expect(response.headers['cache-control']).toBe('no-store');
      expect(response.headers.location).toBeUndefined();
      expect(response.headers['set-cookie']).toBeUndefined();
    },
  );

  it('sanitizes unexpected validation failures instead of logging or echoing causes', async () => {
    vi.spyOn(app.get(TokenRequestService), 'validate').mockImplementation(
      () => {
        throw new Error('private-body-canary');
      },
    );
    const response = await request(app.getHttpServer())
      .post('/oauth/token')
      .set('Content-Type', form)
      .send(new URLSearchParams(valid).toString())
      .expect(500);
    expect(response.body).toEqual({
      error: 'server_error',
      error_description: 'Token request failed.',
    });
    expect(response.headers['cache-control']).toBe('no-store');
    expect(response.headers.location).toBeUndefined();
    expect(response.headers['set-cookie']).toBeUndefined();
  });
});
