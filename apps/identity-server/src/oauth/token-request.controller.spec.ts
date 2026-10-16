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
import { IdpSessionStateService } from '../session/idp-session-state.service.js';
import { RegisterValidationFilter } from '../auth/register-validation.filter.js';
import * as crypto from 'node:crypto';

vi.mock('node:crypto', async (original) => ({
  ...(await original<typeof import('node:crypto')>()),
  createHash: vi.fn(() => {
    throw new Error('Unexpected hashing.');
  }),
  randomBytes: vi.fn(() => {
    throw new Error('Unexpected issuance.');
  }),
}));

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

describe('POST /oauth/token M6.1 (real Express parser + OAuthModule)', () => {
  let app: INestApplication<Server>;
  let logs: MockInstance[];
  const unexpected = vi.fn(() => {
    throw new Error('Unexpected storage/authentication operation.');
  });
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
        getAndDelete: unexpected,
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
      .overrideProvider(IdpSessionStateService)
      .useValue({ touch: unexpected })
      .overrideProvider(AuthorizationService)
      .useValue({ authorize: unexpected })
      .overrideProvider(AuthorizationRequestService)
      .useValue({ validate: unexpected })
      .overrideProvider(AuthorizationCodeService)
      .useValue({ issue: unexpected })
      .useMocker((token) =>
        token === ConfigService
          ? new ConfigService({ COOKIE_NAME: 'iam.sid', COOKIE_SECURE: false })
          : undefined,
      )
      .compile();
    app = module.createNestApplication<INestApplication<Server>>({
      logger: false,
    });
    await app.init();
  });
  beforeEach(() => {
    vi.clearAllMocks();
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
    expect(crypto.createHash).not.toHaveBeenCalled();
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
  }

  it('accepts a fake code and optional opaque verifier; issues no token/session/callback', async () => {
    await check(new URLSearchParams(valid).toString(), 204);
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
    await check(new URLSearchParams(input).toString(), 204);
    expect(validate).toHaveBeenCalledExactlyOnceWith(input, form);
    expect(validate.mock.results[0].value).toEqual({
      ok: true,
      request: input,
    });
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
    '',
    'code_verifier=a&code_verifier=b',
    'code_verifier[]=a',
    'code_verifier[nested]=a',
  ])('rejects ambiguous/empty optional verifier %j', async (suffix) => {
    await check(`${new URLSearchParams(valid)}&${suffix || 'code_verifier='}`);
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

  it('does not use query, headers, Authorization or cookie as a protocol authority', async () => {
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
    await request(app.getHttpServer())
      .post('/oauth/token')
      .set('Content-Type', form)
      .set('Authorization', 'not-even-basic')
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
