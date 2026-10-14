import type { INestApplication } from '@nestjs/common';
import type { Server } from 'node:http';
import { Test } from '@nestjs/testing';
import request from 'supertest';
import {
  afterAll,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
  vi,
} from 'vitest';
import { PrismaService } from '../prisma/prisma.service.js';
import { RedisService } from '../redis/redis.service.js';
import { ConfigService } from '@nestjs/config';
import { AuthModule } from './auth.module.js';
import {
  RegistrationService,
  type SafeRegisteredUser,
} from './registration.service.js';
import {
  PasswordResetConsumeService,
  type PasswordResetConsumeResult,
} from './password-reset-consume.service.js';

describe('POST /auth/register (isolated HTTP)', () => {
  const user: SafeRegisteredUser = {
    id: 'test-user-id',
    email: 'MixedCase@example.invalid',
    username: 'MixedCase',
    status: 'ACTIVE',
    createdAt: new Date('2026-01-01T00:00:00Z'),
  };
  const register = vi.fn<() => Promise<SafeRegisteredUser>>();
  let app: INestApplication<Server>;

  beforeAll(async () => {
    const module = await Test.createTestingModule({ imports: [AuthModule] })
      .overrideProvider(RedisService)
      .useValue({})
      .overrideProvider(PrismaService)
      .useValue({})
      .overrideProvider(RegistrationService)
      .useValue({ register })
      .useMocker((token) =>
        token === ConfigService
          ? new ConfigService({
              LOGIN_MAX_FAILURES: 5,
              LOGIN_LOCK_SECONDS: 900,
              PASSWORD_RESET_TTL_SECONDS: 900,
              SESSION_IDLE_TTL_SECONDS: 1800,
              SESSION_ABSOLUTE_TTL_SECONDS: 28800,
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
    vi.clearAllMocks();
    register.mockResolvedValue(user);
  });
  afterAll(async () => {
    await app.close();
  });

  it('returns 201 without session/tokens; trims only email/username and preserves case/password', async () => {
    const response = await request(app.getHttpServer())
      .post('/auth/register')
      .send({
        email: ' MixedCase@example.invalid ',
        username: ' MixedCase ',
        password: ' opaque e\u0301 input ',
      })
      .expect(201);
    expect(register).toHaveBeenCalledExactlyOnceWith({
      email: user.email,
      username: user.username,
      password: ' opaque e\u0301 input ',
    });
    expect(Object.keys(response.body as object).sort()).toEqual([
      'createdAt',
      'email',
      'id',
      'status',
      'username',
    ]);
    expect(response.headers['set-cookie']).toBeUndefined();
  });

  it('does not invent length/complexity policy or trim a nonempty whitespace password', async () => {
    await request(app.getHttpServer())
      .post('/auth/register')
      .send({ email: user.email, username: user.username, password: ' ' })
      .expect(201);
    expect(register).toHaveBeenCalledWith({
      email: user.email,
      username: user.username,
      password: ' ',
    });
  });

  it.each([
    '{"password":"request-secret-canary",',
    'request-secret-canary',
    '{"password":request-secret-canary}',
  ])(
    'rejects malformed JSON case %# without echoing sensitive body fragments',
    async (body) => {
      const response = await request(app.getHttpServer())
        .post('/auth/register')
        .set('Content-Type', 'application/json')
        .send(body)
        .expect(400);
      expect(
        JSON.stringify(response.body).includes('request-secret-canary'),
      ).toBe(false);
      expect(response.body as unknown).toEqual({
        statusCode: 400,
        error: 'Bad Request',
        message: 'Invalid registration request.',
      });
      expect(register).not.toHaveBeenCalled();
    },
  );

  it.each(['/AUTH/REGISTER', '/auth/register/', '/auth/register?test=1'])(
    'sanitizes parser errors for registration route variant %s',
    async (path) => {
      const response = await request(app.getHttpServer())
        .post(path)
        .set('Content-Type', 'application/json')
        .send('"request-secret-canary"')
        .expect(400);
      expect(response.body as unknown).toEqual({
        statusCode: 400,
        error: 'Bad Request',
        message: 'Invalid registration request.',
      });
      expect(register).not.toHaveBeenCalled();
    },
  );

  it('does not replace parser error conventions on unrelated routes', async () => {
    const response = await request(app.getHttpServer())
      .post('/not-registration')
      .set('Content-Type', 'application/json')
      .send('null')
      .expect(400);
    expect(response.body as unknown).not.toEqual({
      statusCode: 400,
      error: 'Bad Request',
      message: 'Invalid registration request.',
    });
    expect(register).not.toHaveBeenCalled();
  });

  it.each([
    { email: 'invalid-email', username: 'unit', password: 'test-only' },
    { email: user.email, username: '   ', password: 'test-only' },
    { email: user.email, username: 'unit', password: '' },
    { email: user.email, username: 'unit', password: 123 },
    {
      email: user.email,
      username: 'unit',
      password: 'request-secret-canary',
      extra: true,
    },
    { email: user.email, username: 'unit' },
    {},
    [],
    null,
    'not-an-object',
  ])(
    'rejects invalid/unknown body case %# safely without invoking registration',
    async (body) => {
      const response = await request(app.getHttpServer())
        .post('/auth/register')
        .set('Content-Type', 'application/json')
        .send(JSON.stringify(body))
        .expect(400);
      expect(response.body as unknown).toEqual({
        statusCode: 400,
        error: 'Bad Request',
        message: 'Invalid registration request.',
      });
      expect(register).not.toHaveBeenCalled();
    },
  );
});

describe('POST /auth/password-reset/consume (isolated HTTP)', () => {
  const input = {
    token: ' opaque test-only MixedCase e\u0301 token ',
    newPassword: ' opaque test-only \u00e9 password ',
  };
  const consume =
    vi.fn<
      (token: string, password: string) => Promise<PasswordResetConsumeResult>
    >();
  let app: INestApplication<Server>;

  beforeAll(async () => {
    const module = await Test.createTestingModule({ imports: [AuthModule] })
      .overrideProvider(RedisService)
      .useValue({})
      .overrideProvider(PrismaService)
      .useValue({})
      .overrideProvider(PasswordResetConsumeService)
      .useValue({ consume })
      .useMocker((token) =>
        token === ConfigService
          ? new ConfigService({
              LOGIN_MAX_FAILURES: 5,
              LOGIN_LOCK_SECONDS: 900,
              PASSWORD_RESET_TTL_SECONDS: 900,
              SESSION_IDLE_TTL_SECONDS: 1800,
              SESSION_ABSOLUTE_TTL_SECONDS: 28800,
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
    vi.clearAllMocks();
    consume.mockResolvedValue({ ok: true });
  });
  afterAll(async () => {
    await app.close();
  });

  it('returns 204 without body/cookie and passes opaque inputs unchanged', async () => {
    const response = await request(app.getHttpServer())
      .post('/auth/password-reset/consume')
      .send(input)
      .expect(204);
    expect(response.text).toBe('');
    expect(response.headers['set-cookie']).toBeUndefined();
    expect(consume).toHaveBeenCalledExactlyOnceWith(
      input.token,
      input.newPassword,
    );
  });

  it('retains nonempty whitespace inputs without adding password policy', async () => {
    await request(app.getHttpServer())
      .post('/auth/password-reset/consume')
      .send({ token: ' ', newPassword: ' ' })
      .expect(204);
    expect(consume).toHaveBeenCalledExactlyOnceWith(' ', ' ');
  });

  it.each(['unknown', 'expired', 'replayed', 'stale Credential'])(
    'returns the same safe generic 400 for %s service result',
    async () => {
      consume.mockResolvedValueOnce({
        ok: false,
        reason: 'INVALID_OR_EXPIRED_TOKEN',
      });
      const response = await request(app.getHttpServer())
        .post('/auth/password-reset/consume')
        .send(input)
        .expect(400);
      expect(response.body as unknown).toEqual({
        statusCode: 400,
        error: 'Bad Request',
        message: 'Invalid or expired password reset token.',
      });
      expect(response.headers['set-cookie']).toBeUndefined();
    },
  );

  it.each([
    {},
    { token: input.token },
    { newPassword: input.newPassword },
    { token: '', newPassword: input.newPassword },
    { token: input.token, newPassword: '' },
    { token: 123, newPassword: input.newPassword },
    { token: input.token, newPassword: 123 },
    { token: null, newPassword: input.newPassword },
    { token: input.token, newPassword: null },
    { ...input, userId: 'untrusted' },
    null,
    [],
    'not-an-object',
  ])(
    'rejects invalid/non-strict input case %# without echoing secrets or calling service',
    async (body) => {
      const response = await request(app.getHttpServer())
        .post('/auth/password-reset/consume')
        .set('Content-Type', 'application/json')
        .send(JSON.stringify(body))
        .expect(400);
      expect(response.body as unknown).toEqual({
        statusCode: 400,
        error: 'Bad Request',
        message: 'Invalid password reset consume request.',
      });
      expect(consume).not.toHaveBeenCalled();
    },
  );

  it.each([
    '/auth/password-reset/consume',
    '/AUTH/PASSWORD-RESET/CONSUME',
    '/auth/password-reset/consume/',
    '/auth/password-reset/consume?test=1',
  ])('sanitizes malformed JSON on consume route variant %s', async (path) => {
    const response = await request(app.getHttpServer())
      .post(path)
      .set('Content-Type', 'application/json')
      .send(
        '{"token":"token-secret-canary","newPassword":"password-secret-canary",',
      )
      .expect(400);
    expect(response.body as unknown).toEqual({
      statusCode: 400,
      error: 'Bad Request',
      message: 'Invalid password reset consume request.',
    });
    expect(consume).not.toHaveBeenCalled();
  });

  it('preserves the generic token failure on uppercase/trailing-slash/query variants', async () => {
    consume.mockResolvedValue({
      ok: false,
      reason: 'INVALID_OR_EXPIRED_TOKEN',
    });
    for (const path of [
      '/AUTH/PASSWORD-RESET/CONSUME',
      '/auth/password-reset/consume/',
      '/auth/password-reset/consume?test=1',
    ]) {
      const response = await request(app.getHttpServer())
        .post(path)
        .send(input)
        .expect(400);
      expect(response.body as unknown).toEqual({
        statusCode: 400,
        error: 'Bad Request',
        message: 'Invalid or expired password reset token.',
      });
    }
  });

  it('fails closed with a sanitized 500 for operational errors instead of echoing provider details', async () => {
    consume.mockRejectedValueOnce(
      new Error('private ' + input.token + input.newPassword),
    );
    const response = await request(app.getHttpServer())
      .post('/auth/password-reset/consume')
      .send(input)
      .expect(500);
    expect(response.body as unknown).toEqual({
      statusCode: 500,
      error: 'Internal Server Error',
      message: 'Password reset failed.',
    });
    expect(response.headers['set-cookie']).toBeUndefined();
  });
});
