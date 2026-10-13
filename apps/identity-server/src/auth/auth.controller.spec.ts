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
