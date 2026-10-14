import { Logger, type INestApplication } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Test } from '@nestjs/testing';
import type { Server } from 'node:http';
import { randomUUID } from 'node:crypto';
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
} from 'vitest';
import { PrismaService } from '../prisma/prisma.service.js';
import { RedisService } from '../redis/redis.service.js';
import { IdpSessionStateService } from '../session/idp-session-state.service.js';
import { IdpSessionCookieService } from '../session/idp-session-cookie.service.js';
import type { Environment } from '../config/env.schema.js';
import { AuthModule } from './auth.module.js';
import { LoginAttemptService } from './login-attempt.service.js';

describe('POST /auth/login (isolated HTTP + real orchestration/cookie boundary)', () => {
  const user = {
    id: 'c0e21e3f-d3ee-425c-a99f-c2e7a7cab53f',
    email: 'unit@example.invalid',
    username: 'unit',
  };
  const input = {
    identifier: { type: 'email', value: ' MixedCase-e\u0301@example.invalid ' },
    password: ' opaque e\u0301 password ',
  };
  const attempt = vi.fn<LoginAttemptService['attempt']>();
  const create =
    vi.fn<
      (input: {
        data: Record<string, unknown>;
        select: { id: true };
      }) => Promise<{ id: string }>
    >();
  const createState = vi.fn<IdpSessionStateService['create']>();
  const transaction =
    vi.fn<
      (
        callback: (tx: {
          session: { create: typeof create };
        }) => Promise<string>,
      ) => Promise<string>
    >();
  let app: INestApplication<Server>;
  const config = new ConfigService<Environment, true>({
    LOGIN_MAX_FAILURES: 5,
    LOGIN_LOCK_SECONDS: 900,
    PASSWORD_RESET_TTL_SECONDS: 900,
    SESSION_IDLE_TTL_SECONDS: 1800,
    SESSION_ABSOLUTE_TTL_SECONDS: 28800,
    COOKIE_NAME: 'iam.sid',
    COOKIE_SECURE: false,
  });
  beforeAll(async () => {
    const module = await Test.createTestingModule({ imports: [AuthModule] })
      .overrideProvider(PrismaService)
      .useValue({ $transaction: transaction })
      .overrideProvider(RedisService)
      .useValue({})
      .overrideProvider(LoginAttemptService)
      .useValue({ attempt })
      .overrideProvider(IdpSessionStateService)
      .useValue({ create: createState })
      .useMocker((token) => (token === ConfigService ? config : undefined))
      .compile();
    app = module.createNestApplication<INestApplication<Server>>({
      logger: false,
    });
    await app.init();
  });
  beforeEach(() => {
    vi.resetAllMocks();
    attempt.mockResolvedValue({ ok: true, user });
    create.mockImplementation(() => Promise.resolve({ id: randomUUID() }));
    createState.mockResolvedValue(undefined);
    transaction.mockImplementation((callback) =>
      callback({ session: { create } }),
    );
  });
  afterEach(() => vi.restoreAllMocks());
  afterAll(async () => {
    await app.close();
  });

  it.each(['email', 'username'])(
    'returns 204 with one cookie, preserving exact %s/password input',
    async (type) => {
      const body = { ...input, identifier: { ...input.identifier, type } };
      const response = await request(app.getHttpServer())
        .post('/auth/login')
        .send(body)
        .expect(204);
      expect(attempt).toHaveBeenCalledExactlyOnceWith(
        body.identifier,
        body.password,
      );
      expect(response.text).toBe('');
      const id = createState.mock.calls[0]?.[0];
      if (!id) throw new Error('Missing test session identifier.');
      expect(response.headers['set-cookie']).toEqual([
        app.get(IdpSessionCookieService).serialize(id),
      ]);
      expect(transaction).toHaveBeenCalledOnce();
      for (const forbidden of [
        'access_token',
        'refresh_token',
        'id_token',
        'token_type',
        'expires_in',
        'scope',
        'authorization_code',
        'password',
        'credential',
        'userId',
        'roles',
        'permissions',
      ])
        expect(response.text.includes(forbidden)).toBe(false);
    },
  );
  it('uses the existing cookie serializer for a secure configuration', async () => {
    const secure = new IdpSessionCookieService(
      new ConfigService<Environment, true>({
        COOKIE_NAME: 'iam.sid',
        COOKIE_SECURE: true,
      }),
    );
    vi.spyOn(app.get(IdpSessionCookieService), 'serialize').mockImplementation(
      (id) => secure.serialize(id),
    );
    const response = await request(app.getHttpServer())
      .post('/auth/login')
      .send(input)
      .expect(204);
    expect(response.headers['set-cookie']).toEqual([
      secure.serialize(createState.mock.calls[0][0]),
    ]);
  });
  it('never reuses an inbound cookie or browser-selected ID for DB/Redis/cookie', async () => {
    const attackerId = randomUUID();
    const response = await request(app.getHttpServer())
      .post('/auth/login')
      .set('Cookie', 'iam.sid=' + attackerId)
      .send(input)
      .expect(204);
    const id = createState.mock.calls[0][0];
    expect(id).not.toBe(attackerId);
    expect(response.headers['set-cookie']).toEqual([
      app.get(IdpSessionCookieService).serialize(id),
    ]);
    const args: unknown = create.mock.calls[0];
    expect(JSON.stringify(args).includes(attackerId)).toBe(false);
    expect(create.mock.calls[0][0].data).not.toHaveProperty('id');
  });
  it('does not release the cookie before final transaction commit succeeds', async () => {
    let commit!: () => void;
    const committed = new Promise<void>((resolve) => {
      commit = resolve;
    });
    transaction.mockImplementation(async (callback) => {
      const id = await callback({ session: { create } });
      await committed;
      return id;
    });
    const serialize = vi.spyOn(app.get(IdpSessionCookieService), 'serialize');
    const pending = request(app.getHttpServer())
      .post('/auth/login')
      .send(input)
      .then((response) => response);
    try {
      await vi.waitFor(() => expect(createState).toHaveBeenCalledOnce());
      expect(serialize).not.toHaveBeenCalled();
    } finally {
      commit();
    }
    expect((await pending).status).toBe(204);
  });
  it.each([
    ['unknown user', 'INVALID_CREDENTIALS'],
    ['missing Credential', 'INVALID_CREDENTIALS'],
    ['wrong password', 'INVALID_CREDENTIALS'],
    ['disabled', 'DISABLED'],
    ['active lock', 'LOCKED'],
  ] as const)(
    'maps %s to the same generic 401 without session/cookie',
    async (_, reason) => {
      attempt.mockResolvedValue({ ok: false, reason });
      const response = await request(app.getHttpServer())
        .post('/auth/login')
        .send(input)
        .expect(401);
      expect(response.body as unknown).toEqual({
        statusCode: 401,
        error: 'Unauthorized',
        message: 'Invalid login credentials.',
      });
      expect(response.headers['set-cookie']).toBeUndefined();
      expect(transaction).not.toHaveBeenCalled();
      expect(createState).not.toHaveBeenCalled();
    },
  );
  it.each([
    'authentication',
    'PostgreSQL',
    'Redis',
    'commit',
    'cookie',
  ] as const)(
    'returns safe generic 500 and no cookie after %s failure',
    async (stage) => {
      const error = new Error(
        'private password/hash/DATABASE_URL/REDIS_URL/session key',
        { cause: new Error('private cause') },
      );
      if (stage === 'authentication') attempt.mockRejectedValue(error);
      if (stage === 'PostgreSQL') create.mockRejectedValue(error);
      if (stage === 'Redis') createState.mockRejectedValue(error);
      if (stage === 'commit')
        transaction.mockImplementation(async (callback) => {
          await callback({ session: { create } });
          throw error;
        });
      if (stage === 'cookie')
        vi.spyOn(
          app.get(IdpSessionCookieService),
          'serialize',
        ).mockImplementation(() => {
          throw error;
        });
      const response = await request(app.getHttpServer())
        .post('/auth/login')
        .send(input)
        .expect(500);
      expect(response.body as unknown).toEqual({
        statusCode: 500,
        error: 'Internal Server Error',
        message: 'Login failed.',
      });
      expect(response.headers['set-cookie']).toBeUndefined();
      if (stage === 'authentication' || stage === 'PostgreSQL')
        expect(createState).not.toHaveBeenCalled();
    },
  );
  it.each([
    {},
    { password: input.password },
    { identifier: { value: 'x' }, password: input.password },
    { identifier: { type: 'other', value: 'x' }, password: input.password },
    { identifier: { type: 'email' }, password: input.password },
    { identifier: { type: 'email', value: '' }, password: input.password },
    { identifier: input.identifier },
    { ...input, password: '' },
    { ...input, password: 123 },
    { ...input, identifier: null },
    { ...input, sessionId: 'attacker-selected' },
    { ...input, identifier: { ...input.identifier, extra: true } },
    null,
    [],
    'secret-canary',
  ])(
    'rejects strict-body violation case %# without authentication/persistence',
    async (body) => {
      const response = await request(app.getHttpServer())
        .post('/auth/login')
        .set('Content-Type', 'application/json')
        .send(JSON.stringify(body))
        .expect(400);
      expect(response.body as unknown).toEqual({
        statusCode: 400,
        error: 'Bad Request',
        message: 'Invalid login request.',
      });
      expect(response.headers['set-cookie']).toBeUndefined();
      expect(attempt).not.toHaveBeenCalled();
      expect(transaction).not.toHaveBeenCalled();
    },
  );
  it.each(['/auth/login', '/AUTH/LOGIN', '/auth/login/', '/auth/login?test=1'])(
    'sanitizes malformed JSON on login route variant %s',
    async (path) => {
      const response = await request(app.getHttpServer())
        .post(path)
        .set('Content-Type', 'application/json')
        .send('{"password":"password-secret-canary",')
        .expect(400);
      expect(response.body as unknown).toEqual({
        statusCode: 400,
        error: 'Bad Request',
        message: 'Invalid login request.',
      });
      expect(response.headers['set-cookie']).toBeUndefined();
      expect(attempt).not.toHaveBeenCalled();
    },
  );
  it('logs no credentials/state/cookies during success, expected failure or infrastructure failure', async () => {
    const spies = (
      ['error', 'log', 'warn', 'debug', 'verbose', 'fatal'] as const
    ).map((method) => vi.spyOn(Logger.prototype, method));
    const consoles = (['log', 'error', 'warn', 'info', 'debug'] as const).map(
      (method) => vi.spyOn(console, method),
    );
    await request(app.getHttpServer())
      .post('/auth/login')
      .send(input)
      .expect(204);
    attempt.mockResolvedValue({ ok: false, reason: 'LOCKED' });
    await request(app.getHttpServer())
      .post('/auth/login')
      .send(input)
      .expect(401);
    attempt.mockRejectedValue(new Error('private password/hash'));
    await request(app.getHttpServer())
      .post('/auth/login')
      .send(input)
      .expect(500);
    for (const spy of [...spies, ...consoles])
      expect(spy).not.toHaveBeenCalled();
  });
});
