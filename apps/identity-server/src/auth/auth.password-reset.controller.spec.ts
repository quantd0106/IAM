import { Logger, type INestApplication } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Test } from '@nestjs/testing';
import type { Server } from 'node:http';
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
import { AuthModule } from './auth.module.js';
import { RegistrationService } from './registration.service.js';
import {
  PASSWORD_RESET_DELIVERY,
  type PasswordResetDelivery,
} from './password-reset-delivery.js';
import { PasswordResetRequestService } from './password-reset-request.service.js';

describe('POST /auth/password-reset/request (isolated HTTP)', () => {
  const eligible = {
    id: 'test-user-uuid',
    status: 'ACTIVE',
    credential: { id: 'test-credential-uuid' },
  };
  const findUnique = vi.fn<() => Promise<typeof eligible | null>>();
  const setWithTtl = vi.fn<() => Promise<void>>();
  const deliver = vi.fn<PasswordResetDelivery['deliver']>();
  const register = vi.fn();
  let app: INestApplication<Server>;
  let error: ReturnType<typeof vi.spyOn>;

  beforeAll(async () => {
    const module = await Test.createTestingModule({ imports: [AuthModule] })
      .overrideProvider(RedisService)
      .useValue({ setWithTtl })
      .overrideProvider(PrismaService)
      .useValue({ user: { findUnique } })
      .overrideProvider(RegistrationService)
      .useValue({ register })
      .overrideProvider(PASSWORD_RESET_DELIVERY)
      .useValue({ deliver })
      .useMocker((token) =>
        token === ConfigService
          ? new ConfigService({
              LOGIN_MAX_FAILURES: 5,
              LOGIN_LOCK_SECONDS: 900,
              PASSWORD_RESET_TTL_SECONDS: 900,
            })
          : undefined,
      )
      .compile();
    app = module.createNestApplication<INestApplication<Server>>({
      logger: false,
    });
    await app.init();
    error = vi
      .spyOn(Logger.prototype, 'error')
      .mockImplementation(() => undefined);
  });
  beforeEach(() => {
    vi.clearAllMocks();
    findUnique.mockResolvedValue(eligible);
    setWithTtl.mockResolvedValue(undefined);
    deliver.mockResolvedValue(undefined);
  });
  afterAll(async () => {
    await app.close();
    vi.restoreAllMocks();
  });

  it('trims email, preserves case, and returns exactly generic 202 without cookie/secret/userId', async () => {
    const response = await request(app.getHttpServer())
      .post('/auth/password-reset/request')
      .send({ email: ' MixedCase@example.invalid ' })
      .expect(202);
    expect(response.body as unknown).toEqual({ status: 'accepted' });
    expect(response.headers['set-cookie']).toBeUndefined();
    expect(findUnique).toHaveBeenCalledWith({
      where: { email: 'MixedCase@example.invalid' },
      select: { id: true, status: true, credential: { select: { id: true } } },
    });
    expect(deliver.mock.calls.length).toBe(1);
    expect(
      JSON.stringify(response.body).includes(deliver.mock.calls[0][0].token),
    ).toBe(false);
    expect(register).not.toHaveBeenCalled();
  });

  it('has identical status/body for ACTIVE, unknown, DISABLED and missing Credential accounts', async () => {
    const accounts = [
      eligible,
      null,
      { ...eligible, status: 'DISABLED' },
      { ...eligible, credential: null },
    ];
    const results: { status: number; body: unknown }[] = [];
    for (const [index, account] of accounts.entries()) {
      findUnique.mockResolvedValueOnce(account as typeof eligible | null);
      const response = await request(app.getHttpServer())
        .post('/auth/password-reset/request')
        .send({ email: `case${index}@example.invalid` });
      results.push({ status: response.status, body: response.body as unknown });
      expect(response.headers['set-cookie']).toBeUndefined();
    }
    expect(results).toEqual(
      accounts.map(() => ({ status: 202, body: { status: 'accepted' } })),
    );
    expect(setWithTtl.mock.calls.length).toBe(1);
    expect(deliver.mock.calls.length).toBe(1);
  });

  it.each([
    { email: 'invalid-email' },
    {},
    { email: '' },
    { email: '  ' },
    { email: 123 },
    { email: null },
    { email: 'valid@example.invalid', token: 'request-secret-canary' },
    [],
    null,
    'not-an-object',
  ])(
    'rejects invalid/non-strict body case %# with a sanitized 400',
    async (body) => {
      const response = await request(app.getHttpServer())
        .post('/auth/password-reset/request')
        .set('Content-Type', 'application/json')
        .send(JSON.stringify(body))
        .expect(400);
      expect(response.body as unknown).toEqual({
        statusCode: 400,
        error: 'Bad Request',
        message: 'Invalid password reset request.',
      });
      expect(findUnique).not.toHaveBeenCalled();
      expect(deliver.mock.calls.length).toBe(0);
    },
  );

  it.each([
    '/auth/password-reset/request',
    '/AUTH/PASSWORD-RESET/REQUEST',
    '/auth/password-reset/request/',
    '/auth/password-reset/request?test=1',
  ])('sanitizes malformed JSON on reset route variant %s', async (path) => {
    const response = await request(app.getHttpServer())
      .post(path)
      .set('Content-Type', 'application/json')
      .send('{"email":"request-secret-canary",')
      .expect(400);
    expect(response.body as unknown).toEqual({
      statusCode: 400,
      error: 'Bad Request',
      message: 'Invalid password reset request.',
    });
    expect(findUnique).not.toHaveBeenCalled();
  });

  it.each(['lookup', 'redis', 'delivery'])(
    'keeps public 202 and fixed sanitized logging during %s failure',
    async (stage) => {
      if (stage === 'lookup')
        findUnique.mockRejectedValueOnce(
          new Error('private email/driver marker'),
        );
      if (stage === 'redis')
        setWithTtl.mockRejectedValueOnce(
          new Error('private Redis URL/hash marker'),
        );
      if (stage === 'delivery')
        deliver.mockImplementationOnce(({ token }) =>
          Promise.reject(new Error(`private ${token}`)),
        );
      const response = await request(app.getHttpServer())
        .post('/auth/password-reset/request')
        .send({ email: 'valid@example.invalid' })
        .expect(202);
      expect(response.body as unknown).toEqual({ status: 'accepted' });
      expect(response.headers['set-cookie']).toBeUndefined();
      expect(error).toHaveBeenCalledExactlyOnceWith(
        'Password reset request processing failed.',
      );
      if (stage !== 'delivery') expect(deliver.mock.calls.length).toBe(0);
    },
  );

  it('retains generic 202 even if an unexpected service implementation rejects', async () => {
    const failure = vi
      .spyOn(app.get(PasswordResetRequestService), 'request')
      .mockRejectedValueOnce(new Error('private unexpected token marker'));
    try {
      await request(app.getHttpServer())
        .post('/auth/password-reset/request')
        .send({ email: 'valid@example.invalid' })
        .expect(202)
        .expect({ status: 'accepted' });
    } finally {
      failure.mockRestore();
    }
  });

  it.each(['/auth/login', '/auth/change-password'])(
    'does not introduce future endpoint %s',
    async (path) => {
      await request(app.getHttpServer()).post(path).send({}).expect(404);
    },
  );
});
