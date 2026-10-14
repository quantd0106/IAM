import { Logger, type INestApplication } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
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
} from 'vitest';
import type { Environment } from '../config/env.schema.js';
import { PrismaService } from '../prisma/prisma.service.js';
import { RedisService } from '../redis/redis.service.js';
import { IdpSessionCookieService } from '../session/idp-session-cookie.service.js';
import { AuthModule } from './auth.module.js';
import { IdpLogoutService } from './idp-logout.service.js';

const id = '9d3d959a-c65b-4ffc-8086-ad563e59f198';
const otherId = 'c0e21e3f-d3ee-425c-a99f-c2e7a7cab53f';
describe('POST /auth/logout (isolated HTTP + existing cookie boundary)', () => {
  const logout = vi.fn<IdpLogoutService['logout']>();
  const config = new ConfigService<Environment, true>({
    LOGIN_MAX_FAILURES: 5,
    LOGIN_LOCK_SECONDS: 900,
    PASSWORD_RESET_TTL_SECONDS: 900,
    SESSION_IDLE_TTL_SECONDS: 1800,
    SESSION_ABSOLUTE_TTL_SECONDS: 28800,
    COOKIE_NAME: 'iam.sid',
    COOKIE_SECURE: false,
  });
  let app: INestApplication<Server>;
  let cookies: IdpSessionCookieService;
  beforeAll(async () => {
    const module = await Test.createTestingModule({ imports: [AuthModule] })
      .overrideProvider(PrismaService)
      .useValue({})
      .overrideProvider(RedisService)
      .useValue({})
      .overrideProvider(IdpLogoutService)
      .useValue({ logout })
      .useMocker((token) => (token === ConfigService ? config : undefined))
      .compile();
    app = module.createNestApplication<INestApplication<Server>>({
      logger: false,
    });
    await app.init();
    cookies = app.get(IdpSessionCookieService);
  });
  beforeEach(() => {
    vi.resetAllMocks();
    logout.mockResolvedValue(undefined);
  });
  afterEach(() => vi.restoreAllMocks());
  afterAll(async () => {
    await app.close();
  });

  it('returns empty 204 and exactly the cookie service clear header', async () => {
    const parse = vi.spyOn(cookies, 'parse');
    const clear = vi.spyOn(cookies, 'clear');
    const header = 'theme=dark; iam.sid=' + id;
    const response = await request(app.getHttpServer())
      .post('/auth/logout')
      .set('Cookie', header)
      .expect(204);
    expect(parse).toHaveBeenCalledExactlyOnceWith(header);
    expect(logout).toHaveBeenCalledExactlyOnceWith(id);
    expect(clear).toHaveBeenCalledOnce();
    expect(response.headers['set-cookie']).toEqual([cookies.clear()]);
    expect(response.text).toBe('');
    for (const forbidden of [
      id,
      'userId',
      'sessionId',
      'access_token',
      'refresh_token',
      'id_token',
      'roles',
      'permissions',
    ])
      expect(response.text).not.toContain(forbidden);
  });

  it.each([
    undefined,
    '',
    'theme=dark',
    'iam.sid',
    'iam.sid=',
    'iam.sid=invalid',
    'iam.sid=' + id + '; iam.sid=' + id,
    'iam.sid=' + id + '; iam.sid=' + otherId,
    'iam.sid=invalid; iam.sid=' + id,
    'iam.sid=' + id + '; iam.sid=invalid',
    'iam.sid="' + id + '"',
    'iam.sid=%39' + id.slice(1),
    'iam.sid= ' + id,
    'IAM.SID=' + id,
    'iam.sid.extra=' + id,
  ])(
    'clears locally without calling orchestration for invalid/missing cookie case %#',
    async (header) => {
      const pending = request(app.getHttpServer()).post('/auth/logout');
      if (header !== undefined) pending.set('Cookie', header);
      const response = await pending.expect(204);
      expect(response.text).toBe('');
      expect(response.headers['set-cookie']).toEqual([cookies.clear()]);
      expect(logout).not.toHaveBeenCalled();
    },
  );

  it.each(['missing Redis', 'missing row', 'already revoked'])(
    'does not expose %s on successful orchestration',
    async () => {
      const response = await request(app.getHttpServer())
        .post('/auth/logout')
        .set('Cookie', 'iam.sid=' + id)
        .expect(204);
      expect(logout).toHaveBeenCalledExactlyOnceWith(id);
      expect(response.text).toBe('');
      expect(response.headers['set-cookie']).toEqual([cookies.clear()]);
    },
  );

  it.each([false, true])(
    'never accepts body/query/custom-header identifiers (valid cookie=%s)',
    async (withCookie) => {
      const pending = request(app.getHttpServer())
        .post('/auth/logout?sessionId=' + otherId)
        .set('X-Session-Id', otherId)
        .send({ sessionId: otherId });
      if (withCookie) pending.set('Cookie', 'iam.sid=' + id);
      const response = await pending.expect(204);
      if (withCookie) expect(logout).toHaveBeenCalledExactlyOnceWith(id);
      else expect(logout).not.toHaveBeenCalled();
      expect(response.text).toBe('');
      expect(response.headers['set-cookie']).toEqual([cookies.clear()]);
    },
  );

  it('uses clear() for custom secure configuration without rebuilding cookie attributes', async () => {
    const secure = new IdpSessionCookieService(
      new ConfigService<Environment, true>({
        COOKIE_NAME: 'session.+id',
        COOKIE_SECURE: true,
      }),
    );
    vi.spyOn(cookies, 'parse').mockImplementation((header) =>
      secure.parse(header),
    );
    const clear = vi
      .spyOn(cookies, 'clear')
      .mockImplementation(() => secure.clear());
    const response = await request(app.getHttpServer())
      .post('/auth/logout')
      .set('Cookie', 'session.+id=' + id)
      .expect(204);
    expect(logout).toHaveBeenCalledExactlyOnceWith(id);
    expect(clear).toHaveBeenCalledOnce();
    expect(response.headers['set-cookie']).toEqual([secure.clear()]);
  });

  it('waits for completed server-side logout before clearing the cookie', async () => {
    let finish!: () => void;
    logout.mockReturnValue(
      new Promise<void>((resolve) => {
        finish = resolve;
      }),
    );
    const clear = vi.spyOn(cookies, 'clear');
    const pending = request(app.getHttpServer())
      .post('/auth/logout')
      .set('Cookie', 'iam.sid=' + id)
      .then((response) => response);
    try {
      await vi.waitFor(() => expect(logout).toHaveBeenCalledOnce());
      expect(clear).not.toHaveBeenCalled();
    } finally {
      finish();
    }
    expect((await pending).status).toBe(204);
    expect(clear).toHaveBeenCalledOnce();
  });

  it.each(['Redis', 'PostgreSQL'])(
    'returns generic 500 without clearing on %s failure, then permits retry',
    async () => {
      logout.mockRejectedValueOnce(
        new Error('private driver/cookie/URL/session:' + id, {
          cause: new Error('private cause'),
        }),
      );
      const clear = vi.spyOn(cookies, 'clear');
      const failed = await request(app.getHttpServer())
        .post('/auth/logout')
        .set('Cookie', 'iam.sid=' + id)
        .expect(500);
      expect(failed.body as unknown).toEqual({
        statusCode: 500,
        error: 'Internal Server Error',
        message: 'Logout failed.',
      });
      expect(failed.headers['set-cookie']).toBeUndefined();
      expect(clear).not.toHaveBeenCalled();
      const retry = await request(app.getHttpServer())
        .post('/auth/logout')
        .set('Cookie', 'iam.sid=' + id)
        .expect(204);
      expect(retry.headers['set-cookie']).toEqual([cookies.clear()]);
      expect(retry.text).toBe('');
      expect(logout.mock.calls).toEqual([[id], [id]]);
    },
  );

  it('permits concurrent healthy logout requests', async () => {
    const results = await Promise.all(
      [0, 1].map(() =>
        request(app.getHttpServer())
          .post('/auth/logout')
          .set('Cookie', 'iam.sid=' + id),
      ),
    );
    for (const response of results) {
      expect(response.status).toBe(204);
      expect(response.text).toBe('');
      expect(response.headers['set-cookie']).toEqual([cookies.clear()]);
    }
    expect(logout.mock.calls).toEqual([[id], [id]]);
  });

  it('logs no cookie/ID/driver details for success, local cleanup or failure', async () => {
    const spies = (
      ['error', 'log', 'warn', 'debug', 'verbose', 'fatal'] as const
    ).map((method) => vi.spyOn(Logger.prototype, method));
    const consoles = (['log', 'error', 'warn', 'info', 'debug'] as const).map(
      (method) => vi.spyOn(console, method),
    );
    await request(app.getHttpServer())
      .post('/auth/logout')
      .set('Cookie', 'iam.sid=' + id)
      .expect(204);
    await request(app.getHttpServer()).post('/auth/logout').expect(204);
    logout.mockRejectedValue(new Error('private cookie/state'));
    await request(app.getHttpServer())
      .post('/auth/logout')
      .set('Cookie', 'iam.sid=' + id)
      .expect(500);
    for (const spy of [...spies, ...consoles])
      expect(spy).not.toHaveBeenCalled();
  });

  it.each(['/auth/session', '/session', '/me'])(
    'does not add future session route %s',
    async (path) => {
      await request(app.getHttpServer()).get(path).expect(404);
    },
  );
});
