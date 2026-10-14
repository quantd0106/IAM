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
import { IdpSessionStateService } from '../session/idp-session-state.service.js';
import type { IdpSessionState } from '../session/idp-session-state.js';
import { AuthModule } from './auth.module.js';

const currentId = '9d3d959a-c65b-4ffc-8086-ad563e59f198';
const targetId = '227a22b1-b3c2-4b26-9c3d-e581c7c8f698';
const revokedId = '98aa3cfb-2c2e-4aa6-9f02-031148a50be9';
const absentId = '030f78ab-1e02-4e9e-8fcd-d9dd1451b5de';
const foreignId = 'd0cfc4e3-1c40-4c7e-b522-5d8b740b68f8';
const missingId = '693ab9f0-d412-4459-845e-7ee3667326a6';
const userId = 'c0e21e3f-d3ee-425c-a99f-c2e7a7cab53f';
const otherUserId = '511f14a5-a49c-4f3b-b93b-56eaf3a5ae2b';
type Row = {
  id: string;
  userId: string;
  status: 'ACTIVE' | 'REVOKED';
  createdAt: Date;
  lastActivityAt: Date;
  expiresAt: Date;
  ipAddress: string | null;
  userAgent: string | null;
};
type Lookup = {
  where: {
    id: string;
    userId: string;
    status?: 'ACTIVE';
    expiresAt?: { gt: Date };
  };
  select: object;
};
type List = {
  where: { userId: string; status: 'ACTIVE'; expiresAt: { gt: Date } };
  select: object;
  orderBy: object[];
};
type Revoke = {
  where: { id: string; status: 'ACTIVE' };
  data: { status: 'REVOKED' };
};

describe('Own-session HTTP (real orchestration, mocked stores)', () => {
  const rows = new Map<string, Row>();
  const runtime = new Map<string, IdpSessionState>();
  const touch = vi.fn<IdpSessionStateService['touch']>();
  const read = vi.fn<IdpSessionStateService['read']>();
  const invalidate = vi.fn<IdpSessionStateService['invalidate']>();
  const findFirst = vi.fn<(input: Lookup) => Promise<Row | null>>();
  const findMany = vi.fn<(input: List) => Promise<Row[]>>();
  const updateMany = vi.fn<(input: Revoke) => Promise<{ count: number }>>();
  let app: INestApplication<Server>;
  let cookies: IdpSessionCookieService;
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
      .useValue({ session: { findFirst, findMany, updateMany } })
      .overrideProvider(RedisService)
      .useValue({})
      .overrideProvider(IdpSessionStateService)
      .useValue({ touch, read, invalidate })
      .useMocker((token) => (token === ConfigService ? config : undefined))
      .compile();
    app = module.createNestApplication<INestApplication<Server>>({
      logger: false,
    });
    // Keep one ephemeral listener alive while testing both routes; Supertest
    // otherwise auto-closes a shared listener after the first prepared request.
    await app.listen(0, '127.0.0.1');
    cookies = app.get(IdpSessionCookieService);
  });
  beforeEach(() => {
    vi.resetAllMocks();
    rows.clear();
    runtime.clear();
    const now = Date.now();
    for (const [id, owner] of [
      [currentId, userId],
      [targetId, userId],
      [revokedId, userId],
      [absentId, userId],
      [foreignId, otherUserId],
    ]) {
      rows.set(id, {
        id,
        userId: owner,
        status: id === revokedId ? 'REVOKED' : 'ACTIVE',
        createdAt: new Date(now - 5000),
        lastActivityAt: new Date(now - 5000),
        expiresAt: new Date(now + 28800000),
        ipAddress: null,
        userAgent: null,
      });
      if (id !== absentId)
        runtime.set(id, {
          userId: owner,
          authTime: now - 5000,
          mfaLevel: 'password',
          createdAt: now - 5000,
          lastActivityAt: now - 1000,
          absoluteExpiresAt: now + 28800000,
        });
    }
    touch.mockImplementation((id) => {
      const state = runtime.get(id);
      if (!state) return Promise.resolve(null);
      const updated = { ...state, lastActivityAt: Date.now() };
      runtime.set(id, updated);
      return Promise.resolve(updated);
    });
    read.mockImplementation((id) => Promise.resolve(runtime.get(id) ?? null));
    invalidate.mockImplementation((id) => {
      runtime.delete(id);
      return Promise.resolve();
    });
    findFirst.mockImplementation(({ where }) => {
      const row = rows.get(where.id.toLowerCase());
      return Promise.resolve(
        row &&
          row.userId === where.userId &&
          (where.status === undefined || row.status === where.status) &&
          (where.expiresAt === undefined || row.expiresAt > where.expiresAt.gt)
          ? { ...row }
          : null,
      );
    });
    findMany.mockImplementation(({ where }) =>
      Promise.resolve(
        [...rows.values()]
          .filter(
            (r) =>
              r.userId === where.userId &&
              r.status === where.status &&
              r.expiresAt > where.expiresAt.gt,
          )
          .sort(
            (a, b) =>
              b.createdAt.getTime() - a.createdAt.getTime() ||
              b.id.localeCompare(a.id),
          ),
      ),
    );
    updateMany.mockImplementation(({ where }) => {
      const row = rows.get(where.id);
      if (!row || row.status !== where.status)
        return Promise.resolve({ count: 0 });
      row.status = 'REVOKED';
      return Promise.resolve({ count: 1 });
    });
  });
  afterEach(() => vi.restoreAllMocks());
  afterAll(async () => {
    await app.close();
  });
  const cookie = 'iam.sid=' + currentId;
  const list = () =>
    request(app.getHttpServer()).get('/auth/sessions').set('Cookie', cookie);
  const revoke = (id: string) =>
    request(app.getHttpServer())
      .delete('/auth/sessions/' + id)
      .set('Cookie', cookie);
  const authError = {
    statusCode: 401,
    error: 'Unauthorized',
    message: 'Authentication required.',
  };
  const operationError = {
    statusCode: 500,
    error: 'Internal Server Error',
    message: 'Session management failed.',
  };
  const missingError = {
    statusCode: 404,
    error: 'Not Found',
    message: 'Session not found.',
  };

  it('lists only own live sessions, safe ISO fields and current flag, without cookie or persistence writes', async () => {
    const parse = vi.spyOn(cookies, 'parse');
    const snapshot = [...rows.values()].map((r) => ({ ...r }));
    const otherState = runtime.get(targetId);
    const response = await list().expect(200);
    expect(parse).toHaveBeenCalledExactlyOnceWith(cookie);
    const body = response.body as { sessions: Record<string, unknown>[] };
    expect(body.sessions.map((s) => s.id)).toEqual([currentId, targetId]);
    expect(body.sessions.map((s) => s.current)).toEqual([true, false]);
    expect(body.sessions[0].lastActivityAt).toBe(
      new Date(runtime.get(currentId)!.lastActivityAt).toISOString(),
    );
    for (const session of body.sessions)
      expect(Object.keys(session).sort()).toEqual(
        [
          'id',
          'createdAt',
          'lastActivityAt',
          'expiresAt',
          'ipAddress',
          'userAgent',
          'current',
        ].sort(),
      );
    expect(response.headers['set-cookie']).toBeUndefined();
    expect(response.text).not.toMatch(
      /userId|session:|iam\.sid|password|credential|roles|permissions|access_token|refresh_token|id_token/,
    );
    expect([...rows.values()]).toEqual(snapshot);
    expect(runtime.get(targetId)).toEqual(otherState);
    expect(touch).toHaveBeenCalledExactlyOnceWith(currentId);
    expect(read.mock.calls).toEqual([[targetId], [absentId]]);
    expect(updateMany).not.toHaveBeenCalled();
  });

  it.each([
    undefined,
    'other=unrelated',
    'iam.sid=invalid',
    'iam.sid=' + currentId + '; iam.sid=' + currentId,
    'iam.sid="' + currentId + '"',
    'iam.sid=%39' + currentId.slice(1),
  ])(
    'uses identical 401 for invalid cookie case %# on both routes',
    async (header) => {
      for (const pending of [
        request(app.getHttpServer()).get('/auth/sessions'),
        request(app.getHttpServer()).delete('/auth/sessions/' + targetId),
      ]) {
        if (header !== undefined) pending.set('Cookie', header);
        const response = await pending.expect(401);
        expect(response.body as unknown).toEqual(authError);
        expect(response.headers['set-cookie']).toBeUndefined();
      }
      expect(touch).not.toHaveBeenCalled();
      expect(findFirst).not.toHaveBeenCalled();
      expect(invalidate).not.toHaveBeenCalled();
    },
  );
  it.each([
    'missing runtime',
    'missing row',
    'revoked row',
    'wrong owner',
    'expired row',
  ])('returns generic 401 for %s on both routes', async (kind) => {
    if (kind === 'missing runtime') runtime.delete(currentId);
    if (kind === 'missing row') rows.delete(currentId);
    if (kind === 'revoked row') rows.get(currentId)!.status = 'REVOKED';
    if (kind === 'wrong owner') rows.get(currentId)!.userId = otherUserId;
    if (kind === 'expired row')
      rows.get(currentId)!.expiresAt = new Date(Date.now() - 1);
    for (const pending of [list(), revoke(targetId)]) {
      const response = await pending.expect(401);
      expect(response.body as unknown).toEqual(authError);
      expect(response.headers['set-cookie']).toBeUndefined();
    }
    expect(invalidate).not.toHaveBeenCalled();
    expect(updateMany).not.toHaveBeenCalled();
  });
  it('does not accept user/current-session ID or Bearer authentication from alternate HTTP inputs', async () => {
    for (const pending of [
      request(app.getHttpServer()).get(
        '/auth/sessions?userId=' + userId + '&sessionId=' + currentId,
      ),
      request(app.getHttpServer())
        .delete('/auth/sessions/' + targetId)
        .send({ userId, sessionId: currentId }),
    ]) {
      const response = await pending
        .set('X-User-Id', userId)
        .set('X-Session-Id', currentId)
        .set('Authorization', 'Bearer ' + currentId)
        .expect(401);
      expect(response.body as unknown).toEqual(authError);
    }
    expect(touch).not.toHaveBeenCalled();
    expect(invalidate).not.toHaveBeenCalled();
    const response = await list()
      .query({ userId: otherUserId })
      .set('X-User-Id', otherUserId)
      .expect(200);
    expect(
      (response.body as { sessions: { id: string }[] }).sessions.map(
        (s) => s.id,
      ),
    ).toEqual([currentId, targetId]);
  });
  it('ignores attempted userId/target override when a valid cookie authorizes another own revoke', async () => {
    await revoke(targetId)
      .query({ userId: otherUserId })
      .set('X-User-Id', otherUserId)
      .send({ userId: otherUserId, sessionId: foreignId })
      .expect(204);
    expect(invalidate).toHaveBeenCalledExactlyOnceWith(targetId);
    expect(runtime.has(foreignId)).toBe(true);
    expect(rows.get(foreignId)!.status).toBe('ACTIVE');
  });
  it('revokes another owned session idempotently, leaving current session and cookie intact', async () => {
    const before = { ...rows.get(targetId)! };
    for (const count of [1, 2]) {
      const response = await revoke(targetId).expect(204);
      expect(response.text).toBe('');
      expect(response.headers['set-cookie']).toBeUndefined();
      expect(invalidate).toHaveBeenCalledTimes(count);
      expect(runtime.has(targetId)).toBe(false);
      expect(rows.get(targetId)).toEqual({ ...before, status: 'REVOKED' });
      expect(rows.get(currentId)!.status).toBe('ACTIVE');
      expect(runtime.has(currentId)).toBe(true);
    }
    const after = await list().expect(200);
    expect(
      (after.body as { sessions: { id: string }[] }).sessions.map((s) => s.id),
    ).toEqual([currentId]);
  });
  it.each([revokedId, absentId])(
    'allows owned revoked/missing-runtime target case %#',
    async (id) => {
      await revoke(id).expect(204);
      expect(invalidate).toHaveBeenCalledExactlyOnceWith(id);
      expect(rows.get(id)!.status).toBe('REVOKED');
    },
  );
  it('self-revokes, clears exactly through cookie service, then the old cookie receives 401', async () => {
    const clear = vi.spyOn(cookies, 'clear');
    const response = await revoke(currentId).expect(204);
    expect(response.text).toBe('');
    expect(clear).toHaveBeenCalledOnce();
    expect(response.headers['set-cookie']).toEqual([cookies.clear()]);
    expect(runtime.has(currentId)).toBe(false);
    expect(rows.get(currentId)!.status).toBe('REVOKED');
    expect(runtime.has(targetId)).toBe(true);
    expect(rows.get(targetId)!.status).toBe('ACTIVE');
    expect((await list().expect(401)).body as unknown).toEqual(authError);
  });
  it('cross-user and unknown targets share 404 without any target invalidation or DB update', async () => {
    const foreignBefore = { ...rows.get(foreignId)! };
    const foreignState = { ...runtime.get(foreignId)! };
    const foreign = await revoke(foreignId).expect(404);
    const unknown = await revoke(missingId).expect(404);
    expect(foreign.body as unknown).toEqual(missingError);
    expect(unknown.body as unknown).toEqual(missingError);
    expect(foreign.headers['set-cookie']).toBeUndefined();
    expect(unknown.headers['set-cookie']).toBeUndefined();
    expect(rows.get(foreignId)).toEqual(foreignBefore);
    expect(runtime.get(foreignId)).toEqual(foreignState);
    expect(invalidate).not.toHaveBeenCalled();
    expect(updateMany).not.toHaveBeenCalled();
    expect(rows.get(currentId)!.status).toBe('ACTIVE');
  });
  it.each(['invalid', '{' + targetId + '}', targetId + ':suffix'])(
    'returns 400 without touching/authenticating/mutating for malformed target case %#',
    async (id) => {
      const response = await revoke(encodeURIComponent(id)).expect(400);
      expect(response.body as unknown).toEqual({
        statusCode: 400,
        error: 'Bad Request',
        message: 'Invalid session identifier.',
      });
      expect(touch).not.toHaveBeenCalled();
      expect(findFirst).not.toHaveBeenCalled();
      expect(invalidate).not.toHaveBeenCalled();
    },
  );
  it.each([
    'Redis authentication',
    'Prisma authentication',
    'list DB',
    'list Redis',
    'missing current candidate',
    'ownership DB',
    'Redis invalidate',
    'DB revoke',
  ])('returns safe 500/no cookie for %s failure', async (stage) => {
    const secret = new Error('private URL/key/cookie:' + currentId, {
      cause: new Error('private cause'),
    });
    if (stage === 'Redis authentication') touch.mockRejectedValue(secret);
    if (stage === 'Prisma authentication') findFirst.mockRejectedValue(secret);
    if (stage === 'list DB') findMany.mockRejectedValue(secret);
    if (stage === 'list Redis') read.mockRejectedValue(secret);
    if (stage === 'missing current candidate')
      findMany.mockResolvedValue([rows.get(targetId)!]);
    if (stage === 'ownership DB')
      findFirst
        .mockResolvedValueOnce(rows.get(currentId)!)
        .mockRejectedValueOnce(secret);
    if (stage === 'Redis invalidate') invalidate.mockRejectedValue(secret);
    if (stage === 'DB revoke') updateMany.mockRejectedValue(secret);
    const pending =
      stage === 'ownership DB' ||
      stage === 'Redis invalidate' ||
      stage === 'DB revoke'
        ? revoke(currentId)
        : list();
    const response = await pending.expect(500);
    expect(response.body as unknown).toEqual(operationError);
    expect(response.headers['set-cookie']).toBeUndefined();
    if (stage === 'DB revoke') {
      expect(runtime.has(currentId)).toBe(false);
      expect(rows.get(currentId)!.status).toBe('ACTIVE');
    }
  });
  it('does not restore self runtime after DB failure; next management request is 401 and POST logout can repair', async () => {
    updateMany.mockRejectedValueOnce(new Error('controlled fault'));
    await revoke(currentId).expect(500);
    expect(runtime.has(currentId)).toBe(false);
    expect(rows.get(currentId)!.status).toBe('ACTIVE');
    await list().expect(401);
    const retry = await request(app.getHttpServer())
      .post('/auth/logout')
      .set('Cookie', cookie)
      .expect(204);
    expect(retry.headers['set-cookie']).toEqual([cookies.clear()]);
    expect(rows.get(currentId)!.status).toBe('REVOKED');
  });
  it('retries another-own partial revoke using the still-active current session', async () => {
    updateMany.mockRejectedValueOnce(new Error('controlled fault'));
    await revoke(targetId).expect(500);
    expect(runtime.has(targetId)).toBe(false);
    expect(rows.get(targetId)!.status).toBe('ACTIVE');
    await revoke(targetId).expect(204);
    expect(rows.get(targetId)!.status).toBe('REVOKED');
    await list().expect(200);
  });
  it('supports concurrent other-session revoke without altering current state', async () => {
    const before = { ...rows.get(targetId)! };
    const results = await Promise.all([0, 1].map(() => revoke(targetId)));
    for (const response of results) {
      expect(response.status).toBe(204);
      expect(response.headers['set-cookie']).toBeUndefined();
    }
    expect(rows.get(targetId)).toEqual({ ...before, status: 'REVOKED' });
    expect(runtime.has(targetId)).toBe(false);
    expect(rows.size).toBe(5);
    await list().expect(200);
  });
  it('allows concurrent self-revokes after both ownership lookups succeed', async () => {
    const perform = invalidate.getMockImplementation()!;
    let arrivals = 0;
    let release!: () => void;
    const bothOwned = new Promise<void>((resolve) => {
      release = resolve;
    });
    invalidate.mockImplementation(async (id) => {
      if (++arrivals === 2) release();
      await bothOwned;
      await perform(id);
    });
    const results = await Promise.all([0, 1].map(() => revoke(currentId)));
    for (const response of results) {
      expect(response.status).toBe(204);
      expect(response.headers['set-cookie']).toEqual([cookies.clear()]);
    }
    expect(runtime.has(currentId)).toBe(false);
    expect(rows.get(currentId)!.status).toBe('REVOKED');
    expect(rows.size).toBe(5);
    expect(runtime.has(targetId)).toBe(true);
  });
  it('does not log session/cookie/subject or raw driver details', async () => {
    const spies = (
      ['error', 'log', 'warn', 'debug', 'verbose', 'fatal'] as const
    ).map((method) => vi.spyOn(Logger.prototype, method));
    const consoles = (['log', 'error', 'warn', 'info', 'debug'] as const).map(
      (method) => vi.spyOn(console, method),
    );
    await list().expect(200);
    await revoke(foreignId).expect(404);
    await revoke(targetId).expect(204);
    touch.mockRejectedValue(new Error('private cookie/key'));
    await list().expect(500);
    for (const spy of [...spies, ...consoles])
      expect(spy).not.toHaveBeenCalled();
  });
  it.each([
    '/me/sessions',
    '/account/sessions',
    '/session/list',
    '/session/revoke',
    '/auth/sessions/user/' + otherUserId,
  ])('does not introduce alternate/admin route %s', async (path) => {
    await request(app.getHttpServer())
      .get(path)
      .set('Cookie', cookie)
      .expect(404);
  });
});
