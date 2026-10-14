import 'reflect-metadata';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { createConnection, createServer, type Socket } from 'node:net';
import { setTimeout } from 'node:timers/promises';
import {
  Module,
  type INestApplication,
  type LoggerService,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { NestFactory } from '@nestjs/core';
import { Test } from '@nestjs/testing';
import { AppModule } from '../app.module.js';
import { AppConfigModule } from '../config/config.module.js';
import type { Environment } from '../config/env.schema.js';
import { PrismaModule } from '../prisma/prisma.module.js';
import { PrismaService } from '../prisma/prisma.service.js';
import { buildRedisKey } from '../redis/redis-key.js';
import { RedisService } from '../redis/redis.service.js';
import { PasswordService } from '../security/password/password.service.js';
import { SessionModule } from '../session/session.module.js';
import { IdpSessionCookieService } from '../session/idp-session-cookie.service.js';
import { IdpSessionStateService } from '../session/idp-session-state.service.js';
import { IdpLogoutService } from './idp-logout.service.js';
import type { OwnSession } from './idp-own-session.service.js';

@Module({
  imports: [AppConfigModule, PrismaModule, SessionModule],
  providers: [PasswordService],
})
class OwnSessionsCheckModule {}

async function checkOwnSessions(): Promise<void> {
  const context = await NestFactory.createApplicationContext(
    OwnSessionsCheckModule,
    { logger: false, abortOnError: false },
  );
  const config = context.get<ConfigService<Environment, true>>(ConfigService);
  const prisma = context.get(PrismaService);
  const observer = context.get(RedisService);
  const states = context.get(IdpSessionStateService);
  const cookies = context.get(IdpSessionCookieService);
  const users = [randomUUID(), randomUUID()];
  const emails = users.map(() => 'm36-' + randomUUID() + '@example.invalid');
  const password = 'temporary-probe-' + randomUUID();
  const sessionIds = new Set<string>();
  const rateKeys = users.map((id) =>
    buildRedisKey('rate', id, 'login-failure'),
  );
  const redisUrl = new URL(config.getOrThrow('REDIS_URL', { infer: true }));
  let dataAllowed = false;
  let app: INestApplication | undefined;
  let gatewayEnabled = true;
  let gatedSelfId: string | undefined;
  let selfArrivals = 0;
  let releaseSelf!: () => void;
  const bothAuthenticated = new Promise<void>((resolve) => {
    releaseSelf = resolve;
  });
  const sockets = new Set<Socket>();
  const gateway = createServer((incoming) => {
    if (!gatewayEnabled) {
      incoming.destroy();
      return;
    }
    const upstream = createConnection({
      host: redisUrl.hostname,
      port: Number(redisUrl.port || 6379),
    });
    for (const socket of [incoming, upstream]) {
      sockets.add(socket);
      socket.on('error', () => {
        incoming.destroy();
        upstream.destroy();
      });
      socket.on('close', () => {
        sockets.delete(socket);
        incoming.destroy();
        upstream.destroy();
      });
    }
    incoming.pipe(upstream).pipe(incoming);
  });
  const logs: string[] = [];
  const capture = (...messages: unknown[]): void => {
    logs.push(messages.map(String).join(' '));
  };
  const logger: LoggerService = {
    log: capture,
    error: capture,
    warn: capture,
    debug: capture,
    verbose: capture,
    fatal: capture,
  };
  const ready = async (redis: RedisService): Promise<void> => {
    const deadline = Date.now() + 15000;
    for (;;) {
      try {
        await redis.ttl(rateKeys[0]);
        return;
      } catch {
        if (Date.now() >= deadline)
          throw new Error('Own-session probe readiness timeout.');
        await setTimeout(50);
      }
    }
  };
  const cookie = (id: string): string =>
    config.getOrThrow('COOKIE_NAME', { infer: true }) + '=' + id;
  const send = (
    origin: string,
    method: string,
    path: string,
    sessionId?: string,
    body?: unknown,
  ): Promise<Response> =>
    fetch(new URL(path, origin), {
      method,
      headers: {
        ...(sessionId === undefined ? {} : { Cookie: cookie(sessionId) }),
        ...(body === undefined ? {} : { 'Content-Type': 'application/json' }),
      },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      signal: AbortSignal.timeout(10000),
    });
  const expectError = async (
    response: Response,
    status: 400 | 401 | 404 | 500,
  ): Promise<void> => {
    const errors = {
      400: { error: 'Bad Request', message: 'Invalid session identifier.' },
      401: { error: 'Unauthorized', message: 'Authentication required.' },
      404: { error: 'Not Found', message: 'Session not found.' },
      500: {
        error: 'Internal Server Error',
        message: 'Session management failed.',
      },
    };
    assert.equal(response.status, status);
    assert.equal(response.headers.get('set-cookie'), null);
    assert.deepEqual(await response.json(), {
      statusCode: status,
      ...errors[status],
    });
  };
  const login = async (origin: string, userIndex: number): Promise<string> => {
    const response = await send(origin, 'POST', '/auth/login', undefined, {
      identifier: { type: 'email', value: emails[userIndex] },
      password,
    });
    assert.equal(response.status, 204);
    assert.equal(await response.text(), '');
    const headers = response.headers.getSetCookie();
    assert.equal(headers.length, 1);
    const id = cookies.parse(headers[0].split(';')[0]);
    assert.ok(id);
    sessionIds.add(id);
    assert.equal(headers[0], cookies.serialize(id));
    const row = await prisma.session.findUniqueOrThrow({ where: { id } });
    assert.equal(row.userId, users[userIndex]);
    assert.equal(row.status, 'ACTIVE');
    const state = await states.read(id);
    assert.ok(state);
    assert.equal(state.userId, row.userId);
    assert.equal(state.createdAt, row.createdAt.getTime());
    assert.equal(state.absoluteExpiresAt, row.expiresAt.getTime());
    return id;
  };
  const listed = async (
    origin: string,
    current: string,
    expectedIds: string[],
  ): Promise<OwnSession[]> => {
    const response = await send(origin, 'GET', '/auth/sessions', current);
    assert.equal(response.status, 200);
    assert.equal(response.headers.get('set-cookie'), null);
    const body = (await response.json()) as { sessions: OwnSession[] };
    assert.deepEqual(Object.keys(body), ['sessions']);
    assert.equal(body.sessions.filter((s) => s.current).length, 1);
    assert.equal(body.sessions.find((s) => s.current)?.id, current);
    const rows = await prisma.session.findMany({
      where: { id: { in: expectedIds } },
      orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
    });
    assert.deepEqual(
      body.sessions.map((s) => s.id),
      rows.map((r) => r.id),
    );
    for (const session of body.sessions) {
      assert.deepEqual(
        Object.keys(session).sort(),
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
      const row = rows.find((r) => r.id === session.id);
      assert.ok(row);
      const runtime = await states.read(session.id);
      assert.ok(runtime);
      assert.equal(session.createdAt, row.createdAt.toISOString());
      assert.equal(session.expiresAt, row.expiresAt.toISOString());
      assert.equal(
        session.lastActivityAt,
        new Date(runtime.lastActivityAt).toISOString(),
      );
      assert.equal(session.ipAddress, row.ipAddress);
      assert.equal(session.userAgent, row.userAgent);
    }
    assert.ok(
      !/userId|session:|iam\.sid|password|credential|roles|permissions|access_token|refresh_token|id_token/.test(
        JSON.stringify(body),
      ),
    );
    return body.sessions;
  };
  const removed = async (id: string): Promise<void> => {
    assert.equal(await observer.get(buildRedisKey('session', id)), null);
    assert.equal(await states.read(id), null);
    assert.equal(await states.touch(id), null);
    assert.equal(
      (await prisma.session.findUniqueOrThrow({ where: { id } })).status,
      'REVOKED',
    );
  };
  const revokedResponse = async (
    response: Response,
    self = false,
  ): Promise<void> => {
    assert.equal(response.status, 204);
    assert.equal(await response.text(), '');
    assert.deepEqual(
      response.headers.getSetCookie(),
      self ? [cookies.clear()] : [],
    );
  };
  try {
    const issuer = config.getOrThrow('ISSUER_URL', { infer: true });
    const local = (value: string): boolean =>
      ['localhost', '127.0.0.1', '[::1]'].includes(new URL(value).hostname);
    if (
      config.getOrThrow('NODE_ENV', { infer: true }) === 'production' ||
      new URL(issuer).protocol !== 'http:' ||
      !local(issuer) ||
      !local(config.getOrThrow('DATABASE_URL', { infer: true })) ||
      !local(redisUrl.toString()) ||
      redisUrl.protocol !== 'redis:'
    )
      throw new Error(
        'Own-session probe requires the local development stack.',
      );
    dataAllowed = true;
    await ready(observer);
    const hash = await context.get(PasswordService).hash(password);
    for (const [index, id] of users.entries())
      await prisma.user.create({
        data: {
          id,
          email: emails[index],
          username: 'm36-' + randomUUID(),
          credential: { create: { passwordHash: hash } },
        },
      });
    const a1 = await login(issuer, 0);
    const a2 = await login(issuer, 0);
    const a3 = await login(issuer, 0);
    const b1 = await login(issuer, 1);
    const persistentSnapshot = await prisma.session.findMany({
      where: { userId: { in: users } },
      orderBy: { id: 'asc' },
    });
    const a1Before = await states.read(a1);
    const a2Before = await states.read(a2);
    const a3Before = await states.read(a3);
    const otherTtls = await Promise.all(
      [a2, a3].map((id) => observer.ttl(buildRedisKey('session', id))),
    );
    await setTimeout(1100);
    await listed(issuer, a1, [a1, a2, a3]);
    assert.ok(a1Before);
    assert.ok(
      (await states.read(a1))!.lastActivityAt > a1Before.lastActivityAt,
    );
    assert.deepEqual(await states.read(a2), a2Before);
    assert.deepEqual(await states.read(a3), a3Before);
    for (const [index, id] of [a2, a3].entries())
      assert.ok(
        (await observer.ttl(buildRedisKey('session', id))) <= otherTtls[index],
      );
    assert.deepEqual(
      await prisma.session.findMany({
        where: { userId: { in: users } },
        orderBy: { id: 'asc' },
      }),
      persistentSnapshot,
    );
    console.log(
      'Live own list passed: A1/A2/A3 only, current flag, safe ISO fields/order, current touch, no other-session activity/TTL refresh or PostgreSQL writes.',
    );

    for (const header of [
      undefined,
      'other=unrelated',
      cookie('invalid'),
      cookie(a1) + '; ' + cookie(a1),
    ]) {
      const response = await fetch(new URL('/auth/sessions', issuer), {
        headers: header === undefined ? {} : { Cookie: header },
        signal: AbortSignal.timeout(10000),
      });
      await expectError(response, 401);
    }
    const spoofed = await fetch(
      new URL('/auth/sessions?userId=' + users[1], issuer),
      {
        headers: {
          Cookie: cookie(a1),
          'X-User-Id': users[1],
          'X-Session-Id': b1,
          Authorization: 'Bearer ' + b1,
        },
        signal: AbortSignal.timeout(10000),
      },
    );
    assert.equal(spoofed.status, 200);
    assert.deepEqual(
      ((await spoofed.json()) as { sessions: OwnSession[] }).sessions
        .map((s) => s.id)
        .sort(),
      [a1, a2, a3].sort(),
    );
    const noCookie = await fetch(
      new URL('/auth/sessions?userId=' + users[0], issuer),
      {
        headers: {
          'X-User-Id': users[0],
          'X-Session-Id': a1,
          Authorization: 'Bearer ' + a1,
        },
        signal: AbortSignal.timeout(10000),
      },
    );
    await expectError(noCookie, 401);
    console.log(
      'Live authentication source passed: only configured cookie, no request-supplied subject/current ID or Bearer authority.',
    );

    const a2Row = await prisma.session.findUniqueOrThrow({ where: { id: a2 } });
    await revokedResponse(
      await send(issuer, 'DELETE', '/auth/sessions/' + a2, a1),
    );
    await removed(a2);
    assert.deepEqual(await prisma.session.findUnique({ where: { id: a2 } }), {
      ...a2Row,
      status: 'REVOKED',
    });
    await revokedResponse(
      await send(issuer, 'DELETE', '/auth/sessions/' + a2, a1),
    );
    await listed(issuer, a1, [a1, a3]);
    await listed(issuer, a3, [a1, a3]);
    await listed(issuer, b1, [b1]);
    console.log(
      'Live other-own revoke/repeat passed: target Redis absent/read null and retained REVOKED row; current cookie/A3/B1 remain usable.',
    );

    const b1Row = await prisma.session.findUniqueOrThrow({ where: { id: b1 } });
    const b1State = await states.read(b1);
    await expectError(
      await send(issuer, 'DELETE', '/auth/sessions/' + b1, a1, {
        userId: users[1],
      }),
      404,
    );
    const unknown = randomUUID();
    await expectError(
      await send(issuer, 'DELETE', '/auth/sessions/' + unknown, a1),
      404,
    );
    assert.deepEqual(
      await prisma.session.findUnique({ where: { id: b1 } }),
      b1Row,
    );
    assert.deepEqual(await states.read(b1), b1State);
    assert.equal(await observer.get(buildRedisKey('session', unknown)), null);
    assert.equal(
      (await prisma.session.findUniqueOrThrow({ where: { id: a1 } })).status,
      'ACTIVE',
    );
    await expectError(
      await send(issuer, 'DELETE', '/auth/sessions/invalid', a1),
      400,
    );
    console.log(
      'Live IDOR passed: cross-user and unknown targets share generic 404; foreign Redis/row remain unchanged.',
    );

    const a4 = await login(issuer, 0);
    const a4Row = await prisma.session.findUniqueOrThrow({ where: { id: a4 } });
    await Promise.all(
      [0, 1].map(async () =>
        revokedResponse(
          await send(issuer, 'DELETE', '/auth/sessions/' + a4, a1),
        ),
      ),
    );
    await removed(a4);
    assert.deepEqual(await prisma.session.findUnique({ where: { id: a4 } }), {
      ...a4Row,
      status: 'REVOKED',
    });
    await listed(issuer, a1, [a1, a3]);
    const a1Row = await prisma.session.findUniqueOrThrow({ where: { id: a1 } });
    await revokedResponse(
      await send(issuer, 'DELETE', '/auth/sessions/' + a1, a1),
      true,
    );
    await removed(a1);
    assert.deepEqual(await prisma.session.findUnique({ where: { id: a1 } }), {
      ...a1Row,
      status: 'REVOKED',
    });
    await expectError(await send(issuer, 'GET', '/auth/sessions', a1), 401);
    await listed(issuer, a3, [a3]);
    await listed(issuer, b1, [b1]);
    console.log(
      'Live concurrent other revoke and self-revoke passed: no row recreation/timestamp extension; self cookie cleared, old cookie 401, other sessions unaffected.',
    );

    // Additional probe-owned candidates exercise the real list/auth filters.
    const dead = await login(issuer, 0);
    await states.invalidate(dead);
    const corrupt = await login(issuer, 0);
    await observer.setWithTtl(
      buildRedisKey('session', corrupt),
      '{invalid',
      60,
    );
    const mismatch = await login(issuer, 0);
    const mismatchState = await states.read(mismatch);
    assert.ok(mismatchState);
    await states.create(mismatch, { ...mismatchState, userId: users[1] });
    const dbExpired = await login(issuer, 0);
    await prisma.session.update({
      where: { id: dbExpired },
      data: { expiresAt: new Date(Date.now() - 1) },
    });
    const dbRevoked = await login(issuer, 0);
    await prisma.session.update({
      where: { id: dbRevoked },
      data: { status: 'REVOKED' },
    });
    const orphan = randomUUID();
    sessionIds.add(orphan);
    const liveState = await states.read(a3);
    assert.ok(liveState);
    await states.create(orphan, liveState);
    const filtersBefore = await prisma.session.findMany({
      where: { userId: { in: users } },
      orderBy: { id: 'asc' },
    });
    await listed(issuer, a3, [a3]);
    for (const id of [dead, corrupt, mismatch, dbExpired, dbRevoked, orphan])
      await expectError(await send(issuer, 'GET', '/auth/sessions', id), 401);
    assert.deepEqual(
      await prisma.session.findMany({
        where: { userId: { in: users } },
        orderBy: { id: 'asc' },
      }),
      filtersBefore,
    );
    console.log(
      'Live missing/corrupt/wrong-user/expired/revoked/orphan runtime checks passed; list excludes stale candidates without persistence cleanup writes.',
    );

    // Only the temporary AppModule client uses this bounded TCP gateway.
    await new Promise<void>((resolve, reject) => {
      gateway.once('error', reject);
      gateway.listen(0, '127.0.0.1', () => {
        gateway.off('error', reject);
        resolve();
      });
    });
    const address = gateway.address();
    assert.ok(address && typeof address !== 'string');
    const proxyUrl = new URL(redisUrl);
    proxyUrl.hostname = '127.0.0.1';
    proxyUrl.port = String(address.port);
    class GatedLogout extends IdpLogoutService {
      override async logout(id: string): Promise<void> {
        if (id === gatedSelfId) {
          if (++selfArrivals === 2) releaseSelf();
          // Prove the race after both authenticate; bound the test-only barrier.
          await Promise.race([
            bothAuthenticated,
            setTimeout(5000).then(() => {
              throw new Error('Self-revoke probe barrier timeout.');
            }),
          ]);
        }
        await super.logout(id);
      }
    }
    const module = await Test.createTestingModule({ imports: [AppModule] })
      .setLogger(logger)
      .overrideProvider(ConfigService)
      .useValue({
        getOrThrow: (
          name: keyof Environment,
        ): Environment[keyof Environment] =>
          name === 'REDIS_URL'
            ? proxyUrl.toString()
            : config.getOrThrow(name, { infer: true }),
      })
      .overrideProvider(IdpLogoutService)
      .useFactory({
        inject: [IdpSessionStateService, PrismaService],
        factory: (runtime: IdpSessionStateService, database: PrismaService) =>
          new GatedLogout(runtime, database),
      })
      .compile();
    app = module.createNestApplication({ logger });
    await app.listen(0, '127.0.0.1');
    const origin = await app.getUrl();
    const sameClient = app.get(RedisService);
    await ready(sameClient);
    const outageRow = await prisma.session.findUniqueOrThrow({
      where: { id: a3 },
    });
    const outageState = await states.read(a3);
    gatewayEnabled = false;
    for (const socket of sockets) socket.destroy();
    const deadline = Date.now() + 5000;
    for (;;) {
      try {
        await sameClient.ttl(rateKeys[0]);
      } catch {
        break;
      }
      if (Date.now() >= deadline)
        throw new Error('Own-session proxy outage did not take effect.');
      await setTimeout(50);
    }
    await expectError(await send(origin, 'GET', '/auth/sessions', a3), 500);
    await expectError(
      await send(origin, 'DELETE', '/auth/sessions/' + a3, a3),
      500,
    );
    assert.deepEqual(
      await prisma.session.findUnique({ where: { id: a3 } }),
      outageRow,
    );
    assert.deepEqual(await states.read(a3), outageState);
    await expectError(await send(origin, 'GET', '/auth/sessions'), 401);
    const health = await fetch(new URL('/health', origin), {
      signal: AbortSignal.timeout(5000),
    });
    assert.equal(health.status, 200);
    assert.deepEqual(await health.json(), { status: 'ok' });
    gatewayEnabled = true;
    await ready(sameClient);
    assert.equal(app.get(RedisService), sameClient);
    await listed(origin, a3, [a3]);
    console.log(
      'Redis outage passed: list/revoke 500 fail closed with no DB-only fallback or mutation; same client reconnects and list recovers without app restart.',
    );

    gatedSelfId = await login(origin, 0);
    const selfBefore = await prisma.session.findUniqueOrThrow({
      where: { id: gatedSelfId },
    });
    await Promise.all(
      [0, 1].map(async () =>
        revokedResponse(
          await send(
            origin,
            'DELETE',
            '/auth/sessions/' + gatedSelfId!,
            gatedSelfId,
          ),
          true,
        ),
      ),
    );
    assert.equal(selfArrivals, 2);
    await removed(gatedSelfId);
    assert.deepEqual(
      await prisma.session.findUnique({ where: { id: gatedSelfId } }),
      { ...selfBefore, status: 'REVOKED' },
    );
    await listed(origin, a3, [a3]);
    await expectError(
      await send(origin, 'GET', '/auth/sessions', gatedSelfId),
      401,
    );
    console.log(
      'Controlled concurrent live self-revoke after both authenticate passed: both 204/clear, Redis absent, row retained REVOKED, no resurrection.',
    );
    const captured = logs.join('\n');
    for (const secret of [
      ...users,
      ...emails,
      password,
      ...sessionIds,
      redisUrl.toString(),
      proxyUrl.toString(),
      config.getOrThrow('DATABASE_URL', { infer: true }),
      'session:',
      'iam.sid=',
    ])
      assert.ok(!captured.includes(secret));
    console.log(
      'Own-session captured logs contain no probe subjects, session/cookie values, keys, passwords or URLs.',
    );
  } finally {
    gatewayEnabled = true;
    releaseSelf();
    try {
      if (dataAllowed) {
        await ready(observer);
        const rows = await prisma.session.findMany({
          where: { userId: { in: users } },
          select: { id: true },
        });
        for (const row of rows) sessionIds.add(row.id);
        for (const id of sessionIds) {
          const key = buildRedisKey('session', id);
          await observer.delete(key);
          assert.equal(await observer.get(key), null);
        }
        for (const key of rateKeys) {
          await observer.delete(key);
          assert.equal(await observer.get(key), null);
        }
        await prisma.$transaction([
          prisma.session.deleteMany({ where: { userId: { in: users } } }),
          prisma.credential.deleteMany({ where: { userId: { in: users } } }),
          prisma.user.deleteMany({ where: { id: { in: users } } }),
        ]);
        assert.equal(
          await prisma.session.count({ where: { userId: { in: users } } }),
          0,
        );
        assert.equal(
          await prisma.credential.count({ where: { userId: { in: users } } }),
          0,
        );
        assert.equal(
          await prisma.user.count({ where: { id: { in: users } } }),
          0,
        );
        console.log(
          'Own-session cleanup passed: no owned Users/Credentials/Sessions/rate/session keys remain.',
        );
      }
    } finally {
      try {
        await app?.close();
      } finally {
        for (const socket of sockets) socket.destroy();
        try {
          if (gateway.listening)
            await new Promise<void>((resolve, reject) =>
              gateway.close((error) => (error ? reject(error) : resolve())),
            );
        } finally {
          await context.close();
        }
      }
    }
  }
}
void checkOwnSessions().catch(() => {
  // Assertion errors can include session/credential state: print only fixed text.
  console.error('Own-session integration verification failed.');
  process.exitCode = 1;
});
