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

@Module({
  imports: [AppConfigModule, PrismaModule, SessionModule],
  providers: [PasswordService],
})
class LogoutCheckModule {}

async function checkLogout(): Promise<void> {
  const context = await NestFactory.createApplicationContext(
    LogoutCheckModule,
    {
      logger: false,
      abortOnError: false,
    },
  );
  const config = context.get<ConfigService<Environment, true>>(ConfigService);
  const prisma = context.get(PrismaService);
  const observer = context.get(RedisService);
  const states = context.get(IdpSessionStateService);
  const cookies = context.get(IdpSessionCookieService);
  const userId = randomUUID();
  const password = 'temporary-probe-' + randomUUID();
  const email = 'm35-' + randomUUID() + '@example.invalid';
  const sessionIds = new Set<string>();
  const rateKey = buildRedisKey('rate', userId, 'login-failure');
  const sockets = new Set<Socket>();
  let gatewayEnabled = true;
  let dbFault = false;
  let revokeCalls = 0;
  let app: INestApplication | undefined;
  let dataAllowed = false;
  const redisUrl = new URL(config.getOrThrow('REDIS_URL', { infer: true }));
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
        await redis.ttl(rateKey);
        return;
      } catch {
        if (Date.now() >= deadline)
          throw new Error('Logout probe Redis readiness timeout.');
        await setTimeout(50);
      }
    }
  };
  const post = (
    origin: string,
    path: string,
    cookie?: string,
    body?: unknown,
  ): Promise<Response> =>
    fetch(new URL(path, origin), {
      method: 'POST',
      headers: {
        ...(cookie === undefined ? {} : { Cookie: cookie }),
        ...(body === undefined ? {} : { 'Content-Type': 'application/json' }),
      },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      signal: AbortSignal.timeout(10000),
    });
  const success = async (response: Response): Promise<void> => {
    assert.equal(response.status, 204);
    assert.equal(await response.text(), '');
    assert.deepEqual(response.headers.getSetCookie(), [cookies.clear()]);
  };
  const failure = async (response: Response): Promise<void> => {
    assert.equal(response.status, 500);
    assert.equal(response.headers.get('set-cookie'), null);
    assert.deepEqual(await response.json(), {
      statusCode: 500,
      error: 'Internal Server Error',
      message: 'Logout failed.',
    });
  };
  const cookie = (id: string): string =>
    config.getOrThrow('COOKIE_NAME', { infer: true }) + '=' + id;
  const login = async (origin: string): Promise<string> => {
    const response = await post(origin, '/auth/login', undefined, {
      identifier: { type: 'email', value: email },
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
    assert.equal(row.userId, userId);
    assert.equal(row.status, 'ACTIVE');
    assert.deepEqual(await states.read(id), {
      userId,
      authTime: row.createdAt.getTime(),
      mfaLevel: 'password',
      createdAt: row.createdAt.getTime(),
      lastActivityAt: row.lastActivityAt.getTime(),
      absoluteExpiresAt: row.expiresAt.getTime(),
    });
    return id;
  };
  type SessionRow = NonNullable<
    Awaited<ReturnType<typeof prisma.session.findUnique>>
  >;
  const revoked = async (before: SessionRow): Promise<void> => {
    assert.equal(await observer.get(buildRedisKey('session', before.id)), null);
    assert.equal(await states.read(before.id), null);
    assert.equal(await states.touch(before.id), null);
    assert.deepEqual(
      await prisma.session.findUnique({ where: { id: before.id } }),
      { ...before, status: 'REVOKED' },
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
      throw new Error('Logout probe requires the local development stack.');
    dataAllowed = true;
    await ready(observer);
    await prisma.user.create({
      data: {
        id: userId,
        email,
        username: 'm35-' + randomUUID(),
        credential: {
          create: {
            passwordHash: await context.get(PasswordService).hash(password),
          },
        },
      },
    });

    // Primary acceptance exercises the rebuilt, real Compose HTTP application.
    const first = await login(issuer);
    const before = await prisma.session.findUniqueOrThrow({
      where: { id: first },
    });
    await success(await post(issuer, '/auth/logout', cookie(first)));
    await revoked(before);
    await success(await post(issuer, '/auth/logout', cookie(first)));
    await revoked(before);
    console.log(
      'Live Compose logout/repeat passed: 204, cookie cleared, Redis absent/read+touch null, row retained REVOKED with unchanged timestamps/metadata.',
    );

    const unaffected = await login(issuer);
    const rowSnapshot = await prisma.session.findMany({
      orderBy: { id: 'asc' },
    });
    const stateSnapshot = await states.read(unaffected);
    for (const header of [
      undefined,
      'other=unrelated',
      cookie('invalid'),
      cookie(unaffected) + '; ' + cookie(unaffected),
    ])
      await success(await post(issuer, '/auth/logout', header));
    assert.deepEqual(
      await prisma.session.findMany({ orderBy: { id: 'asc' } }),
      rowSnapshot,
    );
    assert.deepEqual(await states.read(unaffected), stateSnapshot);
    console.log(
      'Live missing/malformed/duplicate cookie cleanup passed without modifying Session rows or existing Redis state.',
    );

    const concurrentBefore = await prisma.session.findUniqueOrThrow({
      where: { id: unaffected },
    });
    await Promise.all(
      [0, 1].map(async () =>
        success(await post(issuer, '/auth/logout', cookie(unaffected))),
      ),
    );
    await revoked(concurrentBefore);
    assert.equal(await prisma.session.count({ where: { userId } }), 2);
    const missing = randomUUID();
    assert.equal(
      await prisma.session.findUnique({ where: { id: missing } }),
      null,
    );
    assert.equal(await observer.get(buildRedisKey('session', missing)), null);
    await success(await post(issuer, '/auth/logout', cookie(missing)));
    assert.equal(
      await prisma.session.findUnique({ where: { id: missing } }),
      null,
    );
    assert.equal(await observer.get(buildRedisKey('session', missing)), null);
    const expired = await login(issuer);
    const expiredBefore = await prisma.session.findUniqueOrThrow({
      where: { id: expired },
    });
    await observer.delete(buildRedisKey('session', expired));
    await success(await post(issuer, '/auth/logout', cookie(expired)));
    await revoked(expiredBefore);
    console.log(
      'Live concurrent, unknown UUID and missing runtime state logout passed without new rows or resurrection.',
    );

    // Bounded TCP gateway affects only this temporary AppModule's Redis client.
    // Compose and the direct observer remain online; no topology/process restart.
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
    const proxyConfig = {
      getOrThrow: (name: keyof Environment): Environment[keyof Environment] =>
        name === 'REDIS_URL'
          ? proxyUrl.toString()
          : config.getOrThrow(name, { infer: true }),
    };
    const module = await Test.createTestingModule({ imports: [AppModule] })
      .setLogger(logger)
      .overrideProvider(ConfigService)
      .useValue(proxyConfig)
      .overrideProvider(IdpLogoutService)
      .useFactory({
        inject: [IdpSessionStateService, PrismaService],
        factory: (
          sessions: IdpSessionStateService,
          database: PrismaService,
        ): IdpLogoutService =>
          new IdpLogoutService(sessions, {
            session: {
              updateMany: (input: {
                where: { id: string; status: 'ACTIVE' };
                data: { status: 'REVOKED' };
              }) => {
                revokeCalls++;
                if (dbFault)
                  throw new Error('Controlled private PostgreSQL probe fault.');
                return database.session.updateMany(input);
              },
            },
          } as unknown as PrismaService),
      })
      .compile();
    app = module.createNestApplication({ logger });
    await app.listen(0, '127.0.0.1');
    const origin = await app.getUrl();
    const sameClient = app.get(RedisService);
    await ready(sameClient);
    const outageId = await login(origin);
    const outageBefore = await prisma.session.findUniqueOrThrow({
      where: { id: outageId },
    });
    const outageState = await states.read(outageId);
    gatewayEnabled = false;
    for (const socket of sockets) socket.destroy();
    // Wait for an actual command rejection, not a timing guess or queued write.
    const offlineDeadline = Date.now() + 5000;
    for (;;) {
      try {
        await sameClient.ttl(rateKey);
      } catch {
        break;
      }
      if (Date.now() >= offlineDeadline)
        throw new Error('Logout probe outage did not take effect.');
      await setTimeout(50);
    }
    const callsBefore = revokeCalls;
    await failure(await post(origin, '/auth/logout', cookie(outageId)));
    assert.equal(revokeCalls, callsBefore);
    assert.deepEqual(
      await prisma.session.findUnique({ where: { id: outageId } }),
      outageBefore,
    );
    assert.deepEqual(await states.read(outageId), outageState);
    const health = await fetch(new URL('/health', origin), {
      signal: AbortSignal.timeout(5000),
    });
    assert.equal(health.status, 200);
    assert.deepEqual(await health.json(), { status: 'ok' });
    await success(await post(origin, '/auth/logout')); // Local cleanup needs no Redis.
    gatewayEnabled = true;
    await ready(sameClient);
    assert.equal(app.get(RedisService), sameClient);
    await success(await post(origin, '/auth/logout', cookie(outageId)));
    await revoked(outageBefore);
    console.log(
      'Redis outage passed: generic 500/no cookie/no DB update; process health and no-cookie logout work; same client reconnects and retry completes without app restart.',
    );

    const partialId = await login(origin);
    const partialBefore = await prisma.session.findUniqueOrThrow({
      where: { id: partialId },
    });
    dbFault = true;
    await failure(await post(origin, '/auth/logout', cookie(partialId)));
    assert.equal(await observer.get(buildRedisKey('session', partialId)), null);
    assert.equal(await states.read(partialId), null);
    assert.deepEqual(
      await prisma.session.findUnique({ where: { id: partialId } }),
      partialBefore,
    );
    dbFault = false;
    await success(await post(origin, '/auth/logout', cookie(partialId)));
    await revoked(partialBefore);
    assert.equal(await prisma.session.count({ where: { userId } }), 5);
    console.log(
      'Controlled PostgreSQL revoke failure passed: Redis remains deleted, 500 retains cookie; retry after DEL=0 repairs ACTIVE -> REVOKED.',
    );
    const captured = logs.join('\n');
    for (const secret of [
      userId,
      password,
      email,
      ...sessionIds,
      redisUrl.toString(),
      proxyUrl.toString(),
      config.getOrThrow('DATABASE_URL', { infer: true }),
      'session:',
      cookie(partialId),
      'Controlled private PostgreSQL probe fault.',
    ])
      assert.ok(!captured.includes(secret));
    console.log(
      'Captured application logs contain no probe IDs, cookie values, Redis keys, passwords, URLs or driver fault details.',
    );
  } finally {
    gatewayEnabled = true;
    dbFault = false;
    try {
      if (dataAllowed) {
        await ready(observer);
        const rows = await prisma.session.findMany({
          where: { userId },
          select: { id: true },
        });
        for (const row of rows) sessionIds.add(row.id);
        for (const id of sessionIds) {
          const key = buildRedisKey('session', id);
          await observer.delete(key);
          assert.equal(await observer.get(key), null);
        }
        await observer.delete(rateKey);
        assert.equal(await observer.get(rateKey), null);
        await prisma.$transaction([
          prisma.session.deleteMany({ where: { userId } }),
          prisma.credential.deleteMany({ where: { userId } }),
          prisma.user.deleteMany({ where: { id: userId } }),
        ]);
        assert.equal(await prisma.session.count({ where: { userId } }), 0);
        assert.equal(await prisma.credential.count({ where: { userId } }), 0);
        assert.equal(await prisma.user.count({ where: { id: userId } }), 0);
        console.log(
          'Logout probe cleanup passed: no owned Users/Credentials/Sessions/rate/session keys remain.',
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
void checkLogout().catch(() => {
  // Assertions may contain secret-bearing state; never print errors/causes.
  console.error('Logout integration verification failed.');
  process.exitCode = 1;
});
