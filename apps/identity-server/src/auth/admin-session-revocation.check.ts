import 'reflect-metadata';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { setTimeout } from 'node:timers/promises';
import { Module } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { NestFactory } from '@nestjs/core';
import { AppConfigModule } from '../config/config.module.js';
import type { Environment } from '../config/env.schema.js';
import { PrismaService } from '../prisma/prisma.service.js';
import { RedisService } from '../redis/redis.service.js';
import { buildRedisKey } from '../redis/redis-key.js';
import { IdpSessionStateService } from '../session/idp-session-state.service.js';
import { IdpSessionCookieService } from '../session/idp-session-cookie.service.js';
import { AdminSessionRevocationService } from './admin-session-revocation.service.js';
import { AuthModule } from './auth.module.js';
import { IdpLogoutService } from './idp-logout.service.js';

// Explicit local verification only; no HTTP controller/server for this capability.
@Module({ imports: [AppConfigModule, AuthModule] })
class AdminSessionsCheckModule {}

async function checkAdminSessions(): Promise<void> {
  const context = await NestFactory.createApplicationContext(
    AdminSessionsCheckModule,
    { logger: false, abortOnError: false },
  );
  const config = context.get<ConfigService<Environment, true>>(ConfigService);
  const prisma = context.get(PrismaService);
  const redis = context.get(RedisService);
  const states = context.get(IdpSessionStateService);
  const cookies = context.get(IdpSessionCookieService);
  const service = context.get(AdminSessionRevocationService);
  const userIds = [randomUUID(), randomUUID(), randomUUID()];
  const sessionIds = new Set<string>();
  const rateKeys = userIds.map((id) =>
    buildRedisKey('rate', id, 'login-failure'),
  );
  let dataAllowed = false;
  type Row = NonNullable<Awaited<ReturnType<typeof prisma.session.findUnique>>>;
  const createSession = async (
    userId: string,
    status: 'ACTIVE' | 'REVOKED' = 'ACTIVE',
  ): Promise<Row> => {
    const now = Date.now();
    const absolute =
      now +
      config.getOrThrow('SESSION_ABSOLUTE_TTL_SECONDS', { infer: true }) * 1000;
    const row = await prisma.session.create({
      data: {
        userId,
        status,
        createdAt: new Date(now),
        lastActivityAt: new Date(now),
        expiresAt: new Date(absolute),
      },
    });
    sessionIds.add(row.id);
    await states.create(row.id, {
      userId,
      authTime: now,
      mfaLevel: 'password',
      createdAt: now,
      lastActivityAt: now,
      absoluteExpiresAt: absolute,
    });
    return row;
  };
  const batch = async (): Promise<Row[]> => {
    const rows: Row[] = [];
    for (let index = 0; index < 3; index++)
      rows.push(await createSession(userIds[0]));
    return rows.sort((a, b) => a.id.localeCompare(b.id));
  };
  const assertRevoked = async (rows: Row[]): Promise<void> => {
    for (const row of rows) {
      assert.equal(await redis.get(buildRedisKey('session', row.id)), null);
      assert.equal(await states.read(row.id), null);
      assert.deepEqual(
        await prisma.session.findUnique({ where: { id: row.id } }),
        { ...row, status: 'REVOKED' },
      );
    }
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
      !local(config.getOrThrow('REDIS_URL', { infer: true }))
    )
      throw new Error(
        'Admin-session probe requires the local development stack.',
      );
    dataAllowed = true;
    const deadline = Date.now() + 15000;
    for (;;) {
      try {
        await redis.ttl(rateKeys[0]);
        break;
      } catch {
        if (Date.now() >= deadline)
          throw new Error('Admin-session probe readiness timeout.');
        await setTimeout(50);
      }
    }
    // No credential/admin fixture is needed: these are internal session records,
    // not invented admin authentication. Neither account receives a privilege.
    for (const id of userIds)
      await prisma.user.create({
        data: {
          id,
          email: 'm37-' + randomUUID() + '@example.invalid',
          username: 'm37-' + randomUUID(),
        },
      });
    const usersBefore = await prisma.user.findMany({
      where: { id: { in: userIds } },
      orderBy: { id: 'asc' },
    });
    const other = await createSession(userIds[1]);
    const otherRuntime = await redis.get(buildRedisKey('session', other.id));
    const historical = await createSession(userIds[0], 'REVOKED');
    const historicalRuntime = await redis.get(
      buildRedisKey('session', historical.id),
    );
    const isolation = async (): Promise<void> => {
      assert.deepEqual(
        await prisma.session.findUnique({ where: { id: other.id } }),
        other,
      );
      assert.equal(
        await redis.get(buildRedisKey('session', other.id)),
        otherRuntime,
      );
      assert.deepEqual(
        await prisma.session.findUnique({ where: { id: historical.id } }),
        historical,
      );
      assert.equal(
        await redis.get(buildRedisKey('session', historical.id)),
        historicalRuntime,
      );
      assert.deepEqual(
        await prisma.user.findMany({
          where: { id: { in: userIds } },
          orderBy: { id: 'asc' },
        }),
        usersBefore,
      );
    };

    const initial = await batch();
    await service.revokeUserSessions(userIds[0]);
    await assertRevoked(initial);
    await isolation();
    console.log(
      'Live internal target revocation passed: three ACTIVE rows retained REVOKED, Redis/read absent, timestamps/metadata unchanged, other user/history/account state unchanged.',
    );

    const snapshot = await prisma.session.findMany({
      where: { userId: { in: userIds } },
      orderBy: { id: 'asc' },
    });
    for (const id of [randomUUID(), userIds[2], userIds[0]])
      await service.revokeUserSessions(id);
    assert.deepEqual(
      await prisma.session.findMany({
        where: { userId: { in: userIds } },
        orderBy: { id: 'asc' },
      }),
      snapshot,
    );
    await isolation();
    await assert.rejects(service.revokeUserSessions('user:' + userIds[0]), {
      message: 'Admin session revocation failed.',
    });
    console.log(
      'Unknown/empty/already-processed target success and malformed UUID rejection passed without mutations.',
    );

    const missing = await createSession(userIds[0]);
    await states.invalidate(missing.id);
    await service.revokeUserSessions(userIds[0]);
    await assertRevoked([missing]);
    await isolation();
    console.log(
      'Redis-missing ACTIVE row passed: DEL=0 followed by persistent REVOKED without runtime pre-read.',
    );

    const partial = await batch();
    let fail = true;
    const attempted: string[] = [];
    const faultDatabase = {
      session: {
        updateMany: (input: {
          where: { id: string; status: 'ACTIVE' };
          data: { status: 'REVOKED' };
        }) => {
          attempted.push(input.where.id);
          if (fail && input.where.id === partial[1].id)
            throw new Error(
              'Controlled private PostgreSQL failure ' + userIds[0],
              { cause: new Error('private cause') },
            );
          return prisma.session.updateMany(input);
        },
      },
    } as unknown as PrismaService;
    const partialService = new AdminSessionRevocationService(
      prisma,
      new IdpLogoutService(states, faultDatabase),
    );
    await assert.rejects(partialService.revokeUserSessions(userIds[0]), {
      message: 'Admin session revocation failed.',
    });
    assert.deepEqual(
      attempted,
      partial.slice(0, 2).map((row) => row.id),
    );
    await assertRevoked([partial[0]]);
    assert.equal(
      await redis.get(buildRedisKey('session', partial[1].id)),
      null,
    );
    assert.deepEqual(
      await prisma.session.findUnique({ where: { id: partial[1].id } }),
      partial[1],
    );
    assert.deepEqual(
      await prisma.session.findUnique({ where: { id: partial[2].id } }),
      partial[2],
    );
    assert.ok(await states.read(partial[2].id));
    await isolation();
    fail = false;
    attempted.length = 0;
    await partialService.revokeUserSessions(userIds[0]);
    assert.deepEqual(
      attempted,
      partial.slice(1).map((row) => row.id),
    );
    await assertRevoked(partial);
    await isolation();
    console.log(
      'Live sequential partial failure/retry passed: S1 stays revoked, S2 Redis-deleted/DB-ACTIVE, S3 untouched; retry rediscovers only S2/S3 and completes with no restoration.',
    );

    const concurrent = await batch();
    await Promise.all([
      service.revokeUserSessions(userIds[0]),
      service.revokeUserSessions(userIds[0]),
    ]);
    await assertRevoked(concurrent);
    await isolation();
    console.log(
      'Concurrent privileged calls passed: snapshot rows retained REVOKED and runtime absent with no new row/resurrection.',
    );

    const race = await batch();
    const ownLogout = fetch(new URL('/auth/logout', issuer), {
      method: 'POST',
      headers: {
        Cookie:
          config.getOrThrow('COOKIE_NAME', { infer: true }) + '=' + race[1].id,
      },
      signal: AbortSignal.timeout(10000),
    });
    const [, response] = await Promise.all([
      service.revokeUserSessions(userIds[0]),
      ownLogout,
    ]);
    assert.equal(response.status, 204);
    assert.equal(await response.text(), '');
    assert.deepEqual(response.headers.getSetCookie(), [cookies.clear()]);
    await assertRevoked(race);
    await isolation();
    console.log(
      'Concurrent real POST /auth/logout and internal target revocation passed; DEL=0/update count=0 are safe idempotent outcomes.',
    );

    const beforeLate = await batch();
    let late: Row | undefined;
    class SnapshotLogout extends IdpLogoutService {
      override async logout(id: string): Promise<void> {
        if (late === undefined) late = await createSession(userIds[0]);
        await super.logout(id);
      }
    }
    await new AdminSessionRevocationService(
      prisma,
      new SnapshotLogout(states, prisma),
    ).revokeUserSessions(userIds[0]);
    await assertRevoked(beforeLate);
    assert.ok(late);
    assert.deepEqual(
      await prisma.session.findUnique({ where: { id: late.id } }),
      late,
    );
    assert.ok(await states.read(late.id));
    await isolation();
    await service.revokeUserSessions(userIds[0]);
    await assertRevoked([late]);
    console.log(
      'Live snapshot boundary passed: a newly created post-discovery session remains ACTIVE/live; later invocation can revoke it without account disablement.',
    );

    // Read-only HTTP absence checks; the revocation capability has no route.
    for (const [method, path] of [
      ['DELETE', '/admin/users/' + userIds[0] + '/sessions'],
      ['POST', '/admin/users/' + userIds[0] + '/revoke-sessions'],
      ['DELETE', '/management/users/' + userIds[0] + '/sessions'],
      ['POST', '/auth/admin/revoke-sessions'],
    ]) {
      const result = await fetch(new URL(path, issuer), {
        method,
        signal: AbortSignal.timeout(10000),
      });
      assert.equal(result.status, 404);
      assert.equal(result.headers.get('set-cookie'), null);
      await result.text();
    }
    // A still-live foreign session cannot use request data to gain target-user
    // authority through the unchanged M3.6 route.
    await isolation();
    const beforeIdor = await states.read(other.id);
    assert.ok(beforeIdor);
    const idor = await fetch(
      new URL(
        '/auth/sessions/' + initial[0].id + '?userId=' + userIds[0],
        issuer,
      ),
      {
        method: 'DELETE',
        headers: {
          Cookie:
            config.getOrThrow('COOKIE_NAME', { infer: true }) + '=' + other.id,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ userId: userIds[0] }),
        signal: AbortSignal.timeout(10000),
      },
    );
    assert.equal(idor.status, 404);
    assert.deepEqual(await idor.json(), {
      statusCode: 404,
      error: 'Not Found',
      message: 'Session not found.',
    });
    assert.equal(idor.headers.get('set-cookie'), null);
    // This own-session HTTP request legitimately touches its current O1 cookie;
    // distinguish that existing activity from the internal revocation operation.
    const afterIdor = await states.read(other.id);
    assert.ok(afterIdor);
    assert.deepEqual(afterIdor, {
      ...beforeIdor,
      lastActivityAt: afterIdor.lastActivityAt,
    });
    assert.ok(afterIdor.lastActivityAt >= beforeIdor.lastActivityAt);
    assert.deepEqual(
      await prisma.session.findUnique({ where: { id: other.id } }),
      other,
    );
    assert.equal(
      await prisma.session.count({ where: { userId: { in: userIds } } }),
      sessionIds.size,
    );
    console.log(
      'Dangerous admin HTTP paths remain 404; M3.6 cross-user ownership boundary remains intact, with no public privileged authority.',
    );
  } finally {
    try {
      if (dataAllowed) {
        const rows = await prisma.session.findMany({
          where: { userId: { in: userIds } },
          select: { id: true },
        });
        for (const row of rows) sessionIds.add(row.id);
        for (const id of sessionIds) {
          const key = buildRedisKey('session', id);
          await redis.delete(key);
          assert.equal(await redis.get(key), null);
        }
        for (const key of rateKeys) {
          await redis.delete(key);
          assert.equal(await redis.get(key), null);
        }
        await prisma.$transaction([
          prisma.session.deleteMany({ where: { userId: { in: userIds } } }),
          prisma.credential.deleteMany({ where: { userId: { in: userIds } } }),
          prisma.user.deleteMany({ where: { id: { in: userIds } } }),
        ]);
        assert.equal(
          await prisma.session.count({ where: { userId: { in: userIds } } }),
          0,
        );
        assert.equal(
          await prisma.credential.count({ where: { userId: { in: userIds } } }),
          0,
        );
        assert.equal(
          await prisma.user.count({ where: { id: { in: userIds } } }),
          0,
        );
        console.log(
          'Admin-session cleanup passed: no owned Users/Credentials/Sessions/session/rate keys remain; no temporary HTTP server/proxy was created.',
        );
      }
    } finally {
      await context.close();
    }
  }
}
void checkAdminSessions().catch(() => {
  // Assertions may contain IDs/runtime state; never print error/cause chains.
  console.error('Admin-session integration verification failed.');
  process.exitCode = 1;
});
