import 'reflect-metadata';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { setTimeout } from 'node:timers/promises';
import { Module } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { NestFactory } from '@nestjs/core';
import { AppConfigModule } from '../config/config.module.js';
import type { Environment } from '../config/env.schema.js';
import { PrismaModule } from '../prisma/prisma.module.js';
import { PrismaService } from '../prisma/prisma.service.js';
import { RedisModule } from '../redis/redis.module.js';
import { RedisService } from '../redis/redis.service.js';
import { buildRedisKey } from '../redis/redis-key.js';
import { PasswordService } from '../security/password/password.service.js';
import { SessionModule } from '../session/session.module.js';
import { IdpSessionCookieService } from '../session/idp-session-cookie.service.js';
import { IdpSessionStateService } from '../session/idp-session-state.service.js';
import { parseIdpSessionState } from '../session/idp-session-state.js';
import { IdpLoginService } from './idp-login.service.js';
import { LoginAttemptService } from './login-attempt.service.js';
import {
  LoginValidationService,
  type LoginIdentifier,
} from './login-validation.service.js';

@Module({
  imports: [AppConfigModule, PrismaModule, RedisModule, SessionModule],
  providers: [
    PasswordService,
    LoginValidationService,
    LoginAttemptService,
    IdpLoginService,
  ],
})
class LoginCheckModule {}

async function checkLogin(): Promise<void> {
  const context = await NestFactory.createApplicationContext(LoginCheckModule, {
    logger: false,
    abortOnError: false,
  });
  const config = context.get<ConfigService<Environment, true>>(ConfigService);
  const prisma = context.get(PrismaService);
  const redis = context.get(RedisService);
  const cookies = context.get(IdpSessionCookieService);
  const userIds = [randomUUID(), randomUUID()];
  const sessionIds = new Set<string>();
  const attackerId = randomUUID();
  const password = 'temporary-probe-' + randomUUID();
  const tag = randomUUID();
  const email = 'm34-' + tag + '@example.invalid';
  const username = 'm34-' + tag;
  const secondEmail = 'm34-missing-' + tag + '@example.invalid';
  const rateKeys = userIds.map((id) =>
    buildRedisKey('rate', id, 'login-failure'),
  );
  let dataAllowed = false;
  try {
    const issuer = new URL(config.getOrThrow<string>('ISSUER_URL'));
    const local = (value: string): boolean =>
      ['localhost', '127.0.0.1', '[::1]'].includes(new URL(value).hostname);
    if (
      config.getOrThrow<string>('NODE_ENV') === 'production' ||
      issuer.protocol !== 'http:' ||
      !local(issuer.toString()) ||
      !local(config.getOrThrow<string>('DATABASE_URL')) ||
      !local(config.getOrThrow<string>('REDIS_URL'))
    ) {
      throw new Error('Login probe requires the local development stack.');
    }
    dataAllowed = true;
    const deadline = Date.now() + 10000;
    for (;;) {
      try {
        await redis.ttl(rateKeys[0]);
        break;
      } catch {
        if (Date.now() >= deadline)
          throw new Error('Login probe Redis readiness timeout.');
        await setTimeout(50);
      }
    }
    const hash = await context.get(PasswordService).hash(password);
    await prisma.user.create({
      data: {
        id: userIds[0],
        email,
        username,
        credential: { create: { passwordHash: hash } },
      },
    });
    await prisma.user.create({
      data: {
        id: userIds[1],
        email: secondEmail,
        username: 'm34-missing-' + tag,
      },
    });
    const url = new URL('/auth/login', issuer).toString();
    const post = (
      identifier: LoginIdentifier,
      rawPassword = password,
      cookie?: string,
    ): Promise<Response> =>
      fetch(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(cookie === undefined ? {} : { Cookie: cookie }),
        },
        body: JSON.stringify({ identifier, password: rawPassword }),
        signal: AbortSignal.timeout(10000),
      });
    const accept = async (
      identifier: LoginIdentifier,
      incoming?: string,
    ): Promise<string> => {
      const response = await post(identifier, password, incoming);
      assert.equal(response.status, 204);
      assert.equal(await response.text(), '');
      const headers = response.headers.getSetCookie();
      assert.equal(headers.length, 1);
      const id = cookies.parse(headers[0].split(';')[0]);
      assert.ok(id);
      sessionIds.add(id);
      assert.equal(headers[0], cookies.serialize(id));
      const row = await prisma.session.findUniqueOrThrow({ where: { id } });
      assert.equal(row.userId, userIds[0]);
      assert.equal(row.status, 'ACTIVE');
      assert.equal(row.ipAddress, null);
      assert.equal(row.userAgent, null);
      const now = row.createdAt.getTime();
      const expires = row.expiresAt.getTime();
      assert.equal(row.lastActivityAt.getTime(), now);
      assert.equal(
        expires - now,
        config.getOrThrow<number>('SESSION_ABSOLUTE_TTL_SECONDS') * 1000,
      );
      const raw = await redis.get(buildRedisKey('session', id));
      assert.deepEqual(parseIdpSessionState(raw), {
        userId: row.userId,
        authTime: now,
        mfaLevel: 'password',
        createdAt: now,
        lastActivityAt: now,
        absoluteExpiresAt: expires,
      });
      assert.equal(Object.keys(JSON.parse(raw ?? 'null') as object).length, 6);
      const ttl = await redis.ttl(buildRedisKey('session', id));
      assert.ok(
        ttl > 0 && ttl <= config.getOrThrow<number>('SESSION_IDLE_TTL_SECONDS'),
      );
      assert.ok(ttl * 1000 <= expires - Date.now() + 1000);
      return id;
    };
    const attackerKey = buildRedisKey('session', attackerId);
    assert.equal(await redis.get(attackerKey), null);
    const first = await accept(
      { type: 'email', value: email },
      config.getOrThrow<string>('COOKIE_NAME') + '=' + attackerId,
    );
    assert.notEqual(first, attackerId);
    assert.equal(
      await prisma.session.findUnique({ where: { id: attackerId } }),
      null,
    );
    assert.equal(await redis.get(attackerKey), null);
    const [second, third] = await Promise.all([
      accept({ type: 'email', value: email }),
      accept({ type: 'username', value: username }),
    ]);
    assert.equal(new Set([first, second, third]).size, 3);
    assert.equal(
      await prisma.session.count({ where: { userId: userIds[0] } }),
      3,
    );
    console.log(
      'Live login 204/cookie, same DB/Redis ID and expiry, fixation and concurrent logins passed.',
    );
    const genericFailure = async (
      identifier: LoginIdentifier,
      rawPassword = password,
    ): Promise<void> => {
      const response = await post(identifier, rawPassword);
      assert.equal(response.status, 401);
      assert.equal(response.headers.get('set-cookie'), null);
      assert.deepEqual(await response.json(), {
        statusCode: 401,
        error: 'Unauthorized',
        message: 'Invalid login credentials.',
      });
      assert.equal(
        await prisma.session.count({ where: { userId: { in: userIds } } }),
        3,
      );
    };
    await genericFailure({ type: 'username', value: 'unknown-' + tag });
    await genericFailure({ type: 'email', value: secondEmail });
    await genericFailure(
      { type: 'email', value: email },
      'wrong-temporary-input',
    );
    await prisma.user.update({
      where: { id: userIds[0] },
      data: { status: 'DISABLED' },
    });
    await genericFailure({ type: 'email', value: email });
    await prisma.user.update({
      where: { id: userIds[0] },
      data: { status: 'ACTIVE', lockedUntil: new Date(Date.now() + 60000) },
    });
    await genericFailure({ type: 'username', value: username });
    await prisma.user.update({
      where: { id: userIds[0] },
      data: { lockedUntil: null },
    });
    console.log(
      'Live unknown/missing Credential/wrong password/disabled/locked responses are equivalent 401.',
    );
    // Real DB rollback: fail only the Redis creation boundary after ordinary
    // credential authentication/reset. No lifecycle deletion API is introduced.
    class FailingState extends IdpSessionStateService {
      override create(id: string): Promise<void> {
        sessionIds.add(id);
        return Promise.reject(new Error('Controlled probe Redis failure.'));
      }
    }
    const failingLogin = new IdpLoginService(
      context.get(LoginAttemptService),
      prisma,
      new FailingState(redis, config),
      config,
    );
    await assert.rejects(
      failingLogin.login({ type: 'email', value: email }, password),
      { message: 'IdP login failed.' },
    );
    assert.equal(
      await prisma.session.count({ where: { userId: { in: userIds } } }),
      3,
    );
    for (const id of sessionIds) {
      if ([first, second, third].includes(id)) continue;
      assert.equal(await prisma.session.findUnique({ where: { id } }), null);
      assert.equal(await redis.get(buildRedisKey('session', id)), null);
    }
    console.log(
      'Real PostgreSQL rollback after controlled Redis state creation failure passed.',
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
          'Login probe cleanup passed: no owned Users/Credentials/Sessions/rate/session keys remain.',
        );
      }
    } finally {
      await context.close();
    }
  }
}
void checkLogin().catch(() => {
  // Assertions can contain credentials/state; never print errors or causes.
  console.error('Login integration verification failed.');
  process.exitCode = 1;
});
