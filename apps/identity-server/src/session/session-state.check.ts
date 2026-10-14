import 'reflect-metadata';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { setTimeout } from 'node:timers/promises';
import { Module } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { NestFactory } from '@nestjs/core';
import { AppConfigModule } from '../config/config.module.js';
import type { Environment } from '../config/env.schema.js';
import { buildRedisKey } from '../redis/redis-key.js';
import { RedisService } from '../redis/redis.service.js';
import { IdpSessionStateService } from './idp-session-state.service.js';
import {
  type IdpSessionState,
  parseIdpSessionState,
} from './idp-session-state.js';
import { SessionModule } from './session.module.js';

@Module({ imports: [AppConfigModule, SessionModule] })
class SessionStateCheckModule {}

async function checkSessionState(): Promise<void> {
  const context = await NestFactory.createApplicationContext(
    SessionStateCheckModule,
    {
      logger: false,
      abortOnError: false,
    },
  );
  const redis = context.get(RedisService);
  const config = context.get<ConfigService<Environment, true>>(ConfigService);
  const ownedKeys = new Set<string>();
  const newId = (): string => {
    const id = randomUUID();
    ownedKeys.add(buildRedisKey('session', id));
    return id;
  };
  const key = (id: string): string => buildRedisKey('session', id);
  const state = (absoluteRemainingMs: number): IdpSessionState => {
    const now = Date.now();
    return {
      userId: randomUUID(),
      authTime: now,
      mfaLevel: 'password',
      createdAt: now,
      lastActivityAt: now,
      absoluteExpiresAt: now + absoluteRemainingMs,
    };
  };
  // Short, test-only idle values. No production config/default is changed.
  const sessions = (idleSeconds: number): IdpSessionStateService =>
    new IdpSessionStateService(
      redis,
      new ConfigService<Environment, true>({
        SESSION_IDLE_TTL_SECONDS: idleSeconds,
        SESSION_ABSOLUTE_TTL_SECONDS: config.getOrThrow<number>(
          'SESSION_ABSOLUTE_TTL_SECONDS',
        ),
      }),
    );
  const idle = sessions(2);
  const absolute = sessions(10);

  try {
    // Only readiness reads retry; never queue/retry security state mutations.
    const readinessDeadline = Date.now() + 10000;
    const readinessId = newId();
    for (;;) {
      try {
        await redis.ttl(key(readinessId));
        break;
      } catch {
        if (Date.now() >= readinessDeadline)
          throw new Error('Session probe readiness timeout.');
        await setTimeout(50);
      }
    }

    const idleId = newId();
    const original = state(10000);
    assert.equal(key(idleId), 'session:' + idleId);
    await idle.create(idleId, original);
    const raw = await redis.get(key(idleId));
    assert.deepEqual(parseIdpSessionState(raw), original);
    assert.deepEqual(
      Object.keys(JSON.parse(raw ?? 'null') as object).sort(),
      [
        'userId',
        'authTime',
        'mfaLevel',
        'createdAt',
        'lastActivityAt',
        'absoluteExpiresAt',
      ].sort(),
    );
    assert.equal(await redis.get('iam:' + key(idleId)), null);
    assert.equal(await redis.get('idp:' + key(idleId)), null);
    assert.equal(await redis.get('session:{' + idleId + '}'), null);
    const initialTtl = await redis.ttl(key(idleId));
    assert.ok(initialTtl >= 1 && initialTtl <= 2);
    await setTimeout(700);
    assert.deepEqual(await idle.read(idleId), original);
    const afterReadTtl = await redis.ttl(key(idleId));
    assert.ok(afterReadTtl >= 0 && afterReadTtl <= initialTtl);
    await setTimeout(400);
    const touched = await idle.touch(idleId);
    assert.ok(touched);
    assert.ok(touched.lastActivityAt > original.lastActivityAt);
    assert.deepEqual(
      { ...touched, lastActivityAt: original.lastActivityAt },
      original,
    );
    const afterTouchTtl = await redis.ttl(key(idleId));
    assert.ok(afterTouchTtl >= 1 && afterTouchTtl <= 2);
    await setTimeout(1200);
    assert.ok(await idle.read(idleId)); // Alive beyond the original idle deadline.
    await setTimeout(1000);
    assert.equal(await idle.read(idleId), null); // The previous read did not refresh.
    assert.equal(await idle.touch(idleId), null);
    assert.equal(await redis.get(key(idleId)), null);
    assert.equal(await redis.ttl(key(idleId)), -2);
    console.log(
      'Session idle expiry, activity refresh and non-refreshing read passed.',
    );

    const missingId = newId();
    assert.equal(await absolute.read(missingId), null);
    assert.equal(await absolute.touch(missingId), null);
    assert.equal(await redis.get(key(missingId)), null);

    const absoluteId = newId();
    const bounded = state(2100);
    await absolute.create(absoluteId, bounded);
    const boundedTtl = await redis.ttl(key(absoluteId));
    assert.ok(boundedTtl >= 0 && boundedTtl <= 2);
    let successes = 0;
    while (Date.now() < bounded.absoluteExpiresAt + 200) {
      const results = await Promise.all(
        Array.from({ length: 4 }, () => absolute.touch(absoluteId)),
      );
      for (const updated of results) {
        if (!updated) continue;
        successes++;
        assert.ok(updated.lastActivityAt < bounded.absoluteExpiresAt);
        assert.deepEqual(
          { ...updated, lastActivityAt: bounded.lastActivityAt },
          bounded,
        );
      }
      await setTimeout(100);
    }
    assert.ok(successes > 0);
    assert.equal(await absolute.read(absoluteId), null);
    assert.equal(await absolute.touch(absoluteId), null);
    assert.equal(await redis.get(key(absoluteId)), null);
    assert.equal(await redis.ttl(key(absoluteId)), -2);
    console.log(
      'Session absolute cap and concurrent/missing/expired no-resurrection passed.',
    );

    const expired = {
      ...state(10000),
      authTime: 0,
      createdAt: 0,
      lastActivityAt: 0,
      absoluteExpiresAt: 1,
    };
    const expiredCreateId = newId();
    await assert.rejects(absolute.create(expiredCreateId, expired), {
      message: 'IdP session state is already expired.',
    });
    assert.equal(await redis.get(key(expiredCreateId)), null);
    for (const operation of ['read', 'touch'] as const) {
      const id = newId();
      await redis.setWithTtl(key(id), JSON.stringify(expired), 10);
      assert.equal(await absolute[operation](id), null);
      assert.equal(await redis.get(key(id)), null);
    }

    const valid = state(10000);
    const badObjects: unknown[] = [
      {},
      [],
      'string',
      null,
      { ...valid, userId: undefined },
      { ...valid, userId: 'invalid' },
      { ...valid, userId: 'FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF' },
      { ...valid, userId: '12345678-1234-9234-8234-123456789abc' },
      { ...valid, userId: '12345678-1234-4234-7234-123456789abc' },
      { ...valid, absoluteExpiresAt: undefined },
      { ...valid, mfaLevel: '' },
      { ...valid, mfaLevel: 1 },
      { ...valid, extra: true },
      { ...valid, absoluteExpiresAt: valid.createdAt },
      { ...valid, authTime: valid.absoluteExpiresAt },
      { ...valid, lastActivityAt: valid.absoluteExpiresAt },
      ...(
        [
          'authTime',
          'createdAt',
          'lastActivityAt',
          'absoluteExpiresAt',
        ] as const
      ).flatMap((field) =>
        [
          undefined,
          '123',
          -1,
          1.5,
          NaN,
          Infinity,
          Number.MAX_SAFE_INTEGER + 1,
        ].map((value) => ({ ...valid, [field]: value })),
      ),
    ];
    const malformed = [
      '{',
      JSON.stringify(valid).replace(String(valid.authTime), 'NaN'),
      JSON.stringify(valid).replace(String(valid.authTime), 'Infinity'),
      ...badObjects.map((input) => JSON.stringify(input)),
    ];
    for (const rawState of malformed) {
      for (const operation of ['read', 'touch'] as const) {
        const id = newId();
        await redis.setWithTtl(key(id), rawState, 10);
        assert.equal(await absolute[operation](id), null);
        assert.equal(await redis.get(key(id)), null);
      }
    }
    for (const badState of badObjects) {
      const id = newId();
      await assert.rejects(absolute.create(id, badState as IdpSessionState), {
        message: 'Invalid IdP session state.',
      });
      assert.equal(await redis.get(key(id)), null);
    }
    console.log(
      'Session strict validation, malformed cleanup and absolute invalidation passed.',
    );

    const precisionId = newId();
    const precision = {
      ...state(10000),
      absoluteExpiresAt: Number.MAX_SAFE_INTEGER,
      mfaLevel: ' opaque/未来 "metadata" ',
    };
    await absolute.create(precisionId, precision);
    const preciseTouch = await absolute.touch(precisionId);
    assert.ok(preciseTouch);
    assert.deepEqual(
      { ...preciseTouch, lastActivityAt: precision.lastActivityAt },
      precision,
    );
    assert.deepEqual(
      parseIdpSessionState(await redis.get(key(precisionId))),
      preciseTouch,
    );
    // Huge validated seconds still cap safely at the authoritative timestamp.
    const hugeIdleId = newId();
    await sessions(Number.MAX_SAFE_INTEGER).create(hugeIdleId, state(2000));
    const hugeIdleTtl = await redis.ttl(key(hugeIdleId));
    assert.ok(hugeIdleTtl >= 0 && hugeIdleTtl <= 2);
    console.log(
      'Session lossless safe integers, opaque MFA metadata and large-idle cap passed.',
    );
  } finally {
    try {
      for (const ownedKey of ownedKeys) {
        await redis.delete(ownedKey);
        assert.equal(await redis.get(ownedKey), null);
      }
      console.log('Session probe cleanup passed; all owned keys removed.');
    } finally {
      await context.close();
    }
  }
}

void checkSessionState().catch(() => {
  // Do not print assertions/driver causes containing keys, users or raw state.
  console.error('Session state integration verification failed.');
  process.exitCode = 1;
});
