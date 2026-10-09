import 'reflect-metadata';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { setTimeout } from 'node:timers/promises';
import { NestFactory } from '@nestjs/core';
import { Module } from '@nestjs/common';
import { AppConfigModule } from '../config/config.module.js';
import { buildRedisKey } from './redis-key.js';
import { RedisModule } from './redis.module.js';
import { RedisService } from './redis.service.js';

@Module({ imports: [AppConfigModule, RedisModule] })
class RedisCheckModule {}

async function checkRedis(): Promise<void> {
  const context = await NestFactory.createApplicationContext(RedisCheckModule, {
    logger: false,
    abortOnError: false,
  });
  const redis = context.get(RedisService);
  const key = buildRedisKey('m1.5:test', randomUUID());
  const expiringKey = buildRedisKey(key, 'ttl');

  try {
    await redis.set(key, 'm1.5-ok');
    assert.equal(await redis.get(key), 'm1.5-ok');
    assert.equal(await redis.delete(key), 1);
    assert.equal(await redis.get(key), null);

    await redis.setWithTtl(expiringKey, 'expiring', 2);
    assert.equal(await redis.get(expiringKey), 'expiring');
    const ttl = await redis.ttl(expiringKey);
    assert.ok(ttl > 0 && ttl <= 2);
    await setTimeout(2200);
    assert.equal(await redis.get(expiringKey), null);
    assert.equal(await redis.ttl(expiringKey), -2);
    console.log(`Redis SET/GET/DELETE passed; TTL=${ttl}s; expiry passed.`);
  } finally {
    try {
      await redis.delete(key);
      await redis.delete(expiringKey);
    } finally {
      await context.close();
    }
  }
}

void checkRedis().catch(() => {
  console.error('Redis integration verification failed.');
  process.exitCode = 1;
});
