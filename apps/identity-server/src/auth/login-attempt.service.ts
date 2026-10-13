import { Inject, Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import type { Environment } from '../config/env.schema.js';
import { PrismaService } from '../prisma/prisma.service.js';
import { buildRedisKey } from '../redis/redis-key.js';
import { RedisService } from '../redis/redis.service.js';
import {
  LoginValidationService,
  type LoginIdentifier,
} from './login-validation.service.js';

export type LoginAttemptResult =
  | { ok: true; user: { id: string; email: string; username: string } }
  | { ok: false; reason: 'INVALID_CREDENTIALS' | 'DISABLED' | 'LOCKED' };

@Injectable()
export class LoginAttemptService {
  private readonly maxFailures: number;
  private readonly lockSeconds: number;

  constructor(
    @Inject(LoginValidationService)
    private readonly validation: LoginValidationService,
    @Inject(RedisService) private readonly redis: RedisService,
    @Inject(PrismaService) private readonly prisma: PrismaService,
    @Inject(ConfigService) config: ConfigService<Environment, true>,
  ) {
    this.maxFailures = config.getOrThrow('LOGIN_MAX_FAILURES', { infer: true });
    this.lockSeconds = config.getOrThrow('LOGIN_LOCK_SECONDS', { infer: true });
  }

  async attempt(
    identifier: LoginIdentifier,
    rawPassword: string,
  ): Promise<LoginAttemptResult> {
    const result = await this.validation.validate(identifier, rawPassword);
    if (result.ok) {
      try {
        // Reset must complete before authentication may succeed; DEL=0 is fine.
        await this.redis.delete(
          buildRedisKey('rate', result.user.id, 'login-failure'),
        );
      } catch {
        throw new Error('Login attempt failed.');
      }
      return {
        ok: true,
        user: {
          id: result.user.id,
          email: result.user.email,
          username: result.user.username,
        },
      };
    }
    if (
      result.reason !== 'INVALID_CREDENTIALS' ||
      result.subjectUserId === undefined
    )
      return { ok: false, reason: result.reason };

    try {
      const key = buildRedisKey('rate', result.subjectUserId, 'login-failure');
      const count = await this.redis.incrementWithTtl(key, this.lockSeconds);
      if (count < this.maxFailures)
        return { ok: false, reason: 'INVALID_CREDENTIALS' };

      const now = new Date();
      // PostgreSQL is the lock authority. Racing threshold writers must not
      // extend a future lock established by the first writer.
      await this.prisma.user.updateMany({
        where: {
          id: result.subjectUserId,
          OR: [{ lockedUntil: null }, { lockedUntil: { lte: now } }],
        },
        data: {
          lockedUntil: new Date(now.getTime() + this.lockSeconds * 1000),
        },
      });
      return { ok: false, reason: 'LOCKED' };
    } catch {
      // Counter/reset/lock failures are internal errors, never fail-open.
      throw new Error('Login attempt failed.');
    }
  }
}
