import { Inject, Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { createHash, randomBytes } from 'node:crypto';
import type { Environment } from '../config/env.schema.js';
import { PrismaService } from '../prisma/prisma.service.js';
import { buildRedisKey } from '../redis/redis-key.js';
import { RedisService } from '../redis/redis.service.js';
import {
  PASSWORD_RESET_DELIVERY,
  type PasswordResetDelivery,
} from './password-reset-delivery.js';

@Injectable()
export class PasswordResetRequestService {
  private readonly logger = new Logger(PasswordResetRequestService.name);
  private readonly ttlSeconds: number;

  constructor(
    @Inject(PrismaService) private readonly prisma: PrismaService,
    @Inject(RedisService) private readonly redis: RedisService,
    @Inject(ConfigService) config: ConfigService<Environment, true>,
    @Inject(PASSWORD_RESET_DELIVERY)
    private readonly delivery: PasswordResetDelivery,
  ) {
    this.ttlSeconds = config.getOrThrow('PASSWORD_RESET_TTL_SECONDS', {
      infer: true,
    });
  }

  async request(email: string): Promise<void> {
    try {
      const user = await this.prisma.user.findUnique({
        where: { email },
        select: {
          id: true,
          status: true,
          credential: { select: { id: true } },
        },
      });
      if (user === null || user.status !== 'ACTIVE' || user.credential === null)
        return;

      // Recovery eligibility deliberately ignores temporary login locks.
      const token = randomBytes(32).toString('base64url');
      const tokenHash = createHash('sha256').update(token).digest('hex');
      await this.redis.setWithTtl(
        buildRedisKey('pwdreset', tokenHash),
        JSON.stringify({ userId: user.id }),
        this.ttlSeconds,
      );
      // Never deliver a secret whose state failed to persist.
      await this.delivery.deliver({ email, token });
    } catch {
      // Even operational failures must not turn account existence into an oracle.
      // No original errors, cause chains, identifiers, secrets or hashes.
      this.logger.error('Password reset request processing failed.');
    }
  }
}
