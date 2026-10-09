import {
  Inject,
  Injectable,
  Logger,
  type OnModuleDestroy,
  type OnModuleInit,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import type { Environment } from '../config/env.schema.js';
import { createClient } from 'redis';

@Injectable()
export class RedisService implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(RedisService.name);
  private readonly client: ReturnType<typeof createClient>;
  private shuttingDown = false;

  constructor(@Inject(ConfigService) config: ConfigService<Environment, true>) {
    const url = config.getOrThrow('REDIS_URL', { infer: true });

    try {
      this.client = createClient({
        url,
        // Reject commands while disconnected instead of replaying queued writes.
        disableOfflineQueue: true,
        socket: {
          connectTimeout: 5000,
          reconnectStrategy: (retries) => {
            if (this.shuttingDown) return false;
            const delay = Math.min(50 * 2 ** Math.min(retries, 6), 2000);
            const jitter = Math.floor(Math.random() * 200);
            return delay + jitter;
          },
        },
      });
    } catch {
      throw new Error('Redis client configuration failed.');
    }

    // Never log the error object: messages/stacks can contain connection secrets.
    this.client.on('error', () => {
      this.logger.error('Redis connection error.');
    });
  }

  async onModuleInit(): Promise<void> {
    try {
      await this.client.connect();
    } catch {
      if (this.client.isOpen) this.client.destroy();
      throw new Error('Redis connection initialization failed.');
    }
  }

  async onModuleDestroy(): Promise<void> {
    this.shuttingDown = true;
    if (!this.client.isOpen) return;

    if (!this.client.isReady) {
      this.client.destroy();
      return;
    }

    try {
      await this.client.close();
    } catch {
      if (this.client.isOpen) this.client.destroy();
      this.logger.error(
        'Redis graceful shutdown failed; connection destroyed.',
      );
    }
  }

  async set(key: string, value: string): Promise<void> {
    await this.client.set(key, value);
  }

  async get(key: string): Promise<string | null> {
    return this.client.get(key);
  }

  async delete(key: string): Promise<number> {
    return this.client.del(key);
  }

  async setWithTtl(
    key: string,
    value: string,
    ttlSeconds: number,
  ): Promise<void> {
    if (!Number.isSafeInteger(ttlSeconds) || ttlSeconds <= 0) {
      throw new RangeError(
        'Redis TTL must be a positive safe integer in seconds.',
      );
    }

    await this.client.set(key, value, { EX: ttlSeconds });
  }

  async ttl(key: string): Promise<number> {
    return this.client.ttl(key);
  }
}
