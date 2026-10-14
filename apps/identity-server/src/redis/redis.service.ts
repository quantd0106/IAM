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
import { z } from 'zod';
import { redisSessionStateScript } from './redis-session-state.script.js';

export type RedisSessionStateOperation =
  | { kind: 'create'; serializedState: string; idleTtlSeconds: number }
  | { kind: 'read' }
  | { kind: 'touch'; idleTtlSeconds: number };

const incrementWithTtlScript = `
local count = redis.call('INCR', KEYS[1])
if count == 1 then
  redis.call('EXPIRE', KEYS[1], ARGV[1])
end
return count
`;

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

  onModuleInit(): void {
    // Connect/reconnect in the background; process health is not Redis readiness.
    // Offline commands still reject because disableOfflineQueue remains true.
    void this.client.connect().catch(() => {
      if (this.shuttingDown) return;
      if (this.client.isOpen) this.client.destroy();
      this.logger.error('Redis connection initialization failed.');
    });
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

  async getAndDelete(key: string): Promise<string | null> {
    try {
      return await this.client.getDel(key);
    } catch {
      // Do not forward the key/value, driver error or connection details.
      throw new Error('Redis atomic consume failed.');
    }
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

  /** Fixed session-only Lua; no raw client or caller-supplied script exposure. */
  async sessionState(
    key: string,
    operation: RedisSessionStateOperation,
  ): Promise<string | null> {
    try {
      if (
        !key.startsWith('session:') ||
        !z.uuid().safeParse(key.slice('session:'.length)).success ||
        !['create', 'read', 'touch'].includes(operation.kind)
      )
        throw new Error('Invalid session operation.');
      if (
        operation.kind !== 'read' &&
        (!Number.isSafeInteger(operation.idleTtlSeconds) ||
          operation.idleTtlSeconds <= 0)
      )
        throw new Error('Invalid session TTL.');
      if (
        operation.kind === 'create' &&
        typeof operation.serializedState !== 'string'
      )
        throw new Error('Invalid session input.');

      const reply: unknown = await this.client.eval(redisSessionStateScript, {
        keys: [key],
        arguments: [
          operation.kind,
          operation.kind === 'create' ? operation.serializedState : '',
          operation.kind === 'read' ? '' : String(operation.idleTtlSeconds),
        ],
      });
      if (reply !== null && typeof reply !== 'string')
        throw new Error('Invalid session reply.');
      return reply;
    } catch {
      // No key, state, URL or driver cause chains reach callers or logs.
      throw new Error('Redis IdP session operation failed.');
    }
  }

  async incrementWithTtl(key: string, ttlSeconds: number): Promise<number> {
    if (!Number.isSafeInteger(ttlSeconds) || ttlSeconds <= 0) {
      throw new RangeError(
        'Redis TTL must be a positive safe integer in seconds.',
      );
    }
    try {
      const count: unknown = await this.client.eval(incrementWithTtlScript, {
        keys: [key],
        arguments: [String(ttlSeconds)],
      });
      if (
        typeof count !== 'number' ||
        !Number.isSafeInteger(count) ||
        count <= 0
      )
        throw new Error('Invalid counter reply.');
      return count;
    } catch {
      // Never expose the key, command details or a sensitive driver cause.
      throw new Error('Redis counter increment failed.');
    }
  }
}
