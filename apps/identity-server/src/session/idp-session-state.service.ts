import { Inject, Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import type { Environment } from '../config/env.schema.js';
import { buildRedisKey } from '../redis/redis-key.js';
import { RedisService } from '../redis/redis.service.js';
import {
  idpSessionStateSchema,
  parseIdpSessionState,
  sessionIdSchema,
  type IdpSessionState,
} from './idp-session-state.js';

@Injectable()
export class IdpSessionStateService {
  private readonly idleTtlSeconds: number;

  constructor(
    @Inject(RedisService) private readonly redis: RedisService,
    @Inject(ConfigService) config: ConfigService<Environment, true>,
  ) {
    this.idleTtlSeconds = config.getOrThrow('SESSION_IDLE_TTL_SECONDS', {
      infer: true,
    });
    // The caller owns absoluteExpiresAt (and later PostgreSQL expiresAt).
    // SESSION_ABSOLUTE_TTL_SECONDS stays available for that M3.4 decision.
  }

  async create(sessionId: string, state: IdpSessionState): Promise<void> {
    const key = this.key(sessionId);
    const result = idpSessionStateSchema.safeParse(state);
    if (!result.success) throw new TypeError('Invalid IdP session state.');

    const stored = await this.redis.sessionState(key, {
      kind: 'create',
      serializedState: JSON.stringify(result.data),
      idleTtlSeconds: this.idleTtlSeconds,
    });
    if (stored === null)
      throw new Error('IdP session state is already expired.');
    if (parseIdpSessionState(stored) === null)
      throw new Error('Redis IdP session operation failed.');
  }

  async read(sessionId: string): Promise<IdpSessionState | null> {
    return parseIdpSessionState(
      await this.redis.sessionState(this.key(sessionId), { kind: 'read' }),
    );
  }

  async touch(sessionId: string): Promise<IdpSessionState | null> {
    return parseIdpSessionState(
      await this.redis.sessionState(this.key(sessionId), {
        kind: 'touch',
        idleTtlSeconds: this.idleTtlSeconds,
      }),
    );
  }

  async invalidate(sessionId: string): Promise<void> {
    const key = this.key(sessionId);
    try {
      // DEL=0 is normal for expired state, retries and concurrent logouts.
      await this.redis.delete(key);
    } catch {
      throw new Error('Redis IdP session operation failed.');
    }
  }

  private key(sessionId: string): string {
    if (!sessionIdSchema.safeParse(sessionId).success)
      throw new TypeError('Invalid IdP session identifier.');
    return buildRedisKey('session', sessionId);
  }
}
