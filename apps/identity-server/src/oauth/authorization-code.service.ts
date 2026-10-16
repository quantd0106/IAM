import { Inject, Injectable } from '@nestjs/common';
import { createHash, randomBytes } from 'node:crypto';
import { buildRedisKey } from '../redis/redis-key.js';
import { RedisService } from '../redis/redis.service.js';
import {
  authorizationCodeStateSchema,
  type AuthorizationCodeInput,
  type AuthorizationCodeState,
} from './authorization-code.state.js';

export const AUTHORIZATION_CODE_TTL_SECONDS = 120;
const MAX_RESERVATION_ATTEMPTS = 3;

export type AuthorizationCodeConsumeInput = {
  code: string;
  clientId: string;
  redirectUri: string;
};
export type AuthorizationCodeConsumeResult =
  | { ok: true; state: AuthorizationCodeState }
  | { ok: false; error: 'invalid_grant' };

@Injectable()
export class AuthorizationCodeService {
  constructor(
    @Inject(RedisService)
    private readonly redis: Pick<
      RedisService,
      'setIfAbsentWithTtl' | 'getAndDelete'
    >,
  ) {}

  /** Called only after M6.1 validation. Retrieval burns the code even on failure. */
  async consume(
    input: AuthorizationCodeConsumeInput,
  ): Promise<AuthorizationCodeConsumeResult> {
    try {
      const hash = createHash('sha256').update(input.code).digest('hex');
      const serialized = await this.redis.getAndDelete(
        buildRedisKey('oauth:code', hash),
      );
      if (serialized === null) return { ok: false, error: 'invalid_grant' };
      const state = authorizationCodeStateSchema.parse(JSON.parse(serialized));
      const now = Date.now();
      if (!Number.isSafeInteger(now) || now < 0)
        throw new Error('Invalid consumption clock.');
      if (
        state.expiresAt <= now ||
        state.clientId !== input.clientId ||
        state.redirectUri !== input.redirectUri
      )
        return { ok: false, error: 'invalid_grant' };
      return { ok: true, state };
    } catch {
      // No restore/retry, private cause, bearer credential, key or state leakage.
      throw new Error('Authorization code consumption failed.');
    }
  }

  /** OAuth-internal; caller must have completed request validation and IdP authentication. */
  async issue(input: AuthorizationCodeInput): Promise<{ code: string }> {
    try {
      const issuedAt = Date.now();
      const state = authorizationCodeStateSchema.parse({
        ...input,
        expiresAt: issuedAt + AUTHORIZATION_CODE_TTL_SECONDS * 1000,
      });
      if (
        !Number.isSafeInteger(issuedAt) ||
        issuedAt < 0 ||
        state.expiresAt <= issuedAt
      )
        throw new Error('Invalid authorization-code lifetime.');
      const serialized = JSON.stringify(state);
      for (let attempt = 0; attempt < MAX_RESERVATION_ATTEMPTS; attempt++) {
        const code = randomBytes(32).toString('base64url');
        const hash = createHash('sha256').update(code).digest('hex');
        if (
          await this.redis.setIfAbsentWithTtl(
            buildRedisKey('oauth:code', hash),
            serialized,
            AUTHORIZATION_CODE_TTL_SECONDS,
          )
        )
          return { code };
      }
      throw new Error('Authorization-code reservation exhausted.');
    } catch {
      // Never retain causes, raw codes, hashes, context or Redis command details.
      throw new Error('Authorization code issuance failed.');
    }
  }
}
