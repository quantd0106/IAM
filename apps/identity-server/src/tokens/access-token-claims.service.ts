import { Inject, Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { z } from 'zod';
import type { Environment } from '../config/env.schema.js';
import { authorizationCodeStateSchema } from '../oauth/authorization-code.state.js';

export type AccessTokenClaimsInput = {
  subject: string;
  audience: string;
  scopes: readonly string[];
  roles: readonly string[];
  permissions: readonly string[];
  ttlSeconds?: number;
};

export type AccessTokenClaims = {
  iss: string;
  sub: string;
  aud: string;
  iat: number;
  exp: number;
  scope: string;
  roles: string[];
  permissions: string[];
};

const opaque = z.string().min(1);
const positiveSafeInteger = z
  .number()
  .int()
  .positive()
  .max(Number.MAX_SAFE_INTEGER);
// Unknown properties are discarded, never treated as claim/config authorities.
const inputSchema = z.object({
  subject: z.uuid(),
  audience: opaque,
  scopes: authorizationCodeStateSchema.shape.grantedScopes,
  roles: z.array(opaque),
  permissions: z.array(opaque),
  ttlSeconds: positiveSafeInteger.optional(),
});

@Injectable()
export class AccessTokenClaimsService {
  constructor(
    @Inject(ConfigService)
    private readonly config: ConfigService<Environment, true>,
  ) {}

  /** Trusted subject/audience/grants/RBAC inputs only. No resolution or signing. */
  build(input: AccessTokenClaimsInput): AccessTokenClaims {
    try {
      const values = inputSchema.parse(input);
      const issuer = opaque.parse(
        this.config.getOrThrow('ISSUER_URL', { infer: true }),
      );
      const ttl = positiveSafeInteger.parse(
        values.ttlSeconds ??
          this.config.getOrThrow('ACCESS_TOKEN_TTL_SECONDS', { infer: true }),
      );
      const nowMs = Date.now();
      if (!Number.isSafeInteger(nowMs) || nowMs < 0)
        throw new Error('Invalid claims clock.');
      const issuedAt = Math.floor(nowMs / 1000);
      const expiresAt = issuedAt + ttl;
      if (!Number.isSafeInteger(expiresAt) || expiresAt <= issuedAt)
        throw new Error('Invalid claims expiry.');
      // Exact allowlist; never spread the input or authorization-code state.
      return {
        iss: issuer,
        sub: values.subject,
        aud: values.audience,
        iat: issuedAt,
        exp: expiresAt,
        scope: values.scopes.join(' '),
        roles: [...values.roles],
        permissions: [...values.permissions],
      };
    } catch {
      throw new Error('Access token claims build failed.');
    }
  }
}
