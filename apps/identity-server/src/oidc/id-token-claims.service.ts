import { Inject, Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { z } from 'zod';
import type { Environment } from '../config/env.schema.js';

export type IdTokenClaimsInput = {
  subject: string;
  /** Trusted OAuth client_id, not the access-token resource audience. */
  audience: string;
  nonce: string;
  ttlSeconds: number;
};

export type IdTokenClaims = {
  iss: string;
  sub: string;
  aud: string;
  iat: number;
  exp: number;
  nonce: string;
};

const opaque = z.string().min(1);
const inputSchema = z.object({
  subject: z.uuid(),
  audience: opaque,
  nonce: opaque,
  ttlSeconds: z.number().int().positive().max(Number.MAX_SAFE_INTEGER),
});

@Injectable()
export class IdTokenClaimsService {
  constructor(
    @Inject(ConfigService)
    private readonly config: ConfigService<Environment, true>,
  ) {}

  build(input: IdTokenClaimsInput): IdTokenClaims {
    try {
      const values = inputSchema.parse(input);
      const issuer = opaque.parse(
        this.config.getOrThrow('ISSUER_URL', { infer: true }),
      );
      // Match the frozen Discovery boundary without rewriting the configured issuer
      // or changing global environment/access-token validation.
      const url = new URL(issuer);
      if (
        !['http:', 'https:'].includes(url.protocol) ||
        !url.hostname ||
        url.username !== '' ||
        url.password !== '' ||
        issuer.includes('?') ||
        issuer.includes('#')
      )
        throw new Error('Invalid OIDC issuer configuration.');
      const nowMs = Date.now();
      if (!Number.isSafeInteger(nowMs) || nowMs < 0)
        throw new Error('Invalid claims clock.');
      const issuedAt = Math.floor(nowMs / 1000);
      const expiresAt = issuedAt + values.ttlSeconds;
      if (!Number.isSafeInteger(expiresAt) || expiresAt <= issuedAt)
        throw new Error('Invalid claims expiry.');
      return {
        iss: issuer,
        sub: values.subject,
        aud: values.audience,
        iat: issuedAt,
        exp: expiresAt,
        nonce: values.nonce,
      };
    } catch {
      throw new Error('ID token claims build failed.');
    }
  }
}
