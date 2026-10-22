import { Inject, Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { errors, jwtVerify, type JWTVerifyResult } from 'jose';
import { z } from 'zod';
import type { Environment } from '../config/env.schema.js';
import { authorizationRequestSchema } from '../oauth/authorization-request.schema.js';
import { SigningKeyService } from '../security/signing/signing-key.service.js';

export type UserInfoAuthentication =
  | { ok: true; subject: string }
  | {
      ok: false;
      error: 'missing_credentials' | 'invalid_token' | 'insufficient_scope';
    };

const opaque = z.string().min(1);
const numericDate = z.number().int().min(0).max(Number.MAX_SAFE_INTEGER);
const accessTokenSchema = z
  .strictObject({
    iss: opaque,
    sub: z.uuid(),
    aud: opaque,
    iat: numericDate,
    exp: numericDate,
    scope: authorizationRequestSchema.shape.scope,
    roles: z.array(opaque),
    permissions: z.array(opaque),
  })
  .refine((claims) => claims.exp > claims.iat);

// Only credential-derived JOSE failures are invalid_token. Configuration, key
// loading and unexpected library/runtime faults remain sanitized server failures.
const invalidJwtErrors = [
  errors.JOSEAlgNotAllowed,
  errors.JOSENotSupported,
  errors.JWSInvalid,
  errors.JWSSignatureVerificationFailed,
  errors.JWTInvalid,
  errors.JWTClaimValidationFailed,
  errors.JWTExpired,
];

@Injectable()
export class UserInfoAccessTokenService {
  constructor(
    @Inject(ConfigService)
    private readonly config: ConfigService<Environment, true>,
    @Inject(SigningKeyService) private readonly keys: SigningKeyService,
  ) {}

  async authenticate(authorization: unknown): Promise<UserInfoAuthentication> {
    try {
      if (authorization === undefined)
        return { ok: false, error: 'missing_credentials' };
      if (typeof authorization !== 'string')
        return { ok: false, error: 'invalid_token' };
      // RFC 6750 token68 with 1*SP; scheme is case-insensitive, token is untouched.
      const bearer = /^Bearer +([A-Za-z0-9._~+/-]+=*)$/i.exec(authorization);
      // JS $ also matches before a final newline: require a complete exact match.
      if (!bearer || bearer[0] !== authorization)
        return { ok: false, error: 'invalid_token' };
      const issuer = opaque.parse(
        this.config.getOrThrow('ISSUER_URL', { infer: true }),
      );
      const publicKey = await this.keys.getPublicVerificationKey();
      const kid = opaque.parse(await this.keys.getKeyId());
      let verified: JWTVerifyResult;
      try {
        verified = await jwtVerify(bearer[1], publicKey, {
          algorithms: ['RS256'],
          issuer,
          requiredClaims: [
            'iss',
            'sub',
            'aud',
            'iat',
            'exp',
            'scope',
            'roles',
            'permissions',
          ],
          // Intentional M7.4 single-resource-audience MVP compatibility policy:
          // validate scalar aud below, not a fixed UserInfo-specific audience.
        });
      } catch (error) {
        if (invalidJwtErrors.some((type) => error instanceof type))
          return { ok: false, error: 'invalid_token' };
        throw error;
      }
      const parsed = accessTokenSchema.safeParse(verified.payload);
      if (verified.protectedHeader.kid !== kid || !parsed.success)
        return { ok: false, error: 'invalid_token' };
      if (!parsed.data.scope.includes('openid'))
        return { ok: false, error: 'insufficient_scope' };
      return { ok: true, subject: parsed.data.sub };
    } catch {
      throw new Error('UserInfo access-token validation failed.');
    }
  }
}
