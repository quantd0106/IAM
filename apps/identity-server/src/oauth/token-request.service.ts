import { Injectable } from '@nestjs/common';
import { z } from 'zod';
import {
  tokenRequestSchema,
  type TokenRequest,
} from './token-request.schema.js';

export type TokenRequestResult =
  | { ok: true; request: TokenRequest }
  | { ok: false; error: 'invalid_request' | 'unsupported_grant_type' };

// Inspect only the discriminator before the strict grant-specific boundary.
const grantSchema = z.object({ grant_type: z.string().min(1) });

@Injectable()
export class TokenRequestService {
  // M6.1 has no injected dependencies or I/O. Code consumption starts in M6.2.
  validate(body: unknown, contentType: string | undefined): TokenRequestResult {
    if (
      contentType?.split(';')[0].trim().toLowerCase() !==
      'application/x-www-form-urlencoded'
    )
      return { ok: false, error: 'invalid_request' };
    const grant = grantSchema.safeParse(body);
    if (!grant.success) return { ok: false, error: 'invalid_request' };
    if (
      !['authorization_code', 'refresh_token'].includes(grant.data.grant_type)
    )
      return { ok: false, error: 'unsupported_grant_type' };
    const input = tokenRequestSchema.safeParse(body);
    if (!input.success) return { ok: false, error: 'invalid_request' };
    return {
      ok: true,
      request: input.data,
    };
  }
}
