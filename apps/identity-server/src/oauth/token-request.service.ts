import { Injectable } from '@nestjs/common';
import {
  tokenRequestSchema,
  type TokenRequest,
} from './token-request.schema.js';

export type TokenRequestResult =
  | { ok: true; request: TokenRequest }
  | { ok: false; error: 'invalid_request' | 'unsupported_grant_type' };

@Injectable()
export class TokenRequestService {
  // M6.1 has no injected dependencies or I/O. Code consumption starts in M6.2.
  validate(body: unknown, contentType: string | undefined): TokenRequestResult {
    if (
      contentType?.split(';')[0].trim().toLowerCase() !==
      'application/x-www-form-urlencoded'
    )
      return { ok: false, error: 'invalid_request' };
    const input = tokenRequestSchema.safeParse(body);
    if (!input.success) return { ok: false, error: 'invalid_request' };
    if (input.data.grant_type !== 'authorization_code')
      return { ok: false, error: 'unsupported_grant_type' };
    return {
      ok: true,
      request: { ...input.data, grant_type: 'authorization_code' },
    };
  }
}
