import { Inject, Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import type { Environment } from '../config/env.schema.js';
import { sessionIdSchema } from './idp-session-state.js';

@Injectable()
export class IdpSessionCookieService {
  private readonly cookieName: string;
  private readonly secure: boolean;

  constructor(@Inject(ConfigService) config: ConfigService<Environment, true>) {
    this.cookieName = config.getOrThrow('COOKIE_NAME', { infer: true });
    this.secure = config.getOrThrow('COOKIE_SECURE', { infer: true });
  }

  serialize(sessionId: string): string {
    if (!sessionIdSchema.safeParse(sessionId).success)
      throw new TypeError('Invalid IdP session identifier.');
    return (
      this.cookieName +
      '=' +
      sessionId +
      '; Path=/; HttpOnly; SameSite=Lax' +
      (this.secure ? '; Secure' : '')
    );
  }

  /** Recognition only: a syntactically valid UUID is not an authenticated session. */
  parse(cookieHeader: string | undefined): string | null {
    if (typeof cookieHeader !== 'string') return null;
    let sessionId: string | null = null;
    for (const rawPair of cookieHeader.split(';')) {
      // Tolerate only pair-leading SP/HTAB; never trim/decode the UUID value.
      const pair = rawPair.replace(/^[ \t]+/, '');
      const separator = pair.indexOf('=');
      const name = separator < 0 ? pair : pair.slice(0, separator);
      if (name !== this.cookieName) continue;
      if (sessionId !== null || separator < 0) return null;
      const value = pair.slice(separator + 1);
      const result = sessionIdSchema.safeParse(value);
      if (!result.success) return null;
      sessionId = result.data;
    }
    return sessionId;
  }
}
