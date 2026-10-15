import { Inject, Injectable } from '@nestjs/common';
import {
  IdpSessionAuthenticationService,
  type AuthenticatedIdpSession,
} from '../session/idp-session-authentication.service.js';
import {
  AuthorizationRequestService,
  type AuthorizationRequestResult,
} from './authorization-request.service.js';

export type AuthorizationResult =
  | (Extract<AuthorizationRequestResult, { ok: true }> & {
      session: Pick<
        AuthenticatedIdpSession,
        'sessionId' | 'userId' | 'authTime' | 'mfaLevel'
      >;
    })
  | Extract<AuthorizationRequestResult, { ok: false }>
  | { ok: false; error: 'authentication_required' };

@Injectable()
export class AuthorizationService {
  constructor(
    @Inject(AuthorizationRequestService)
    private readonly requests: Pick<AuthorizationRequestService, 'validate'>,
    @Inject(IdpSessionAuthenticationService)
    private readonly sessions: Pick<
      IdpSessionAuthenticationService,
      'authenticate'
    >,
  ) {}

  async authorize(
    query: unknown,
    cookieHeader: string | undefined,
  ): Promise<AuthorizationResult> {
    try {
      const validated = await this.requests.validate(query);
      if (!validated.ok) return validated;
      const session = await this.sessions.authenticate(cookieHeader);
      if (session === null)
        return { ok: false, error: 'authentication_required' };
      // Trusted transient subject for later M5.5; never persisted or sent by M5.4.
      return {
        ...validated,
        session: {
          sessionId: session.sessionId,
          userId: session.userId,
          authTime: session.authTime,
          mfaLevel: session.mfaLevel,
        },
      };
    } catch {
      throw new Error('Authorization request failed.');
    }
  }
}
