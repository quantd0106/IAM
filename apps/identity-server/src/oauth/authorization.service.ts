import { Inject, Injectable } from '@nestjs/common';
import {
  IdpSessionAuthenticationService,
  type AuthenticatedIdpSession,
} from '../session/idp-session-authentication.service.js';
import {
  AuthorizationRequestService,
  type AuthorizationRequestResult,
} from './authorization-request.service.js';
import { AuthorizationCodeService } from './authorization-code.service.js';

export type AuthorizationResult =
  | (Extract<AuthorizationRequestResult, { ok: true }> & {
      session: Pick<
        AuthenticatedIdpSession,
        'sessionId' | 'userId' | 'authTime' | 'mfaLevel'
      >;
      authorizationCode: string;
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
    @Inject(AuthorizationCodeService)
    private readonly codes: Pick<AuthorizationCodeService, 'issue'>,
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
      const { code } = await this.codes.issue({
        clientId: validated.client.clientId,
        userId: session.userId,
        redirectUri: validated.request.redirect_uri,
        grantedScopes: validated.grantedScopes,
        codeChallenge: validated.request.code_challenge ?? null,
        nonce: validated.request.nonce ?? null,
        authTime: session.authTime,
      });
      return {
        ...validated,
        authorizationCode: code,
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
