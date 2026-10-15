import { Inject, Injectable } from '@nestjs/common';
import type { Prisma } from '../generated/prisma/client.js';
import { PrismaService } from '../prisma/prisma.service.js';
import { IdpSessionCookieService } from './idp-session-cookie.service.js';
import { IdpSessionStateService } from './idp-session-state.service.js';
import { sessionIdSchema, type IdpSessionState } from './idp-session-state.js';

// Retain M3.6's selection/coherence checks for current and candidate sessions.
export const sessionAuthenticationSelect = {
  id: true,
  userId: true,
  status: true,
  createdAt: true,
  expiresAt: true,
  ipAddress: true,
  userAgent: true,
} as const;
type PersistentSession = Prisma.SessionGetPayload<{
  select: typeof sessionAuthenticationSelect;
}>;

export function isCoherentIdpSession(
  row: PersistentSession,
  state: IdpSessionState,
  userId: string,
  now: Date,
): boolean {
  return (
    row.userId === userId &&
    state.userId === userId &&
    row.status === 'ACTIVE' &&
    row.expiresAt > now &&
    row.createdAt.getTime() === state.createdAt &&
    row.expiresAt.getTime() === state.absoluteExpiresAt
  );
}

export type AuthenticatedIdpSession = {
  sessionId: string;
  userId: string;
  authTime: number;
  mfaLevel: string;
  // Internal M3.6 listing reuses the same touch result and lookup instant.
  state: IdpSessionState;
  now: Date;
};

@Injectable()
export class IdpSessionAuthenticationService {
  constructor(
    @Inject(IdpSessionStateService)
    private readonly states: Pick<IdpSessionStateService, 'touch'>,
    @Inject(PrismaService)
    private readonly prisma: Pick<PrismaService, 'session'>,
    @Inject(IdpSessionCookieService)
    private readonly cookies: Pick<IdpSessionCookieService, 'parse'>,
  ) {}

  async authenticate(
    cookieHeader: string | undefined,
  ): Promise<AuthenticatedIdpSession | null> {
    try {
      const id = this.cookies.parse(cookieHeader);
      return id === null ? null : await this.authenticateSessionId(id);
    } catch {
      throw new Error('IdP session authentication failed.');
    }
  }

  /** Internal M3.6 caller already parsed the configured cookie. Never a query/header authority. */
  async authenticateSessionId(
    sessionId: string,
  ): Promise<AuthenticatedIdpSession | null> {
    try {
      if (!sessionIdSchema.safeParse(sessionId).success) return null;
      const state = await this.states.touch(sessionId);
      if (state === null) return null;
      const now = new Date();
      const row = await this.prisma.session.findFirst({
        where: {
          id: sessionId,
          userId: state.userId,
          status: 'ACTIVE',
          expiresAt: { gt: now },
        },
        select: sessionAuthenticationSelect,
      });
      if (
        row === null ||
        row.id !== sessionId ||
        !isCoherentIdpSession(row, state, state.userId, now)
      )
        return null;
      return {
        sessionId,
        userId: state.userId,
        authTime: state.authTime,
        mfaLevel: state.mfaLevel,
        state,
        now,
      };
    } catch {
      throw new Error('IdP session authentication failed.');
    }
  }
}
