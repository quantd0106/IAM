import { Inject, Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service.js';
import { IdpSessionStateService } from '../session/idp-session-state.service.js';
import { sessionIdSchema } from '../session/idp-session-state.js';
import { IdpLogoutService } from './idp-logout.service.js';
import {
  IdpSessionAuthenticationService,
  isCoherentIdpSession,
  sessionAuthenticationSelect as sessionSelect,
} from '../session/idp-session-authentication.service.js';

export type OwnSession = {
  id: string;
  createdAt: string;
  lastActivityAt: string;
  expiresAt: string;
  ipAddress: string | null;
  userAgent: string | null;
  current: boolean;
};
export type OwnSessionListResult =
  | { ok: true; sessions: OwnSession[] }
  | { ok: false; reason: 'UNAUTHENTICATED' };
export type OwnSessionRevokeResult =
  | { ok: true; current: boolean }
  | {
      ok: false;
      reason: 'UNAUTHENTICATED' | 'INVALID_IDENTIFIER' | 'NOT_FOUND';
    };

@Injectable()
export class IdpOwnSessionService {
  constructor(
    @Inject(IdpSessionStateService)
    private readonly states: IdpSessionStateService,
    @Inject(PrismaService) private readonly prisma: PrismaService,
    @Inject(IdpLogoutService) private readonly logout: IdpLogoutService,
    @Inject(IdpSessionAuthenticationService)
    private readonly authentication: IdpSessionAuthenticationService,
  ) {}

  async list(currentSessionId: string): Promise<OwnSessionListResult> {
    try {
      const authenticated =
        await this.authentication.authenticateSessionId(currentSessionId);
      if (authenticated === null)
        return { ok: false, reason: 'UNAUTHENTICATED' };
      const { state, now } = authenticated;
      const rows = await this.prisma.session.findMany({
        where: {
          userId: state.userId,
          status: 'ACTIVE',
          expiresAt: { gt: now },
        },
        select: sessionSelect,
        orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
      });
      const sessions: OwnSession[] = [];
      for (const row of rows) {
        if (
          row.userId !== state.userId ||
          row.status !== 'ACTIVE' ||
          row.expiresAt <= now
        )
          continue;
        // Reuse the current touch result; listing never refreshes other sessions.
        const runtime =
          row.id === currentSessionId ? state : await this.states.read(row.id);
        if (
          runtime === null ||
          !isCoherentIdpSession(row, runtime, state.userId, now)
        )
          continue;
        sessions.push({
          id: row.id,
          createdAt: row.createdAt.toISOString(),
          lastActivityAt: new Date(runtime.lastActivityAt).toISOString(),
          expiresAt: row.expiresAt.toISOString(),
          ipAddress: row.ipAddress,
          userAgent: row.userAgent,
          current: row.id === currentSessionId,
        });
      }
      if (sessions.filter((session) => session.current).length !== 1)
        throw new Error('Current session consistency failed.');
      return { ok: true, sessions };
    } catch {
      throw new Error('IdP own-session management failed.');
    }
  }

  async revoke(
    currentSessionId: string,
    targetSessionId: string,
  ): Promise<OwnSessionRevokeResult> {
    // Validate before touch: malformed targets cannot cause a runtime mutation.
    if (!sessionIdSchema.safeParse(targetSessionId).success)
      return { ok: false, reason: 'INVALID_IDENTIFIER' };
    try {
      const authenticated =
        await this.authentication.authenticateSessionId(currentSessionId);
      if (authenticated === null)
        return { ok: false, reason: 'UNAUTHENTICATED' };
      const target = await this.prisma.session.findFirst({
        where: { id: targetSessionId, userId: authenticated.state.userId },
        select: { id: true, userId: true },
      });
      if (target === null || target.userId !== authenticated.state.userId)
        return { ok: false, reason: 'NOT_FOUND' };
      // Use the proven row UUID (PostgreSQL's canonical spelling) for the key.
      // No target runtime operation occurs before this ownership lookup.
      await this.logout.logout(target.id);
      return { ok: true, current: target.id === currentSessionId };
    } catch {
      throw new Error('IdP own-session management failed.');
    }
  }
}
