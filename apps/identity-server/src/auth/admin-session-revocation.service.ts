import { Inject, Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service.js';
import { sessionIdSchema } from '../session/idp-session-state.js';
import { IdpLogoutService } from './idp-logout.service.js';

/**
 * Internal capability only. The trusted caller must authorize the action before
 * invoking it; a target UUID is not authorization and this service grants none.
 */
@Injectable()
export class AdminSessionRevocationService {
  constructor(
    @Inject(PrismaService) private readonly prisma: PrismaService,
    @Inject(IdpLogoutService) private readonly logout: IdpLogoutService,
  ) {}

  async revokeUserSessions(targetUserId: string): Promise<void> {
    try {
      // User and session identifiers share the existing canonical UUID domain.
      if (!sessionIdSchema.safeParse(targetUserId).success)
        throw new Error('Invalid target identifier.');
      const sessions = await this.prisma.session.findMany({
        where: { userId: targetUserId, status: 'ACTIVE' },
        select: { id: true },
        orderBy: { id: 'asc' },
      });
      // This snapshot does not block new logins. Stop on the first failure;
      // completed revokes remain completed and a fresh discovery supports retry.
      for (const session of sessions) await this.logout.logout(session.id);
    } catch {
      throw new Error('Admin session revocation failed.');
    }
  }
}
