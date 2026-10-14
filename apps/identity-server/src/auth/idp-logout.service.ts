import { Inject, Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service.js';
import { IdpSessionStateService } from '../session/idp-session-state.service.js';

@Injectable()
export class IdpLogoutService {
  constructor(
    @Inject(IdpSessionStateService)
    private readonly sessions: IdpSessionStateService,
    @Inject(PrismaService) private readonly prisma: PrismaService,
  ) {}

  async logout(sessionId: string): Promise<void> {
    try {
      await this.sessions.invalidate(sessionId);
      await this.prisma.session.updateMany({
        where: { id: sessionId, status: 'ACTIVE' },
        data: { status: 'REVOKED' },
      });
    } catch {
      // No cross-store transaction: never restore deleted runtime state.
      // A retry may complete the persistent revoke after DEL=0.
      throw new Error('IdP logout failed.');
    }
  }
}
