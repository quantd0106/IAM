import { Inject, Injectable } from '@nestjs/common';
import { z } from 'zod';
import { PrismaService } from '../prisma/prisma.service.js';
import { authorizationCodeStateSchema } from '../oauth/authorization-code.state.js';
import { RefreshTokenGeneratorService } from './refresh-token-generator.service.js';
import { requireRefreshTokenIssuance } from './refresh-token-issuance.policy.js';

export type InitialRefreshTokenInput = {
  userId: string;
  clientRecordId: string;
  sessionId: string;
  grantedScopes: readonly string[];
  ttlSeconds: number;
};

const inputSchema = z.object({
  userId: z.uuid(),
  clientRecordId: z.uuid(),
  sessionId: z.uuid(),
  grantedScopes: authorizationCodeStateSchema.shape.grantedScopes.refine(
    (scopes) => new Set(scopes).size === scopes.length,
  ),
  ttlSeconds: z.number(),
});

@Injectable()
export class RefreshTokenIssuerService {
  constructor(
    @Inject(PrismaService)
    private readonly prisma: Pick<PrismaService, '$transaction'>,
    @Inject(RefreshTokenGeneratorService)
    private readonly generator: Pick<RefreshTokenGeneratorService, 'generate'>,
  ) {}

  async issueInitial(
    input: InitialRefreshTokenInput,
  ): Promise<{ refreshToken: string }> {
    try {
      const values = inputSchema.parse(input);
      const { ttlSeconds } = requireRefreshTokenIssuance({
        refreshTokenTtl: values.ttlSeconds,
      });
      const nowMs = Date.now();
      const expiresMs = nowMs + ttlSeconds * 1000;
      const issuedAt = new Date(nowMs);
      const expiresAt = new Date(expiresMs);
      if (
        !Number.isSafeInteger(nowMs) ||
        nowMs < 0 ||
        !Number.isSafeInteger(expiresMs) ||
        expiresMs <= nowMs ||
        !Number.isFinite(issuedAt.getTime()) ||
        !Number.isFinite(expiresAt.getTime())
      )
        throw new Error('Invalid refresh lifetime.');
      const { rawToken, tokenHash } = this.generator.generate();
      await this.prisma.$transaction(async (tx) => {
        const family = await tx.refreshTokenFamily.create({
          data: {
            userId: values.userId,
            clientId: values.clientRecordId,
            sessionId: values.sessionId,
            grantedScopes: [...values.grantedScopes],
            status: 'ACTIVE',
            reuseDetectedAt: null,
            revokedAt: null,
            createdAt: issuedAt,
          },
          select: { id: true },
        });
        await tx.refreshToken.create({
          data: {
            familyId: family.id,
            tokenHash,
            parentTokenId: null,
            status: 'ACTIVE',
            issuedAt,
            expiresAt,
            consumedAt: null,
            revokedAt: null,
          },
          select: { id: true },
        });
      });
      // Commit is the delivery boundary; no retry, raw persistence or code restoration.
      return { refreshToken: rawToken };
    } catch {
      throw new Error('Refresh token issuance failed.');
    }
  }
}
