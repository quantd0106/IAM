import { Inject, Injectable } from '@nestjs/common';
import { z } from 'zod';
import type { Prisma } from '../generated/prisma/client.js';
import { PrismaService } from '../prisma/prisma.service.js';
import { authorizationCodeStateSchema } from '../oauth/authorization-code.state.js';
import { RefreshTokenGeneratorService } from './refresh-token-generator.service.js';
import { AccessTokenIssuerService } from './access-token-issuer.service.js';
import { requireAccessTokenIssuance } from './access-token-issuance.policy.js';

export type RefreshTokenRotationInput = {
  rawRefreshToken: string;
  clientRecordId: string;
  requestedScope?: string;
  accessTokenAudience: string;
  accessTokenTtl: number;
};
export type RefreshTokenRotationResult =
  | {
      ok: true;
      accessToken: string;
      tokenType: 'Bearer';
      expiresIn: number;
      scope: string;
      refreshToken: string;
    }
  | { ok: false; error: 'invalid_grant' | 'invalid_scope' };

const selection = {
  id: true,
  familyId: true,
  status: true,
  expiresAt: true,
  consumedAt: true,
  revokedAt: true,
  family: {
    select: {
      id: true,
      userId: true,
      clientId: true,
      status: true,
      grantedScopes: true,
      reuseDetectedAt: true,
      revokedAt: true,
    },
  },
} as const satisfies Prisma.RefreshTokenSelect;
// Driver corruption is operational, not a credential oracle. Scope corruption has
// its explicit invalid_grant contract below (including legacy NULL/[] snapshots).
const rowSchema = z.object({
  id: z.uuid(),
  familyId: z.uuid(),
  status: z.enum(['ACTIVE', 'CONSUMED', 'REVOKED']),
  expiresAt: z.date(),
  consumedAt: z.date().nullable(),
  revokedAt: z.date().nullable(),
  family: z.object({
    id: z.uuid(),
    userId: z.uuid(),
    clientId: z.uuid(),
    status: z.enum(['ACTIVE', 'REVOKED']),
    grantedScopes: z.unknown(),
    reuseDetectedAt: z.date().nullable(),
    revokedAt: z.date().nullable(),
  }),
});
const scopesSchema = authorizationCodeStateSchema.shape.grantedScopes.refine(
  (values) => new Set(values).size === values.length,
);
const invalidGrant = { ok: false, error: 'invalid_grant' } as const;
const invalidScope = { ok: false, error: 'invalid_scope' } as const;

@Injectable()
export class RefreshTokenRotationService {
  constructor(
    @Inject(PrismaService)
    private readonly prisma: Pick<PrismaService, '$transaction'>,
    @Inject(RefreshTokenGeneratorService)
    private readonly generator: Pick<
      RefreshTokenGeneratorService,
      'hash' | 'generate'
    >,
    @Inject(AccessTokenIssuerService)
    private readonly accessTokens: Pick<AccessTokenIssuerService, 'issue'>,
  ) {}

  async rotate(
    input: RefreshTokenRotationInput,
  ): Promise<RefreshTokenRotationResult> {
    try {
      const clientId = z.uuid().parse(input.clientRecordId);
      const issuance = requireAccessTokenIssuance(input);
      const raw = input.rawRefreshToken;
      if (
        typeof raw !== 'string' ||
        raw.length !== 43 ||
        !/^[A-Za-z0-9_-]{43}$/.test(raw)
      )
        return invalidGrant;
      const tokenHash = this.generator.hash(raw);
      // No standalone preflight read: this transaction owns validation AND consume.
      // Await $transaction: credentials escape only after commit, including commit failures.
      return await this.prisma.$transaction(
        async (tx): Promise<RefreshTokenRotationResult> => {
          const found = await tx.refreshToken.findUnique({
            where: { tokenHash },
            select: selection,
          });
          if (found === null) return invalidGrant;
          const token = rowSchema.parse(found);
          if (token.familyId !== token.family.id)
            throw new Error('Invalid refresh family relation.');
          const now = Date.now();
          if (
            !Number.isSafeInteger(now) ||
            now < 0 ||
            !Number.isFinite(new Date(now).getTime())
          )
            throw new Error('Invalid refresh rotation clock.');
          const rotationAt = new Date(now);
          if (
            token.family.clientId !== clientId ||
            token.status !== 'ACTIVE' ||
            token.consumedAt !== null ||
            token.revokedAt !== null ||
            token.expiresAt.getTime() <= now ||
            token.family.status !== 'ACTIVE' ||
            token.family.revokedAt !== null ||
            token.family.reuseDetectedAt !== null
          )
            return invalidGrant;
          const stored = scopesSchema.safeParse(token.family.grantedScopes);
          if (!stored.success) return invalidGrant;
          let scopes = [...stored.data];
          if (input.requestedScope !== undefined) {
            if (typeof input.requestedScope !== 'string')
              throw new Error('Invalid internal scope type.');
            const requested = scopesSchema.safeParse(
              input.requestedScope.split(' '),
            );
            if (
              !requested.success ||
              !requested.data.every((scope) => stored.data.includes(scope))
            )
              return invalidScope;
            scopes = [...requested.data];
          }
          const { rawToken, tokenHash: replacementHash } =
            this.generator.generate();
          const access = await this.accessTokens.issue({
            subject: token.family.userId,
            audience: issuance.audience,
            scopes,
            ttlSeconds: issuance.ttlSeconds,
            roles: [],
            permissions: [],
          });
          // PostgreSQL re-evaluates this predicate after a competing writer commits.
          // A losing request may hold transient signed material, but never delivers it.
          const consumed = await tx.refreshToken.updateMany({
            where: {
              id: token.id,
              familyId: token.familyId,
              status: 'ACTIVE',
              consumedAt: null,
              revokedAt: null,
              expiresAt: { gt: rotationAt },
            },
            data: { status: 'CONSUMED', consumedAt: rotationAt },
          });
          if (consumed.count === 0) return invalidGrant;
          if (consumed.count !== 1) throw new Error('Invalid consume result.');
          await tx.refreshToken.create({
            data: {
              familyId: token.familyId,
              parentTokenId: token.id,
              tokenHash: replacementHash,
              status: 'ACTIVE',
              issuedAt: rotationAt,
              expiresAt: token.expiresAt,
              consumedAt: null,
              revokedAt: null,
            },
            select: { id: true },
          });
          return {
            ok: true,
            accessToken: access.accessToken,
            tokenType: 'Bearer',
            expiresIn: access.expiresIn,
            scope: access.scope,
            refreshToken: rawToken,
          };
        },
        { isolationLevel: 'ReadCommitted' },
      );
    } catch {
      throw new Error('Refresh token rotation failed.');
    }
  }
}
