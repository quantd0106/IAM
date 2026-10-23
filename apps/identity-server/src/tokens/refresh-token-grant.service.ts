import { Inject, Injectable } from '@nestjs/common';
import { z } from 'zod';
import type { Prisma } from '../generated/prisma/client.js';
import { PrismaService } from '../prisma/prisma.service.js';
import { authorizationCodeStateSchema } from '../oauth/authorization-code.state.js';
import { RefreshTokenGeneratorService } from './refresh-token-generator.service.js';

export type RefreshTokenGrantInput = {
  rawRefreshToken: string;
  clientRecordId: string;
  requestedScope?: string;
};
export type RefreshTokenGrantResult =
  | { ok: true; subject: string; scopes: string[] }
  | { ok: false; error: 'invalid_grant' | 'invalid_scope' };

const selection = {
  status: true,
  expiresAt: true,
  consumedAt: true,
  revokedAt: true,
  family: {
    select: {
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
  status: z.enum(['ACTIVE', 'CONSUMED', 'REVOKED']),
  expiresAt: z.date(),
  consumedAt: z.date().nullable(),
  revokedAt: z.date().nullable(),
  family: z.object({
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
export class RefreshTokenGrantService {
  constructor(
    @Inject(PrismaService)
    private readonly prisma: Pick<PrismaService, 'refreshToken'>,
    @Inject(RefreshTokenGeneratorService)
    private readonly generator: Pick<RefreshTokenGeneratorService, 'hash'>,
  ) {}

  /** M8.5-only read. NOT a consume/rotation concurrency authority. */
  async validate(
    input: RefreshTokenGrantInput,
  ): Promise<RefreshTokenGrantResult> {
    try {
      const clientId = z.uuid().parse(input.clientRecordId);
      const raw = input.rawRefreshToken;
      if (
        typeof raw !== 'string' ||
        raw.length !== 43 ||
        !/^[A-Za-z0-9_-]{43}$/.test(raw)
      )
        return invalidGrant;
      const tokenHash = this.generator.hash(raw);
      const found = await this.prisma.refreshToken.findUnique({
        where: { tokenHash },
        select: selection,
      });
      if (found === null) return invalidGrant;
      const token = rowSchema.parse(found);
      const now = Date.now();
      if (
        !Number.isSafeInteger(now) ||
        now < 0 ||
        !Number.isFinite(new Date(now).getTime())
      )
        throw new Error('Invalid refresh validation clock.');
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
      if (input.requestedScope === undefined)
        return {
          ok: true,
          subject: token.family.userId,
          scopes: [...stored.data],
        };
      if (typeof input.requestedScope !== 'string')
        throw new Error('Invalid internal scope type.');
      const requested = scopesSchema.safeParse(input.requestedScope.split(' '));
      if (
        !requested.success ||
        !requested.data.every((scope) => stored.data.includes(scope))
      )
        return invalidScope;
      return {
        ok: true,
        subject: token.family.userId,
        scopes: [...requested.data],
      };
    } catch {
      throw new Error('Refresh token grant validation failed.');
    }
  }
}
