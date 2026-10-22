import { Inject, Injectable } from '@nestjs/common';
import { z } from 'zod';
import { PrismaService } from '../prisma/prisma.service.js';

export type UserInfoClaims = {
  sub: string;
  preferred_username?: string;
  email?: string;
};

export type UserInfoClaimsInput = {
  subject: string;
  /** Only scopes from the fully verified canonical access token. */
  scopes: readonly string[];
};

export type UserInfoClaimsResult =
  { ok: true; claims: UserInfoClaims } | { ok: false; error: 'invalid_token' };

const inputSchema = z.object({
  subject: z.uuid(),
  scopes: z.array(z.string()),
});
// Registration owns normalization. Never trim or repair persisted values here.
const profileSchema = z.object({
  username: z.string().min(1),
  email: z.email(),
});

@Injectable()
export class UserInfoClaimsService {
  constructor(@Inject(PrismaService) private readonly prisma: PrismaService) {}

  async resolve(input: UserInfoClaimsInput): Promise<UserInfoClaimsResult> {
    try {
      const { subject, scopes } = inputSchema.parse(input);
      const profile = scopes.includes('profile');
      const email = scopes.includes('email');
      const claims: UserInfoClaims = { sub: subject };
      if (!profile && !email) return { ok: true, claims };

      const row = await this.prisma.user.findUnique({
        where: { id: subject },
        select: { username: true, email: true },
      });
      if (row === null) return { ok: false, error: 'invalid_token' };
      const values = profileSchema.parse(row);
      if (profile) claims.preferred_username = values.username;
      if (email) claims.email = values.email;
      return { ok: true, claims };
    } catch {
      throw new Error('UserInfo claims resolution failed.');
    }
  }
}
