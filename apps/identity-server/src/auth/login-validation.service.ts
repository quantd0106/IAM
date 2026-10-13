import { Inject, Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service.js';
import { PasswordService } from '../security/password/password.service.js';

export type LoginIdentifier =
  { type: 'email'; value: string } | { type: 'username'; value: string };

// Internal authentication result, not a response for an HTTP login endpoint.
export type LoginValidationResult =
  | { ok: true; user: { id: string; email: string; username: string } }
  | { ok: false; reason: 'INVALID_CREDENTIALS' | 'DISABLED' | 'LOCKED' };

@Injectable()
export class LoginValidationService {
  constructor(
    @Inject(PrismaService) private readonly prisma: PrismaService,
    @Inject(PasswordService) private readonly passwords: PasswordService,
  ) {}

  async validate(
    identifier: LoginIdentifier,
    rawPassword: string,
  ): Promise<LoginValidationResult> {
    const user = await this.prisma.user
      .findUnique({
        where:
          identifier.type === 'email'
            ? { email: identifier.value }
            : { username: identifier.value },
        select: {
          id: true,
          email: true,
          username: true,
          status: true,
          lockedUntil: true,
          credential: { select: { passwordHash: true } },
        },
      })
      .catch(() => {
        // Do not propagate driver/query details, identifiers, or cause chains.
        throw new Error('Login validation lookup failed.');
      });

    if (user === null || user.credential === null)
      return { ok: false, reason: 'INVALID_CREDENTIALS' };
    if (user.status === 'DISABLED') return { ok: false, reason: 'DISABLED' };
    if (user.lockedUntil !== null && user.lockedUntil.getTime() > Date.now())
      return { ok: false, reason: 'LOCKED' };

    // PasswordService already sanitizes internal failures; let them reject,
    // rather than disguising malformed hashes as ordinary wrong passwords.
    const verified = await this.passwords.verify(
      user.credential.passwordHash,
      rawPassword,
    );
    if (!verified) return { ok: false, reason: 'INVALID_CREDENTIALS' };
    return {
      ok: true,
      user: { id: user.id, email: user.email, username: user.username },
    };
  }
}
