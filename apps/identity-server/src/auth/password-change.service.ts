import { Inject, Injectable, Logger } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service.js';
import { PasswordService } from '../security/password/password.service.js';

export type PasswordChangeResult =
  | { ok: true }
  | { ok: false; reason: 'INVALID_CURRENT_PASSWORD' | 'PASSWORD_UNCHANGED' };

@Injectable()
export class PasswordChangeService {
  private readonly logger = new Logger(PasswordChangeService.name);

  constructor(
    @Inject(PrismaService) private readonly prisma: PrismaService,
    @Inject(PasswordService) private readonly passwords: PasswordService,
  ) {}

  // userId must come from a trusted authenticated caller, never a public body.
  async changePassword(
    userId: string,
    currentPassword: string,
    newPassword: string,
  ): Promise<PasswordChangeResult> {
    if (
      [userId, currentPassword, newPassword].some(
        (value) => typeof value !== 'string' || value.length === 0,
      )
    )
      throw new TypeError(
        'Password change input must contain non-empty strings.',
      );

    const credential = await this.prisma.credential
      .findUnique({
        where: { userId },
        select: { passwordHash: true },
      })
      .catch(() => {
        throw new Error('Password change failed.');
      });
    if (credential === null)
      return { ok: false, reason: 'INVALID_CURRENT_PASSWORD' };

    // PasswordService sanitizes internal failures; do not disguise them as mismatches.
    if (
      !(await this.passwords.verify(credential.passwordHash, currentPassword))
    )
      return { ok: false, reason: 'INVALID_CURRENT_PASSWORD' };
    if (newPassword === currentPassword)
      return { ok: false, reason: 'PASSWORD_UNCHANGED' };

    const passwordHash = await this.passwords.hash(newPassword);
    // One atomic CAS write; Argon2 work occurs before any database write/transaction.
    const updated = await this.prisma.credential
      .updateMany({
        where: { userId, passwordHash: credential.passwordHash },
        data: { passwordHash, passwordUpdatedAt: new Date() },
      })
      .catch(() => {
        throw new Error('Password change failed.');
      });
    if (updated.count === 0)
      return { ok: false, reason: 'INVALID_CURRENT_PASSWORD' };
    if (updated.count !== 1) throw new Error('Password change failed.');

    // Provisional event only; M12 owns persistent audit storage.
    this.logger.log({ event: 'PASSWORD_CHANGED', userId });
    return { ok: true };
  }
}
