import { Inject, Injectable, Logger } from '@nestjs/common';
import { createHash } from 'node:crypto';
import { z } from 'zod';
import { PrismaService } from '../prisma/prisma.service.js';
import { buildRedisKey } from '../redis/redis-key.js';
import { RedisService } from '../redis/redis.service.js';
import { PasswordService } from '../security/password/password.service.js';

export type PasswordResetConsumeResult =
  { ok: true } | { ok: false; reason: 'INVALID_OR_EXPIRED_TOKEN' };

const resetStateSchema = z.strictObject({
  // M2.8 stores the existing PostgreSQL UUID User primary key, not public input.
  userId: z.uuid(),
});

function parseResetState(value: string): { userId: string } | null {
  try {
    const input: unknown = JSON.parse(value);
    const result = resetStateSchema.safeParse(input);
    return result.success ? result.data : null;
  } catch {
    // Never propagate Redis contents or parser/validation errors.
    return null;
  }
}

@Injectable()
export class PasswordResetConsumeService {
  private readonly logger = new Logger(PasswordResetConsumeService.name);

  constructor(
    @Inject(RedisService) private readonly redis: RedisService,
    @Inject(PrismaService) private readonly prisma: PrismaService,
    @Inject(PasswordService) private readonly passwords: PasswordService,
  ) {}

  async consume(
    rawToken: string,
    newPassword: string,
  ): Promise<PasswordResetConsumeResult> {
    try {
      const tokenHash = createHash('sha256').update(rawToken).digest('hex');
      const key = buildRedisKey('pwdreset', tokenHash);
      // Cheap non-destructive precheck: arbitrary missing tokens cannot force Argon2.
      const preview = await this.redis.get(key);
      const prechecked = preview === null ? null : parseResetState(preview);
      if (prechecked === null)
        return { ok: false, reason: 'INVALID_OR_EXPIRED_TOKEN' };

      // Hashing failure must occur before the one-time token is destroyed.
      const passwordHash = await this.passwords.hash(newPassword);
      // Only this atomic GETDEL claims ownership; GET + DEL is not a substitute.
      const consumed = await this.redis.getAndDelete(key);
      const state = consumed === null ? null : parseResetState(consumed);
      if (state === null || state.userId !== prechecked.userId)
        return { ok: false, reason: 'INVALID_OR_EXPIRED_TOKEN' };

      // After GETDEL, never restore the token, even if persistence fails.
      const updated = await this.prisma.credential.updateMany({
        where: { userId: state.userId },
        data: { passwordHash, passwordUpdatedAt: new Date() },
      });
      if (updated.count === 0)
        return { ok: false, reason: 'INVALID_OR_EXPIRED_TOKEN' };
      if (updated.count !== 1) throw new Error('Unexpected update count.');

      // Provisional event only; persistent audit infrastructure remains M12.
      this.logger.log({ event: 'PASSWORD_RESET', userId: state.userId });
      return { ok: true };
    } catch {
      // Fail closed without driver details, secrets, Redis key or cause chains.
      throw new Error('Password reset consume failed.');
    }
  }
}
