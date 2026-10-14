import { Inject, Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import type { Environment } from '../config/env.schema.js';
import { PrismaService } from '../prisma/prisma.service.js';
import { IdpSessionStateService } from '../session/idp-session-state.service.js';
import { LoginAttemptService } from './login-attempt.service.js';
import type { LoginIdentifier } from './login-validation.service.js';

export type IdpLoginResult = { ok: true; sessionId: string } | { ok: false };

@Injectable()
export class IdpLoginService {
  private readonly absoluteTtlSeconds: number;

  constructor(
    @Inject(LoginAttemptService) private readonly attempts: LoginAttemptService,
    @Inject(PrismaService) private readonly prisma: PrismaService,
    @Inject(IdpSessionStateService)
    private readonly sessions: IdpSessionStateService,
    @Inject(ConfigService) config: ConfigService<Environment, true>,
  ) {
    this.absoluteTtlSeconds = config.getOrThrow(
      'SESSION_ABSOLUTE_TTL_SECONDS',
      { infer: true },
    );
  }

  async login(
    identifier: LoginIdentifier,
    rawPassword: string,
  ): Promise<IdpLoginResult> {
    try {
      const authenticated = await this.attempts.attempt(
        identifier,
        rawPassword,
      );
      if (!authenticated.ok) return { ok: false };

      const nowMs = Date.now();
      const lifetimeMs = this.absoluteTtlSeconds * 1000;
      const absoluteExpiresAt = nowMs + lifetimeMs;
      if (
        !Number.isSafeInteger(nowMs) ||
        nowMs < 0 ||
        !Number.isSafeInteger(lifetimeMs) ||
        lifetimeMs <= 0 ||
        !Number.isSafeInteger(absoluteExpiresAt) ||
        absoluteExpiresAt <= nowMs ||
        !Number.isFinite(new Date(absoluteExpiresAt).getTime())
      )
        throw new Error('Invalid session lifetime.');

      const sessionId = await this.prisma.$transaction(async (transaction) => {
        const session = await transaction.session.create({
          data: {
            userId: authenticated.user.id,
            status: 'ACTIVE',
            createdAt: new Date(nowMs),
            lastActivityAt: new Date(nowMs),
            expiresAt: new Date(absoluteExpiresAt),
          },
          select: { id: true },
        });
        await this.sessions.create(session.id, {
          userId: authenticated.user.id,
          authTime: nowMs,
          mfaLevel: 'password',
          createdAt: nowMs,
          lastActivityAt: nowMs,
          absoluteExpiresAt,
        });
        return session.id;
      });
      // Return only after commit; no browser-provided identifier enters this path.
      return { ok: true, sessionId };
    } catch {
      // No credentials, session IDs, driver messages or causes escape.
      // A final commit failure can leave only a TTL-bounded Redis orphan.
      throw new Error('IdP login failed.');
    }
  }
}
