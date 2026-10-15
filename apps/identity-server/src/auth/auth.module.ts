import { Module } from '@nestjs/common';
import { APP_FILTER } from '@nestjs/core';
import { PrismaModule } from '../prisma/prisma.module.js';
import { PasswordService } from '../security/password/password.service.js';
import { AuthController } from './auth.controller.js';
import { AuthSessionsController } from './auth-sessions.controller.js';
import { IdpOwnSessionService } from './idp-own-session.service.js';
import { AdminSessionRevocationService } from './admin-session-revocation.service.js';
import { RegistrationService } from './registration.service.js';
import { RegisterValidationFilter } from './register-validation.filter.js';
import { LoginValidationService } from './login-validation.service.js';
import { LoginAttemptService } from './login-attempt.service.js';
import { RedisModule } from '../redis/redis.module.js';
import { SessionModule } from '../session/session.module.js';
import { SessionAuthenticationModule } from '../session/session-authentication.module.js';
import { IdpLoginService } from './idp-login.service.js';
import { IdpLogoutService } from './idp-logout.service.js';
import { PasswordChangeService } from './password-change.service.js';
import { PasswordResetRequestService } from './password-reset-request.service.js';
import { PasswordResetConsumeService } from './password-reset-consume.service.js';
import {
  PASSWORD_RESET_DELIVERY,
  noOpPasswordResetDelivery,
} from './password-reset-delivery.js';

@Module({
  imports: [
    PrismaModule,
    RedisModule,
    SessionModule,
    SessionAuthenticationModule,
  ],
  controllers: [AuthController, AuthSessionsController],
  providers: [
    RegistrationService,
    LoginValidationService,
    LoginAttemptService,
    IdpLoginService,
    IdpLogoutService,
    IdpOwnSessionService,
    AdminSessionRevocationService,
    PasswordChangeService,
    PasswordResetRequestService,
    PasswordResetConsumeService,
    { provide: PASSWORD_RESET_DELIVERY, useValue: noOpPasswordResetDelivery },
    PasswordService,
    { provide: APP_FILTER, useClass: RegisterValidationFilter },
  ],
  // Internal DI capability, not HTTP access or an authorization decision.
  exports: [AdminSessionRevocationService],
})
export class AuthModule {}
