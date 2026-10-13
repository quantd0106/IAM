import { Module } from '@nestjs/common';
import { APP_FILTER } from '@nestjs/core';
import { PrismaModule } from '../prisma/prisma.module.js';
import { PasswordService } from '../security/password/password.service.js';
import { AuthController } from './auth.controller.js';
import { RegistrationService } from './registration.service.js';
import { RegisterValidationFilter } from './register-validation.filter.js';
import { LoginValidationService } from './login-validation.service.js';
import { LoginAttemptService } from './login-attempt.service.js';
import { RedisModule } from '../redis/redis.module.js';

@Module({
  imports: [PrismaModule, RedisModule],
  controllers: [AuthController],
  providers: [
    RegistrationService,
    LoginValidationService,
    LoginAttemptService,
    PasswordService,
    { provide: APP_FILTER, useClass: RegisterValidationFilter },
  ],
})
export class AuthModule {}
