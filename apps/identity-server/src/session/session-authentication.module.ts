import { Module } from '@nestjs/common';
import { PrismaModule } from '../prisma/prisma.module.js';
import { SessionModule } from './session.module.js';
import { IdpSessionAuthenticationService } from './idp-session-authentication.service.js';

@Module({
  imports: [SessionModule, PrismaModule],
  providers: [IdpSessionAuthenticationService],
  exports: [IdpSessionAuthenticationService],
})
export class SessionAuthenticationModule {}
