import { Module } from '@nestjs/common';
import { RedisModule } from '../redis/redis.module.js';
import { IdpSessionStateService } from './idp-session-state.service.js';
import { IdpSessionCookieService } from './idp-session-cookie.service.js';

@Module({
  imports: [RedisModule],
  providers: [IdpSessionStateService, IdpSessionCookieService],
  exports: [IdpSessionStateService, IdpSessionCookieService],
})
export class SessionModule {}
