import { Module } from '@nestjs/common';
import { RedisModule } from '../redis/redis.module.js';
import { IdpSessionStateService } from './idp-session-state.service.js';

@Module({
  imports: [RedisModule],
  providers: [IdpSessionStateService],
  exports: [IdpSessionStateService],
})
export class SessionModule {}
