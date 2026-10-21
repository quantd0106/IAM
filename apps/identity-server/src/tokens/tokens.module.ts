import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { AccessTokenClaimsService } from './access-token-claims.service.js';

@Module({
  imports: [ConfigModule],
  providers: [AccessTokenClaimsService],
  exports: [AccessTokenClaimsService],
})
export class TokensModule {}
