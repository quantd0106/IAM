import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { AccessTokenClaimsService } from './access-token-claims.service.js';
import { AccessTokenIssuerService } from './access-token-issuer.service.js';
import { RefreshTokenGeneratorService } from './refresh-token-generator.service.js';
import { SigningKeyModule } from '../security/signing/signing-key.module.js';

@Module({
  imports: [ConfigModule, SigningKeyModule],
  providers: [
    AccessTokenClaimsService,
    AccessTokenIssuerService,
    RefreshTokenGeneratorService,
  ],
  exports: [
    AccessTokenClaimsService,
    AccessTokenIssuerService,
    RefreshTokenGeneratorService,
  ],
})
export class TokensModule {}
