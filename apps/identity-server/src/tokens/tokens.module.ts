import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { AccessTokenClaimsService } from './access-token-claims.service.js';
import { AccessTokenIssuerService } from './access-token-issuer.service.js';
import { RefreshTokenGeneratorService } from './refresh-token-generator.service.js';
import { SigningKeyModule } from '../security/signing/signing-key.module.js';
import { PrismaModule } from '../prisma/prisma.module.js';
import { RefreshTokenIssuerService } from './refresh-token-issuer.service.js';

@Module({
  imports: [ConfigModule, SigningKeyModule, PrismaModule],
  providers: [
    AccessTokenClaimsService,
    AccessTokenIssuerService,
    RefreshTokenGeneratorService,
    RefreshTokenIssuerService,
  ],
  exports: [
    AccessTokenClaimsService,
    AccessTokenIssuerService,
    RefreshTokenGeneratorService,
    RefreshTokenIssuerService,
  ],
})
export class TokensModule {}
