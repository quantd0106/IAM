import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { SigningKeyModule } from '../security/signing/signing-key.module.js';
import { DiscoveryController } from './discovery.controller.js';
import { DiscoveryService } from './discovery.service.js';
import { JwksController } from './jwks.controller.js';
import { JwksService } from './jwks.service.js';
import { IdTokenClaimsService } from './id-token-claims.service.js';
import { IdTokenIssuerService } from './id-token-issuer.service.js';
import { UserInfoAccessTokenService } from './userinfo-access-token.service.js';
import { UserInfoController } from './userinfo.controller.js';

@Module({
  imports: [ConfigModule, SigningKeyModule],
  controllers: [DiscoveryController, JwksController, UserInfoController],
  providers: [
    DiscoveryService,
    JwksService,
    IdTokenClaimsService,
    IdTokenIssuerService,
    UserInfoAccessTokenService,
  ],
})
export class OidcModule {}
