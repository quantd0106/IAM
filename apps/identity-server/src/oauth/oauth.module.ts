import { Module } from '@nestjs/common';
import { ClientRegistryModule } from '../client-registry/client-registry.module.js';
import { AuthorizationRequestService } from './authorization-request.service.js';
import { OAuthController } from './oauth.controller.js';
import { SessionAuthenticationModule } from '../session/session-authentication.module.js';
import { AuthorizationService } from './authorization.service.js';
import { AuthorizationCodeService } from './authorization-code.service.js';
import { RedisModule } from '../redis/redis.module.js';
import { TokenRequestService } from './token-request.service.js';
import { TokensModule } from '../tokens/tokens.module.js';

@Module({
  imports: [
    ClientRegistryModule,
    SessionAuthenticationModule,
    RedisModule,
    TokensModule,
  ],
  controllers: [OAuthController],
  providers: [
    AuthorizationRequestService,
    AuthorizationService,
    AuthorizationCodeService,
    TokenRequestService,
  ],
})
export class OAuthModule {}
