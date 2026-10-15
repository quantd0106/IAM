import { Module } from '@nestjs/common';
import { ClientRegistryModule } from '../client-registry/client-registry.module.js';
import { AuthorizationRequestService } from './authorization-request.service.js';
import { OAuthController } from './oauth.controller.js';
import { SessionAuthenticationModule } from '../session/session-authentication.module.js';
import { AuthorizationService } from './authorization.service.js';

@Module({
  imports: [ClientRegistryModule, SessionAuthenticationModule],
  controllers: [OAuthController],
  providers: [AuthorizationRequestService, AuthorizationService],
})
export class OAuthModule {}
