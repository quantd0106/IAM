import { Module } from '@nestjs/common';
import { ClientRegistryModule } from '../client-registry/client-registry.module.js';
import { AuthorizationRequestService } from './authorization-request.service.js';
import { OAuthController } from './oauth.controller.js';

@Module({
  imports: [ClientRegistryModule],
  controllers: [OAuthController],
  providers: [AuthorizationRequestService],
})
export class OAuthModule {}
