import { Module } from '@nestjs/common';
import { AppConfigModule } from './config/config.module.js';
import { HealthController } from './health.controller.js';
import { AuthModule } from './auth/auth.module.js';
import { SessionModule } from './session/session.module.js';
import { ClientRegistryModule } from './client-registry/client-registry.module.js';
import { OAuthModule } from './oauth/oauth.module.js';

@Module({
  imports: [
    AppConfigModule,
    AuthModule,
    SessionModule,
    ClientRegistryModule,
    OAuthModule,
  ],
  controllers: [HealthController],
})
export class AppModule {}
