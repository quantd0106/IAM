import { Module } from '@nestjs/common';
import { AppConfigModule } from './config/config.module.js';
import { HealthController } from './health.controller.js';
import { AuthModule } from './auth/auth.module.js';
import { SessionModule } from './session/session.module.js';
import { ClientRegistryModule } from './client-registry/client-registry.module.js';
import { OAuthModule } from './oauth/oauth.module.js';
import { SigningKeyModule } from './security/signing/signing-key.module.js';

@Module({
  imports: [
    AppConfigModule,
    AuthModule,
    SessionModule,
    ClientRegistryModule,
    OAuthModule,
    SigningKeyModule,
  ],
  controllers: [HealthController],
})
export class AppModule {}
