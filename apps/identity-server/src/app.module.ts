import { Module } from '@nestjs/common';
import { AppConfigModule } from './config/config.module.js';
import { HealthController } from './health.controller.js';
import { AuthModule } from './auth/auth.module.js';
import { SessionModule } from './session/session.module.js';
import { ClientRegistryModule } from './client-registry/client-registry.module.js';

@Module({
  imports: [AppConfigModule, AuthModule, SessionModule, ClientRegistryModule],
  controllers: [HealthController],
})
export class AppModule {}
