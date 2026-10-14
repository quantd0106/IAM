import { Module } from '@nestjs/common';
import { AppConfigModule } from './config/config.module.js';
import { HealthController } from './health.controller.js';
import { AuthModule } from './auth/auth.module.js';
import { SessionModule } from './session/session.module.js';

@Module({
  imports: [AppConfigModule, AuthModule, SessionModule],
  controllers: [HealthController],
})
export class AppModule {}
