import { Module } from '@nestjs/common';
import { AppConfigModule } from './config/config.module.js';
import { HealthController } from './health.controller.js';

@Module({
  imports: [AppConfigModule],
  controllers: [HealthController],
})
export class AppModule {}
