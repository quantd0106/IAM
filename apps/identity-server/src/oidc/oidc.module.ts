import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { DiscoveryController } from './discovery.controller.js';
import { DiscoveryService } from './discovery.service.js';

@Module({
  imports: [ConfigModule],
  controllers: [DiscoveryController],
  providers: [DiscoveryService],
})
export class OidcModule {}
