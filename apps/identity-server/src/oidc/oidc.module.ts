import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { SigningKeyModule } from '../security/signing/signing-key.module.js';
import { DiscoveryController } from './discovery.controller.js';
import { DiscoveryService } from './discovery.service.js';
import { JwksController } from './jwks.controller.js';
import { JwksService } from './jwks.service.js';

@Module({
  imports: [ConfigModule, SigningKeyModule],
  controllers: [DiscoveryController, JwksController],
  providers: [DiscoveryService, JwksService],
})
export class OidcModule {}
