import { Module } from '@nestjs/common';
import { PrismaModule } from '../prisma/prisma.module.js';
import { ClientSecretService } from './client-secret.service.js';

@Module({
  imports: [PrismaModule],
  providers: [ClientSecretService],
  exports: [ClientSecretService],
})
export class ClientRegistryModule {}
