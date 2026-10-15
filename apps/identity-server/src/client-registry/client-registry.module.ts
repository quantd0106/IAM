import { Module } from '@nestjs/common';
import { PrismaModule } from '../prisma/prisma.module.js';
import { ClientSecretService } from './client-secret.service.js';
import { ClientLookupService } from './client-lookup.service.js';
import { ScopeLookupService } from './scope-lookup.service.js';

@Module({
  imports: [PrismaModule],
  providers: [ClientSecretService, ClientLookupService, ScopeLookupService],
  exports: [ClientSecretService, ClientLookupService, ScopeLookupService],
})
export class ClientRegistryModule {}
