import { Module } from '@nestjs/common';
import { PrismaModule } from '../prisma/prisma.module.js';
import { ClientSecretService } from './client-secret.service.js';
import { ClientLookupService } from './client-lookup.service.js';
import { ScopeLookupService } from './scope-lookup.service.js';
import { ClientAuthenticationService } from './client-authentication.service.js';

@Module({
  imports: [PrismaModule],
  providers: [
    ClientSecretService,
    ClientLookupService,
    ScopeLookupService,
    ClientAuthenticationService,
  ],
  exports: [
    ClientSecretService,
    ClientLookupService,
    ScopeLookupService,
    ClientAuthenticationService,
  ],
})
export class ClientRegistryModule {}
