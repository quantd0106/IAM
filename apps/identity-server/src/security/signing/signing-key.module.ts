import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { SigningKeyService } from './signing-key.service.js';

@Module({
  imports: [ConfigModule],
  providers: [SigningKeyService],
  exports: [SigningKeyService],
})
export class SigningKeyModule {}
