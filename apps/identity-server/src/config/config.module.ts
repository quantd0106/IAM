import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { fileURLToPath } from 'node:url';
import { validateEnvironment } from './env.schema.js';

@Module({
  imports: [
    ConfigModule.forRoot({
      envFilePath: fileURLToPath(new URL('../../.env', import.meta.url)),
      isGlobal: true,
      cache: true,
      skipProcessEnv: true,
      // A Nest config factory validates during DI initialization, before listen.
      // Only this configuration boundary reads the resolved file/shell environment.
      load: [() => validateEnvironment(process.env)],
    }),
  ],
  exports: [ConfigModule],
})
export class AppConfigModule {}
