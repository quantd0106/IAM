import 'reflect-metadata';
import { NestFactory } from '@nestjs/core';
import { ConfigService } from '@nestjs/config';
import type { Environment } from './config/env.schema.js';
import { AppModule } from './app.module.js';

async function bootstrap(): Promise<void> {
  const app = await NestFactory.create(AppModule);
  const config = app.get<ConfigService<Environment, true>>(ConfigService);
  const port = config.get('IDENTITY_SERVER_PORT', { infer: true });

  await app.listen(port);
}

void bootstrap();
