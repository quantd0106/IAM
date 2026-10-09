import type { Server } from 'node:http';
import { Test, TestingModule } from '@nestjs/testing';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { ConfigService } from '@nestjs/config';
import { validateEnvironment, type Environment } from './config/env.schema.js';
import request from 'supertest';
import type { INestApplication } from '@nestjs/common';
import { AppModule } from './app.module.js';

describe('Identity Server', () => {
  let app: INestApplication<Server>;

  beforeAll(async () => {
    // Complete isolated values override any local .env; no live DB/Redis is used.
    const environment = validateEnvironment({
      NODE_ENV: 'test',
      DATABASE_URL: 'postgresql://test:test@127.0.0.1:1/test',
      REDIS_URL: 'redis://127.0.0.1:1',
      ISSUER_URL: 'http://localhost:3000',
      JWT_PRIVATE_KEY_PATH: './test-placeholder-private.pem',
      JWT_PUBLIC_KEY_PATH: './test-placeholder-public.pem',
      JWT_KEY_ID: 'test-placeholder',
      TOTP_ENCRYPTION_KEY: 'test-only-placeholder',
    });
    for (const [name, value] of Object.entries(environment))
      vi.stubEnv(name, String(value));
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

    app = moduleFixture.createNestApplication<INestApplication<Server>>();
    await app.init();
  });

  afterAll(async () => {
    await app.close();
    vi.unstubAllEnvs();
  });

  it('initializes the application module', () => {
    expect(app).toBeDefined();
  });

  it('exposes typed configuration without raw process environment fallback', () => {
    const config = app.get<ConfigService<Environment, true>>(ConfigService);
    expect(config.get('IDENTITY_SERVER_PORT', { infer: true })).toBe(3000);
    expect(config.get('COOKIE_SECURE', { infer: true })).toBe(false);
    vi.stubEnv('IDENTITY_SERVER_PORT', '9999');
    expect(config.get('IDENTITY_SERVER_PORT', { infer: true })).toBe(3000);
    vi.stubEnv('IDENTITY_SERVER_PORT', '3000');
  });

  it('fails on a missing secret during DI initialization before listen', async () => {
    const listen = vi.fn();
    vi.stubEnv('TOTP_ENCRYPTION_KEY', undefined);
    try {
      await expect(
        Test.createTestingModule({ imports: [AppModule] })
          .compile()
          .then(listen),
      ).rejects.toThrow('TOTP_ENCRYPTION_KEY');
      expect(listen).not.toHaveBeenCalled();
    } finally {
      vi.stubEnv('TOTP_ENCRYPTION_KEY', 'test-only-placeholder');
    }
  });

  it('returns a healthy status', async () => {
    await request(app.getHttpServer())
      .get('/health')
      .expect(200)
      .expect({ status: 'ok' });
  });
});
