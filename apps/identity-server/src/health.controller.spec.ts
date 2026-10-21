import type { Server } from 'node:http';
import { Test, TestingModule } from '@nestjs/testing';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { ConfigService } from '@nestjs/config';
import { validateEnvironment, type Environment } from './config/env.schema.js';
import request from 'supertest';
import type { INestApplication } from '@nestjs/common';
import { AppModule } from './app.module.js';
import { RedisService } from './redis/redis.service.js';
import { SigningKeyService } from './security/signing/signing-key.service.js';
import { AccessTokenClaimsService } from './tokens/access-token-claims.service.js';

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
    })
      .overrideProvider(RedisService)
      .useValue({})
      .compile();

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

  it('builds internal claims without initializing signing keys or affecting health', async () => {
    const keys = app.get(SigningKeyService);
    const methods = [
      'getPrivateSigningKey',
      'getPublicVerificationKey',
      'getPublicJwk',
      'getKeyId',
    ] as const;
    const spies = methods.map((method) => vi.spyOn(keys, method));
    try {
      const claims = app.get(AccessTokenClaimsService).build({
        subject: 'c0e21e3f-d3ee-425c-a99f-c2e7a7cab53f',
        audience: 'student-api',
        scopes: ['openid', 'profile'],
        roles: [],
        permissions: [],
      });
      expect(claims).toMatchObject({
        aud: 'student-api',
        scope: 'openid profile',
        roles: [],
        permissions: [],
      });
      for (const spy of spies) expect(spy).not.toHaveBeenCalled();
      await request(app.getHttpServer())
        .get('/health')
        .expect(200)
        .expect({ status: 'ok' });
    } finally {
      for (const spy of spies) spy.mockRestore();
    }
  });

  it('keeps startup/health independent of lazy signing-key initialization failure', async () => {
    const keys = app.get(SigningKeyService);
    expect(keys).toBeInstanceOf(SigningKeyService);
    await expect(keys.getPublicJwk()).rejects.toThrowError(
      new Error('Signing key initialization failed.'),
    );
    await request(app.getHttpServer())
      .get('/health')
      .expect(200)
      .expect({ status: 'ok' });
  });

  it.each(['/.well-known/jwks.json', '/.well-known/openid-configuration'])(
    'does not add the future HTTP endpoint %s',
    async (path) => {
      await request(app.getHttpServer()).get(path).expect(404);
    },
  );

  it('keeps process health available when registration cannot reach PostgreSQL', async () => {
    const response = await request(app.getHttpServer())
      .post('/auth/register')
      .send({
        email: 'offline@example.invalid',
        username: 'offline',
        password: 'test-only offline input',
      })
      .expect(500);
    expect(response.body as unknown).toEqual({
      statusCode: 500,
      error: 'Internal Server Error',
      message: 'Registration failed.',
    });
    expect(response.headers['set-cookie']).toBeUndefined();
    await request(app.getHttpServer())
      .get('/health')
      .expect(200)
      .expect({ status: 'ok' });
  }, 15000);
});
