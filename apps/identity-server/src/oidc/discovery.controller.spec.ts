import { Logger, type INestApplication } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Test } from '@nestjs/testing';
import type { Server } from 'node:http';
import request from 'supertest';
import {
  afterAll,
  afterEach,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
  vi,
  type MockInstance,
} from 'vitest';
import type { Environment } from '../config/env.schema.js';
import { OidcModule } from './oidc.module.js';
import { DiscoveryService } from './discovery.service.js';

describe('GET /.well-known/openid-configuration', () => {
  let app: INestApplication<Server>;
  let logs: MockInstance[];
  const config = new ConfigService<Environment, true>({
    ISSUER_URL: 'https://iam.example.test/',
    JWT_PRIVATE_KEY_PATH: './nonexistent-private-canary.pem',
    JWT_PUBLIC_KEY_PATH: './nonexistent-public-canary.pem',
    DATABASE_URL: 'private-config-canary',
    REDIS_URL: 'private-config-canary',
  });
  const expected = {
    issuer: 'https://iam.example.test/',
    authorization_endpoint: 'https://iam.example.test/oauth/authorize',
    token_endpoint: 'https://iam.example.test/oauth/token',
    userinfo_endpoint: 'https://iam.example.test/oidc/userinfo',
    jwks_uri: 'https://iam.example.test/.well-known/jwks.json',
    scopes_supported: ['openid', 'profile', 'email'],
    response_types_supported: ['code'],
    response_modes_supported: ['query'],
    grant_types_supported: ['authorization_code'],
    subject_types_supported: ['public'],
    id_token_signing_alg_values_supported: ['RS256'],
    token_endpoint_auth_methods_supported: ['client_secret_basic', 'none'],
    code_challenge_methods_supported: ['S256'],
    claims_parameter_supported: false,
    request_parameter_supported: false,
    request_uri_parameter_supported: false,
  };
  beforeAll(async () => {
    const module = await Test.createTestingModule({ imports: [OidcModule] })
      .overrideProvider(ConfigService)
      .useValue(config)
      .compile();
    app = module.createNestApplication<INestApplication<Server>>({
      logger: false,
    });
    await app.init();
  });
  beforeEach(() => {
    logs = [console, Logger, Logger.prototype].flatMap((target) =>
      ['log', 'info', 'warn', 'error', 'debug', 'verbose', 'fatal'].flatMap(
        (name) =>
          name in target
            ? [
                vi
                  .spyOn(target, name as 'log')
                  .mockImplementation(() => undefined),
              ]
            : [],
      ),
    );
  });
  afterEach(() => {
    try {
      for (const log of logs) expect(log).not.toHaveBeenCalled();
    } finally {
      vi.restoreAllMocks();
    }
  });
  afterAll(async () => {
    await app.close();
  });

  it('returns exact public JSON/no-store without authentication, stores or real key files', async () => {
    const get = vi.spyOn(config, 'getOrThrow');
    const response = await request(app.getHttpServer())
      .get('/.well-known/openid-configuration')
      .expect(200);
    expect(response.headers['content-type']).toMatch(/^application\/json/);
    expect(response.headers['cache-control']).toBe('no-store');
    expect(response.headers.location).toBeUndefined();
    expect(response.headers['set-cookie']).toBeUndefined();
    expect(response.headers['www-authenticate']).toBeUndefined();
    expect(response.body as unknown).toEqual(expected);
    expect(get).toHaveBeenCalledExactlyOnceWith('ISSUER_URL', { infer: true });
    expect(response.text.includes('canary')).toBe(false);
  });
  it('ignores Host, forwarded host/proto, Origin, query, cookies and caller credentials', async () => {
    const response = await request(app.getHttpServer())
      .get(
        '/.well-known/openid-configuration?issuer=https%3A%2F%2Fcaller.invalid',
      )
      .set('Host', 'caller.invalid')
      .set('X-Forwarded-Host', 'caller.invalid')
      .set('X-Forwarded-Proto', 'http')
      .set('Origin', 'https://caller.invalid')
      .set('Cookie', 'iam.sid=untrusted-canary')
      .set('Authorization', 'Bearer untrusted-canary')
      .expect(200);
    expect(response.body as unknown).toEqual(expected);
    expect(response.headers['set-cookie']).toBeUndefined();
    expect(response.headers.location).toBeUndefined();
  });
  it.each(['config', 'internal'])(
    'sanitizes %s errors without logging native/private details',
    async (kind) => {
      if (kind === 'config')
        vi.spyOn(config, 'getOrThrow').mockImplementation(() => {
          throw new Error('private-config-canary');
        });
      else
        vi.spyOn(app.get(DiscoveryService), 'build').mockImplementation(() => {
          throw new Error('private-config-canary', {
            cause: new Error('native private cause'),
          });
        });
      const response = await request(app.getHttpServer())
        .get('/.well-known/openid-configuration')
        .expect(500);
      expect(response.body as unknown).toEqual({
        error: 'server_error',
        error_description: 'Discovery request failed.',
      });
      expect(response.headers['cache-control']).toBe('no-store');
      expect(response.headers['set-cookie']).toBeUndefined();
      expect(response.headers.location).toBeUndefined();
      expect(response.text.includes('canary')).toBe(false);
    },
  );
  it.each(['/.well-known/jwks.json', '/oidc/userinfo', '/oauth/token'])(
    'does not introduce staged/unsupported route %s',
    async (path) => {
      await request(app.getHttpServer()).get(path).expect(404);
    },
  );
});
