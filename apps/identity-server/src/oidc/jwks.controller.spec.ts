import { Logger, type INestApplication } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
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
import { SigningKeyModule } from '../security/signing/signing-key.module.js';
import {
  SigningKeyService,
  type PublicSigningJwk,
} from '../security/signing/signing-key.service.js';
import { DiscoveryController } from './discovery.controller.js';
import { DiscoveryService } from './discovery.service.js';
import { JwksController } from './jwks.controller.js';
import { JwksService } from './jwks.service.js';
import { OidcModule } from './oidc.module.js';
import { IdTokenClaimsService } from './id-token-claims.service.js';
import { IdTokenIssuerService } from './id-token-issuer.service.js';
import { UserInfoAccessTokenService } from './userinfo-access-token.service.js';
import { UserInfoController } from './userinfo.controller.js';

describe('public GET /.well-known/jwks.json', () => {
  let app: INestApplication<Server>;
  let logs: MockInstance[];
  const publicKey: PublicSigningJwk = {
    kty: 'RSA',
    kid: 'MiXeD-e\u0301-Key',
    alg: 'RS256',
    use: 'sig',
    n: 'opaque_Modulus-unchanged',
    e: 'AQAB',
  };
  const getPublicJwk = vi.fn<() => Promise<PublicSigningJwk>>();
  const unexpected = vi.fn(() => {
    throw new Error('Unexpected private capability.');
  });
  beforeAll(async () => {
    const module = await Test.createTestingModule({ imports: [OidcModule] })
      .overrideProvider(SigningKeyService)
      .useValue({
        getPublicJwk,
        getPrivateSigningKey: unexpected,
        getPublicVerificationKey: unexpected,
        getKeyId: unexpected,
      })
      .overrideProvider(ConfigService)
      .useValue(new ConfigService({ ISSUER_URL: 'http://localhost:3000' }))
      .compile();
    app = module.createNestApplication<INestApplication<Server>>({
      logger: false,
    });
    await app.init();
    expect(getPublicJwk).not.toHaveBeenCalled();
  });
  beforeEach(() => {
    vi.clearAllMocks();
    getPublicJwk.mockResolvedValue(publicKey);
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
      expect(unexpected).not.toHaveBeenCalled();
      for (const log of logs) expect(log).not.toHaveBeenCalled();
    } finally {
      vi.restoreAllMocks();
    }
  });
  afterAll(async () => {
    await app.close();
  });

  it('wires only Config and signing capabilities in the existing non-global OIDC module', () => {
    expect(Reflect.getMetadata('imports', OidcModule) as unknown).toEqual([
      ConfigModule,
      SigningKeyModule,
    ]);
    expect(Reflect.getMetadata('providers', OidcModule) as unknown).toEqual([
      DiscoveryService,
      JwksService,
      IdTokenClaimsService,
      IdTokenIssuerService,
      UserInfoAccessTokenService,
    ]);
    expect(Reflect.getMetadata('controllers', OidcModule) as unknown).toEqual([
      DiscoveryController,
      JwksController,
      UserInfoController,
    ]);
    expect(
      (Reflect.getMetadata('exports', OidcModule) as unknown) ?? [],
    ).toEqual([]);
    expect(
      Reflect.getMetadata('__module:global__', OidcModule) as unknown,
    ).not.toBe(true);
  });
  it('returns exact one-key public JSON/cache without login, cookie, redirect or challenge', async () => {
    const response = await request(app.getHttpServer())
      .get('/.well-known/jwks.json')
      .expect(200);
    expect(response.headers['content-type']).toMatch(/^application\/json/);
    expect(response.headers['cache-control']).toBe('public, max-age=300');
    expect(response.headers['set-cookie']).toBeUndefined();
    expect(response.headers.location).toBeUndefined();
    expect(response.headers['www-authenticate']).toBeUndefined();
    expect(response.headers.etag).toBeUndefined();
    expect(response.headers['last-modified']).toBeUndefined();
    expect(response.body as unknown).toEqual({ keys: [publicKey] });
    expect(getPublicJwk).toHaveBeenCalledExactlyOnceWith();
  });
  it('ignores Cookie/Authorization/Host/forwarded headers and key-selection queries', async () => {
    const response = await request(app.getHttpServer())
      .get('/.well-known/jwks.json?kid=caller&alg=HS256&version=2&kid=another')
      .set('Host', 'caller.invalid')
      .set('X-Forwarded-Host', 'caller.invalid')
      .set('X-Forwarded-Proto', 'http')
      .set('Cookie', 'iam.sid=untrusted-canary')
      .set('Authorization', 'Basic untrusted-canary')
      .expect(200);
    expect(response.body as unknown).toEqual({ keys: [publicKey] });
    expect(response.headers['set-cookie']).toBeUndefined();
    expect(response.headers.location).toBeUndefined();
    expect(response.headers['www-authenticate']).toBeUndefined();
    expect(getPublicJwk).toHaveBeenCalledExactlyOnceWith();
  });
  it('does not introduce ETag, Last-Modified or conditional 304 behavior', async () => {
    const response = await request(app.getHttpServer())
      .get('/.well-known/jwks.json')
      .set('If-None-Match', '*')
      .set('If-Modified-Since', 'Tue, 01 Jan 2100 00:00:00 GMT')
      .expect(200);
    expect(response.body as unknown).toEqual({ keys: [publicKey] });
    expect(response.headers.etag).toBeUndefined();
    expect(response.headers['last-modified']).toBeUndefined();
  });
  it.each(['signing', 'internal'])(
    'sanitizes %s failure without private/native details or logs',
    async (kind) => {
      const native = new Error('private-native-PEM-path-kid-canary', {
        cause: new Error('private-native-cause'),
      });
      if (kind === 'signing') getPublicJwk.mockRejectedValue(native);
      else vi.spyOn(app.get(JwksService), 'build').mockRejectedValue(native);
      const response = await request(app.getHttpServer())
        .get('/.well-known/jwks.json')
        .expect(500);
      expect(response.body as unknown).toEqual({
        error: 'server_error',
        error_description: 'JWKS request failed.',
      });
      expect(response.headers['content-type']).toMatch(/^application\/json/);
      expect(response.headers['cache-control']).toBe('no-store');
      expect(response.headers['set-cookie']).toBeUndefined();
      expect(response.headers.location).toBeUndefined();
      expect(response.headers['www-authenticate']).toBeUndefined();
      expect(response.headers.etag).toBeUndefined();
      expect(response.text.includes('canary')).toBe(false);
    },
  );
});
