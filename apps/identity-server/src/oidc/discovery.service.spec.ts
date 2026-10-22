import { Logger } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { Test } from '@nestjs/testing';
import {
  afterEach,
  beforeEach,
  describe,
  expect,
  it,
  vi,
  type MockInstance,
} from 'vitest';
import type { Environment } from '../config/env.schema.js';
import { DiscoveryService } from './discovery.service.js';

const { forbiddenImport, forbiddenIO } = vi.hoisted(() => ({
  forbiddenImport: vi.fn(() => {
    throw new Error('Unexpected discovery dependency.');
  }),
  forbiddenIO: vi.fn(() => {
    throw new Error('Unexpected discovery I/O.');
  }),
}));
vi.mock('../prisma/prisma.service.js', () => {
  forbiddenImport();
  return {};
});
vi.mock('../redis/redis.service.js', () => {
  forbiddenImport();
  return {};
});
vi.mock('../security/signing/signing-key.service.js', () => {
  forbiddenImport();
  return {};
});
vi.mock('../tokens/access-token-issuer.service.js', () => {
  forbiddenImport();
  return {};
});
vi.mock('../client-registry/client-lookup.service.js', () => {
  forbiddenImport();
  return {};
});
vi.mock('../client-registry/scope-lookup.service.js', () => {
  forbiddenImport();
  return {};
});
vi.mock('jose', () => {
  forbiddenImport();
  return {};
});
vi.mock('node:fs/promises', async (original) => ({
  ...(await original<typeof import('node:fs/promises')>()),
  readFile: forbiddenIO,
  writeFile: forbiddenIO,
}));
vi.mock('node:fs', async (original) => ({
  ...(await original<typeof import('node:fs')>()),
  readFile: forbiddenIO,
  readFileSync: forbiddenIO,
  writeFile: forbiddenIO,
  writeFileSync: forbiddenIO,
}));
vi.mock('node:http', async (original) => ({
  ...(await original<typeof import('node:http')>()),
  get: forbiddenIO,
  request: forbiddenIO,
}));
vi.mock('node:https', async (original) => ({
  ...(await original<typeof import('node:https')>()),
  get: forbiddenIO,
  request: forbiddenIO,
}));

const configFor = (
  issuer: unknown = 'http://localhost:3000',
): ConfigService<Environment, true> =>
  new ConfigService<Environment, true>({
    ISSUER_URL: issuer,
    DATABASE_URL: 'private-config-canary',
    REDIS_URL: 'private-config-canary',
    JWT_PRIVATE_KEY_PATH: 'private-config-canary',
    JWT_PUBLIC_KEY_PATH: 'private-config-canary',
    JWT_KEY_ID: 'private-config-canary',
    TOTP_ENCRYPTION_KEY: 'private-config-canary',
    clientSecret: 'private-config-canary',
  });

describe('DiscoveryService exact public Config-only metadata', () => {
  let logs: MockInstance[];
  beforeEach(() => {
    vi.clearAllMocks();
    vi.spyOn(globalThis, 'fetch').mockImplementation(forbiddenIO);
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
      expect(forbiddenImport).not.toHaveBeenCalled();
      expect(forbiddenIO).not.toHaveBeenCalled();
      for (const log of logs) expect(log).not.toHaveBeenCalled();
    } finally {
      vi.restoreAllMocks();
    }
  });
  it.each([
    ['http://localhost:3000', 'http://localhost:3000'],
    ['https://iam.example.test', 'https://iam.example.test'],
    ['https://iam.example.test/', 'https://iam.example.test'],
    [
      'https://IAM.example.test:443/issuer/subpath/',
      'https://iam.example.test',
    ],
    ['http://[::1]:3000/', 'http://[::1]:3000'],
    [
      'https://iam.example.test/issuer%3Fname%23part',
      'https://iam.example.test',
    ],
  ])(
    'preserves exact issuer %s but constructs root-absolute endpoint URLs',
    (issuer, root) => {
      const config = configFor(issuer);
      const get = vi.spyOn(config, 'getOrThrow');
      const metadata = new DiscoveryService(config).build();
      expect(metadata).toEqual({
        issuer,
        authorization_endpoint: root + '/oauth/authorize',
        token_endpoint: root + '/oauth/token',
        userinfo_endpoint: root + '/oidc/userinfo',
        jwks_uri: root + '/.well-known/jwks.json',
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
      });
      expect(get).toHaveBeenCalledExactlyOnceWith('ISSUER_URL', {
        infer: true,
      });
      expect(Object.keys(metadata)).toHaveLength(16);
      expect(JSON.stringify(metadata).includes('private-config-canary')).toBe(
        false,
      );
    },
  );
  it('does not advertise unsupported grants, algorithms, auth methods or application scopes', () => {
    const metadata = new DiscoveryService(configFor()).build();
    expect(metadata.response_types_supported).not.toContain('token');
    expect(metadata.response_types_supported).not.toContain('id_token');
    for (const grant of [
      'implicit',
      'refresh_token',
      'password',
      'client_credentials',
      'urn:ietf:params:oauth:grant-type:device_code',
    ])
      expect(metadata.grant_types_supported).not.toContain(grant);
    for (const algorithm of ['ES256', 'HS256', 'none'])
      expect(metadata.id_token_signing_alg_values_supported).not.toContain(
        algorithm,
      );
    for (const method of [
      'client_secret_post',
      'client_secret_jwt',
      'private_key_jwt',
    ])
      expect(metadata.token_endpoint_auth_methods_supported).not.toContain(
        method,
      );
    expect(metadata.code_challenge_methods_supported).not.toContain('plain');
    expect(metadata.subject_types_supported).not.toContain('pairwise');
    expect(metadata.scopes_supported).not.toContain(
      'banking.transactions.read',
    );
    for (const property of [
      'revocation_endpoint',
      'registration_endpoint',
      'introspection_endpoint',
      'end_session_endpoint',
      'claims_supported',
      'request_object_signing_alg_values_supported',
    ])
      expect(metadata).not.toHaveProperty(property);
  });
  it('returns fresh metadata/arrays without letting callers change future responses', () => {
    const service = new DiscoveryService(configFor());
    const first = service.build();
    first.scopes_supported.reverse();
    first.issuer = 'https://caller.invalid';
    expect(service.build().scopes_supported).toEqual([
      'openid',
      'profile',
      'email',
    ]);
    expect(service.build().issuer).toBe('http://localhost:3000');
  });
  it.each([
    undefined,
    null,
    '',
    42,
    {},
    [],
    new String('https://iam.example.test'),
    'relative',
    'ftp://iam.example.test',
    'https://',
    'https://iam.example.test?private-config-canary',
    'https://iam.example.test?',
    'https://iam.example.test/#private-config-canary',
    'https://iam.example.test/#',
    'https://user:private-config-canary@iam.example.test',
    'https://user@iam.example.test',
  ])(
    'sanitizes invalid Discovery issuer configuration %# without normalization',
    (issuer) => {
      // Explicitly stub undefined: ConfigService construction may omit absent properties.
      const config = configFor();
      vi.spyOn(config, 'getOrThrow').mockReturnValue(issuer);
      let error: unknown;
      try {
        new DiscoveryService(config).build();
      } catch (caught) {
        error = caught;
      }
      expect(error).toBeInstanceOf(Error);
      expect((error as Error).message).toBe('Discovery metadata build failed.');
      expect((error as Error).cause).toBeUndefined();
    },
  );
  it('sanitizes thrown configuration failures without private causes or logs', () => {
    const config = configFor();
    vi.spyOn(config, 'getOrThrow').mockImplementation(() => {
      throw new Error('private-config-canary', {
        cause: new Error('private-config-canary'),
      });
    });
    expect(() => new DiscoveryService(config).build()).toThrowError(
      new Error('Discovery metadata build failed.'),
    );
  });
  it('initializes Discovery with only Config and no eager reads or signing dependency', async () => {
    const config = configFor();
    const get = vi.spyOn(config, 'getOrThrow');
    // OIDC module wiring is tested separately: JWKS now intentionally imports signing.
    // Keep the pure Discovery import/I/O traps above fully enforced.
    const module = await Test.createTestingModule({
      imports: [ConfigModule],
      providers: [DiscoveryService],
    })
      .overrideProvider(ConfigService)
      .useValue(config)
      .compile();
    try {
      for (const log of logs) log.mockClear(); // Nest DI logs are not Discovery logs.
      expect(get).not.toHaveBeenCalled();
      expect(module.get(DiscoveryService).build().issuer).toBe(
        'http://localhost:3000',
      );
    } finally {
      await module.close();
    }
  });
});
