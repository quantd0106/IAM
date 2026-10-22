import { Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Test } from '@nestjs/testing';
import type { Environment } from '../config/env.schema.js';
import {
  afterEach,
  beforeEach,
  describe,
  expect,
  it,
  vi,
  type MockInstance,
} from 'vitest';
import {
  IdTokenClaimsService,
  type IdTokenClaimsInput,
} from './id-token-claims.service.js';

const { forbiddenImport, forbiddenIO } = vi.hoisted(() => ({
  forbiddenImport: vi.fn(() => {
    throw new Error('Unexpected ID claims dependency.');
  }),
  forbiddenIO: vi.fn(() => {
    throw new Error('Unexpected ID claims I/O.');
  }),
}));
vi.mock('../security/signing/signing-key.service.js', () => {
  forbiddenImport();
  return {};
});
vi.mock('../prisma/prisma.service.js', () => {
  forbiddenImport();
  return {};
});
vi.mock('../redis/redis.service.js', () => {
  forbiddenImport();
  return {};
});
vi.mock('../client-registry/client-lookup.service.js', () => {
  forbiddenImport();
  return {};
});
vi.mock('../oauth/authorization-code.state.js', () => {
  forbiddenImport();
  return {};
});
vi.mock('../oauth/authorization-code.service.js', () => {
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

const input: IdTokenClaimsInput = {
  subject: 'c0e21e3f-d3ee-425c-a99f-c2e7a7cab53f',
  audience: 'student-spa',
  nonce: 'opaque-nonce-value',
  ttlSeconds: 600,
};
const now = 1800000000123;
const configFor = (
  issuer: unknown = 'http://localhost:3000',
): ConfigService<Environment, true> =>
  new ConfigService<Environment, true>({
    ISSUER_URL: issuer,
    ACCESS_TOKEN_TTL_SECONDS: 3,
    REFRESH_TOKEN_TTL_SECONDS: 7,
    JWT_PRIVATE_KEY_PATH: 'private-input-canary',
    JWT_PUBLIC_KEY_PATH: 'private-input-canary',
    JWT_KEY_ID: 'private-input-canary',
  });

describe('IdTokenClaimsService explicit six-claim OIDC capability', () => {
  let config: ConfigService<Environment, true>;
  let service: IdTokenClaimsService;
  let logs: MockInstance[];
  beforeEach(() => {
    vi.clearAllMocks();
    vi.spyOn(Date, 'now').mockReturnValue(now);
    vi.spyOn(globalThis, 'fetch').mockImplementation(forbiddenIO);
    config = configFor();
    service = new IdTokenClaimsService(config);
    logs = [console, Logger, Logger.prototype].flatMap((target) =>
      ['log', 'info', 'error', 'warn', 'debug', 'verbose', 'fatal'].flatMap(
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
  const fails = (value: unknown): void => {
    let caught: unknown;
    try {
      service.build(value as IdTokenClaimsInput);
    } catch (error) {
      caught = error;
    }
    expect(caught).toBeInstanceOf(Error);
    expect((caught as Error).message).toBe('ID token claims build failed.');
    expect((caught as Error).cause).toBeUndefined();
    expect((caught as Error).stack?.includes('private-input-canary')).toBe(
      false,
    );
  };

  it('constructs exactly six claims with one NumericDate clock and explicit TTL', () => {
    expect(service.build(input)).toEqual({
      iss: 'http://localhost:3000',
      sub: input.subject,
      aud: 'student-spa',
      iat: 1800000000,
      exp: 1800000600,
      nonce: 'opaque-nonce-value',
    });
    expect(Date.now).toHaveBeenCalledOnce();
  });
  it('depends only on ConfigService, with no eager reads, stores, signing or code-state dependency', async () => {
    const get = vi.spyOn(config, 'getOrThrow');
    const module = await Test.createTestingModule({
      providers: [
        IdTokenClaimsService,
        { provide: ConfigService, useValue: config },
      ],
    }).compile();
    try {
      for (const log of logs) {
        expect(
          log.mock.calls
            .flat()
            .some(
              (value: unknown) =>
                typeof value === 'string' &&
                [
                  'private-input-canary',
                  input.subject,
                  input.audience,
                  input.nonce,
                ].some((marker) => value.includes(marker)),
            ),
        ).toBe(false);
        log.mockClear();
      }
      expect(get).not.toHaveBeenCalled();
      expect(module.get(IdTokenClaimsService).build(input).aud).toBe(
        'student-spa',
      );
      expect(get).toHaveBeenCalledExactlyOnceWith('ISSUER_URL', {
        infer: true,
      });
    } finally {
      await module.close();
    }
  });
  it.each([
    'http://localhost:3000',
    'https://iam.example.test',
    'https://iam.example.test/',
    'https://IAM.example.test:443/issuer/subpath/',
    'http://[::1]:3000/',
    'https://iam.example.test/issuer%3Fname%23part',
  ])(
    'preserves exact valid configured issuer %#, ignoring caller/HTTP/resource overrides',
    (issuer) => {
      service = new IdTokenClaimsService(configFor(issuer));
      const claims = service.build({
        ...input,
        iss: 'https://caller.invalid',
        issuer: 'https://caller.invalid',
        Host: 'caller.invalid',
        'X-Forwarded-Host': 'caller.invalid',
        Origin: 'https://caller.invalid',
        redirect_uri: 'https://caller.invalid',
        accessTokenAudience: 'student-api',
      } as IdTokenClaimsInput);
      expect(claims.iss).toBe(issuer);
      expect(claims.aud).toBe('student-spa');
    },
  );
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
    'https://iam.example.test?private-input-canary',
    'https://iam.example.test?',
    'https://iam.example.test/#private-input-canary',
    'https://iam.example.test/#',
    'https://user:private-input-canary@iam.example.test',
    'https://user@iam.example.test',
  ])(
    'rejects invalid OIDC issuer configuration %# without repairing or exposing it',
    (issuer) => {
      vi.spyOn(config, 'getOrThrow').mockReturnValue(issuer);
      fails(input);
    },
  );
  it.each([input.subject, input.subject.toUpperCase()])(
    'preserves valid UUID subject case %#',
    (subject) => {
      expect(service.build({ ...input, subject }).sub).toBe(subject);
    },
  );
  it.each([
    undefined,
    null,
    '',
    'private-input-canary',
    ' ' + input.subject,
    input.subject + ' ',
    1,
    [input.subject],
    {},
  ])('rejects invalid subject %# without querying a user', (subject) => {
    fails({ ...input, subject });
  });
  it.each([
    'student-spa',
    'banking-web',
    'admin-portal',
    ' STUDENT-SPA ',
    ' e\u0301 /+%2F💠 ',
    '   ',
  ])(
    'preserves explicit opaque OAuth client_id audience %# without mapping to a resource API',
    (audience) => {
      expect(service.build({ ...input, audience }).aud).toBe(audience);
    },
  );
  it.each([
    'opaque-nonce-value',
    'Case-Sensitive',
    ' Opaque +%2F e\u0301💠 ',
    '   ',
    '\u0000\nnonce',
  ])(
    'preserves the exact nonce %# under existing opaque protocol semantics',
    (nonce) => {
      expect(service.build({ ...input, nonce }).nonce).toBe(nonce);
    },
  );
  it.each(['audience', 'nonce'] as const)(
    'requires a nonempty scalar %s, without coercion',
    (field) => {
      for (const value of [
        undefined,
        null,
        '',
        1,
        [],
        ['value'],
        {},
        new String('value'),
      ])
        fails({ ...input, [field]: value });
    },
  );
  it.each([1, 37, 600, 900])(
    'uses explicit TTL %s without reading an access/session/default lifetime',
    (ttlSeconds) => {
      const get = vi.spyOn(config, 'getOrThrow');
      const claims = service.build({ ...input, ttlSeconds });
      expect(claims.exp - claims.iat).toBe(ttlSeconds);
      expect(
        Number.isSafeInteger(claims.iat) && Number.isSafeInteger(claims.exp),
      ).toBe(true);
      expect(get).toHaveBeenCalledExactlyOnceWith('ISSUER_URL', {
        infer: true,
      });
    },
  );
  it.each([
    undefined,
    null,
    0,
    -1,
    1.5,
    NaN,
    Infinity,
    Number.MAX_SAFE_INTEGER + 1,
    '600',
    {},
    [],
  ])(
    'rejects missing/non-positive/non-integer/unsafe TTL %# without fallback',
    (ttlSeconds) => {
      fails({ ...input, ttlSeconds });
    },
  );
  it('captures one instant across a second boundary', () => {
    vi.mocked(Date.now)
      .mockReturnValueOnce(1800000000999)
      .mockReturnValue(1800000001000);
    const claims = service.build(input);
    expect(claims.iat).toBe(1800000000);
    expect(claims.exp).toBe(1800000600);
    expect(Date.now).toHaveBeenCalledOnce();
  });
  it('accepts exact safe expiry arithmetic and rejects overflow without a speculative TTL cap', () => {
    vi.mocked(Date.now).mockReturnValue(1000);
    expect(
      service.build({ ...input, ttlSeconds: Number.MAX_SAFE_INTEGER - 1 }).exp,
    ).toBe(Number.MAX_SAFE_INTEGER);
    fails({ ...input, ttlSeconds: Number.MAX_SAFE_INTEGER });
  });
  it.each([-1, 1.5, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1])(
    'sanitizes invalid clock %#',
    (instant) => {
      vi.mocked(Date.now).mockReturnValue(instant);
      fails(input);
    },
  );
  it('accepts epoch zero without introducing another clock/skew policy', () => {
    vi.mocked(Date.now).mockReturnValue(0);
    expect(service.build(input)).toMatchObject({ iat: 0, exp: 600 });
  });
  it('cannot leak arbitrary input or access-token/profile/session/hash claims', () => {
    const extra = Object.fromEntries(
      [
        'scope',
        'roles',
        'permissions',
        'accessTokenAudience',
        'client_id',
        'email',
        'username',
        'name',
        'profile',
        'auth_time',
        'authTime',
        'acr',
        'amr',
        'azp',
        'at_hash',
        'c_hash',
        's_hash',
        'jti',
        'nbf',
        'sessionId',
        'code',
        'code_verifier',
        'code_challenge',
        'refresh_token',
        'password',
        'passwordHash',
        'jwk',
        'typ',
        'kid',
      ].map((field) => [field, 'private-input-canary']),
    );
    const claims = service.build(Object.freeze({ ...input, ...extra }));
    expect(Object.keys(claims).sort()).toEqual([
      'aud',
      'exp',
      'iat',
      'iss',
      'nonce',
      'sub',
    ]);
    expect(JSON.stringify(claims).includes('private-input-canary')).toBe(false);
  });
  it('returns a fresh payload without retaining mutable caller state', () => {
    const first = service.build(input);
    first.nonce = 'caller';
    first.aud = 'student-api';
    first.iss = 'https://caller.invalid';
    expect(service.build(input)).not.toBe(first);
    expect(service.build(input)).toMatchObject({
      aud: input.audience,
      nonce: input.nonce,
      iss: 'http://localhost:3000',
    });
  });
  it.each([undefined, null, [], '', 42])(
    'sanitizes invalid top-level input %#',
    (value) => {
      fails(value);
    },
  );
  it.each(['config', 'clock', 'getter'])(
    'sanitizes thrown %s failures without causes or private logs',
    (stage) => {
      const native = new Error('private-input-canary', {
        cause: new Error('private-input-canary'),
      });
      if (stage === 'config')
        vi.spyOn(config, 'getOrThrow').mockImplementation(() => {
          throw native;
        });
      if (stage === 'clock')
        vi.mocked(Date.now).mockImplementation(() => {
          throw native;
        });
      fails(
        stage === 'getter'
          ? {
              ...input,
              get nonce(): never {
                throw native;
              },
            }
          : input,
      );
    },
  );
});
