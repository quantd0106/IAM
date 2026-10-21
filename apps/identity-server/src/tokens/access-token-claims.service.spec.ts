import { Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
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
import { validateEnvironment, type Environment } from '../config/env.schema.js';
import { authorizationCodeStateSchema } from '../oauth/authorization-code.state.js';
import {
  AccessTokenClaimsService,
  type AccessTokenClaimsInput,
} from './access-token-claims.service.js';

const { forbiddenImport, forbiddenIO } = vi.hoisted(() => ({
  forbiddenImport: vi.fn(() => {
    throw new Error('Unexpected signing/storage dependency.');
  }),
  forbiddenIO: vi.fn(() => {
    throw new Error('Unexpected claims I/O.');
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

const subject = 'c0e21e3f-d3ee-425c-a99f-c2e7a7cab53f';
const now = 1800000000123;
const input: AccessTokenClaimsInput = {
  subject,
  audience: 'banking-api',
  scopes: ['openid', 'profile'],
  roles: [],
  permissions: [],
};
const configFor = (
  overrides: Record<string, unknown> = {},
): ConfigService<Environment, true> =>
  new ConfigService<Environment, true>(
    validateEnvironment({
      NODE_ENV: 'test',
      DATABASE_URL: 'postgresql://test:test@127.0.0.1:1/test',
      REDIS_URL: 'redis://127.0.0.1:1',
      ISSUER_URL: 'http://localhost:3000',
      JWT_PRIVATE_KEY_PATH: './unread-placeholder-private.pem',
      JWT_PUBLIC_KEY_PATH: './unread-placeholder-public.pem',
      JWT_KEY_ID: 'unused-placeholder',
      TOTP_ENCRYPTION_KEY: 'unused-placeholder',
      AUTH_CODE_TTL_SECONDS: 3,
      REFRESH_TOKEN_TTL_SECONDS: 7,
      SESSION_IDLE_TTL_SECONDS: 11,
      SESSION_ABSOLUTE_TTL_SECONDS: 13,
      ...overrides,
    }),
  );

describe('AccessTokenClaimsService M6.6 payload-only capability', () => {
  let config: ConfigService<Environment, true>;
  let service: AccessTokenClaimsService;
  let logs: MockInstance[];
  beforeEach(() => {
    vi.clearAllMocks();
    vi.spyOn(Date, 'now').mockReturnValue(now);
    vi.spyOn(globalThis, 'fetch').mockImplementation(forbiddenIO);
    config = configFor();
    service = new AccessTokenClaimsService(config);
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
  const unsafe =
    (value: unknown): (() => unknown) =>
    () =>
      service.build(value as AccessTokenClaimsInput);
  const fails = (work: () => unknown): void => {
    let caught: unknown;
    try {
      work();
    } catch (error) {
      caught = error;
    }
    expect(caught).toBeInstanceOf(Error);
    const error = caught as Error;
    expect(error.message).toBe('Access token claims build failed.');
    expect(error.cause).toBeUndefined();
    expect((error.stack ?? '').includes('private-input-canary')).toBe(false);
  };

  it('needs only ConfigService and performs no eager build or signing imports', async () => {
    const get = vi.spyOn(config, 'getOrThrow');
    const module = await Test.createTestingModule({
      providers: [
        AccessTokenClaimsService,
        { provide: ConfigService, useValue: config },
      ],
    }).compile();
    try {
      // Nest DI logs are not claims logs and contain no input/config values.
      for (const log of logs) {
        expect(
          log.mock.calls
            .flat()
            .some(
              (value: unknown) =>
                typeof value === 'string' &&
                [subject, 'banking-api', 'http://localhost:3000'].some(
                  (marker) => value.includes(marker),
                ),
            ),
        ).toBe(false);
        log.mockClear();
      }
      expect(get).not.toHaveBeenCalled();
      expect(module.get(AccessTokenClaimsService).build(input).sub).toBe(
        subject,
      );
    } finally {
      await module.close();
    }
  });
  it('constructs exactly eight canonical claims using the 600-second config default', () => {
    const claims = service.build(input);
    expect(claims).toEqual({
      iss: 'http://localhost:3000',
      sub: subject,
      aud: 'banking-api',
      iat: 1800000000,
      exp: 1800000600,
      scope: 'openid profile',
      roles: [],
      permissions: [],
    });
    expect(Object.keys(claims).sort()).toEqual(
      [
        'iss',
        'sub',
        'aud',
        'iat',
        'exp',
        'scope',
        'roles',
        'permissions',
      ].sort(),
    );
    expect(claims.exp - claims.iat).toBe(600);
    expect(
      Number.isSafeInteger(claims.iat) && Number.isSafeInteger(claims.exp),
    ).toBe(true);
    expect(Date.now).toHaveBeenCalledOnce();
  });
  it('preserves the validated issuer text and cannot be overridden by caller properties', () => {
    const issuer = 'https://ISSUER.example:443/a/../issuer?x=%2f';
    service = new AccessTokenClaimsService(
      configFor({ ISSUER_URL: ' ' + issuer + ' ' }),
    );
    expect(
      service.build({
        ...input,
        iss: 'https://attacker.invalid',
        issuer: 'https://other.invalid',
        Host: 'caller-host',
        redirect_uri: 'caller-redirect',
        client_id: 'caller-client',
      } as AccessTokenClaimsInput).iss,
    ).toBe(issuer);
  });
  it('reads only trusted issuer/access-token TTL config, never another TTL or signing configuration', () => {
    const get = vi.spyOn(config, 'getOrThrow');
    service.build(input);
    expect(get.mock.calls).toEqual([
      ['ISSUER_URL', { infer: true }],
      ['ACCESS_TOKEN_TTL_SECONDS', { infer: true }],
    ]);
  });
  it.each([subject, subject.toUpperCase()])(
    'preserves valid UUID subject case %#',
    (value) => {
      expect(service.build({ ...input, subject: value }).sub).toBe(value);
    },
  );
  it.each([
    undefined,
    null,
    '',
    'private-input-canary',
    ' ' + subject,
    subject + ' ',
    1,
    [subject],
    { subject },
  ])('rejects invalid subject case %#', (value) => {
    fails(unsafe({ ...input, subject: value }));
  });
  it.each([
    'banking-api',
    'student-api',
    ' BANKING-API ',
    ' e\u0301 /+%2F💠 ',
    '   ',
  ])(
    'preserves exact explicit audience case %# without inference/normalization',
    (audience) => {
      expect(service.build({ ...input, audience }).aud).toBe(audience);
    },
  );
  it.each([
    undefined,
    null,
    '',
    1,
    ['banking-api'],
    { audience: 'banking-api' },
  ])('rejects missing/empty/non-scalar audience case %#', (audience) => {
    fails(unsafe({ ...input, audience }));
  });
  it('uses one captured clock instant even across a second boundary', () => {
    vi.mocked(Date.now)
      .mockReturnValueOnce(1800000000999)
      .mockReturnValue(1800000001000);
    const claims = service.build(input);
    expect(claims.iat).toBe(1800000000);
    expect(claims.exp).toBe(1800000600);
    expect(Date.now).toHaveBeenCalledOnce();
  });
  it('uses a configured access-token TTL override instead of hard-coding 600', () => {
    const claims = new AccessTokenClaimsService(
      configFor({ ACCESS_TOKEN_TTL_SECONDS: '321' }),
    ).build(input);
    expect(claims.exp - claims.iat).toBe(321);
  });
  it.each([1, 37, 900])(
    'uses trusted explicit TTL %s exactly, without reading default TTL',
    (ttlSeconds) => {
      const get = vi.spyOn(config, 'getOrThrow');
      const claims = service.build({ ...input, ttlSeconds });
      expect(claims.exp - claims.iat).toBe(ttlSeconds);
      expect(get.mock.calls).toEqual([['ISSUER_URL', { infer: true }]]);
    },
  );
  it.each([
    0,
    -1,
    1.5,
    NaN,
    Infinity,
    Number.MAX_SAFE_INTEGER + 1,
    '600',
    null,
    {},
    [],
  ])('rejects malformed explicit TTL case %#', (ttlSeconds) => {
    fails(unsafe({ ...input, ttlSeconds }));
  });
  it('accepts safe arithmetic at the boundary and rejects overflow without an arbitrary TTL cap', () => {
    vi.mocked(Date.now).mockReturnValue(1000);
    expect(
      service.build({ ...input, ttlSeconds: Number.MAX_SAFE_INTEGER - 1 }).exp,
    ).toBe(Number.MAX_SAFE_INTEGER);
    fails(unsafe({ ...input, ttlSeconds: Number.MAX_SAFE_INTEGER }));
  });
  it.each([-1, 1.5, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1])(
    'sanitizes an invalid clock case %#',
    (instant) => {
      vi.mocked(Date.now).mockReturnValue(instant);
      fails(unsafe(input));
    },
  );
  it('accepts epoch zero without a new skew policy', () => {
    vi.mocked(Date.now).mockReturnValue(0);
    expect(service.build(input)).toMatchObject({ iat: 0, exp: 600 });
  });
  it('joins already-granted scopes without sorting/dedup/intersection or permission mapping', () => {
    const scopes = [
      'profile',
      'openid',
      'profile',
      'BANKING.read',
      'banking.transactions.read',
    ];
    expect(
      authorizationCodeStateSchema.shape.grantedScopes.safeParse(scopes)
        .success,
    ).toBe(true);
    const claims = service.build({ ...input, scopes });
    expect(claims.scope).toBe(scopes.join(' '));
    expect(claims.roles).toEqual([]);
    expect(claims.permissions).toEqual([]);
  });
  it.each([
    undefined,
    null,
    [],
    'openid profile',
    [''],
    [' openid'],
    ['openid '],
    ['openid profile'],
    ['a\tb'],
    ['a\nb'],
    ['a"b'],
    ['a\\b'],
    ['café'],
    [1],
    [{}],
    new Array<string>(1),
  ])('rejects malformed granted scopes case %#', (scopes) => {
    fails(unsafe({ ...input, scopes }));
  });
  it('accepts the full existing RFC 6749 scope-token character set', () => {
    const token = Array.from({ length: 0x7e - 0x21 + 1 }, (_, index) =>
      String.fromCharCode(index + 0x21),
    )
      .filter((char) => char !== '"' && char !== '\\')
      .join('');
    expect(service.build({ ...input, scopes: [token] }).scope).toBe(token);
  });
  it('preserves opaque role/permission values, order and duplicates separately from scopes', () => {
    const roles = [' ROLE ', 'BANK_EMPLOYEE', 'BANK_EMPLOYEE', 'Rôle-e\u0301'];
    const permissions = [
      'transaction.view',
      'transaction.view',
      ' Perm\n"\\💠 ',
    ];
    const claims = service.build({ ...input, roles, permissions });
    expect(claims.roles).toEqual(roles);
    expect(claims.permissions).toEqual(permissions);
    expect(claims.scope).toBe('openid profile');
    expect(JSON.parse(JSON.stringify(claims)) as unknown).toEqual(claims);
    const distinct = service.build({
      ...input,
      scopes: ['BANK_EMPLOYEE'],
      roles: ['banking.transactions.read'],
      permissions: ['openid'],
    });
    expect(distinct.scope).toBe('BANK_EMPLOYEE');
    expect(distinct.roles).toEqual(['banking.transactions.read']);
    expect(distinct.permissions).toEqual(['openid']);
  });
  it.each(['roles', 'permissions'] as const)(
    'requires an explicit array and nonempty string entries for %s',
    (field) => {
      for (const value of [
        undefined,
        null,
        '',
        'value',
        [''],
        [null],
        [1],
        [{}],
        [new String('value')],
        new Array<string>(1),
      ])
        fails(unsafe({ ...input, [field]: value }));
      expect(service.build({ ...input, [field]: [] })[field]).toEqual([]);
    },
  );
  it('does not retain caller-owned arrays or mutate frozen inputs', () => {
    const scopes = ['profile', 'openid'];
    const roles = ['role'];
    const permissions = ['permission'];
    const claims = service.build({ ...input, scopes, roles, permissions });
    scopes.push('later');
    roles.push('later');
    permissions.push('later');
    expect(claims.scope).toBe('profile openid');
    expect(claims.roles).toEqual(['role']);
    expect(claims.permissions).toEqual(['permission']);
    claims.roles.push('output');
    claims.permissions.push('output');
    expect(roles).toEqual(['role', 'later']);
    expect(permissions).toEqual(['permission', 'later']);
    const frozen = Object.freeze({
      ...input,
      scopes: Object.freeze(['openid']),
      roles: Object.freeze(['role']),
      permissions: Object.freeze(['permission']),
    });
    expect(service.build(frozen)).toMatchObject({
      scope: 'openid',
      roles: ['role'],
      permissions: ['permission'],
    });
  });
  it('does not leak arbitrary sensitive/unlisted caller fields into the exact payload', () => {
    const extra = Object.fromEntries(
      [
        'kid',
        'alg',
        'typ',
        'jti',
        'nonce',
        'auth_time',
        'sessionId',
        'email',
        'username',
        'password',
        'profile',
        'clientSecret',
        'codeVerifier',
        'codeChallenge',
        'authorizationCode',
        'refreshToken',
        'ipAddress',
        'userAgent',
        'prismaMetadata',
      ].map((key) => [key, 'private-input-canary']),
    );
    const claims = service.build({ ...input, ...extra });
    expect(Object.keys(claims)).toHaveLength(8);
    expect(JSON.stringify(claims).includes('private-input-canary')).toBe(false);
  });
  it.each([undefined, null, [], '', 42])(
    'sanitizes invalid top-level input case %#',
    (value) => {
      fails(unsafe(value));
    },
  );
  it.each(['ISSUER_URL', 'ACCESS_TOKEN_TTL_SECONDS'] as const)(
    'sanitizes native config failure in %s without attaching its cause',
    (name) => {
      const actual = config.getOrThrow.bind(config);
      vi.spyOn(config, 'getOrThrow').mockImplementation((key, options) => {
        if (key === name)
          throw new Error('private-input-canary', {
            cause: new Error('private-input-canary'),
          });
        return actual(key, options);
      });
      fails(unsafe(input));
    },
  );
  it('sanitizes a thrown clock/getter error without reading or logging private input', () => {
    vi.mocked(Date.now).mockImplementation(() => {
      throw new Error('private-input-canary');
    });
    fails(unsafe(input));
    const faulty = {
      ...input,
      get audience(): never {
        throw new Error('private-input-canary');
      },
    };
    fails(unsafe(faulty));
  });
});
