import { Logger } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { Test } from '@nestjs/testing';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { validateEnvironment, type Environment } from '../config/env.schema.js';
import { RedisService } from '../redis/redis.service.js';
import { IdpSessionCookieService } from './idp-session-cookie.service.js';
import { IdpSessionStateService } from './idp-session-state.service.js';
import { SessionModule } from './session.module.js';

const id = '9d3d959a-c65b-4ffc-8086-ad563e59f198';
const otherId = 'c0e21e3f-d3ee-425c-a99f-c2e7a7cab53f';
const developmentHeader = 'iam.sid=' + id + '; Path=/; HttpOnly; SameSite=Lax';
const required = {
  DATABASE_URL: 'postgresql://test:test@127.0.0.1:1/test',
  REDIS_URL: 'redis://127.0.0.1:1',
  ISSUER_URL: 'http://localhost:3000',
  JWT_PRIVATE_KEY_PATH: './test-placeholder-private.pem',
  JWT_PUBLIC_KEY_PATH: './test-placeholder-public.pem',
  JWT_KEY_ID: 'test-placeholder',
  TOTP_ENCRYPTION_KEY: 'test-only-placeholder',
};

function configure(
  cookieName = 'iam.sid',
  secure = false,
): IdpSessionCookieService {
  return new IdpSessionCookieService(
    new ConfigService<Environment, true>({
      COOKIE_NAME: cookieName,
      COOKIE_SECURE: secure,
    }),
  );
}

const invalidValues: unknown[] = [
  '',
  'abc',
  'session:' + id,
  '{' + id + '}',
  ' ' + id,
  id + ' ',
  '\t' + id,
  id + '\t',
  id + '\r',
  id + '\n',
  id + '\r\nX-Test: injected',
  id.replace('-', ' '),
  '"' + id + '"',
  '%39' + id.slice(1),
  'eyJhbGciOiJSUzI1NiJ9.payload.signature',
  'opaque-refresh-token',
  JSON.stringify({ userId: otherId, mfaLevel: 'password' }),
  id + '=extra',
  id + '\u0000',
  id + '\u00a0',
  id + '\u200b',
  '12345678-1234-9234-8234-123456789abc',
  '12345678-1234-4234-7234-123456789abc',
  undefined,
  null,
  123,
  {},
  [],
];

describe('IdpSessionCookieService (pure boundary)', () => {
  afterEach(() => vi.restoreAllMocks());

  it('emits exactly the development session cookie and only the raw UUID as its value', () => {
    const cookie = configure();
    const header = cookie.serialize(id);
    expect(header).toBe(developmentHeader);
    expect(header.split(';')[0]).toBe('iam.sid=' + id);
    expect(header.split(';').slice(1)).toEqual([
      ' Path=/',
      ' HttpOnly',
      ' SameSite=Lax',
    ]);
    expect(cookie.parse(header.split(';')[0])).toBe(id);
  });

  it('emits Secure exactly once as an attribute only when configured true', () => {
    expect(configure('iam.sid', true).serialize(id)).toBe(
      developmentHeader + '; Secure',
    );
    expect(configure('iam.sid', false).serialize(id)).toBe(developmentHeader);
  });

  it.each(['iam.sid', 'session', 'iam_session', 'session-id', 'session.+id'])(
    'honors the exact configured cookie name (case %#)',
    (name) => {
      const cookie = configure(name);
      expect(cookie.serialize(id)).toBe(
        name + '=' + id + '; Path=/; HttpOnly; SameSite=Lax',
      );
      expect(cookie.parse(name + '=' + id)).toBe(id);
      if (name !== 'iam.sid') expect(cookie.parse('iam.sid=' + id)).toBeNull();
    },
  );

  it.each([
    id,
    id.toUpperCase(),
    '00000000-0000-0000-0000-000000000000',
    'ffffffff-ffff-ffff-ffff-ffffffffffff',
  ])(
    'preserves UUID bytes accepted by the canonical session validator (case %#)',
    (value) => {
      expect(configure().serialize(value).split(';')[0]).toBe(
        'iam.sid=' + value,
      );
      expect(configure().parse('iam.sid=' + value)).toBe(value);
    },
  );

  it.each(
    [...invalidValues, id + '; Secure'].map((input, index) => ({
      input,
      index,
    })),
  )(
    'rejects an invalid serialization input before producing a header (case $index)',
    ({ input }) => {
      expect(() => configure().serialize(input as string)).toThrowError(
        new TypeError('Invalid IdP session identifier.'),
      );
    },
  );

  it('reads only typed COOKIE_NAME and COOKIE_SECURE, without another NODE_ENV policy', () => {
    const config = new ConfigService<Environment, true>({
      COOKIE_NAME: 'session-id',
      COOKIE_SECURE: true,
    });
    const get = vi.spyOn(config, 'getOrThrow');
    const cookie = new IdpSessionCookieService(config);
    expect(get.mock.calls).toEqual([
      ['COOKIE_NAME', { infer: true }],
      ['COOKIE_SECURE', { infer: true }],
    ]);
    expect(cookie.serialize(id)).toBe(
      'session-id=' + id + '; Path=/; HttpOnly; SameSite=Lax; Secure',
    );
  });

  it.each([
    { NODE_ENV: 'development', COOKIE_SECURE: undefined, secure: false },
    { NODE_ENV: 'test', COOKIE_SECURE: undefined, secure: false },
    { NODE_ENV: 'development', COOKIE_SECURE: true, secure: true },
    { NODE_ENV: 'test', COOKIE_SECURE: true, secure: true },
    { NODE_ENV: 'production', COOKIE_SECURE: undefined, secure: true },
    { NODE_ENV: 'production', COOKIE_SECURE: true, secure: true },
  ])(
    'follows centrally validated secure-cookie policy (case %#)',
    ({ secure, ...input }) => {
      const environment = validateEnvironment({
        ...required,
        ...input,
        ISSUER_URL:
          input.NODE_ENV === 'production'
            ? 'https://id.example.test'
            : required.ISSUER_URL,
      });
      const cookie = new IdpSessionCookieService(
        new ConfigService<Environment, true>(environment),
      );
      expect(cookie.serialize(id)).toBe(
        developmentHeader + (secure ? '; Secure' : ''),
      );
    },
  );

  it('does not include state/tokens or persistent-cookie attributes', () => {
    const header = configure('iam.sid', true).serialize(id);
    expect(header.split(';')[0]).toBe('iam.sid=' + id);
    for (const forbidden of [
      'userId',
      'authTime',
      'mfaLevel',
      'createdAt',
      'lastActivityAt',
      'absoluteExpiresAt',
      '{',
      '}',
      'access_token',
      'refresh_token',
      'id_token',
      'roles',
      'permissions',
      'password',
      'Domain=',
      'Max-Age=',
      'Expires=',
      'Partitioned',
      'Priority',
    ]) {
      expect(header.includes(forbidden)).toBe(false);
    }
  });

  it.each([
    undefined,
    '',
    ' ',
    'foo=bar; theme=dark',
    'iam.sid.extra=' + id,
    'IAM.SID=' + id,
    'sid=' + id,
    'iam.sid',
    'iam.sid =' + id,
  ])(
    'returns null for missing or non-exact session-cookie names (case %#)',
    (header) => {
      expect(configure().parse(header)).toBeNull();
    },
  );

  it.each([
    'iam.sid=' + id,
    'foo=bar; iam.sid=' + id + '; theme=dark',
    ' \tiam.sid=' + id,
    'foo=bar;\t iam.sid=' + id + '; theme=dark',
    'iam.sid.extra=invalid; IAM.SID=invalid; sid=invalid; iam.sid=' + id,
    'other=contains=equals; iam.sid=' + id + '; unrelated=%75uid',
    'unrelated="text"; iam.sid=' + id + ';',
  ])(
    'ignores unrelated cookies and tolerates only leading pair OWS (case %#)',
    (header) => {
      expect(configure().parse(header)).toBe(id);
    },
  );

  it.each(invalidValues.map((input, index) => ({ input, index })))(
    'fails closed on malformed session values without decoding/normalization (case $index)',
    ({ input }) => {
      const raw = typeof input === 'string' ? input : JSON.stringify(input);
      expect(configure().parse('iam.sid=' + raw)).toBeNull();
    },
  );

  it.each([
    'iam.sid=' + id + '; iam.sid=' + id,
    'iam.sid=' + id + '; iam.sid=' + otherId,
    'iam.sid=' + id + '; iam.sid=invalid',
    'iam.sid=invalid; iam.sid=' + id,
    'iam.sid=' + id + '; iam.sid=',
    'iam.sid=; iam.sid=' + id,
    'iam.sid=' + id + '; iam.sid',
    'iam.sid=' + id + '; theme=dark;\t iam.sid=' + otherId,
  ])(
    'rejects ambiguous duplicate session cookies regardless of value or order (case %#)',
    (header) => {
      expect(configure().parse(header)).toBeNull();
    },
  );

  it('uses literal matching for configurable token-safe names, not regex matching', () => {
    const cookie = configure('session.+id');
    expect(cookie.parse('session.+id=' + id)).toBe(id);
    expect(cookie.parse('sessionXid=' + id)).toBeNull();
    expect(
      cookie.parse('session.+id=' + id + '; session.+id=' + id),
    ).toBeNull();
  });

  it('does not throw for unexpected non-string client header input', () => {
    for (const input of [null, {}, [], 42])
      expect(configure().parse(input as unknown as string)).toBeNull();
  });

  it('never logs cookie headers/values or invalid identifiers', () => {
    const spies = (
      ['error', 'log', 'warn', 'debug', 'verbose', 'fatal'] as const
    ).map((method) => vi.spyOn(Logger.prototype, method));
    const consoleSpies = (
      ['error', 'log', 'warn', 'info', 'debug'] as const
    ).map((method) => vi.spyOn(console, method));
    const cookie = configure();
    cookie.serialize(id);
    cookie.parse('iam.sid=' + id);
    cookie.parse('iam.sid=' + id + '; iam.sid=invalid');
    expect(() => cookie.serialize('private invalid marker')).toThrowError(
      new TypeError('Invalid IdP session identifier.'),
    );
    for (const spy of [...spies, ...consoleSpies])
      expect(spy).not.toHaveBeenCalled();
  });

  it('exports both services without issuing cookies or performing Redis commands on initialization', async () => {
    const redis = {
      sessionState: vi.fn(),
      get: vi.fn(),
      set: vi.fn(),
      delete: vi.fn(),
      setWithTtl: vi.fn(),
      incrementWithTtl: vi.fn(),
      getAndDelete: vi.fn(),
    };
    const module = await Test.createTestingModule({
      imports: [
        ConfigModule.forRoot({
          isGlobal: true,
          ignoreEnvFile: true,
          ignoreEnvVars: true,
        }),
        SessionModule,
      ],
      providers: [
        {
          provide: 'session-consumer',
          inject: [IdpSessionStateService, IdpSessionCookieService],
          useFactory: (
            state: IdpSessionStateService,
            cookie: IdpSessionCookieService,
          ) => ({ state, cookie }),
        },
      ],
    })
      .overrideProvider(RedisService)
      .useValue(redis)
      .overrideProvider(ConfigService)
      .useValue(
        new ConfigService<Environment, true>({
          COOKIE_NAME: 'iam.sid',
          COOKIE_SECURE: false,
          SESSION_IDLE_TTL_SECONDS: 1800,
          SESSION_ABSOLUTE_TTL_SECONDS: 28800,
        }),
      )
      .compile();
    try {
      await module.init();
      const services = module.get<{
        state: IdpSessionStateService;
        cookie: IdpSessionCookieService;
      }>('session-consumer');
      expect(services.state).toBeInstanceOf(IdpSessionStateService);
      expect(services.cookie).toBeInstanceOf(IdpSessionCookieService);
      expect(services.cookie.serialize(id)).toBe(developmentHeader);
      expect(services.cookie.parse('iam.sid=' + id)).toBe(id);
      for (const method of Object.values(redis))
        expect(method).not.toHaveBeenCalled();
    } finally {
      await module.close();
    }
  });
});
