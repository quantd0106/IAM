import { Logger } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { Test } from '@nestjs/testing';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { Environment } from '../config/env.schema.js';
import { RedisService } from '../redis/redis.service.js';
import {
  idpSessionStateSchema,
  parseIdpSessionState,
  type IdpSessionState,
} from './idp-session-state.js';
import { IdpSessionStateService } from './idp-session-state.service.js';
import { SessionModule } from './session.module.js';

const sessionId = '9d3d959a-c65b-4ffc-8086-ad563e59f198';
const key = 'session:' + sessionId;
const state: IdpSessionState = {
  userId: 'c0e21e3f-d3ee-425c-a99f-c2e7a7cab53f',
  authTime: 1900000000000,
  mfaLevel: 'password',
  createdAt: 1900000000000,
  lastActivityAt: 1900000000000,
  absoluteExpiresAt: 1900028800000,
};
const config = new ConfigService<Environment, true>({
  SESSION_IDLE_TTL_SECONDS: 1800,
  SESSION_ABSOLUTE_TTL_SECONDS: 28800,
  COOKIE_NAME: 'iam.sid',
  COOKIE_SECURE: false,
});

const invalidStates: unknown[] = [
  {},
  [],
  'string',
  null,
  { ...state, userId: undefined },
  { ...state, userId: 'not-a-uuid' },
  { ...state, userId: 'FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF' },
  { ...state, userId: '12345678-1234-9234-8234-123456789abc' },
  { ...state, userId: '12345678-1234-4234-7234-123456789abc' },
  { ...state, absoluteExpiresAt: undefined },
  { ...state, mfaLevel: '' },
  { ...state, mfaLevel: 1 },
  { ...state, extra: true },
  ...(
    ['authTime', 'createdAt', 'lastActivityAt', 'absoluteExpiresAt'] as const
  ).flatMap((field) =>
    [undefined, '123', -1, 1.5, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1].map(
      (value) => ({ ...state, [field]: value }),
    ),
  ),
  { ...state, absoluteExpiresAt: state.createdAt },
  { ...state, authTime: state.absoluteExpiresAt },
  { ...state, lastActivityAt: state.absoluteExpiresAt },
];

describe('IdpSessionStateService', () => {
  const redis = {
    sessionState: vi.fn<RedisService['sessionState']>(),
    set: vi.fn(),
    get: vi.fn(),
    delete: vi.fn(),
    setWithTtl: vi.fn(),
  };
  let service: IdpSessionStateService;

  beforeEach(() => {
    vi.resetAllMocks();
    redis.sessionState.mockResolvedValue(JSON.stringify(state));
    service = new IdpSessionStateService(
      redis as unknown as RedisService,
      config,
    );
  });
  afterEach(() => vi.restoreAllMocks());

  it('does not perform Redis commands in the constructor', () => {
    expect(redis.sessionState).not.toHaveBeenCalled();
  });

  it('exports a session-only service without initialization commands or persistence', async () => {
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
          inject: [IdpSessionStateService],
          useFactory: (sessions: IdpSessionStateService) => sessions,
        },
      ],
    })
      .overrideProvider(ConfigService)
      .useValue(config)
      .overrideProvider(RedisService)
      .useValue(redis)
      .compile();
    try {
      await module.init();
      expect(module.get('session-consumer')).toBeInstanceOf(
        IdpSessionStateService,
      );
      expect(redis.sessionState).not.toHaveBeenCalled();
    } finally {
      await module.close();
    }
  });

  it('creates only the six fields with the canonical key and validated idle configuration', async () => {
    await expect(service.create(sessionId, state)).resolves.toBeUndefined();
    expect(redis.sessionState).toHaveBeenCalledExactlyOnceWith(key, {
      kind: 'create',
      serializedState: JSON.stringify(state),
      idleTtlSeconds: 1800,
    });
    expect(redis.set).not.toHaveBeenCalled();
    expect(redis.setWithTtl).not.toHaveBeenCalled();
  });

  it.each(['', 'not-a-uuid', '{' + sessionId + '}', sessionId + ':suffix'])(
    'rejects an invalid identifier before any Redis operation (case %#)',
    async (id) => {
      await expect(service.create(id, state)).rejects.toEqual(
        new TypeError('Invalid IdP session identifier.'),
      );
      await expect(service.read(id)).rejects.toEqual(
        new TypeError('Invalid IdP session identifier.'),
      );
      await expect(service.touch(id)).rejects.toEqual(
        new TypeError('Invalid IdP session identifier.'),
      );
      expect(redis.sessionState).not.toHaveBeenCalled();
    },
  );

  it.each(invalidStates.map((input, index) => ({ input, index })))(
    'rejects invalid/extra/incomplete state before writing (case $index)',
    async ({ input }) => {
      await expect(
        service.create(sessionId, input as IdpSessionState),
      ).rejects.toEqual(new TypeError('Invalid IdP session state.'));
      expect(redis.sessionState).not.toHaveBeenCalled();
    },
  );

  it('rejects expired creation according to the atomic Redis clock decision', async () => {
    redis.sessionState.mockResolvedValue(null);
    const expired = {
      ...state,
      authTime: 0,
      createdAt: 0,
      lastActivityAt: 0,
      absoluteExpiresAt: 1,
    };
    await expect(service.create(sessionId, expired)).rejects.toEqual(
      new Error('IdP session state is already expired.'),
    );
  });

  it('uses opaque MFA metadata without an assurance enum or normalization', async () => {
    const opaque = { ...state, mfaLevel: ' synthetic/未来 "metadata" ' };
    redis.sessionState.mockResolvedValue(JSON.stringify(opaque));
    await service.create(sessionId, opaque);
    expect(await service.read(sessionId)).toEqual(opaque);
  });

  it('reads existing state without passing a refresh TTL or issuing writes', async () => {
    expect(await service.read(sessionId)).toEqual(state);
    expect(redis.sessionState).toHaveBeenCalledExactlyOnceWith(key, {
      kind: 'read',
    });
    expect(redis.set).not.toHaveBeenCalled();
    expect(redis.setWithTtl).not.toHaveBeenCalled();
    expect(redis.delete).not.toHaveBeenCalled();
  });

  it.each(['read', 'touch'] as const)(
    '%s returns null after atomic invalidation of missing/expired/corrupt state',
    async (operation) => {
      redis.sessionState.mockResolvedValue(null);
      expect(await service[operation](sessionId)).toBeNull();
      expect(redis.set).not.toHaveBeenCalled();
      expect(redis.setWithTtl).not.toHaveBeenCalled();
    },
  );

  it.each([
    '{',
    '{}',
    '[]',
    '"string"',
    'null',
    ...invalidStates.map((input) => JSON.stringify(input)),
  ])(
    'does not return malformed or partially validated reply (case %#)',
    async (raw) => {
      redis.sessionState.mockResolvedValue(raw);
      expect(await service.read(sessionId)).toBeNull();
      expect(await service.touch(sessionId)).toBeNull();
    },
  );

  it('returns updated activity from one atomic transition preserving the five other fields', async () => {
    const updated = { ...state, lastActivityAt: state.lastActivityAt + 1000 };
    redis.sessionState.mockResolvedValue(JSON.stringify(updated));
    expect(await service.touch(sessionId)).toEqual(updated);
    expect(redis.sessionState).toHaveBeenCalledExactlyOnceWith(key, {
      kind: 'touch',
      idleTtlSeconds: 1800,
    });
    expect(redis.get).not.toHaveBeenCalled();
    expect(redis.set).not.toHaveBeenCalled();
  });

  it('fails closed on an invalid create reply', async () => {
    redis.sessionState.mockResolvedValue('{}');
    await expect(service.create(sessionId, state)).rejects.toEqual(
      new Error('Redis IdP session operation failed.'),
    );
  });

  it.each(['create', 'read', 'touch'] as const)(
    '%s propagates the sanitized operational failure without fallback or logging',
    async (operation) => {
      const spies = ['error', 'log', 'warn', 'debug', 'verbose', 'fatal'].map(
        (method) =>
          vi.spyOn(
            Logger.prototype,
            method as 'error' | 'log' | 'warn' | 'debug' | 'verbose' | 'fatal',
          ),
      );
      const consoleSpies = [
        vi.spyOn(console, 'log'),
        vi.spyOn(console, 'error'),
      ];
      redis.sessionState.mockRejectedValue(
        new Error('Redis IdP session operation failed.'),
      );
      await expect(service[operation](sessionId, state)).rejects.toEqual(
        new Error('Redis IdP session operation failed.'),
      );
      expect(redis.get).not.toHaveBeenCalled();
      expect(redis.set).not.toHaveBeenCalled();
      for (const spy of [...spies, ...consoleSpies])
        expect(spy).not.toHaveBeenCalled();
    },
  );
});

describe('IdP runtime state representation', () => {
  it('accepts non-negative safe-integer millisecond timestamps, including the upper bound', () => {
    const edge = {
      ...state,
      authTime: 0,
      createdAt: 0,
      lastActivityAt: 0,
      absoluteExpiresAt: Number.MAX_SAFE_INTEGER,
    };
    expect(idpSessionStateSchema.safeParse(edge).success).toBe(true);
    expect(parseIdpSessionState(JSON.stringify(edge))).toEqual(edge);
  });
});
