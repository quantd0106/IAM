import { Logger } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import { ConfigModule, ConfigService } from '@nestjs/config';
import type { Environment } from '../config/env.schema.js';
import type { createClient } from 'redis';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { RedisModule } from './redis.module.js';
import { RedisService } from './redis.service.js';
import type { INestApplication } from '@nestjs/common';
import type { Server } from 'node:http';
import request from 'supertest';
import { HealthController } from '../health.controller.js';
import { redisSessionStateScript } from './redis-session-state.script.js';
import { SessionModule } from '../session/session.module.js';
import { IdpSessionStateService } from '../session/idp-session-state.service.js';

type ClientOptions = NonNullable<Parameters<typeof createClient>[0]>;

const { client, createClientMock } = vi.hoisted(() => {
  const client = {
    isOpen: false,
    isReady: false,
    on: vi.fn<(event: string, listener: (error: Error) => void) => void>(),
    connect: vi.fn<() => Promise<void>>(),
    close: vi.fn<() => Promise<void>>(),
    destroy: vi.fn<() => void>(),
    set: vi.fn<
      (
        key: string,
        value: string,
        options?: { EX: number; NX?: boolean },
      ) => Promise<string | null>
    >(),
    get: vi.fn<(key: string) => Promise<string | null>>(),
    getDel: vi.fn<(key: string) => Promise<string | null>>(),
    del: vi.fn<(key: string) => Promise<number>>(),
    ttl: vi.fn<(key: string) => Promise<number>>(),
    eval: vi.fn<
      (
        script: string,
        options: { keys: string[]; arguments: string[] },
      ) => Promise<unknown>
    >(),
  };
  return {
    client,
    createClientMock: vi.fn<(options: ClientOptions) => typeof client>(),
  };
});

vi.mock('redis', () => ({ createClient: createClientMock }));

describe('RedisService', () => {
  const config = new ConfigService<Environment, true>({
    REDIS_URL: 'redis://127.0.0.1:6379',
    SESSION_IDLE_TTL_SECONDS: 1800,
    SESSION_ABSOLUTE_TTL_SECONDS: 28800,
    COOKIE_NAME: 'iam.sid',
    COOKIE_SECURE: false,
  });
  beforeEach(() => {
    vi.resetAllMocks();
    client.isOpen = false;
    client.isReady = false;
    createClientMock.mockReturnValue(client);
    client.connect.mockImplementation(() => {
      client.isOpen = true;
      client.isReady = true;
      return Promise.resolve();
    });
    client.close.mockImplementation(() => {
      client.isOpen = false;
      client.isReady = false;
      return Promise.resolve();
    });
    client.destroy.mockImplementation(() => {
      client.isOpen = false;
      client.isReady = false;
    });
    client.set.mockResolvedValue('OK');
    client.get.mockResolvedValue('value');
    client.getDel.mockResolvedValue('value');
    client.del.mockResolvedValue(1);
    client.ttl.mockResolvedValue(10);
    client.eval.mockResolvedValue(1);
  });

  afterEach(() => {
    vi.unstubAllEnvs();
    vi.restoreAllMocks();
  });

  it('requires validated REDIS_URL configuration', () => {
    vi.stubEnv('REDIS_URL', undefined);
    expect(
      () => new RedisService(new ConfigService<Environment, true>()),
    ).toThrow('REDIS_URL');
    expect(createClientMock).not.toHaveBeenCalled();
  });

  it('sanitizes errors when creating the client', () => {
    createClientMock.mockImplementationOnce(() => {
      throw new Error('secret-bearing URL');
    });
    expect(() => new RedisService(config)).toThrow(
      'Redis client configuration failed.',
    );
  });

  it('exports the service, installs an error listener before connect, and closes cleanly', async () => {
    const module = await Test.createTestingModule({
      imports: [
        ConfigModule.forRoot({
          isGlobal: true,
          ignoreEnvFile: true,
          ignoreEnvVars: true,
        }),
        RedisModule,
        SessionModule,
      ],
      providers: [
        {
          provide: 'redis-consumer',
          inject: [RedisService],
          useFactory: (redis: RedisService): { redis: RedisService } => ({
            redis,
          }),
        },
      ],
    })
      .overrideProvider(ConfigService)
      .useValue(config)
      .compile();
    const { redis } = module.get<{ redis: RedisService }>('redis-consumer');

    try {
      await module.init();
      expect(redis).toBeInstanceOf(RedisService);
      expect(client.on).toHaveBeenCalledWith('error', expect.any(Function));
      expect(client.on.mock.invocationCallOrder[0]).toBeLessThan(
        client.connect.mock.invocationCallOrder[0],
      );
      expect(client.connect).toHaveBeenCalledOnce();
    } finally {
      await module.close();
    }
    expect(client.close).toHaveBeenCalledOnce();
    expect(client.destroy).not.toHaveBeenCalled();
  });

  it('uses capped exponential backoff with jitter and stops retrying on shutdown', async () => {
    const service = new RedisService(config);
    const options = createClientMock.mock.calls[0]?.[0];
    const strategy = options?.socket?.reconnectStrategy;
    if (typeof strategy !== 'function')
      throw new Error('Missing reconnect strategy.');
    const cause = new Error('offline');

    vi.spyOn(Math, 'random').mockReturnValue(0);
    expect(strategy(0, cause)).toBe(50);
    expect(strategy(1, cause)).toBe(100);
    expect(strategy(100, cause)).toBe(2000);
    vi.mocked(Math.random).mockReturnValue(0.995);
    expect(strategy(100, cause)).toBe(2199);
    expect(options?.disableOfflineQueue).toBe(true);

    await service.onModuleDestroy();
    expect(strategy(1, cause)).toBe(false);
  });

  it('logs only a fixed safe message for connection errors', () => {
    const log = vi
      .spyOn(Logger.prototype, 'error')
      .mockImplementation(() => undefined);
    new RedisService(config);
    const listener = client.on.mock.calls.find(
      ([event]) => event === 'error',
    )?.[1];
    if (!listener) throw new Error('Missing error listener.');
    listener(new Error('redis://user:secret@localhost:6379'));
    expect(log).toHaveBeenCalledExactlyOnceWith('Redis connection error.');
  });

  it('handles background connection rejection with a fixed sanitized log, without blocking bootstrap', async () => {
    const log = vi
      .spyOn(Logger.prototype, 'error')
      .mockImplementation(() => undefined);
    const service = new RedisService(config);
    client.isOpen = true;
    client.connect.mockRejectedValueOnce(
      new Error('redis://user:secret@localhost:6379'),
    );
    expect(service.onModuleInit()).toBeUndefined();
    await Promise.resolve();
    expect(log).toHaveBeenCalledExactlyOnceWith(
      'Redis connection initialization failed.',
    );
    expect(client.destroy).toHaveBeenCalledOnce();
  });

  it('bootstraps HTTP /health while connection is pending and offline commands reject', async () => {
    let rejectConnect!: (error: Error) => void;
    const connecting = new Promise<void>((_, reject) => {
      rejectConnect = reject;
    });
    client.connect.mockImplementation(() => {
      client.isOpen = true;
      return connecting;
    });
    client.del.mockRejectedValue(new Error('offline'));
    client.eval.mockRejectedValue(new Error('offline'));
    client.getDel.mockRejectedValue(new Error('offline'));
    const module = await Test.createTestingModule({
      imports: [
        ConfigModule.forRoot({
          isGlobal: true,
          ignoreEnvFile: true,
          ignoreEnvVars: true,
        }),
        RedisModule,
        SessionModule,
      ],
      controllers: [HealthController],
    })
      .overrideProvider(ConfigService)
      .useValue(config)
      .compile();
    const app = module.createNestApplication<INestApplication<Server>>({
      logger: false,
    });
    try {
      await app.init();
      expect(client.isReady).toBe(false);
      await request(app.getHttpServer())
        .get('/health')
        .expect(200)
        .expect({ status: 'ok' });
      const redis = module.get(RedisService);
      await expect(redis.delete('test:key')).rejects.toThrow('offline');
      await expect(redis.incrementWithTtl('test:key', 900)).rejects.toThrow(
        'Redis counter increment failed.',
      );
      await expect(redis.getAndDelete('test:key')).rejects.toThrow(
        'Redis atomic consume failed.',
      );
      const sessions = module.get(IdpSessionStateService);
      const id = '9d3d959a-c65b-4ffc-8086-ad563e59f198';
      await expect(sessions.read(id)).rejects.toEqual(
        new Error('Redis IdP session operation failed.'),
      );
      await expect(sessions.touch(id)).rejects.toEqual(
        new Error('Redis IdP session operation failed.'),
      );
      await expect(
        sessions.create(id, {
          userId: id,
          authTime: 0,
          mfaLevel: 'password',
          createdAt: 0,
          lastActivityAt: 0,
          absoluteExpiresAt: Number.MAX_SAFE_INTEGER,
        }),
      ).rejects.toEqual(new Error('Redis IdP session operation failed.'));
      expect(createClientMock.mock.calls[0]?.[0].disableOfflineQueue).toBe(
        true,
      );
      expect(client.set).not.toHaveBeenCalled();
    } finally {
      await app.close();
      rejectConnect(new Error('shutdown'));
      await Promise.resolve();
    }
    expect(client.destroy).toHaveBeenCalledOnce();
  });

  it('cancels reconnecting sockets during shutdown', async () => {
    const service = new RedisService(config);
    client.isOpen = true;
    client.isReady = false;
    await service.onModuleDestroy();
    expect(client.destroy).toHaveBeenCalledOnce();
    expect(client.close).not.toHaveBeenCalled();
  });

  it('does nothing on shutdown if the client is already closed', async () => {
    await new RedisService(config).onModuleDestroy();
    expect(client.close).not.toHaveBeenCalled();
    expect(client.destroy).not.toHaveBeenCalled();
  });

  it('destroys the socket if graceful close fails', async () => {
    const log = vi
      .spyOn(Logger.prototype, 'error')
      .mockImplementation(() => undefined);
    const service = new RedisService(config);
    client.isOpen = true;
    client.isReady = true;
    client.close.mockRejectedValueOnce(new Error('close failed'));
    await service.onModuleDestroy();
    expect(client.destroy).toHaveBeenCalledOnce();
    expect(log).toHaveBeenCalledExactlyOnceWith(
      'Redis graceful shutdown failed; connection destroyed.',
    );
  });

  it('delegates string operations and explicit seconds-based TTL to the client', async () => {
    const service = new RedisService(config);
    await service.set('test:key', 'value');
    expect(client.set).toHaveBeenCalledWith('test:key', 'value');
    expect(await service.get('test:key')).toBe('value');
    expect(client.get).toHaveBeenCalledWith('test:key');
    expect(await service.delete('test:key')).toBe(1);
    expect(client.del).toHaveBeenCalledWith('test:key');
    await service.setWithTtl('test:ttl', 'value', 10);
    expect(client.set).toHaveBeenCalledWith('test:ttl', 'value', { EX: 10 });
    expect(await service.ttl('test:ttl')).toBe(10);
    expect(client.ttl).toHaveBeenCalledWith('test:ttl');
    client.get.mockResolvedValueOnce(null);
    expect(await service.get('missing')).toBeNull();
  });

  it.each([0, -1, 1.5, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1])(
    'rejects invalid TTL seconds (%s)',
    async (ttlSeconds) => {
      const service = new RedisService(config);
      await expect(
        service.setWithTtl('test:key', 'value', ttlSeconds),
      ).rejects.toThrow(RangeError);
      expect(client.set).not.toHaveBeenCalled();
    },
  );

  it('propagates command failures to callers', async () => {
    client.get.mockRejectedValueOnce(new Error('command failed'));
    await expect(new RedisService(config).get('test:key')).rejects.toThrow(
      'command failed',
    );
  });
  describe('conditional TTL reservation', () => {
    it.each([
      ['OK', true],
      [null, false],
    ] as const)(
      'uses one NX + EX SET and returns reservation outcome (%#)',
      async (reply, expected) => {
        client.set.mockResolvedValue(reply);
        expect(
          await new RedisService(config).setIfAbsentWithTtl(
            'test:reserved',
            'value',
            120,
          ),
        ).toBe(expected);
        expect(client.set).toHaveBeenCalledExactlyOnceWith(
          'test:reserved',
          'value',
          { EX: 120, NX: true },
        );
        expect(client.get).not.toHaveBeenCalled();
        expect(client.del).not.toHaveBeenCalled();
        expect(client.eval).not.toHaveBeenCalled();
      },
    );
    it.each([0, -1, 1.5, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1])(
      'rejects invalid TTL before SET (%#)',
      async (ttl) => {
        await expect(
          new RedisService(config).setIfAbsentWithTtl('test:key', 'value', ttl),
        ).rejects.toThrow(RangeError);
        expect(client.set).not.toHaveBeenCalled();
      },
    );
    it('sanitizes failures without logging/cause/key/value/URL', async () => {
      const log = vi.spyOn(Logger.prototype, 'error');
      client.set.mockRejectedValue(
        new Error('private key/value/redis://user:secret@host', {
          cause: new Error('private cause'),
        }),
      );
      const failure: unknown = await new RedisService(config)
        .setIfAbsentWithTtl('test:key', 'value', 120)
        .catch((error: unknown) => error);
      expect(failure).toEqual(new Error('Redis conditional write failed.'));
      expect(failure).not.toHaveProperty('cause');
      expect(log).not.toHaveBeenCalled();
    });
    it('fails closed on unexpected SET replies', async () => {
      client.set.mockResolvedValue('unexpected');
      await expect(
        new RedisService(config).setIfAbsentWithTtl('test:key', 'value', 120),
      ).rejects.toEqual(new Error('Redis conditional write failed.'));
    });
  });

  it.each(['value', null])(
    'delegates atomic GETDEL and returns the previous string or null (case %#)',
    async (value) => {
      client.getDel.mockResolvedValue(value);
      expect(await new RedisService(config).getAndDelete('test:consume')).toBe(
        value,
      );
      expect(client.getDel).toHaveBeenCalledExactlyOnceWith('test:consume');
      expect(client.get).not.toHaveBeenCalled();
      expect(client.del).not.toHaveBeenCalled();
      expect(client.set).not.toHaveBeenCalled();
    },
  );

  it('sanitizes atomic consume failure without logging key/value/URL or driver causes', async () => {
    const spies = [
      vi.spyOn(Logger.prototype, 'error'),
      vi.spyOn(Logger.prototype, 'log'),
      vi.spyOn(Logger.prototype, 'warn'),
      vi.spyOn(Logger.prototype, 'debug'),
      vi.spyOn(Logger.prototype, 'verbose'),
      vi.spyOn(Logger.prototype, 'fatal'),
      vi.spyOn(console, 'error'),
      vi.spyOn(console, 'log'),
    ];
    client.getDel.mockRejectedValue(
      new Error('private key/value/redis://user:secret@host'),
    );
    await expect(
      new RedisService(config).getAndDelete('test:consume'),
    ).rejects.toEqual(new Error('Redis atomic consume failed.'));
    for (const spy of spies) expect(spy).not.toHaveBeenCalled();
    expect(client.get).not.toHaveBeenCalled();
    expect(client.del).not.toHaveBeenCalled();
  });

  it.each([0, -1, 1.5, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1])(
    'rejects invalid atomic-counter TTL (%s)',
    async (ttlSeconds) => {
      await expect(
        new RedisService(config).incrementWithTtl('test:key', ttlSeconds),
      ).rejects.toThrow(RangeError);
      expect(client.eval).not.toHaveBeenCalled();
    },
  );

  it.each([1, 5])(
    'uses one atomic INCR/first-EXPIRE script and returns validated count %i',
    async (count) => {
      client.eval.mockResolvedValue(count);
      expect(
        await new RedisService(config).incrementWithTtl(
          'rate:test-uuid:login-failure',
          900,
        ),
      ).toBe(count);
      expect(client.eval).toHaveBeenCalledExactlyOnceWith(expect.any(String), {
        keys: ['rate:test-uuid:login-failure'],
        arguments: ['900'],
      });
      const script = client.eval.mock.calls[0]?.[0];
      expect(script).toContain("redis.call('INCR', KEYS[1])");
      expect(script).toContain('if count == 1 then');
      expect(script).toContain("redis.call('EXPIRE', KEYS[1], ARGV[1])");
      expect(client.get).not.toHaveBeenCalled();
      expect(client.set).not.toHaveBeenCalled();
    },
  );

  it.each([
    null,
    undefined,
    '1',
    {},
    0,
    -1,
    1.5,
    NaN,
    Infinity,
    Number.MAX_SAFE_INTEGER + 1,
  ])('rejects malformed atomic counter reply case %#', async (reply) => {
    client.eval.mockResolvedValue(reply);
    await expect(
      new RedisService(config).incrementWithTtl('test:key', 900),
    ).rejects.toEqual(new Error('Redis counter increment failed.'));
  });

  it('sanitizes atomic command errors without logging key/user/URL details', async () => {
    const log = vi
      .spyOn(Logger.prototype, 'error')
      .mockImplementation(() => undefined);
    const service = new RedisService(config);
    client.eval.mockRejectedValue(
      new Error('test-only private key/user/Redis URL marker'),
    );
    await expect(
      service.incrementWithTtl('rate:test-uuid:login-failure', 900),
    ).rejects.toEqual(new Error('Redis counter increment failed.'));
    expect(log).not.toHaveBeenCalled();
  });

  describe('fixed session-only transition', () => {
    const key = 'session:9d3d959a-c65b-4ffc-8086-ad563e59f198';

    it.each(['create', 'read', 'touch'] as const)(
      'executes %s as exactly one fixed Lua operation',
      async (kind) => {
        client.eval.mockResolvedValue('state');
        const operation =
          kind === 'read'
            ? { kind }
            : kind === 'create'
              ? { kind, serializedState: 'state', idleTtlSeconds: 1800 }
              : { kind, idleTtlSeconds: 1800 };
        expect(
          await new RedisService(config).sessionState(key, operation),
        ).toBe('state');
        expect(client.eval).toHaveBeenCalledExactlyOnceWith(
          redisSessionStateScript,
          {
            keys: [key],
            arguments: [
              kind,
              kind === 'create' ? 'state' : '',
              kind === 'read' ? '' : '1800',
            ],
          },
        );
        expect(client.get).not.toHaveBeenCalled();
        expect(client.set).not.toHaveBeenCalled();
        expect(client.del).not.toHaveBeenCalled();
      },
    );

    it('accepts the absent reply without recreating a key', async () => {
      client.eval.mockResolvedValue(null);
      expect(
        await new RedisService(config).sessionState(key, {
          kind: 'touch',
          idleTtlSeconds: 1800,
        }),
      ).toBeNull();
      expect(client.set).not.toHaveBeenCalled();
    });

    it('keeps missing check, validation, server clock, activity and bounded expiry inside Lua', () => {
      expect(redisSessionStateScript).toContain(
        'if not raw then return nil end',
      );
      expect(redisSessionStateScript).toContain('pcall(cjson.decode, raw)');
      expect(redisSessionStateScript).toContain('count == 6');
      expect(redisSessionStateScript).toContain("redis.call('DEL', key)");
      expect(
        redisSessionStateScript.match(/redis.call\('TIME'\)/g),
      ).toHaveLength(1);
      expect(redisSessionStateScript).toContain(
        "if operation == 'read' then return raw end",
      );
      expect(redisSessionStateScript).toContain('state.lastActivityAt = now');
      expect(redisSessionStateScript).toContain(
        'math.min(idleSeconds * 1000, state.absoluteExpiresAt - now)',
      );
      expect(redisSessionStateScript).toContain(
        "redis.call('SET', key, raw, 'PXAT', string.format('%.0f', deadline))",
      );
    });

    it.each([
      'rate:test:login-failure',
      'pwdreset:test',
      'iam:session:test',
      'session:not-a-uuid',
      'session:{9d3d959a-c65b-4ffc-8086-ad563e59f198}',
    ])(
      'rejects keys outside the canonical UUID session namespace (case %#)',
      async (invalidKey) => {
        await expect(
          new RedisService(config).sessionState(invalidKey, { kind: 'read' }),
        ).rejects.toEqual(new Error('Redis IdP session operation failed.'));
        expect(client.eval).not.toHaveBeenCalled();
      },
    );

    it.each([0, -1, 1.5, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1])(
      'rejects unsafe session TTL without EVAL (case %#)',
      async (idleTtlSeconds) => {
        await expect(
          new RedisService(config).sessionState(key, {
            kind: 'touch',
            idleTtlSeconds,
          }),
        ).rejects.toEqual(new Error('Redis IdP session operation failed.'));
        expect(client.eval).not.toHaveBeenCalled();
      },
    );

    it.each([undefined, 0, 1, [], {}, true])(
      'fails closed on an unexpected script reply (case %#)',
      async (reply) => {
        client.eval.mockResolvedValue(reply);
        await expect(
          new RedisService(config).sessionState(key, { kind: 'read' }),
        ).rejects.toEqual(new Error('Redis IdP session operation failed.'));
      },
    );

    it.each(['create', 'read', 'touch'] as const)(
      'sanitizes %s driver errors and drops causes without logging',
      async (kind) => {
        const spies = [
          vi.spyOn(Logger.prototype, 'error'),
          vi.spyOn(Logger.prototype, 'log'),
          vi.spyOn(Logger.prototype, 'warn'),
          vi.spyOn(console, 'log'),
          vi.spyOn(console, 'error'),
        ];
        client.eval.mockRejectedValue(
          new Error('private session/key/state/redis://user:secret@host', {
            cause: new Error('private driver cause'),
          }),
        );
        const operation =
          kind === 'read'
            ? { kind }
            : kind === 'create'
              ? { kind, serializedState: 'private state', idleTtlSeconds: 1800 }
              : { kind, idleTtlSeconds: 1800 };
        await expect(
          new RedisService(config).sessionState(key, operation),
        ).rejects.toEqual(new Error('Redis IdP session operation failed.'));
        for (const spy of spies) expect(spy).not.toHaveBeenCalled();
      },
    );
  });
});
