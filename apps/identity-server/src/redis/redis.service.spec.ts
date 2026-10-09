import { Logger } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import type { createClient } from 'redis';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { RedisModule } from './redis.module.js';
import { RedisService } from './redis.service.js';

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
      (key: string, value: string, options?: { EX: number }) => Promise<string>
    >(),
    get: vi.fn<(key: string) => Promise<string | null>>(),
    del: vi.fn<(key: string) => Promise<number>>(),
    ttl: vi.fn<(key: string) => Promise<number>>(),
  };
  return {
    client,
    createClientMock: vi.fn<(options: ClientOptions) => typeof client>(),
  };
});

vi.mock('redis', () => ({ createClient: createClientMock }));

describe('RedisService', () => {
  beforeEach(() => {
    vi.resetAllMocks();
    vi.stubEnv('REDIS_URL', 'redis://127.0.0.1:6379');
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
    client.del.mockResolvedValue(1);
    client.ttl.mockResolvedValue(10);
  });

  afterEach(() => {
    vi.unstubAllEnvs();
    vi.restoreAllMocks();
  });

  it.each([undefined, '', '   '])(
    'rejects missing/blank REDIS_URL (%s)',
    (url) => {
      vi.stubEnv('REDIS_URL', url);
      expect(() => new RedisService()).toThrow('REDIS_URL is required');
      expect(createClientMock).not.toHaveBeenCalled();
    },
  );

  it.each(['not-a-url', 'http://localhost:6379', 'redis://'])(
    'rejects an invalid Redis URL (%s)',
    (url) => {
      vi.stubEnv('REDIS_URL', url);
      expect(() => new RedisService()).toThrow('REDIS_URL must be a valid');
      expect(createClientMock).not.toHaveBeenCalled();
    },
  );

  it('exports the service, installs an error listener before connect, and closes cleanly', async () => {
    const module = await Test.createTestingModule({
      imports: [RedisModule],
      providers: [
        {
          provide: 'redis-consumer',
          inject: [RedisService],
          useFactory: (redis: RedisService): { redis: RedisService } => ({
            redis,
          }),
        },
      ],
    }).compile();
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
    const service = new RedisService();
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
    new RedisService();
    const listener = client.on.mock.calls.find(
      ([event]) => event === 'error',
    )?.[1];
    if (!listener) throw new Error('Missing error listener.');
    listener(new Error('redis://user:secret@localhost:6379'));
    expect(log).toHaveBeenCalledExactlyOnceWith('Redis connection error.');
  });

  it('destroys the client and sanitizes initialization failures', async () => {
    const service = new RedisService();
    client.isOpen = true;
    client.connect.mockRejectedValueOnce(
      new Error('redis://user:secret@localhost:6379'),
    );
    await expect(service.onModuleInit()).rejects.toThrow(
      'Redis connection initialization failed.',
    );
    expect(client.destroy).toHaveBeenCalledOnce();
  });

  it('cancels reconnecting sockets during shutdown', async () => {
    const service = new RedisService();
    client.isOpen = true;
    client.isReady = false;
    await service.onModuleDestroy();
    expect(client.destroy).toHaveBeenCalledOnce();
    expect(client.close).not.toHaveBeenCalled();
  });

  it('does nothing on shutdown if the client is already closed', async () => {
    await new RedisService().onModuleDestroy();
    expect(client.close).not.toHaveBeenCalled();
    expect(client.destroy).not.toHaveBeenCalled();
  });

  it('destroys the socket if graceful close fails', async () => {
    const log = vi
      .spyOn(Logger.prototype, 'error')
      .mockImplementation(() => undefined);
    const service = new RedisService();
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
    const service = new RedisService();
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
      const service = new RedisService();
      await expect(
        service.setWithTtl('test:key', 'value', ttlSeconds),
      ).rejects.toThrow(RangeError);
      expect(client.set).not.toHaveBeenCalled();
    },
  );

  it('propagates command failures to callers', async () => {
    client.get.mockRejectedValueOnce(new Error('command failed'));
    await expect(new RedisService().get('test:key')).rejects.toThrow(
      'command failed',
    );
  });
});
