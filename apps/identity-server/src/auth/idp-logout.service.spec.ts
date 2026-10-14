import { Logger } from '@nestjs/common';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { PrismaService } from '../prisma/prisma.service.js';
import { IdpSessionStateService } from '../session/idp-session-state.service.js';
import { IdpLogoutService } from './idp-logout.service.js';

const id = '9d3d959a-c65b-4ffc-8086-ad563e59f198';
const update = { where: { id, status: 'ACTIVE' }, data: { status: 'REVOKED' } };
describe('IdpLogoutService', () => {
  const sessions = {
    invalidate: vi.fn<IdpSessionStateService['invalidate']>(),
    create: vi.fn(),
    touch: vi.fn(),
  };
  const updateMany =
    vi.fn<(input: typeof update) => Promise<{ count: number }>>();
  const service = new IdpLogoutService(
    sessions as unknown as IdpSessionStateService,
    { session: { updateMany } } as unknown as PrismaService,
  );
  beforeEach(() => {
    vi.resetAllMocks();
    sessions.invalidate.mockResolvedValue(undefined);
    updateMany.mockResolvedValue({ count: 1 });
  });
  afterEach(() => vi.restoreAllMocks());

  it.each([1, 0])(
    'invalidates then conditionally revokes, accepting count %i',
    async (count) => {
      updateMany.mockResolvedValue({ count });
      await expect(service.logout(id)).resolves.toBeUndefined();
      expect(sessions.invalidate).toHaveBeenCalledExactlyOnceWith(id);
      expect(updateMany).toHaveBeenCalledExactlyOnceWith(update);
      expect(sessions.invalidate.mock.invocationCallOrder[0]).toBeLessThan(
        updateMany.mock.invocationCallOrder[0],
      );
      expect(sessions.create).not.toHaveBeenCalled();
      expect(sessions.touch).not.toHaveBeenCalled();
    },
  );

  it('waits for Redis completion before DB and DB completion before success', async () => {
    let finishRedis!: () => void;
    let finishDb!: () => void;
    sessions.invalidate.mockReturnValue(
      new Promise<void>((resolve) => {
        finishRedis = resolve;
      }),
    );
    updateMany.mockReturnValue(
      new Promise<{ count: number }>((resolve) => {
        finishDb = () => resolve({ count: 1 });
      }),
    );
    let finished = false;
    const pending = service.logout(id).then(() => {
      finished = true;
    });
    expect(updateMany).not.toHaveBeenCalled();
    expect(finished).toBe(false);
    finishRedis();
    await vi.waitFor(() => expect(updateMany).toHaveBeenCalledOnce());
    expect(finished).toBe(false);
    finishDb();
    await pending;
    expect(finished).toBe(true);
  });

  it.each(['Redis', 'PostgreSQL'])(
    'sanitizes %s failure without rollback, causes or logging',
    async (stage) => {
      const spies = (
        ['error', 'log', 'warn', 'debug', 'verbose', 'fatal'] as const
      ).map((method) => vi.spyOn(Logger.prototype, method));
      const consoles = (['log', 'error', 'warn', 'info', 'debug'] as const).map(
        (method) => vi.spyOn(console, method),
      );
      const privateMessage = 'private driver/URL/session:' + id;
      const driverError = new Error(privateMessage, {
        cause: new Error('private cause'),
      });
      if (stage === 'Redis') sessions.invalidate.mockRejectedValue(driverError);
      else updateMany.mockRejectedValue(driverError);
      const error: unknown = await service
        .logout(id)
        .catch((error: unknown) => error);
      expect(error).toEqual(new Error('IdP logout failed.'));
      expect(error).not.toHaveProperty('cause');
      expect((error as Error).stack).not.toContain(privateMessage);
      expect(sessions.invalidate).toHaveBeenCalledExactlyOnceWith(id);
      if (stage === 'Redis') expect(updateMany).not.toHaveBeenCalled();
      else expect(updateMany).toHaveBeenCalledExactlyOnceWith(update);
      expect(sessions.create).not.toHaveBeenCalled();
      expect(sessions.touch).not.toHaveBeenCalled();
      for (const spy of [...spies, ...consoles])
        expect(spy).not.toHaveBeenCalled();
    },
  );

  it('repairs a partial failure on retry without recreating runtime state', async () => {
    updateMany.mockRejectedValueOnce(new Error('controlled fault'));
    await expect(service.logout(id)).rejects.toThrow('IdP logout failed.');
    await expect(service.logout(id)).resolves.toBeUndefined();
    expect(sessions.invalidate.mock.calls).toEqual([[id], [id]]);
    expect(updateMany.mock.calls).toEqual([[update], [update]]);
    expect(sessions.create).not.toHaveBeenCalled();
  });

  it('supports repeated/concurrent logout with one conditional state transition and no new row', async () => {
    let active = true;
    let runtimePresent = true;
    sessions.invalidate.mockImplementation(() => {
      runtimePresent = false;
      return Promise.resolve();
    });
    updateMany.mockImplementation(() => {
      const count = active ? 1 : 0;
      active = false;
      return Promise.resolve({ count });
    });
    await Promise.all([service.logout(id), service.logout(id)]);
    await service.logout(id);
    expect(runtimePresent).toBe(false);
    expect(active).toBe(false);
    expect(updateMany.mock.calls).toEqual([[update], [update], [update]]);
    expect(sessions.create).not.toHaveBeenCalled();
    expect(sessions.touch).not.toHaveBeenCalled();
  });

  it('does not log successful logout', async () => {
    const spies = (
      ['error', 'log', 'warn', 'debug', 'verbose', 'fatal'] as const
    ).map((method) => vi.spyOn(Logger.prototype, method));
    const consoles = (['log', 'error', 'warn', 'info', 'debug'] as const).map(
      (method) => vi.spyOn(console, method),
    );
    await service.logout(id);
    for (const spy of [...spies, ...consoles])
      expect(spy).not.toHaveBeenCalled();
  });
});
