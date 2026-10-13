import {
  ConflictException,
  InternalServerErrorException,
  Logger,
} from '@nestjs/common';
import { Test } from '@nestjs/testing';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { Prisma } from '../generated/prisma/client.js';
import { PrismaService } from '../prisma/prisma.service.js';
import { PasswordService } from '../security/password/password.service.js';
import { RegistrationService } from './registration.service.js';

describe('RegistrationService (isolated unit)', () => {
  const input = {
    email: 'UnitCase@example.invalid',
    username: 'UnitCase',
    password: ' opaque test-only input ',
  };
  const user = {
    id: 'test-user-id',
    email: input.email,
    username: input.username,
    status: 'ACTIVE' as const,
    createdAt: new Date('2026-01-01T00:00:00Z'),
  };
  const hashValue = 'test-only encoded hash marker';
  const createUser = vi.fn<() => Promise<typeof user>>();
  const createCredential = vi.fn<() => Promise<{ id: string }>>();
  const transaction = {
    user: { create: createUser },
    credential: { create: createCredential },
  };
  const transact =
    vi.fn<
      (
        operation: (value: typeof transaction) => Promise<typeof user>,
      ) => Promise<typeof user>
    >();
  const hash = vi.fn<(raw: string) => Promise<string>>();
  let service: RegistrationService;
  let log: ReturnType<typeof vi.spyOn>;
  let committed: boolean;

  beforeEach(async () => {
    vi.resetAllMocks();
    committed = false;
    createUser.mockResolvedValue(user);
    createCredential.mockResolvedValue({ id: 'test-credential-id' });
    hash.mockResolvedValue(hashValue);
    transact.mockImplementation(async (operation) => {
      const result = await operation(transaction);
      committed = true;
      return result;
    });
    const module = await Test.createTestingModule({
      providers: [
        RegistrationService,
        { provide: PrismaService, useValue: { $transaction: transact } },
        { provide: PasswordService, useValue: { hash } },
      ],
    }).compile();
    service = module.get(RegistrationService);
    log = vi.spyOn(Logger.prototype, 'log').mockImplementation(() => {
      expect(committed).toBe(true);
    });
  });

  afterEach(() => vi.restoreAllMocks());

  function uniqueError(field: string, modelName = 'User'): Error {
    return new Prisma.PrismaClientKnownRequestError(
      'test-only sensitive driver details',
      {
        code: 'P2002',
        clientVersion: '7.10.0',
        meta: {
          modelName,
          driverAdapterError: {
            cause: {
              kind: 'UniqueConstraintViolation',
              constraint: {
                index:
                  modelName === 'User'
                    ? `users_${field}_key`
                    : 'credentials_user_id_key',
              },
            },
          },
        },
      },
    );
  }

  it('hashes opaque input before a transaction and creates only the required fields', async () => {
    const result = await service.register(input);
    expect(hash).toHaveBeenCalledExactlyOnceWith(input.password);
    expect(hash.mock.invocationCallOrder[0]).toBeLessThan(
      transact.mock.invocationCallOrder[0],
    );
    expect(transact).toHaveBeenCalledOnce();
    expect(createUser).toHaveBeenCalledExactlyOnceWith({
      data: { email: input.email, username: input.username },
      select: {
        id: true,
        email: true,
        username: true,
        status: true,
        createdAt: true,
      },
    });
    expect(createCredential).toHaveBeenCalledExactlyOnceWith({
      data: { userId: user.id, passwordHash: hashValue },
      select: { id: true },
    });
    expect(result).toEqual(user);
    expect(log).toHaveBeenCalledExactlyOnceWith({
      event: 'USER_REGISTERED',
      userId: user.id,
    });
  });

  it('explicitly projects a safe response even if a client result has extra sensitive fields', async () => {
    createUser.mockResolvedValue({
      ...user,
      password: input.password,
      passwordHash: hashValue,
      credential: {},
    } as typeof user);
    const result = await service.register(input);
    expect(Object.keys(result).sort()).toEqual([
      'createdAt',
      'email',
      'id',
      'status',
      'username',
    ]);
  });

  it.each(['email', 'username'])(
    'maps the User %s uniqueness error to 409 without audit',
    async (field) => {
      createUser.mockRejectedValue(uniqueError(field));
      await expect(service.register(input)).rejects.toThrow(
        new ConflictException('Email or username is already registered.'),
      );
      expect(createCredential).not.toHaveBeenCalled();
      expect(committed).toBe(false);
      expect(log).not.toHaveBeenCalled();
    },
  );

  it.each([
    uniqueError('id'),
    uniqueError('userId', 'Credential'),
    new Prisma.PrismaClientKnownRequestError('test-only private metadata', {
      code: 'P2002',
      clientVersion: '7.10.0',
      meta: { modelName: 'User' },
    }),
    new Error('test-only private driver details'),
  ])(
    'does not disguise unrelated failures as duplicates (case %#)',
    async (error) => {
      transact.mockRejectedValue(error);
      await expect(service.register(input)).rejects.toThrow(
        new InternalServerErrorException('Registration failed.'),
      );
      expect(log).not.toHaveBeenCalled();
    },
  );

  it('does not open a transaction or emit audit if hashing fails', async () => {
    hash.mockRejectedValue(new Error('test-only private hashing details'));
    await expect(service.register(input)).rejects.toThrow(
      'Registration failed.',
    );
    expect(transact).not.toHaveBeenCalled();
    expect(log).not.toHaveBeenCalled();
  });

  it('returns no success and no event if Credential creation fails', async () => {
    createCredential.mockRejectedValue(
      new Error('test-only private credential details'),
    );
    await expect(service.register(input)).rejects.toThrow(
      'Registration failed.',
    );
    expect(createUser).toHaveBeenCalledOnce();
    expect(committed).toBe(false);
    expect(log).not.toHaveBeenCalled();
  });

  it('emits no audit event when the commit itself fails', async () => {
    transact.mockImplementation(async (operation) => {
      await operation(transaction);
      throw new Error('commit failed');
    });
    await expect(service.register(input)).rejects.toThrow(
      'Registration failed.',
    );
    expect(log).not.toHaveBeenCalled();
  });
});
