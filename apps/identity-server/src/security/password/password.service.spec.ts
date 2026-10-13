import { Logger } from '@nestjs/common';
import { Test, type TestingModule } from '@nestjs/testing';
import * as argon2 from 'argon2';
import {
  afterAll,
  afterEach,
  beforeAll,
  describe,
  expect,
  it,
  vi,
} from 'vitest';
import { PasswordService } from './password.service.js';

// Spy wrappers still execute the real native library unless explicitly overridden.
vi.mock('argon2', { spy: true });

describe('PasswordService', () => {
  const rawPassword = ' test-only opaque input ';
  const unicodePassword = ' mật-khẩu-🔐-日本語-e\u0301 ';
  let module: TestingModule;
  let service: PasswordService;
  let firstHash: string;
  let secondHash: string;
  let unicodeHash: string;
  let emptyHash: string;

  beforeAll(async () => {
    module = await Test.createTestingModule({
      providers: [PasswordService],
    }).compile();
    service = module.get(PasswordService);
    // Only four real hashes, using full library defaults, shared across checks.
    firstHash = await service.hash(rawPassword);
    secondHash = await service.hash(rawPassword);
    unicodeHash = await service.hash(unicodePassword);
    emptyHash = await service.hash('');
  }, 30000);

  afterEach(() => {
    vi.clearAllMocks();
  });

  afterAll(async () => {
    await module.close();
  });

  it('is injectable without any infrastructure dependency', () => {
    expect(service).toBeInstanceOf(PasswordService);
  });

  it('returns encoded Argon2id hashes with the installed library defaults', () => {
    expect(typeof firstHash).toBe('string');
    expect(firstHash.startsWith('$argon2id$')).toBe(true);
    expect(argon2.needsRehash(firstHash)).toBe(false);
  });

  it('verifies the correct input and rejects an incorrect input', async () => {
    expect(await service.verify(firstHash, rawPassword)).toBe(true);
    expect(await service.verify(firstHash, 'different test-only input')).toBe(
      false,
    );
  });

  it('uses independent salts and verifies both hashes of the same input', async () => {
    // Assert only the comparison result so a failed assertion cannot dump hashes.
    expect(firstHash !== secondHash).toBe(true);
    expect(await service.verify(firstHash, rawPassword)).toBe(true);
    expect(await service.verify(secondHash, rawPassword)).toBe(true);
  });

  it('round-trips Unicode without normalization', async () => {
    expect(await service.verify(unicodeHash, unicodePassword)).toBe(true);
    expect(
      await service.verify(unicodeHash, unicodePassword.normalize('NFC')),
    ).toBe(false);
  });

  it('does not trim input', async () => {
    expect(await service.verify(firstHash, rawPassword.trim())).toBe(false);
  });

  it('accepts an empty string at the primitive layer without password policy', async () => {
    expect(emptyHash.startsWith('$argon2id$')).toBe(true);
    expect(await service.verify(emptyHash, '')).toBe(true);
    expect(await service.verify(emptyHash, 'nonempty test input')).toBe(false);
  });

  it.each(['', 'not-an-encoded-hash', '$argon2id$broken'])(
    'rejects malformed hash case %# with a generic safe error',
    async (encodedHash) => {
      await expect(service.verify(encodedHash, rawPassword)).rejects.toThrow(
        'Password verification failed.',
      );
    },
  );

  it('explicitly selects Argon2id and passes raw input unchanged', async () => {
    vi.mocked(argon2.hash).mockResolvedValueOnce('test-only encoded result');
    await service.hash(rawPassword);
    expect(argon2.hash).toHaveBeenCalledExactlyOnceWith(rawPassword, {
      type: argon2.argon2id,
    });
  });

  it('uses the official verification API and keeps its false result', async () => {
    vi.mocked(argon2.verify).mockResolvedValueOnce(false);
    expect(await service.verify('test-only encoded input', rawPassword)).toBe(
      false,
    );
    expect(argon2.verify).toHaveBeenCalledExactlyOnceWith(
      'test-only encoded input',
      rawPassword,
    );
  });

  it('does not log or expose sensitive native errors and does not hide failures', async () => {
    const consoleSpies = [
      vi.spyOn(console, 'log'),
      vi.spyOn(console, 'info'),
      vi.spyOn(console, 'warn'),
      vi.spyOn(console, 'error'),
      vi.spyOn(console, 'debug'),
    ];
    const loggerSpies = [
      vi.spyOn(Logger.prototype, 'log'),
      vi.spyOn(Logger.prototype, 'error'),
      vi.spyOn(Logger.prototype, 'warn'),
      vi.spyOn(Logger.prototype, 'debug'),
      vi.spyOn(Logger.prototype, 'verbose'),
      vi.spyOn(Logger.prototype, 'fatal'),
    ];
    try {
      expect(await service.verify(firstHash, rawPassword)).toBe(true);
      vi.mocked(argon2.hash).mockRejectedValueOnce(
        new Error('test-only sensitive password/hash/salt marker'),
      );
      await expect(service.hash(rawPassword)).rejects.toEqual(
        new Error('Password hashing failed.'),
      );
      vi.mocked(argon2.verify).mockRejectedValueOnce(
        new Error('test-only sensitive password/hash/salt marker'),
      );
      await expect(service.verify(firstHash, rawPassword)).rejects.toEqual(
        new Error('Password verification failed.'),
      );
      for (const spy of [...consoleSpies, ...loggerSpies])
        expect(spy).not.toHaveBeenCalled();
    } finally {
      for (const spy of [...consoleSpies, ...loggerSpies]) spy.mockRestore();
    }
  });
});
