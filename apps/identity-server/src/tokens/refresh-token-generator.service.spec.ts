import { Logger } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import { readFileSync } from 'node:fs';
import ts from 'typescript';
import {
  afterEach,
  beforeEach,
  describe,
  expect,
  it,
  vi,
  type MockInstance,
} from 'vitest';
import { RefreshTokenGeneratorService } from './refresh-token-generator.service.js';

const { random, makeHash } = vi.hoisted(() => ({
  random: vi.fn<(size: number) => Buffer>(),
  makeHash: vi.fn<typeof import('node:crypto').createHash>(),
}));
vi.mock('node:crypto', async (original) => ({
  ...(await original<typeof import('node:crypto')>()),
  randomBytes: random,
  createHash: makeHash,
}));
const crypto =
  await vi.importActual<typeof import('node:crypto')>('node:crypto');
const canary = 'private-crypto-input-output-native-canary';

// Never let assertion diagnostics dump a credential, digest, native cause or logs.
const fails = (work: () => unknown, message: string): void => {
  let caught: unknown;
  try {
    work();
  } catch (error) {
    caught = error;
  }
  expect(caught instanceof Error).toBe(true);
  if (!(caught instanceof Error)) return;
  expect(caught.message === message).toBe(true);
  expect(caught.cause === undefined).toBe(true);
  expect(Object.keys(caught).length === 0).toBe(true);
  expect((caught.stack ?? '').includes(canary)).toBe(false);
};

describe('M8.3 RefreshTokenGeneratorService material-only capability', () => {
  let service: RefreshTokenGeneratorService;
  let logs: MockInstance[];
  beforeEach(() => {
    vi.resetAllMocks();
    random.mockImplementation((size) => crypto.randomBytes(size));
    makeHash.mockImplementation((algorithm, options) =>
      crypto.createHash(algorithm, options),
    );
    service = new RefreshTokenGeneratorService();
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
      for (const log of logs) expect(log.mock.calls.length === 0).toBe(true);
    } finally {
      vi.restoreAllMocks();
    }
  });

  it('requests exactly 32 real CSPRNG bytes and returns canonical unpadded 43-char base64url plus a 64-char hash', () => {
    const output = service.generate();
    expect(random).toHaveBeenCalledExactlyOnceWith(32);
    expect(Object.keys(output).sort()).toEqual(['rawToken', 'tokenHash']);
    expect(
      typeof output.rawToken === 'string' && output.rawToken.length === 43,
    ).toBe(true);
    expect(/^[A-Za-z0-9_-]{43}$/.test(output.rawToken)).toBe(true);
    expect(/[=+/]/.test(output.rawToken)).toBe(false);
    const decoded = Buffer.from(output.rawToken, 'base64url');
    expect(
      decoded.length === 32 &&
        decoded.toString('base64url') === output.rawToken,
    ).toBe(true);
    expect(
      typeof output.tokenHash === 'string' && output.tokenHash.length === 64,
    ).toBe(true);
    expect(/^[0-9a-f]{64}$/.test(output.tokenHash)).toBe(true);
    expect(output.tokenHash === service.hash(output.rawToken)).toBe(true);
  });

  it('hashes the exact ENCODED credential string through the same public hash helper', () => {
    const hash = vi.spyOn(service, 'hash');
    const output = service.generate();
    expect(
      hash.mock.calls.length === 1 && hash.mock.calls[0][0] === output.rawToken,
    ).toBe(true);
    expect(
      output.tokenHash ===
        crypto
          .createHash('sha256')
          .update(output.rawToken, 'utf8')
          .digest('hex'),
    ).toBe(true);
  });

  it('has 256 distinct well-formed raw strings/hashes in a real-random sanity sample (not a collision proof)', () => {
    const raw = new Set<string>();
    const hashes = new Set<string>();
    for (let i = 0; i < 256; i++) {
      const output = service.generate();
      expect(
        /^[A-Za-z0-9_-]{43}$/.test(output.rawToken) &&
          Buffer.from(output.rawToken, 'base64url').length === 32,
      ).toBe(true);
      expect(
        /^[0-9a-f]{64}$/.test(output.tokenHash) &&
          output.tokenHash === service.hash(output.rawToken),
      ).toBe(true);
      raw.add(output.rawToken);
      hashes.add(output.tokenHash);
    }
    expect(raw.size === 256 && hashes.size === 256).toBe(true);
    expect(
      random.mock.calls.length === 256 &&
        random.mock.calls.every(([size]) => size === 32),
    ).toBe(true);
  });

  it('returns fresh independent objects, even when crypto is deliberately repeated, without retaining material', () => {
    random.mockImplementation(() => Buffer.alloc(32, 7));
    const first = service.generate();
    const second = service.generate();
    expect(
      first !== second &&
        first.rawToken === second.rawToken &&
        first.tokenHash === second.tokenHash,
    ).toBe(true);
    first.rawToken = 'mutated test object';
    first.tokenHash = 'mutated test object';
    expect(second.tokenHash === service.hash(second.rawToken)).toBe(true);
    expect(Reflect.ownKeys(service).length === 0).toBe(true);
  });

  it('matches the public SHA-256 abc known vector in exact lowercase hex', () => {
    const expected =
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad';
    expect(service.hash('abc') === expected).toBe(true);
  });

  it('selects sha256, exact UTF-8 input and hex explicitly without consuming randomness', () => {
    const digest = crypto.createHash('sha256');
    const update = vi.spyOn(digest, 'update');
    const finish = vi.spyOn(digest, 'digest');
    makeHash.mockReturnValueOnce(digest);
    const input = ' exact e\u0301 credential %2B= ';
    const output = service.hash(input);
    expect(makeHash).toHaveBeenCalledExactlyOnceWith('sha256');
    expect(
      update.mock.calls.length === 1 &&
        update.mock.calls[0][0] === input &&
        update.mock.calls[0][1] === 'utf8',
    ).toBe(true);
    expect(
      finish.mock.calls.length === 1 && finish.mock.calls[0][0] === 'hex',
    ).toBe(true);
    expect(
      output ===
        crypto.createHash('sha256').update(input, 'utf8').digest('hex'),
    ).toBe(true);
    expect(random).not.toHaveBeenCalled();
  });

  it('is deterministic and never trims, casefolds, decodes, repairs padding or normalizes Unicode', () => {
    for (const [left, right] of [
      ['Token', 'token'],
      ['abc', 'abc '],
      ['abc', ' abc'],
      ['abc', '%61bc'],
      ['abc', 'YWJj'],
      ['YWJj', 'YWJj='],
      ['a+b', 'a b'],
      ['\u00e9', 'e\u0301'],
    ]) {
      expect(service.hash(left) === service.hash(left)).toBe(true);
      expect(service.hash(left) !== service.hash(right)).toBe(true);
      for (const value of [left, right])
        expect(
          service.hash(value) ===
            crypto.createHash('sha256').update(value, 'utf8').digest('hex'),
        ).toBe(true);
    }
    // Nonempty opaque input need not match the generator's credential alphabet.
    expect(
      service.hash(' ') ===
        crypto.createHash('sha256').update(' ', 'utf8').digest('hex'),
    ).toBe(true);
  });

  it.each([
    '',
    null,
    undefined,
    0,
    true,
    [],
    {},
    Buffer.from('abc'),
    new String('abc'),
  ])(
    'safely rejects invalid runtime hash input case %# before crypto',
    (input) => {
      fails(
        () => service.hash(input as string),
        'Refresh token hashing failed.',
      );
      expect(makeHash).not.toHaveBeenCalled();
      expect(random).not.toHaveBeenCalled();
    },
  );

  it('sanitizes a random-source exception without retrying or attempting hashing', () => {
    random.mockImplementationOnce(() => {
      throw new Error(canary);
    });
    fails(() => service.generate(), 'Refresh token generation failed.');
    expect(random).toHaveBeenCalledExactlyOnceWith(32);
    expect(makeHash).not.toHaveBeenCalled();
  });

  it.each([
    null,
    undefined,
    new Uint8Array(32),
    Buffer.alloc(0),
    Buffer.alloc(31),
    Buffer.alloc(33),
  ])(
    'fails closed on malformed random material case %# without repairing/retrying',
    (material) => {
      random.mockReturnValueOnce(material as Buffer);
      fails(() => service.generate(), 'Refresh token generation failed.');
      expect(random).toHaveBeenCalledExactlyOnceWith(32);
      expect(makeHash).not.toHaveBeenCalled();
    },
  );

  it.each([
    '',
    'A'.repeat(42),
    'A'.repeat(44),
    'A'.repeat(42) + '=',
    'A'.repeat(42) + '+',
    'A'.repeat(42) + '/',
    'A'.repeat(43) + '\n',
    'A'.repeat(42) + '\u00e9',
    'A'.repeat(42) + 'B', // Correct decoded size, but nonzero unused bits: noncanonical.
  ])(
    'fails closed on malformed/noncanonical raw encoding case %#',
    (encoded) => {
      const bytes = Buffer.alloc(32);
      vi.spyOn(bytes, 'toString').mockReturnValueOnce(encoded);
      random.mockReturnValueOnce(bytes);
      fails(() => service.generate(), 'Refresh token generation failed.');
      expect(random).toHaveBeenCalledExactlyOnceWith(32);
      expect(makeHash).not.toHaveBeenCalled();
    },
  );

  it.each(['create', 'update', 'digest'] as const)(
    'sanitizes native %s failures for both direct hash and generation',
    (stage) => {
      const injectFailure = (): void => {
        if (stage === 'create')
          makeHash.mockImplementationOnce(() => {
            throw new Error(canary);
          });
        else {
          const digest = crypto.createHash('sha256');
          if (stage === 'update')
            vi.spyOn(digest, 'update').mockImplementationOnce(() => {
              throw new Error(canary);
            });
          else
            vi.spyOn(digest, 'digest').mockImplementationOnce(() => {
              throw new Error(canary);
            });
          makeHash.mockReturnValueOnce(digest);
        }
      };
      injectFailure();
      fails(() => service.hash(canary), 'Refresh token hashing failed.');
      injectFailure();
      fails(() => service.generate(), 'Refresh token generation failed.');
      expect(random).toHaveBeenCalledExactlyOnceWith(32);
    },
  );

  it.each([
    undefined,
    null,
    Buffer.alloc(32),
    '',
    'a'.repeat(63),
    'a'.repeat(65),
    'A'.repeat(64),
    'g'.repeat(64),
    'a'.repeat(64) + '\n',
  ])(
    'rejects malformed digest representation case %# in both public methods',
    (output) => {
      const badDigest = (): void => {
        const digest = crypto.createHash('sha256');
        vi.spyOn(digest, 'digest').mockReturnValueOnce(output as never);
        makeHash.mockReturnValueOnce(digest);
      };
      badDigest();
      fails(() => service.hash(canary), 'Refresh token hashing failed.');
      badDigest();
      fails(() => service.generate(), 'Refresh token generation failed.');
    },
  );

  it('is injectable with no dependencies, state or startup generation', async () => {
    const module = await Test.createTestingModule({
      providers: [RefreshTokenGeneratorService],
    }).compile();
    try {
      for (const log of logs) log.mockClear();
      await module.init();
      const injectable = module.get(RefreshTokenGeneratorService);
      expect(injectable instanceof RefreshTokenGeneratorService).toBe(true);
      expect(Reflect.ownKeys(injectable).length === 0).toBe(true);
      expect(
        (Reflect.getMetadata(
          'design:paramtypes',
          RefreshTokenGeneratorService,
        ) as unknown) ?? [],
      ).toEqual([]);
      expect(
        (Reflect.getMetadata(
          'self:paramtypes',
          RefreshTokenGeneratorService,
        ) as unknown) ?? [],
      ).toEqual([]);
      expect(random).not.toHaveBeenCalled();
      expect(makeHash).not.toHaveBeenCalled();
      expect(/^[0-9a-f]{64}$/.test(injectable.generate().tokenHash)).toBe(true);
    } finally {
      await module.close();
    }
  });

  it('statically permits only Nest/Node crypto imports: no Prisma/Redis, filesystem/network persistence or hidden dynamic imports', () => {
    const text = readFileSync(
      new URL('./refresh-token-generator.service.ts', import.meta.url),
      'utf8',
    );
    const source = ts.createSourceFile(
      'generator.ts',
      text,
      ts.ScriptTarget.Latest,
      true,
    );
    const imports = source.statements
      .filter(ts.isImportDeclaration)
      .map((statement) =>
        ts.isStringLiteral(statement.moduleSpecifier)
          ? statement.moduleSpecifier.text
          : '',
      );
    expect(imports.sort()).toEqual(['@nestjs/common', 'node:crypto']);
    let dynamicDependency = false;
    const inspect = (node: ts.Node): void => {
      if (
        ts.isCallExpression(node) &&
        (node.expression.kind === ts.SyntaxKind.ImportKeyword ||
          (ts.isIdentifier(node.expression) &&
            node.expression.text === 'require'))
      )
        dynamicDependency = true;
      ts.forEachChild(node, inspect);
    };
    inspect(source);
    expect(dynamicDependency).toBe(false);
    const implementation = source.statements.find(ts.isClassDeclaration);
    expect(
      implementation !== undefined &&
        !implementation.members.some(
          (member) =>
            ts.isConstructorDeclaration(member) ||
            ts.isPropertyDeclaration(member),
        ),
    ).toBe(true);
  });
});
