import { Test } from '@nestjs/testing';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { PrismaModule } from './prisma.module.js';
import { PrismaService } from './prisma.service.js';

// Unit tests isolate lifecycle behavior; real connectivity is verified separately.
vi.mock('../generated/prisma/client.js', () => ({
  PrismaClient: class {
    readonly $connect = vi
      .fn<() => Promise<void>>()
      .mockResolvedValue(undefined);
    readonly $disconnect = vi
      .fn<() => Promise<void>>()
      .mockResolvedValue(undefined);
  },
}));

describe('PrismaModule', () => {
  afterEach(() => {
    vi.unstubAllEnvs();
    vi.clearAllMocks();
  });

  it.each([undefined, '', '   '])(
    'rejects a missing or blank DATABASE_URL (%s)',
    (databaseUrl) => {
      vi.stubEnv('DATABASE_URL', databaseUrl);

      expect(() => new PrismaService()).toThrow(
        'DATABASE_URL is required to initialize PrismaService.',
      );
    },
  );

  it('exports PrismaService and manages its connection lifecycle', async () => {
    vi.stubEnv(
      'DATABASE_URL',
      'postgresql://iam:iam_dev_password@localhost:5432/iam?schema=public',
    );
    const module = await Test.createTestingModule({
      imports: [PrismaModule],
      providers: [
        {
          provide: 'prisma-consumer',
          inject: [PrismaService],
          useFactory: (prisma: PrismaService): { prisma: PrismaService } => ({
            prisma,
          }),
        },
      ],
    }).compile();
    const { prisma } = module.get<{ prisma: PrismaService }>('prisma-consumer');
    const connect = vi.spyOn(prisma, '$connect');
    const disconnect = vi.spyOn(prisma, '$disconnect');

    try {
      await module.init();
      expect(prisma).toBeInstanceOf(PrismaService);
      expect(connect).toHaveBeenCalledOnce();
    } finally {
      await module.close();
    }

    expect(disconnect).toHaveBeenCalledOnce();
  });
});
