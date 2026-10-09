import { Test } from '@nestjs/testing';
import { ConfigModule, ConfigService } from '@nestjs/config';
import type { Environment } from '../config/env.schema.js';
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

  it('requires the validated DATABASE_URL configuration', () => {
    vi.stubEnv('DATABASE_URL', undefined);
    expect(
      () => new PrismaService(new ConfigService<Environment, true>()),
    ).toThrow('DATABASE_URL');
  });

  it('exports PrismaService and manages its connection lifecycle', async () => {
    const config = new ConfigService<Environment, true>({
      DATABASE_URL: 'postgresql://test:test@localhost:5432/test',
    });
    const module = await Test.createTestingModule({
      imports: [
        ConfigModule.forRoot({
          isGlobal: true,
          ignoreEnvFile: true,
          ignoreEnvVars: true,
        }),
        PrismaModule,
      ],
      providers: [
        {
          provide: 'prisma-consumer',
          inject: [PrismaService],
          useFactory: (prisma: PrismaService): { prisma: PrismaService } => ({
            prisma,
          }),
        },
      ],
    })
      .overrideProvider(ConfigService)
      .useValue(config)
      .compile();
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
