import { PrismaPg } from '@prisma/adapter-pg';
import { PrismaClient } from '../src/generated/prisma/client.js';

export async function runSeed(
  databaseUrl: string | undefined,
): Promise<number> {
  const connectionString = databaseUrl?.trim();
  if (!connectionString) throw new Error('DATABASE_URL is required.');

  const prisma = new PrismaClient({
    adapter: new PrismaPg({
      connectionString,
      connectionTimeoutMillis: 5000,
    }),
  });

  try {
    await prisma.$connect();
    await prisma.$queryRaw`SELECT 1`;
    // Future task-owned deterministic domain seed steps are invoked here.
    // No domain models/datasets exist in M1.8; do not create or mutate data.
    return 0;
  } finally {
    await prisma.$disconnect();
  }
}
