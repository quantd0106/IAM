import { PrismaPg } from '@prisma/adapter-pg';
import { PrismaClient, type Prisma } from '../src/generated/prisma/client.js';
import { ClientSecretService } from '../src/client-registry/client-secret.service.js';

const oidcScopes = ['openid', 'profile', 'email'] as const;
const demoClients = [
  {
    clientId: 'student-spa',
    name: 'Student SPA',
    clientType: 'PUBLIC',
    redirectUri: 'http://localhost:3200/callback',
    scopes: oidcScopes,
  },
  {
    clientId: 'banking-web',
    name: 'Banking Web / BFF',
    clientType: 'CONFIDENTIAL',
    redirectUri: 'http://localhost:3100/auth/callback',
    scopes: [...oidcScopes, 'banking.transactions.read'],
  },
  {
    clientId: 'admin-portal',
    name: 'Admin Portal / BFF',
    clientType: 'CONFIDENTIAL',
    redirectUri: 'http://localhost:3300/auth/callback',
    scopes: oidcScopes,
  },
] as const;

/** Apply one logical dataset (including unchanged reruns) in the caller's transaction. */
export async function applyDemoRegistry(
  transaction: Prisma.TransactionClient,
): Promise<number> {
  const scopeIds = new Map<string, string>();
  for (const name of [...oidcScopes, 'banking.transactions.read']) {
    const scope = await transaction.scope.upsert({
      where: { name },
      create: { name },
      update: {},
      select: { id: true },
    });
    scopeIds.set(name, scope.id);
  }

  // The same service/CAS operates on this transaction; Nest still injects PrismaService.
  const secrets = new ClientSecretService(transaction);
  for (const demo of demoClients) {
    const canonical = {
      name: demo.name,
      clientType: demo.clientType,
      enabled: true,
      ...(demo.clientType === 'PUBLIC' ? { clientSecretHash: null } : {}),
    };
    const client = await transaction.client.upsert({
      where: { clientId: demo.clientId },
      create: { clientId: demo.clientId, ...canonical },
      update: canonical,
      select: { id: true, clientSecretHash: true },
    });
    // No delivery channel exists yet. Discard the one-time plaintext return;
    // never persist/log it or rotate a hash already provisioned by an earlier run.
    if (demo.clientType === 'CONFIDENTIAL' && client.clientSecretHash === null)
      await secrets.issueSecret(client.id);

    // Converge only these canonical clients' registrations; never delete scopes/clients.
    await transaction.clientRedirectUri.deleteMany({
      where: { clientId: client.id, redirectUri: { not: demo.redirectUri } },
    });
    const redirect = { clientId: client.id, redirectUri: demo.redirectUri };
    await transaction.clientRedirectUri.upsert({
      where: { clientId_redirectUri: redirect },
      create: redirect,
      update: {},
    });
    const allowedScopeIds = demo.scopes.map((name) => {
      const id = scopeIds.get(name);
      if (!id) throw new Error('Demo scope missing.');
      return id;
    });
    await transaction.clientScope.deleteMany({
      where: { clientId: client.id, scopeId: { notIn: allowedScopeIds } },
    });
    for (const scopeId of allowedScopeIds) {
      const assignment = { clientId: client.id, scopeId };
      await transaction.clientScope.upsert({
        where: { clientId_scopeId: assignment },
        create: assignment,
        update: {},
      });
    }
  }
  return 1;
}

export async function runSeed(
  databaseUrl: string | undefined,
): Promise<number> {
  const connectionString = databaseUrl?.trim();
  if (!connectionString) throw new Error('DATABASE_URL is required.');

  try {
    const prisma = new PrismaClient({
      adapter: new PrismaPg({
        connectionString,
        connectionTimeoutMillis: 5000,
      }),
    });
    try {
      await prisma.$connect();
      await prisma.$queryRaw`SELECT 1`;
      return await prisma.$transaction(applyDemoRegistry);
    } finally {
      await prisma.$disconnect();
    }
  } catch {
    // Do not expose driver/crypto causes, credentials or connection URLs.
    throw new Error('Seed failed.');
  }
}
