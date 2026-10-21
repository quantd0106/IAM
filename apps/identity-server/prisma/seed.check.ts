// Explicit local PostgreSQL verification. All probe changes are rolled back.
import 'dotenv/config';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { PrismaPg } from '@prisma/adapter-pg';
import * as argon2 from 'argon2';
import { z } from 'zod';
import { PrismaClient, type Prisma } from '../src/generated/prisma/client.js';
import { applyDemoRegistry } from './seed.runner.js';

const expected = [
  {
    clientId: 'student-spa',
    accessTokenAudience: 'student-api',
    name: 'Student SPA',
    clientType: 'PUBLIC',
    redirectUri: 'http://localhost:3200/callback',
    scopes: ['email', 'openid', 'profile'],
  },
  {
    clientId: 'banking-web',
    accessTokenAudience: 'banking-api',
    name: 'Banking Web / BFF',
    clientType: 'CONFIDENTIAL',
    redirectUri: 'http://localhost:3100/auth/callback',
    scopes: ['banking.transactions.read', 'email', 'openid', 'profile'],
  },
  {
    clientId: 'admin-portal',
    accessTokenAudience: 'identity-server',
    name: 'Admin Portal / BFF',
    clientType: 'CONFIDENTIAL',
    redirectUri: 'http://localhost:3300/auth/callback',
    scopes: ['email', 'openid', 'profile'],
  },
];
const names = ['banking.transactions.read', 'email', 'openid', 'profile'];
type Snapshot = { relation: string; count: number; fingerprint: string }[];
// Fingerprint full rows on the server, never output hashes or credential material.
const snapshot = (
  prisma: Prisma.TransactionClient,
): Promise<Snapshot> => prisma.$queryRaw<Snapshot>`
  SELECT 'users'::text AS relation, COUNT(*)::int AS count,
    md5(COALESCE(jsonb_agg(to_jsonb(t) ORDER BY id)::text, '[]')) AS fingerprint FROM users t
  UNION ALL SELECT 'credentials', COUNT(*)::int,
    md5(COALESCE(jsonb_agg(to_jsonb(t) ORDER BY id)::text, '[]')) FROM credentials t
  UNION ALL SELECT 'sessions', COUNT(*)::int,
    md5(COALESCE(jsonb_agg(to_jsonb(t) ORDER BY id)::text, '[]')) FROM sessions t
  UNION ALL SELECT 'clients', COUNT(*)::int,
    md5(COALESCE(jsonb_agg(to_jsonb(t) ORDER BY id)::text, '[]')) FROM clients t
  UNION ALL SELECT 'client_redirect_uris', COUNT(*)::int,
    md5(COALESCE(jsonb_agg(to_jsonb(t) ORDER BY id)::text, '[]')) FROM client_redirect_uris t
  UNION ALL SELECT 'scopes', COUNT(*)::int,
    md5(COALESCE(jsonb_agg(to_jsonb(t) ORDER BY id)::text, '[]')) FROM scopes t
  UNION ALL SELECT 'client_scopes', COUNT(*)::int,
    md5(COALESCE(jsonb_agg(to_jsonb(t) ORDER BY client_id, scope_id)::text, '[]')) FROM client_scopes t
  UNION ALL SELECT '_prisma_migrations', COUNT(*)::int,
    md5(COALESCE(jsonb_agg(to_jsonb(t) ORDER BY id)::text, '[]')) FROM _prisma_migrations t
  ORDER BY relation
`;

async function checkSeed(): Promise<void> {
  const connectionString = process.env.DATABASE_URL?.trim();
  if (!connectionString) throw new Error('DATABASE_URL is required.');
  const url = new URL(connectionString);
  if (
    !['development', 'test'].includes(process.env.NODE_ENV ?? 'development') ||
    !['postgresql:', 'postgres:'].includes(url.protocol) ||
    !['localhost', '127.0.0.1', '[::1]'].includes(url.hostname)
  )
    throw new Error('Seed probe requires local development PostgreSQL.');
  const prisma = new PrismaClient({
    adapter: new PrismaPg({ connectionString, connectionTimeoutMillis: 5000 }),
  });
  const rollback = new Error('Rollback probe-owned transaction.');
  let completed = false;
  try {
    await prisma.$connect();
    const before = await snapshot(prisma);
    try {
      await prisma.$transaction(
        async (tx) => {
          const existingClients = await tx.client.findMany({
            where: {
              clientId: { in: expected.map((client) => client.clientId) },
            },
          });
          const marker = `m4.5-seed-${randomUUID()}`;
          // Unrelated exact strings must not be normalized, enabled or overwritten.
          const unrelated = await tx.client.create({
            data: {
              clientId: ` ${marker}-Student-SPA `,
              name: ` ${marker} `,
              clientType: 'PUBLIC',
              enabled: false,
              accessTokenTtl: 123,
              refreshTokenTtl: 456,
            },
          });
          const unrelatedScope = await tx.scope.create({
            data: { name: ` ${marker}-OpenID ` },
          });
          const unrelatedRedirect = await tx.clientRedirectUri.create({
            data: {
              clientId: unrelated.id,
              redirectUri: ' https://EXAMPLE.test/callback ',
            },
          });
          const unrelatedAssignment = await tx.clientScope.create({
            data: { clientId: unrelated.id, scopeId: unrelatedScope.id },
          });
          const preserved = JSON.stringify({
            unrelated,
            unrelatedScope,
            unrelatedRedirect,
            unrelatedAssignment,
          });

          assert.equal(await applyDemoRegistry(tx), 1);
          const clients = await tx.client.findMany({
            where: {
              clientId: { in: expected.map((client) => client.clientId) },
            },
            include: {
              redirectUris: true,
              allowedScopes: { include: { scope: true } },
            },
          });
          assert.equal(clients.length, 3);
          for (const demo of expected) {
            const client = clients.find(
              (client) => client.clientId === demo.clientId,
            );
            assert.ok(client);
            assert.ok(z.uuid().safeParse(client.id).success);
            assert.equal(client.name, demo.name);
            assert.equal(client.clientType, demo.clientType);
            assert.equal(client.enabled, true);
            assert.equal(client.accessTokenAudience, demo.accessTokenAudience);
            const existing = existingClients.find(
              (row) => row.id === client.id,
            );
            assert.equal(
              client.accessTokenTtl,
              existing?.accessTokenTtl ?? 600,
            );
            assert.equal(
              client.refreshTokenTtl,
              existing?.refreshTokenTtl ?? 2592000,
            );
            if (demo.clientType === 'PUBLIC')
              assert.ok(client.clientSecretHash === null);
            else {
              assert.ok(typeof client.clientSecretHash === 'string');
              // Existing hashes are deliberately preserved, not rehashed/rotated.
              if (existing && existing.clientSecretHash !== null)
                assert.ok(
                  client.clientSecretHash === existing.clientSecretHash,
                );
              else {
                assert.ok(client.clientSecretHash.startsWith('$argon2id$'));
                assert.ok(!argon2.needsRehash(client.clientSecretHash));
              }
            }
            assert.deepEqual(
              client.redirectUris.map((row) => row.redirectUri),
              [demo.redirectUri],
            );
            assert.ok(
              client.redirectUris.every(
                (row) =>
                  row.clientId === client.id &&
                  z.uuid().safeParse(row.id).success,
              ),
            );
            assert.deepEqual(
              client.allowedScopes.map((row) => row.scope.name).sort(),
              demo.scopes,
            );
            assert.ok(
              client.allowedScopes.every(
                (row) =>
                  row.clientId === client.id && row.scopeId === row.scope.id,
              ),
            );
            assert.equal(
              new Set(client.allowedScopes.map((row) => row.scopeId)).size,
              demo.scopes.length,
            );
          }
          const scopes = await tx.scope.findMany({
            where: { name: { in: names } },
            orderBy: { name: 'asc' },
          });
          assert.deepEqual(
            scopes.map((row) => row.name),
            names,
          );
          assert.ok(scopes.every((row) => z.uuid().safeParse(row.id).success));
          const constraints = await tx.$queryRaw<{ definition: string }[]>`
          SELECT pg_get_constraintdef(oid) AS definition FROM pg_constraint
          WHERE conrelid = 'public.client_scopes'::regclass AND contype IN ('p', 'f')
          ORDER BY pg_get_constraintdef(oid)
        `;
          assert.deepEqual(
            constraints.map((row) => row.definition),
            [
              'FOREIGN KEY (client_id) REFERENCES clients(id) ON UPDATE CASCADE ON DELETE RESTRICT',
              'FOREIGN KEY (scope_id) REFERENCES scopes(id) ON UPDATE CASCADE ON DELETE RESTRICT',
              'PRIMARY KEY (client_id, scope_id)',
            ],
          );
          const first = await snapshot(tx);
          assert.equal(await applyDemoRegistry(tx), 1);
          // Includes counts, UUIDs, exact links, confidential hashes and all unrelated rows.
          assert.ok(
            JSON.stringify(await snapshot(tx)) === JSON.stringify(first),
          );
          const afterUnrelated = {
            unrelated: await tx.client.findUniqueOrThrow({
              where: { id: unrelated.id },
            }),
            unrelatedScope: await tx.scope.findUniqueOrThrow({
              where: { id: unrelatedScope.id },
            }),
            unrelatedRedirect: await tx.clientRedirectUri.findUniqueOrThrow({
              where: { id: unrelatedRedirect.id },
            }),
            unrelatedAssignment: await tx.clientScope.findUniqueOrThrow({
              where: { clientId_scopeId: unrelatedAssignment },
            }),
          };
          assert.ok(JSON.stringify(afterUnrelated) === preserved);
          completed = true;
          throw rollback;
        },
        { timeout: 15000 },
      );
    } catch (error) {
      if (error !== rollback) throw error;
    }
    assert.ok(completed);
    assert.ok(
      JSON.stringify(await snapshot(prisma)) === JSON.stringify(before),
    );
    console.log(
      'Demo seed passed: exact 3 clients/3 redirects/4 scopes/10 assignments; UUIDs/defaults/PUBLIC NULL/confidential lifecycle/PK/FKs; two runs unchanged including hashes; unrelated fixture unchanged.',
    );
    console.log(
      'Seed probe rollback passed: all domain and migration rows restored unchanged; no probe-owned data remains.',
    );
  } finally {
    await prisma.$disconnect();
  }
}

void checkSeed().catch(() => {
  console.error(
    'Demo seed verification failed; inspect local development database configuration/schema and rerun.',
  );
  process.exitCode = 1;
});
