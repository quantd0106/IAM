// Explicit bounded local verification only. No HTTP/Redis/secret lifecycle calls.
import 'reflect-metadata';
import 'dotenv/config';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import type { LoggerService } from '@nestjs/common';
import { Test, type TestingModule } from '@nestjs/testing';
import { PrismaPg } from '@prisma/adapter-pg';
import { PrismaClient, type Prisma } from '../src/generated/prisma/client.js';
import { PrismaService } from '../src/prisma/prisma.service.js';
import { ClientRegistryModule } from '../src/client-registry/client-registry.module.js';
import { ClientLookupService } from '../src/client-registry/client-lookup.service.js';
import { ScopeLookupService } from '../src/client-registry/scope-lookup.service.js';

const demos = [
  {
    clientId: 'student-spa',
    clientType: 'PUBLIC',
    redirectUri: 'http://localhost:3200/callback',
    scopes: ['email', 'openid', 'profile'],
  },
  {
    clientId: 'banking-web',
    clientType: 'CONFIDENTIAL',
    redirectUri: 'http://localhost:3100/auth/callback',
    scopes: ['banking.transactions.read', 'email', 'openid', 'profile'],
  },
  {
    clientId: 'admin-portal',
    clientType: 'CONFIDENTIAL',
    redirectUri: 'http://localhost:3300/auth/callback',
    scopes: ['email', 'openid', 'profile'],
  },
];
type Snapshot = { relation: string; count: number; fingerprint: string }[];
// Full-row fingerprints are calculated on the server; no secret/hash values leave it.
const snapshot = (
  db: Prisma.TransactionClient,
): Promise<Snapshot> => db.$queryRaw<Snapshot>`
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
type Writes = {
  relation: string;
  inserted: bigint;
  updated: bigint;
  deleted: bigint;
}[];
// Current-transaction counters detect even an UPDATE writing unchanged values.
const writes = (
  db: Prisma.TransactionClient,
): Promise<Writes> => db.$queryRaw<Writes>`
  SELECT relname::text AS relation, n_tup_ins AS inserted, n_tup_upd AS updated, n_tup_del AS deleted
  FROM pg_stat_xact_user_tables WHERE schemaname = 'public' ORDER BY relname
`;
async function rejected(
  operation: Promise<unknown>,
  message: string,
): Promise<void> {
  let failed = false;
  try {
    await operation;
  } catch (error) {
    failed = true;
    assert.ok(error instanceof Error);
    assert.equal(error.message, message);
    assert.equal(error.cause, undefined);
    assert.deepEqual(Object.keys(error), []);
  }
  assert.ok(failed);
}

async function checkClientLookups(): Promise<void> {
  const connectionString = process.env.DATABASE_URL?.trim();
  if (!connectionString) throw new Error('DATABASE_URL is required.');
  const url = new URL(connectionString);
  if (
    !['development', 'test'].includes(process.env.NODE_ENV ?? 'development') ||
    !['postgresql:', 'postgres:'].includes(url.protocol) ||
    !['localhost', '127.0.0.1', '[::1]'].includes(url.hostname)
  )
    throw new Error(
      'Client lookup probe requires local development PostgreSQL.',
    );
  const prisma = new PrismaClient({
    adapter: new PrismaPg({ connectionString, connectionTimeoutMillis: 5000 }),
  });
  let capturedLogs = 0;
  const capture = (): void => {
    capturedLogs++;
  };
  const logger: LoggerService = {
    log: capture,
    warn: capture,
    error: capture,
    debug: capture,
    verbose: capture,
    fatal: capture,
  };
  const originals = {
    log: console.log,
    info: console.info,
    warn: console.warn,
    error: console.error,
    debug: console.debug,
  };
  const contexts: TestingModule[] = [];
  const capabilities = async (tx: Prisma.TransactionClient) => {
    // Real module/exports/DI, reusing this probe's transaction instead of starting an app.
    const context = await Test.createTestingModule({
      imports: [ClientRegistryModule],
    })
      .overrideProvider(PrismaService)
      .useValue(tx)
      .setLogger(logger)
      .compile();
    contexts.push(context);
    // Observe capability calls, not framework test-container compilation logs.
    capturedLogs = 0;
    return {
      clients: context.get(ClientLookupService),
      scopes: context.get(ScopeLookupService),
    };
  };
  try {
    await prisma.$connect();
    const before = await snapshot(prisma);
    for (const method of ['log', 'info', 'warn', 'error', 'debug'] as const)
      console[method] = capture;
    await prisma.$transaction(
      async (tx) => {
        // Canonical lookup must succeed when PostgreSQL itself prohibits writes.
        await tx.$executeRaw`SET TRANSACTION READ ONLY`;
        const { clients, scopes } = await capabilities(tx);
        for (const demo of demos) {
          const client = await clients.requireEnabledClient(demo.clientId);
          assert.equal(client.clientId, demo.clientId);
          assert.equal(client.clientType, demo.clientType);
          assert.deepEqual(client.redirectUris, [demo.redirectUri]);
          assert.deepEqual(Object.keys(client).sort(), [
            'accessTokenTtl',
            'clientId',
            'clientType',
            'id',
            'name',
            'redirectUris',
            'refreshTokenTtl',
          ]);
          assert.equal(Object.hasOwn(client, 'clientSecretHash'), false);
          const registered = await tx.client.findUniqueOrThrow({
            where: { id: client.id },
            select: { enabled: true },
          });
          assert.equal(registered.enabled, true);
          assert.deepEqual(
            await scopes.getAllowedScopeNames(client.id),
            demo.scopes,
          );
          await rejected(
            clients.requireEnabledClient(client.id),
            'Client unavailable.',
          );
        }
        // Prove exact matching while the canonical client is still ENABLED;
        // disabled rejection must not mask accidental normalization/fallback.
        for (const value of [
          'Student-spa',
          'student-spa ',
          ' student-spa',
          'STUDENT-SPA',
          'student-*',
          'student-%',
          'student-spa-extra',
          'prefix-student-spa',
        ])
          await rejected(
            clients.requireEnabledClient(value),
            'Client unavailable.',
          );
        const activity = await writes(tx);
        assert.ok(
          activity.every(
            (row) =>
              row.inserted === 0n && row.updated === 0n && row.deleted === 0n,
          ),
        );
        assert.equal(capturedLogs, 0);
      },
      { timeout: 15000 },
    );

    const rollback = new Error('Rollback lookup probe-owned state.');
    let completed = false;
    try {
      await prisma.$transaction(
        async (tx) => {
          const { clients, scopes } = await capabilities(tx);
          const student = await clients.requireEnabledClient('student-spa');
          // Temporary disabled state is never committed, including on assertion failure.
          await tx.client.update({
            where: { id: student.id },
            data: { enabled: false },
          });
          const marker = `m4.6-lookup-${randomUUID()}`;
          const fixture = await tx.client.create({
            data: {
              clientId: ` ${marker}-Client `,
              name: marker,
              clientType: 'PUBLIC',
            },
            select: { id: true, clientId: true },
          });
          const exactScopes = [
            `${marker}.Read`,
            `${marker}.read`,
            ` ${marker}.read `,
            `${marker}.caf\u00e9`,
            `${marker}.cafe\u0301`,
          ];
          for (const name of exactScopes) {
            const scope = await tx.scope.create({
              data: { name },
              select: { id: true },
            });
            await tx.clientScope.create({
              data: { clientId: fixture.id, scopeId: scope.id },
            });
          }
          const state = await snapshot(tx);
          const activity = await writes(tx);
          await rejected(
            clients.requireEnabledClient('student-spa'),
            'Client unavailable.',
          );
          for (const value of [`${marker}-unknown`, student.id])
            await rejected(
              clients.requireEnabledClient(value),
              'Client unavailable.',
            );
          assert.equal(
            (await clients.requireEnabledClient(fixture.clientId)).clientId,
            fixture.clientId,
          );
          assert.deepEqual(
            await scopes.getAllowedScopeNames(fixture.id),
            [...exactScopes].sort(),
          );
          const unknownId = randomUUID();
          assert.equal(await tx.client.count({ where: { id: unknownId } }), 0);
          assert.deepEqual(await scopes.getAllowedScopeNames(unknownId), []);
          await rejected(
            scopes.getAllowedScopeNames('student-spa'),
            'Invalid client record identifier.',
          );
          // No row changes AND no INSERT/UPDATE/DELETE (including no-op writes).
          assert.deepEqual(await writes(tx), activity);
          assert.ok(
            JSON.stringify(await snapshot(tx)) === JSON.stringify(state),
          );
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
    assert.equal(capturedLogs, 0);
    Object.assign(console, originals);
    console.log(
      'Client lookup passed: exact seeded PUBLIC/CONFIDENTIAL metadata and redirects; no secret hash exposure; canonical scopes 3/4/3 in deterministic order; PostgreSQL READ ONLY transaction succeeded.',
    );
    console.log(
      'Negative lookup passed: unknown/disabled/case/whitespace/wildcard/internal-ID rejection; exact opaque scope names; invalid UUID; zero lookup writes by transaction counters and full-row fingerprints.',
    );
    console.log(
      'Lookup probe rollback passed: no owned rows/state remain; all pre-existing domain/migration rows and canonical seed data unchanged; no service logs.',
    );
  } finally {
    Object.assign(console, originals);
    try {
      for (const context of contexts) await context.close();
    } finally {
      await prisma.$disconnect();
    }
  }
}

void checkClientLookups().catch(() => {
  console.error(
    'Client/scope lookup verification failed; inspect local development database configuration and seeded registry, then rerun.',
  );
  process.exitCode = 1;
});
