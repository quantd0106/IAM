import 'reflect-metadata';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import type { LoggerService } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Test } from '@nestjs/testing';
import * as argon2 from 'argon2';
import { AppConfigModule } from '../config/config.module.js';
import type { Environment } from '../config/env.schema.js';
import type { Prisma } from '../generated/prisma/client.js';
import { PrismaService } from '../prisma/prisma.service.js';
import { ClientRegistryModule } from './client-registry.module.js';
import { ClientSecretService } from './client-secret.service.js';

// Explicit local verification only. No HTTP server, Redis or secret fixture.
async function checkClientSecrets(): Promise<void> {
  let capturedLogs = 0;
  const capture = (): void => {
    capturedLogs++;
  };
  const logger: LoggerService = {
    log: capture,
    error: capture,
    warn: capture,
    debug: capture,
    verbose: capture,
    fatal: capture,
  };
  // Compile first, validate the target, then initialize/connect: never probe a remote DB.
  const context = await Test.createTestingModule({
    imports: [AppConfigModule, ClientRegistryModule],
  })
    .setLogger(logger)
    .compile();
  const config = context.get<ConfigService<Environment, true>>(ConfigService);
  const prisma = context.get(PrismaService);
  const service = context.get(ClientSecretService);
  const marker = `m4.4-client-${randomUUID()}`;
  const owned = {
    clientId: { in: [`${marker}-confidential`, `${marker}-public`] },
  };
  let cleanupAllowed = false;
  type Snapshot = { relation: string; count: number; fingerprint: string }[];
  let before: Snapshot | undefined;
  // Full-row fingerprints stay inside this process and are never printed.
  const snapshot = (): Promise<Snapshot> => prisma.$queryRaw<Snapshot>`
    SELECT 'users'::text AS relation, COUNT(*)::int AS count,
      md5(COALESCE(jsonb_agg(to_jsonb(u) ORDER BY id)::text, '[]')) AS fingerprint FROM users u
    UNION ALL
    SELECT 'credentials', COUNT(*)::int,
      md5(COALESCE(jsonb_agg(to_jsonb(c) ORDER BY id)::text, '[]')) FROM credentials c
    UNION ALL
    SELECT 'sessions', COUNT(*)::int,
      md5(COALESCE(jsonb_agg(to_jsonb(s) ORDER BY id)::text, '[]')) FROM sessions s
    UNION ALL
    SELECT 'clients', COUNT(*)::int,
      md5(COALESCE(jsonb_agg(to_jsonb(c) ORDER BY id)::text, '[]')) FROM clients c
    UNION ALL
    SELECT 'client_redirect_uris', COUNT(*)::int,
      md5(COALESCE(jsonb_agg(to_jsonb(r) ORDER BY id)::text, '[]')) FROM client_redirect_uris r
    UNION ALL
    SELECT 'scopes', COUNT(*)::int,
      md5(COALESCE(jsonb_agg(to_jsonb(s) ORDER BY id)::text, '[]')) FROM scopes s
    UNION ALL
    SELECT 'client_scopes', COUNT(*)::int,
      md5(COALESCE(jsonb_agg(to_jsonb(s) ORDER BY client_id, scope_id)::text, '[]')) FROM client_scopes s
    UNION ALL
    SELECT '_prisma_migrations', COUNT(*)::int,
      md5(COALESCE(jsonb_agg(to_jsonb(m) ORDER BY id)::text, '[]')) FROM _prisma_migrations m
    ORDER BY relation
  `;
  const originals = {
    log: console.log,
    info: console.info,
    warn: console.warn,
    error: console.error,
    debug: console.debug,
  };
  const restoreConsole = (): void => {
    Object.assign(console, originals);
  };
  const safeError = (error: unknown, forbidden: string[]): void => {
    assert.ok(error instanceof Error);
    assert.equal(error.message, 'Client secret issuance failed.');
    assert.equal(error.cause, undefined);
    assert.deepEqual(Object.keys(error), []);
    for (const value of forbidden)
      assert.ok(!(error.message + (error.stack ?? '')).includes(value));
  };
  const rejected = async (
    operation: Promise<unknown>,
    forbidden: string[],
  ): Promise<void> => {
    let failed = false;
    try {
      await operation;
    } catch (error) {
      failed = true;
      safeError(error, forbidden);
    }
    assert.ok(failed);
  };
  try {
    const databaseUrl = config.getOrThrow('DATABASE_URL', { infer: true });
    const url = new URL(databaseUrl);
    if (
      !['development', 'test'].includes(
        config.getOrThrow('NODE_ENV', { infer: true }),
      ) ||
      !['postgresql:', 'postgres:'].includes(url.protocol) ||
      !['localhost', '127.0.0.1', '[::1]'].includes(url.hostname)
    )
      throw new Error(
        'Client secret probe requires local development PostgreSQL.',
      );
    await context.init();
    const columns = await prisma.$queryRaw<
      { name: string; type: string; nullable: string }[]
    >`
      SELECT column_name::text AS name, udt_name::text AS type, is_nullable::text AS nullable
      FROM information_schema.columns WHERE table_schema = 'public' AND table_name = 'clients'
      ORDER BY ordinal_position
    `;
    assert.deepEqual(
      columns.map(({ name }) => name),
      [
        'id',
        'client_id',
        'name',
        'client_type',
        'client_secret_hash',
        'enabled',
        'access_token_ttl',
        'refresh_token_ttl',
      ],
    );
    assert.deepEqual(
      columns.find(({ name }) => name === 'client_secret_hash'),
      {
        name: 'client_secret_hash',
        type: 'text',
        nullable: 'YES',
      },
    );
    const tables = await prisma.$queryRaw<{ name: string }[]>`
      SELECT table_name::text AS name FROM information_schema.tables WHERE table_schema = 'public'
    `;
    assert.deepEqual(tables.map(({ name }) => name).sort(), [
      '_prisma_migrations',
      'client_redirect_uris',
      'client_scopes',
      'clients',
      'credentials',
      'scopes',
      'sessions',
      'users',
    ]);
    before = await snapshot();
    assert.equal(
      before.find(({ relation }) => relation === '_prisma_migrations')?.count,
      6,
    );
    assert.equal(await prisma.client.count({ where: owned }), 0);
    cleanupAllowed = true;
    const confidential = await prisma.client.create({
      data: {
        clientId: `${marker}-confidential`,
        name: marker,
        clientType: 'CONFIDENTIAL',
        enabled: false,
      },
    });
    const publicClient = await prisma.client.create({
      data: {
        clientId: `${marker}-public`,
        name: marker,
        clientType: 'PUBLIC',
      },
    });
    assert.equal(confidential.clientSecretHash, null);
    assert.equal(publicClient.clientSecretHash, null);

    capturedLogs = 0;
    for (const method of ['log', 'info', 'warn', 'error', 'debug'] as const)
      console[method] = capture;
    const issued = await service.issueSecret(confidential.id);
    assert.deepEqual(Object.keys(issued), ['clientSecret']);
    assert.equal(issued.clientSecret.length, 43);
    assert.match(issued.clientSecret, /^[A-Za-z0-9_-]+$/);
    assert.equal(Buffer.from(issued.clientSecret, 'base64url').length, 32);
    const first = await prisma.client.findUniqueOrThrow({
      where: { id: confidential.id },
    });
    const firstHash = first.clientSecretHash;
    assert.ok(typeof firstHash === 'string');
    assert.ok(firstHash.startsWith('$argon2id$'));
    assert.ok(firstHash !== issued.clientSecret);
    assert.ok(await argon2.verify(firstHash, issued.clientSecret));
    assert.deepEqual({ ...first, clientSecretHash: null }, confidential);

    const rotated = await service.issueSecret(confidential.id);
    assert.deepEqual(Object.keys(rotated), ['clientSecret']);
    const second = await prisma.client.findUniqueOrThrow({
      where: { id: confidential.id },
    });
    const secondHash = second.clientSecretHash;
    assert.ok(typeof secondHash === 'string');
    assert.ok(secondHash.startsWith('$argon2id$'));
    assert.ok(
      rotated.clientSecret !== issued.clientSecret && secondHash !== firstHash,
    );
    assert.ok(secondHash !== rotated.clientSecret);
    assert.ok(await argon2.verify(secondHash, rotated.clientSecret));
    assert.equal(await argon2.verify(secondHash, issued.clientSecret), false);
    assert.deepEqual({ ...second, clientSecretHash: null }, confidential);
    const forbidden = [
      databaseUrl,
      issued.clientSecret,
      rotated.clientSecret,
      firstHash,
      secondHash,
    ];

    await rejected(service.issueSecret(publicClient.id), forbidden);
    assert.deepEqual(
      await prisma.client.findUniqueOrThrow({ where: { id: publicClient.id } }),
      publicClient,
    );
    const unknown = randomUUID();
    assert.equal(await prisma.client.count({ where: { id: unknown } }), 0);
    await rejected(service.issueSecret(unknown), forbidden);

    // Controlled persistence boundary failure; real read/crypto, no successful return/write.
    const failedPersistence = new ClientSecretService({
      client: {
        findUnique: (input: Prisma.ClientFindUniqueArgs) =>
          prisma.client.findUnique(input),
        updateMany: () =>
          Promise.reject(
            new Error(secondHash, { cause: new Error(databaseUrl) }),
          ),
      },
    } as unknown as PrismaService);
    await rejected(failedPersistence.issueSecret(confidential.id), forbidden);
    assert.deepEqual(
      await prisma.client.findUniqueOrThrow({ where: { id: confidential.id } }),
      second,
    );

    // Both actual PostgreSQL reads must complete with the same hash before crypto/CAS.
    // Only this probe gates the boundary; no production test hook or timing sleep.
    let release!: () => void;
    let failGate!: () => void;
    const gate = new Promise<void>((resolve, reject) => {
      release = resolve;
      failGate = () =>
        reject(new Error('Client secret probe read gate timeout.'));
    });
    const observed: (string | null)[] = [];
    const concurrent = new ClientSecretService({
      client: {
        findUnique: async (input: Prisma.ClientFindUniqueArgs) => {
          const row = await prisma.client.findUnique(input);
          assert.ok(row && row.id === confidential.id);
          observed.push(row.clientSecretHash);
          if (observed.length === 2) release();
          await gate;
          return row;
        },
        updateMany: (input: Prisma.ClientUpdateManyArgs) =>
          prisma.client.updateMany(input),
      },
    } as unknown as PrismaService);
    const gateTimeout = setTimeout(failGate, 10000);
    gateTimeout.unref();
    try {
      const results = await Promise.allSettled([
        concurrent.issueSecret(confidential.id),
        concurrent.issueSecret(confidential.id),
      ]);
      assert.equal(observed.length, 2);
      assert.ok(observed.every((hash) => hash === secondHash));
      const winners = results.filter((result) => result.status === 'fulfilled');
      const losers = results.filter((result) => result.status === 'rejected');
      assert.equal(winners.length, 1);
      assert.equal(losers.length, 1);
      const winner = winners[0].value;
      assert.deepEqual(Object.keys(winner), ['clientSecret']);
      const current = await prisma.client.findUniqueOrThrow({
        where: { id: confidential.id },
      });
      const currentHash = current.clientSecretHash;
      assert.ok(typeof currentHash === 'string');
      assert.ok(currentHash.startsWith('$argon2id$'));
      assert.ok(await argon2.verify(currentHash, winner.clientSecret));
      assert.equal(
        await argon2.verify(currentHash, rotated.clientSecret),
        false,
      );
      assert.ok(currentHash !== winner.clientSecret);
      assert.deepEqual({ ...current, clientSecretHash: null }, confidential);
      safeError(losers[0].reason, [
        ...forbidden,
        winner.clientSecret,
        currentHash,
      ]);
    } finally {
      clearTimeout(gateTimeout);
      release();
    }
    assert.equal(capturedLogs, 0);
    restoreConsole();
    console.log(
      'Client secret real PostgreSQL NULL baseline/32-byte base64url/Argon2id hash-only/issuance/rotation/new verifies-old rejects/PUBLIC NULL/unknown/sanitized persistence failure passed.',
    );
    console.log(
      'Client secret deterministic live CAS passed: two same-snapshot reads, one winner, one sanitized loser; current hash verifies only winning returned raw.',
    );
    console.log(
      'Client secret operations produced no console/Nest logs; schema unchanged, nullable hash is the only persisted secret field and six migrations remain.',
    );
  } finally {
    restoreConsole();
    try {
      if (cleanupAllowed) {
        await prisma.client.deleteMany({ where: owned });
        assert.equal(await prisma.client.count({ where: owned }), 0);
        assert.deepEqual(await snapshot(), before);
        console.log(
          'Client secret probe cleanup passed: zero owned Clients; all pre-existing domain and migration rows unchanged.',
        );
      }
    } finally {
      await context.close();
    }
  }
}

void checkClientSecrets().catch(() => {
  // Never print raw secrets, encoded hashes, assertion detail or driver causes.
  console.error(
    'Client secret verification failed; inspect local development PostgreSQL configuration and rerun.',
  );
  process.exitCode = 1;
});
