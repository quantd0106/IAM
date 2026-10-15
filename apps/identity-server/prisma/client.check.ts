// Explicit local PostgreSQL verification only; never startup or seed code.
import 'dotenv/config';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { PrismaPg } from '@prisma/adapter-pg';
import {
  ClientType,
  Prisma,
  PrismaClient,
  type Client,
} from '../src/generated/prisma/client.js';

async function checkClients(): Promise<void> {
  const connectionString = process.env.DATABASE_URL?.trim();
  if (!connectionString) throw new Error('DATABASE_URL is required.');
  const url = new URL(connectionString);
  if (
    !['development', 'test'].includes(process.env.NODE_ENV ?? 'development') ||
    !['postgresql:', 'postgres:'].includes(url.protocol) ||
    !['localhost', '127.0.0.1', '[::1]'].includes(url.hostname)
  )
    throw new Error('Client probe requires local development PostgreSQL.');

  const prisma = new PrismaClient({
    adapter: new PrismaPg({ connectionString, connectionTimeoutMillis: 5000 }),
  });
  const marker = `m4.1-client-${randomUUID()}`;
  const clientIds = [
    marker,
    `${marker}-public`,
    `${marker}-confidential`,
    `${marker}-no-hash`,
    ` ${marker}-Example `,
    ` ${marker}-example `,
  ];
  const owned = { clientId: { in: clientIds } };
  let cleanupAllowed = false;
  type Snapshot = { relation: string; count: number; fingerprint: string }[];
  let before: Snapshot | undefined;
  // Fingerprint full rows inside PostgreSQL; never print rows or credentials.
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
    ORDER BY relation
  `;
  const create = (data: Prisma.ClientCreateInput): Promise<Client> =>
    prisma.client.create({ data });

  try {
    await prisma.$connect();
    const columns = await prisma.$queryRaw<
      {
        name: string;
        type: string;
        nullable: string;
        defaultValue: string | null;
      }[]
    >`
      SELECT column_name::text AS name, udt_name::text AS type,
        is_nullable::text AS nullable, column_default AS "defaultValue"
      FROM information_schema.columns
      WHERE table_schema = 'public' AND table_name = 'clients'
      ORDER BY ordinal_position
    `;
    assert.deepEqual(columns, [
      { name: 'id', type: 'uuid', nullable: 'NO', defaultValue: null },
      { name: 'client_id', type: 'text', nullable: 'NO', defaultValue: null },
      { name: 'name', type: 'text', nullable: 'NO', defaultValue: null },
      {
        name: 'client_type',
        type: 'ClientType',
        nullable: 'NO',
        defaultValue: null,
      },
      {
        name: 'client_secret_hash',
        type: 'text',
        nullable: 'YES',
        defaultValue: null,
      },
      { name: 'enabled', type: 'bool', nullable: 'NO', defaultValue: 'true' },
      {
        name: 'access_token_ttl',
        type: 'int4',
        nullable: 'NO',
        defaultValue: '600',
      },
      {
        name: 'refresh_token_ttl',
        type: 'int4',
        nullable: 'NO',
        defaultValue: '2592000',
      },
    ]);
    const constraints = await prisma.$queryRaw<
      { kind: string; definition: string }[]
    >`
      SELECT contype::text AS kind, pg_get_constraintdef(oid) AS definition
      FROM pg_constraint
      -- Check Client-owned constraints; the incoming FK is verified by the M4.2 probe.
      WHERE conrelid = 'public.clients'::regclass
        -- PostgreSQL 18 also lists NOT NULL constraints; checked via columns above.
        AND contype <> 'n'
    `;
    assert.deepEqual(constraints, [
      { kind: 'p', definition: 'PRIMARY KEY (id)' },
    ]);
    const indexes = await prisma.$queryRaw<{ definition: string }[]>`
      SELECT indexdef AS definition FROM pg_indexes
      WHERE schemaname = 'public' AND tablename = 'clients'
    `;
    assert.equal(indexes.length, 2);
    assert.ok(
      indexes.some(({ definition }) =>
        /^CREATE UNIQUE INDEX .* ON public\.clients USING btree \(client_id\)$/.test(
          definition,
        ),
      ),
    );
    const labels = await prisma.$queryRaw<{ label: string }[]>`
      SELECT e.enumlabel::text AS label FROM pg_enum e
      JOIN pg_type t ON t.oid = e.enumtypid
      JOIN pg_namespace n ON n.oid = t.typnamespace
      WHERE n.nspname = 'public' AND t.typname = 'ClientType'
      ORDER BY e.enumsortorder
    `;
    assert.deepEqual(
      labels.map(({ label }) => label),
      ['PUBLIC', 'CONFIDENTIAL'],
    );
    assert.deepEqual(Object.values(ClientType), ['PUBLIC', 'CONFIDENTIAL']);
    console.log(
      'Client exact columns/types/nullability/defaults/UUID PK/unique index/enum/no outgoing FK or CHECK policies passed.',
    );

    before = await snapshot();
    assert.equal(await prisma.client.count({ where: owned }), 0);
    cleanupAllowed = true;
    const minimal = await create({
      clientId: clientIds[0],
      name: marker,
      clientType: ClientType.PUBLIC,
    });
    assert.match(
      minimal.id,
      /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i,
    );
    assert.deepEqual(minimal, {
      id: minimal.id,
      clientId: clientIds[0],
      name: marker,
      clientType: ClientType.PUBLIC,
      clientSecretHash: null,
      enabled: true,
      accessTokenTtl: 600,
      refreshTokenTtl: 2592000,
    });
    let duplicateRejected = false;
    try {
      await create({
        clientId: clientIds[0],
        name: marker,
        clientType: ClientType.PUBLIC,
      });
    } catch (error) {
      assert.ok(error instanceof Prisma.PrismaClientKnownRequestError);
      assert.equal(error.code, 'P2002');
      duplicateRejected = true;
    }
    assert.ok(duplicateRejected);
    const publicClient = await create({
      clientId: clientIds[1],
      name: marker,
      clientType: ClientType.PUBLIC,
      clientSecretHash: null,
    });
    assert.equal(
      (
        await prisma.client.findUniqueOrThrow({
          where: { clientId: publicClient.clientId },
        })
      ).clientSecretHash,
      null,
    );

    // Opaque persistence marker only: NOT a real credential or hash algorithm.
    const syntheticHash = 'm4.1-test-only-hash-marker';
    const confidential = await create({
      clientId: clientIds[2],
      name: marker,
      clientType: ClientType.CONFIDENTIAL,
      clientSecretHash: syntheticHash,
      enabled: false,
      accessTokenTtl: 123,
      refreshTokenTtl: 456,
    });
    const readBack: Client = await prisma.client.findUniqueOrThrow({
      where: { id: confidential.id },
    });
    assert.deepEqual(readBack, confidential);
    assert.equal(readBack.clientSecretHash, syntheticHash);
    assert.equal(readBack.enabled, false);
    assert.equal(readBack.accessTokenTtl, 123);
    assert.equal(readBack.refreshTokenTtl, 456);
    const noHash = await create({
      clientId: clientIds[3],
      name: marker,
      clientType: ClientType.CONFIDENTIAL,
    });
    assert.equal(noHash.clientSecretHash, null);
    for (const clientId of clientIds.slice(4)) {
      const name = ` ${marker}-Name `;
      const row = await create({
        clientId,
        name,
        clientType: ClientType.PUBLIC,
      });
      assert.equal(row.clientId, clientId);
      assert.equal(row.name, name);
      assert.deepEqual(
        await prisma.client.findUniqueOrThrow({ where: { clientId } }),
        row,
      );
    }
    assert.equal(await prisma.client.count({ where: owned }), clientIds.length);
    console.log(
      'Client generated types/UUID/defaults/real DB duplicate P2002/PUBLIC NULL/confidential synthetic marker and NULL/explicit seconds/disabled persistence/exact strings passed.',
    );
  } finally {
    try {
      if (cleanupAllowed) {
        await prisma.client.deleteMany({ where: owned });
        assert.equal(await prisma.client.count({ where: owned }), 0);
        assert.deepEqual(await snapshot(), before);
        console.log(
          'Client probe cleanup passed: zero probe rows; all pre-existing Client/User/Credential/Session rows unchanged.',
        );
      }
    } finally {
      await prisma.$disconnect();
    }
  }
}

void checkClients().catch(() => {
  // No assertions, driver causes, URLs or synthetic hash values in logs.
  console.error(
    'Client persistence verification failed; inspect local development database configuration/schema and rerun.',
  );
  process.exitCode = 1;
});
