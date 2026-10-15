// Explicit local PostgreSQL verification only; never startup, seed or URI policy.
import 'dotenv/config';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { PrismaPg } from '@prisma/adapter-pg';
import {
  Prisma,
  PrismaClient,
  type ClientRedirectUri,
} from '../src/generated/prisma/client.js';

async function checkClientRedirectUris(): Promise<void> {
  const connectionString = process.env.DATABASE_URL?.trim();
  if (!connectionString) throw new Error('DATABASE_URL is required.');
  const url = new URL(connectionString);
  if (
    !['development', 'test'].includes(process.env.NODE_ENV ?? 'development') ||
    !['postgresql:', 'postgres:'].includes(url.protocol) ||
    !['localhost', '127.0.0.1', '[::1]'].includes(url.hostname)
  )
    throw new Error(
      'Redirect URI probe requires local development PostgreSQL.',
    );

  const prisma = new PrismaClient({
    adapter: new PrismaPg({ connectionString, connectionTimeoutMillis: 5000 }),
  });
  const marker = `m4.2-client-${randomUUID()}`;
  const clientIds = [`${marker}-a`, `${marker}-b`];
  const ownedClients = { clientId: { in: clientIds } };
  // Pre-own the missing-parent insert's ID so even an unexpected success is cleaned.
  const orphanProbeId = randomUUID();
  let cleanupAllowed = false;
  type Snapshot = { relation: string; count: number; fingerprint: string }[];
  let before: Snapshot | undefined;
  // Fingerprint full rows inside PostgreSQL; never return/log credential material.
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
    ORDER BY relation
  `;
  const create = (
    data: Prisma.ClientRedirectUriUncheckedCreateInput,
  ): Promise<ClientRedirectUri> => prisma.clientRedirectUri.create({ data });
  const expectConstraint = async (
    operation: () => Promise<unknown>,
    code: 'P2002' | 'P2003',
  ): Promise<void> => {
    let rejected = false;
    try {
      await operation();
    } catch (error) {
      assert.ok(error instanceof Prisma.PrismaClientKnownRequestError);
      assert.equal(error.code, code);
      rejected = true;
    }
    assert.ok(rejected);
  };

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
      WHERE table_schema = 'public' AND table_name = 'client_redirect_uris'
      ORDER BY ordinal_position
    `;
    assert.deepEqual(columns, [
      { name: 'id', type: 'uuid', nullable: 'NO', defaultValue: null },
      { name: 'client_id', type: 'uuid', nullable: 'NO', defaultValue: null },
      {
        name: 'redirect_uri',
        type: 'text',
        nullable: 'NO',
        defaultValue: null,
      },
    ]);
    const constraints = await prisma.$queryRaw<
      { kind: string; definition: string }[]
    >`
      SELECT contype::text AS kind, pg_get_constraintdef(oid) AS definition
      FROM pg_constraint WHERE conrelid = 'public.client_redirect_uris'::regclass
        AND contype <> 'n' -- PostgreSQL 18 NOT NULL metadata is checked above.
      ORDER BY contype
    `;
    assert.deepEqual(constraints, [
      {
        kind: 'f',
        definition:
          'FOREIGN KEY (client_id) REFERENCES clients(id) ON UPDATE CASCADE ON DELETE RESTRICT',
      },
      { kind: 'p', definition: 'PRIMARY KEY (id)' },
    ]);
    const indexes = await prisma.$queryRaw<{ definition: string }[]>`
      SELECT indexdef AS definition FROM pg_indexes
      WHERE schemaname = 'public' AND tablename = 'client_redirect_uris'
    `;
    assert.equal(indexes.length, 2);
    assert.ok(
      indexes.some(
        ({ definition }) =>
          definition ===
          'CREATE UNIQUE INDEX client_redirect_uris_client_id_redirect_uri_key ON public.client_redirect_uris USING btree (client_id, redirect_uri)',
      ),
    );
    const scopeTables = await prisma.$queryRaw<{ name: string }[]>`
      SELECT table_name::text AS name FROM information_schema.tables
      WHERE table_schema = 'public' AND table_name IN ('scopes', 'client_scopes', 'Scope', 'ClientScope')
    `;
    assert.deepEqual(scopeTables, []);
    console.log(
      'Redirect URI exact columns/types/NOT NULL/UUID PK/FK to internal Client.id/composite unique/no CHECK or Scope tables passed.',
    );

    before = await snapshot();
    assert.equal(await prisma.client.count({ where: ownedClients }), 0);
    assert.equal(
      await prisma.clientRedirectUri.count({ where: { id: orphanProbeId } }),
      0,
    );
    cleanupAllowed = true;
    const a = await prisma.client.create({
      data: { clientId: clientIds[0], name: marker, clientType: 'PUBLIC' },
    });
    const b = await prisma.client.create({
      data: { clientId: clientIds[1], name: marker, clientType: 'PUBLIC' },
    });
    assert.deepEqual(
      (
        await prisma.client.findUniqueOrThrow({
          where: { id: a.id },
          include: { redirectUris: true },
        })
      ).redirectUris,
      [],
    );

    const uri = 'https://m4-2.example.test/callback';
    const first = await create({ clientId: a.id, redirectUri: uri });
    assert.match(
      first.id,
      /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i,
    );
    assert.deepEqual(first, { id: first.id, clientId: a.id, redirectUri: uri });
    assert.equal(
      (
        await prisma.client.findUniqueOrThrow({
          where: { id: a.id },
          include: { redirectUris: true },
        })
      ).redirectUris.length,
      1,
    );
    const second = await create({
      clientId: a.id,
      redirectUri: 'https://m4-2.example.test/callback-secondary',
    });
    const relation = await prisma.client.findUniqueOrThrow({
      where: { id: a.id },
      include: { redirectUris: { orderBy: { redirectUri: 'asc' } } },
    });
    assert.deepEqual(relation.redirectUris, [first, second]);
    const backReference = await prisma.clientRedirectUri.findUniqueOrThrow({
      where: { id: first.id },
      include: { client: true },
    });
    assert.equal(backReference.client.id, a.id);
    assert.equal(backReference.client.clientId, clientIds[0]);
    await expectConstraint(
      () => create({ clientId: a.id, redirectUri: uri }),
      'P2002',
    );

    const sharedUri = 'https://shared.example.test/callback';
    await create({ clientId: a.id, redirectUri: sharedUri });
    await create({ clientId: b.id, redirectUri: sharedUri });
    assert.equal(
      await prisma.clientRedirectUri.count({
        where: { redirectUri: sharedUri, clientId: { in: [a.id, b.id] } },
      }),
      2,
    );
    const missingClientId = randomUUID();
    assert.equal(
      await prisma.client.count({ where: { id: missingClientId } }),
      0,
    );
    await expectConstraint(
      () =>
        create({
          id: orphanProbeId,
          clientId: missingClientId,
          redirectUri: uri,
        }),
      'P2003',
    );
    console.log(
      'Redirect URI generated types/Prisma UUID/zero-one-many relation/back-reference/same-client P2002/cross-client URI reuse/missing-parent P2003 passed.',
    );

    // Equality via the generated composite unique API only; no runtime matcher.
    const exactRead = (
      redirectUri: string,
    ): Promise<ClientRedirectUri | null> =>
      prisma.clientRedirectUri.findUnique({
        where: { clientId_redirectUri: { clientId: a.id, redirectUri } },
      });
    assert.deepEqual(await exactRead(uri), first);
    for (const candidate of [
      `${uri}/`,
      'https://m4-2.example.test/Callback',
      `${uri}?x=1`,
      'https://m4-2.example.test/call',
      `${uri}-suffix`,
      'https://m4-2.example.test/prefix/callback',
    ])
      assert.equal(await exactRead(candidate), null);
    const localUri = 'http://localhost:3200/callback';
    const localRow = await create({ clientId: a.id, redirectUri: localUri });
    assert.deepEqual(await exactRead(localUri), localRow);
    for (const candidate of [
      `${localUri}/`,
      `${localUri}?x=1`,
      'http://localhost:3200/Callback',
      'http://localhost:3200/call',
    ])
      assert.equal(await exactRead(candidate), null);
    // These intentionally unusual values test opaque storage, not registration policy.
    for (const value of [
      ` ${uri} `,
      'https://m4-2.example.test/CALLBACK',
      'HTTPS://M4-2.EXAMPLE.TEST:443/callback',
      'https://m4-2.example.test/call%62ack',
      `${uri}?b=2&a=1`,
      `${uri}?a=1&b=2`,
      'https://wildcard.example.test/*',
      'https://percent.example.test/%',
    ]) {
      assert.equal(await exactRead(value), null);
      const row = await create({ clientId: a.id, redirectUri: value });
      assert.equal(row.redirectUri, value);
      assert.deepEqual(await exactRead(value), row);
    }
    assert.equal(
      await exactRead('https://wildcard.example.test/anything'),
      null,
    );
    assert.equal(
      await exactRead('https://percent.example.test/anything'),
      null,
    );
    assert.deepEqual(await exactRead(uri), first);
    console.log(
      'Redirect URI exact equality/near-match rejection/case-whitespace-encoding-port-query round-trip/literal star and percent without expansion passed.',
    );
  } finally {
    try {
      if (cleanupAllowed) {
        const owners = await prisma.client.findMany({
          where: ownedClients,
          select: { id: true },
        });
        const ownedRedirects = {
          OR: [
            { clientId: { in: owners.map(({ id }) => id) } },
            { id: orphanProbeId },
          ],
        };
        await prisma.clientRedirectUri.deleteMany({ where: ownedRedirects });
        assert.equal(
          await prisma.clientRedirectUri.count({ where: ownedRedirects }),
          0,
        );
        await prisma.client.deleteMany({ where: ownedClients });
        assert.equal(await prisma.client.count({ where: ownedClients }), 0);
        assert.deepEqual(await snapshot(), before);
        console.log(
          'Redirect URI probe cleanup passed: zero owned redirect/Client rows; all pre-existing User/Credential/Session/Client/redirect rows unchanged.',
        );
      }
    } finally {
      await prisma.$disconnect();
    }
  }
}

void checkClientRedirectUris().catch(() => {
  // Never print assertions, driver causes, connection URLs or Client hash fields.
  console.error(
    'Client redirect URI persistence verification failed; inspect local development database configuration/schema and rerun.',
  );
  process.exitCode = 1;
});
