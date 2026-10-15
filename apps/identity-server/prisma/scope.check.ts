// Explicit local PostgreSQL verification only; never startup, seed or scope policy.
import 'dotenv/config';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { PrismaPg } from '@prisma/adapter-pg';
import {
  Prisma,
  PrismaClient,
  type ClientScope,
  type Scope,
} from '../src/generated/prisma/client.js';

async function checkScopes(): Promise<void> {
  const connectionString = process.env.DATABASE_URL?.trim();
  if (!connectionString) throw new Error('DATABASE_URL is required.');
  const url = new URL(connectionString);
  if (
    !['development', 'test'].includes(process.env.NODE_ENV ?? 'development') ||
    !['postgresql:', 'postgres:'].includes(url.protocol) ||
    !['localhost', '127.0.0.1', '[::1]'].includes(url.hostname)
  )
    throw new Error('Scope probe requires local development PostgreSQL.');

  const prisma = new PrismaClient({
    adapter: new PrismaPg({ connectionString, connectionTimeoutMillis: 5000 }),
  });
  const marker = `m4.3.scope-${randomUUID()}`;
  const clientIds = [`${marker}-client-a`, `${marker}-client-b`];
  const scopeNames = [
    `${marker}.alpha`,
    `${marker}.beta`,
    `${marker}.read`,
    `${marker}.Read`,
    `${marker}.read:detail`,
    ` ${marker}.read `,
    `${marker}.read write`,
    `${marker}.caf\u00e9`,
    `${marker}.cafe\u0301`,
  ];
  const ownedClients = { clientId: { in: clientIds } };
  const ownedScopes = { name: { in: scopeNames } };
  let cleanupAllowed = false;
  type Snapshot = { relation: string; count: number; fingerprint: string }[];
  let before: Snapshot | undefined;
  // Fingerprint complete rows inside PostgreSQL; never print rows or hashes.
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
    ORDER BY relation
  `;
  const createScope = (name: string): Promise<Scope> =>
    prisma.scope.create({ data: { name } });
  const assign = (clientId: string, scopeId: string): Promise<ClientScope> =>
    prisma.clientScope.create({ data: { clientId, scopeId } });
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
        tableName: string;
        name: string;
        type: string;
        nullable: string;
        defaultValue: string | null;
      }[]
    >`
      SELECT table_name::text AS "tableName", column_name::text AS name,
        udt_name::text AS type, is_nullable::text AS nullable, column_default AS "defaultValue"
      FROM information_schema.columns
      WHERE table_schema = 'public' AND table_name IN ('scopes', 'client_scopes')
      ORDER BY table_name, ordinal_position
    `;
    assert.deepEqual(columns, [
      {
        tableName: 'client_scopes',
        name: 'client_id',
        type: 'uuid',
        nullable: 'NO',
        defaultValue: null,
      },
      {
        tableName: 'client_scopes',
        name: 'scope_id',
        type: 'uuid',
        nullable: 'NO',
        defaultValue: null,
      },
      {
        tableName: 'scopes',
        name: 'id',
        type: 'uuid',
        nullable: 'NO',
        defaultValue: null,
      },
      {
        tableName: 'scopes',
        name: 'name',
        type: 'text',
        nullable: 'NO',
        defaultValue: null,
      },
    ]);
    const constraints = await prisma.$queryRaw<
      { tableName: string; kind: string; definition: string }[]
    >`
      SELECT cl.relname::text AS "tableName", c.contype::text AS kind,
        pg_get_constraintdef(c.oid) AS definition
      FROM pg_constraint c JOIN pg_class cl ON cl.oid = c.conrelid
      WHERE c.conrelid IN ('public.scopes'::regclass, 'public.client_scopes'::regclass)
        AND c.contype <> 'n' -- PostgreSQL 18 NOT NULL metadata is checked above.
      ORDER BY cl.relname, c.contype, pg_get_constraintdef(c.oid)
    `;
    assert.deepEqual(constraints, [
      {
        tableName: 'client_scopes',
        kind: 'f',
        definition:
          'FOREIGN KEY (client_id) REFERENCES clients(id) ON UPDATE CASCADE ON DELETE RESTRICT',
      },
      {
        tableName: 'client_scopes',
        kind: 'f',
        definition:
          'FOREIGN KEY (scope_id) REFERENCES scopes(id) ON UPDATE CASCADE ON DELETE RESTRICT',
      },
      {
        tableName: 'client_scopes',
        kind: 'p',
        definition: 'PRIMARY KEY (client_id, scope_id)',
      },
      { tableName: 'scopes', kind: 'p', definition: 'PRIMARY KEY (id)' },
    ]);
    const indexes = await prisma.$queryRaw<{ definition: string }[]>`
      SELECT indexdef AS definition FROM pg_indexes
      WHERE schemaname = 'public' AND tablename IN ('scopes', 'client_scopes')
      ORDER BY tablename, indexname
    `;
    assert.deepEqual(
      indexes.map(({ definition }) => definition),
      [
        'CREATE UNIQUE INDEX client_scopes_pkey ON public.client_scopes USING btree (client_id, scope_id)',
        'CREATE UNIQUE INDEX scopes_name_key ON public.scopes USING btree (name)',
        'CREATE UNIQUE INDEX scopes_pkey ON public.scopes USING btree (id)',
      ],
    );
    console.log(
      'Scope/ClientScope exact columns/types/NOT NULL/UUID PK/name unique/composite PK/internal UUID FKs/RESTRICT-CASCADE/no extra CHECK policies passed.',
    );

    before = await snapshot();
    assert.equal(await prisma.client.count({ where: ownedClients }), 0);
    assert.equal(await prisma.scope.count({ where: ownedScopes }), 0);
    cleanupAllowed = true;
    const a = await prisma.client.create({
      data: { clientId: clientIds[0], name: marker, clientType: 'PUBLIC' },
    });
    const b = await prisma.client.create({
      data: { clientId: clientIds[1], name: marker, clientType: 'PUBLIC' },
    });
    const alpha = await createScope(scopeNames[0]);
    const beta = await createScope(scopeNames[1]);
    assert.match(
      alpha.id,
      /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i,
    );
    assert.deepEqual(alpha, { id: alpha.id, name: scopeNames[0] });
    assert.deepEqual(
      (
        await prisma.client.findUniqueOrThrow({
          where: { id: a.id },
          include: { allowedScopes: true },
        })
      ).allowedScopes,
      [],
    );
    assert.deepEqual(
      (
        await prisma.scope.findUniqueOrThrow({
          where: { id: alpha.id },
          include: { clientScopes: true },
        })
      ).clientScopes,
      [],
    );
    await expectConstraint(() => createScope(alpha.name), 'P2002');

    const first = await assign(a.id, alpha.id);
    assert.deepEqual(first, { clientId: a.id, scopeId: alpha.id });
    assert.equal(
      (
        await prisma.client.findUniqueOrThrow({
          where: { id: a.id },
          include: { allowedScopes: true },
        })
      ).allowedScopes.length,
      1,
    );
    assert.equal(
      (
        await prisma.scope.findUniqueOrThrow({
          where: { id: alpha.id },
          include: { clientScopes: true },
        })
      ).clientScopes.length,
      1,
    );
    await assign(a.id, beta.id);
    await assign(b.id, alpha.id);
    const fromClient = await prisma.client.findUniqueOrThrow({
      where: { id: a.id },
      include: { allowedScopes: { include: { scope: true } } },
    });
    assert.deepEqual(
      fromClient.allowedScopes.map(({ scope }) => scope.name).sort(),
      [alpha.name, beta.name].sort(),
    );
    assert.ok(
      fromClient.allowedScopes.every(
        (link) => link.clientId === a.id && link.scopeId === link.scope.id,
      ),
    );
    const fromScope = await prisma.scope.findUniqueOrThrow({
      where: { id: alpha.id },
      include: { clientScopes: { include: { client: true } } },
    });
    assert.deepEqual(
      fromScope.clientScopes.map(({ client }) => client.clientId).sort(),
      [...clientIds].sort(),
    );
    assert.ok(
      fromScope.clientScopes.every(
        (link) => link.scopeId === alpha.id && link.clientId === link.client.id,
      ),
    );
    assert.deepEqual(
      await prisma.clientScope.findUniqueOrThrow({
        where: { clientId_scopeId: { clientId: a.id, scopeId: alpha.id } },
        include: { client: true, scope: true },
      }),
      { ...first, client: a, scope: alpha },
    );
    await expectConstraint(() => assign(a.id, alpha.id), 'P2002');
    const missingClientId = randomUUID();
    const missingScopeId = randomUUID();
    assert.equal(
      await prisma.client.count({ where: { id: missingClientId } }),
      0,
    );
    assert.equal(
      await prisma.scope.count({ where: { id: missingScopeId } }),
      0,
    );
    await expectConstraint(() => assign(missingClientId, alpha.id), 'P2003');
    await expectConstraint(() => assign(a.id, missingScopeId), 'P2003');
    console.log(
      'Scope/ClientScope generated types/Prisma UUID/zero-one-many relations both ways/unique name and assignment P2002/both missing-parent P2003 passed.',
    );

    // Opaque storage probes only: no parsing, splitting or scope-name policy.
    for (const name of scopeNames.slice(2)) {
      assert.equal(await prisma.scope.findUnique({ where: { name } }), null);
      const row = await createScope(name);
      assert.equal(row.name, name);
      assert.deepEqual(
        await prisma.scope.findUniqueOrThrow({ where: { name } }),
        row,
      );
    }
    assert.equal(
      await prisma.scope.count({ where: ownedScopes }),
      scopeNames.length,
    );
    console.log(
      'Scope exact name persistence passed: case/whitespace/colon/embedded space/composed and decomposed Unicode remain distinct unchanged text.',
    );
  } finally {
    try {
      if (cleanupAllowed) {
        const owners = await prisma.client.findMany({
          where: ownedClients,
          select: { id: true },
        });
        const scopes = await prisma.scope.findMany({
          where: ownedScopes,
          select: { id: true },
        });
        // Includes any unexpectedly successful FK probe through its owned parent.
        const ownedAssignments = {
          OR: [
            { clientId: { in: owners.map(({ id }) => id) } },
            { scopeId: { in: scopes.map(({ id }) => id) } },
          ],
        };
        await prisma.clientScope.deleteMany({ where: ownedAssignments });
        assert.equal(
          await prisma.clientScope.count({ where: ownedAssignments }),
          0,
        );
        await prisma.scope.deleteMany({ where: ownedScopes });
        await prisma.client.deleteMany({ where: ownedClients });
        assert.equal(await prisma.scope.count({ where: ownedScopes }), 0);
        assert.equal(await prisma.client.count({ where: ownedClients }), 0);
        assert.deepEqual(await snapshot(), before);
        console.log(
          'Scope probe cleanup passed: zero owned ClientScope/Scope/Client rows; all pre-existing User/Credential/Session/Client/redirect/Scope/ClientScope rows unchanged.',
        );
      }
    } finally {
      await prisma.$disconnect();
    }
  }
}

void checkScopes().catch(() => {
  // No assertion detail, driver cause, URL or Client hash field is exposed.
  console.error(
    'Scope persistence verification failed; inspect local development database configuration/schema and rerun.',
  );
  process.exitCode = 1;
});
