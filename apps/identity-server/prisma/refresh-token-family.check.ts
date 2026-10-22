// Explicit local PostgreSQL schema probe. All owned fixtures are rolled back.
import 'dotenv/config';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { PrismaPg } from '@prisma/adapter-pg';
import { z } from 'zod';
import {
  Prisma,
  PrismaClient,
  RefreshTokenFamilyStatus,
  type RefreshTokenFamily,
} from '../src/generated/prisma/client.js';

type Snapshot = { relation: string; count: number; fingerprint: string }[];
// Compute full-row fingerprints inside PostgreSQL; never print rows or hashes.
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
  UNION ALL SELECT 'refresh_token_families', COUNT(*)::int,
    md5(COALESCE(jsonb_agg(to_jsonb(t) ORDER BY id)::text, '[]')) FROM refresh_token_families t
  UNION ALL SELECT '_prisma_migrations', COUNT(*)::int,
    md5(COALESCE(jsonb_agg(to_jsonb(t) ORDER BY id)::text, '[]')) FROM _prisma_migrations t
  ORDER BY relation
`;

async function checkFamilies(): Promise<void> {
  const connectionString = process.env.DATABASE_URL?.trim();
  if (!connectionString) throw new Error('DATABASE_URL is required.');
  const url = new URL(connectionString);
  assert.ok(
    ['development', 'test'].includes(process.env.NODE_ENV ?? 'development') &&
      ['postgres:', 'postgresql:'].includes(url.protocol) &&
      ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname),
    'Family probe requires local development PostgreSQL.',
  );
  const prisma = new PrismaClient({
    adapter: new PrismaPg({ connectionString, connectionTimeoutMillis: 5000 }),
  });
  const rollback = new Error('Rollback owned family fixtures.');
  let before: Snapshot | undefined;
  let completed = false;
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
      WHERE table_schema='public' AND table_name='refresh_token_families'
      ORDER BY ordinal_position
    `;
    assert.ok(
      JSON.stringify(columns) ===
        JSON.stringify([
          { name: 'id', type: 'uuid', nullable: 'NO', defaultValue: null },
          { name: 'user_id', type: 'uuid', nullable: 'NO', defaultValue: null },
          {
            name: 'client_id',
            type: 'uuid',
            nullable: 'NO',
            defaultValue: null,
          },
          {
            name: 'session_id',
            type: 'uuid',
            nullable: 'NO',
            defaultValue: null,
          },
          {
            name: 'status',
            type: 'RefreshTokenFamilyStatus',
            nullable: 'NO',
            defaultValue: '\'ACTIVE\'::"RefreshTokenFamilyStatus"',
          },
          {
            name: 'reuse_detected_at',
            type: 'timestamp',
            nullable: 'YES',
            defaultValue: null,
          },
          {
            name: 'revoked_at',
            type: 'timestamp',
            nullable: 'YES',
            defaultValue: null,
          },
          {
            name: 'created_at',
            type: 'timestamp',
            nullable: 'NO',
            defaultValue: 'CURRENT_TIMESTAMP',
          },
        ]),
      'Family must expose exactly the eight intended columns/defaults.',
    );
    const enums = await prisma.$queryRaw<{ label: string }[]>`
      SELECT e.enumlabel::text AS label FROM pg_enum e
      JOIN pg_type t ON t.oid=e.enumtypid JOIN pg_namespace n ON n.oid=t.typnamespace
      WHERE n.nspname='public' AND t.typname='RefreshTokenFamilyStatus'
      ORDER BY e.enumsortorder
    `;
    assert.deepEqual(
      enums.map((row) => row.label),
      ['ACTIVE', 'REVOKED'],
    );
    assert.deepEqual(Object.values(RefreshTokenFamilyStatus), [
      'ACTIVE',
      'REVOKED',
    ]);
    const constraints = await prisma.$queryRaw<{ definition: string }[]>`
      SELECT pg_get_constraintdef(oid) AS definition FROM pg_constraint
      WHERE conrelid='public.refresh_token_families'::regclass AND contype <> 'n'
      ORDER BY pg_get_constraintdef(oid)
    `;
    assert.deepEqual(
      constraints.map((row) => row.definition),
      [
        'FOREIGN KEY (client_id) REFERENCES clients(id) ON UPDATE CASCADE ON DELETE RESTRICT',
        'FOREIGN KEY (session_id) REFERENCES sessions(id) ON UPDATE CASCADE ON DELETE RESTRICT',
        'FOREIGN KEY (user_id) REFERENCES users(id) ON UPDATE CASCADE ON DELETE RESTRICT',
        'PRIMARY KEY (id)',
      ],
    );
    const indexes = await prisma.$queryRaw<{ definition: string }[]>`
      SELECT indexdef AS definition FROM pg_indexes
      WHERE schemaname='public' AND tablename='refresh_token_families' ORDER BY indexname
    `;
    assert.deepEqual(
      indexes.map((row) => row.definition),
      [
        'CREATE INDEX refresh_token_families_client_id_status_idx ON public.refresh_token_families USING btree (client_id, status)',
        'CREATE UNIQUE INDEX refresh_token_families_pkey ON public.refresh_token_families USING btree (id)',
        'CREATE INDEX refresh_token_families_session_id_status_idx ON public.refresh_token_families USING btree (session_id, status)',
        'CREATE INDEX refresh_token_families_user_id_status_idx ON public.refresh_token_families USING btree (user_id, status)',
      ],
    );
    const future = await prisma.$queryRaw<{ absent: boolean }[]>`
      SELECT to_regclass('public.refresh_tokens') IS NULL AND
        to_regtype('public."RefreshTokenStatus"') IS NULL AS absent
    `;
    assert.ok(
      future.length === 1 && future[0].absent,
      'M8.2 objects must not exist.',
    );
    before = await snapshot(prisma);
    try {
      await prisma.$transaction(
        async (tx) => {
          const marker = 'm81-' + randomUUID();
          const user = await tx.user.create({
            data: { email: marker + '@example.invalid', username: marker },
          });
          const client = await tx.client.create({
            data: { clientId: marker, name: marker, clientType: 'PUBLIC' },
          });
          const session = await tx.session.create({
            data: { userId: user.id, expiresAt: new Date(Date.now() + 60000) },
          });
          const bindings = {
            userId: user.id,
            clientId: client.id,
            sessionId: session.id,
          };
          const first: RefreshTokenFamily = await tx.refreshTokenFamily.create({
            data: bindings,
          });
          assert.ok(
            z.uuid().safeParse(first.id).success &&
              first.clientId === client.id &&
              first.clientId !== client.clientId,
          );
          assert.deepEqual(Object.keys(first).sort(), [
            'clientId',
            'createdAt',
            'id',
            'reuseDetectedAt',
            'revokedAt',
            'sessionId',
            'status',
            'userId',
          ]);
          assert.ok(
            first.status === RefreshTokenFamilyStatus.ACTIVE &&
              first.reuseDetectedAt === null &&
              first.revokedAt === null &&
              first.createdAt instanceof Date &&
              Number.isFinite(first.createdAt.getTime()),
          );
          const second = await tx.refreshTokenFamily.create({ data: bindings });
          assert.ok(
            first.id !== second.id &&
              (await tx.refreshTokenFamily.count({ where: bindings })) === 2,
            'Same user/client/session must allow multiple families.',
          );
          // Persistence-only fixture, not an implemented revocation transition/service.
          const time = new Date('2026-01-01T00:00:00.000Z');
          const revoked = await tx.refreshTokenFamily.create({
            data: {
              ...bindings,
              status: RefreshTokenFamilyStatus.REVOKED,
              reuseDetectedAt: time,
              revokedAt: time,
            },
          });
          assert.ok(
            revoked.status === RefreshTokenFamilyStatus.REVOKED &&
              revoked.reuseDetectedAt?.getTime() === time.getTime() &&
              revoked.revokedAt?.getTime() === time.getTime(),
          );
          const ids = [first.id, second.id, revoked.id].sort();
          for (const families of [
            (
              await tx.user.findUniqueOrThrow({
                where: { id: user.id },
                select: { refreshTokenFamilies: { select: { id: true } } },
              })
            ).refreshTokenFamilies,
            (
              await tx.client.findUniqueOrThrow({
                where: { id: client.id },
                select: { refreshTokenFamilies: { select: { id: true } } },
              })
            ).refreshTokenFamilies,
            (
              await tx.session.findUniqueOrThrow({
                where: { id: session.id },
                select: { refreshTokenFamilies: { select: { id: true } } },
              })
            ).refreshTokenFamilies,
          ])
            assert.ok(
              JSON.stringify(families.map((row) => row.id).sort()) ===
                JSON.stringify(ids),
              'Generated parent back-relation mismatch.',
            );

          const rejectForeignKey = async (
            operation: () => Promise<unknown>,
          ): Promise<void> => {
            // PostgreSQL errors abort a transaction; recover only this expected test
            // statement through a fixed savepoint, preserving the outer rollback.
            await tx.$executeRaw`SAVEPOINT m81_expected_fk`;
            let rejected = false;
            try {
              await operation();
            } catch (error) {
              await tx.$executeRaw`ROLLBACK TO SAVEPOINT m81_expected_fk`;
              if (
                !(error instanceof Prisma.PrismaClientKnownRequestError) ||
                error.code !== 'P2003'
              )
                throw error; // The top-level probe boundary suppresses all private details.
              rejected = true;
            } finally {
              await tx.$executeRaw`RELEASE SAVEPOINT m81_expected_fk`;
            }
            assert.ok(rejected, 'Foreign-key operation must be rejected.');
          };
          const missing = randomUUID();
          assert.ok(
            (await tx.user.count({ where: { id: missing } })) === 0 &&
              (await tx.client.count({ where: { id: missing } })) === 0 &&
              (await tx.session.count({ where: { id: missing } })) === 0,
          );
          for (const field of ['userId', 'clientId', 'sessionId'] as const)
            await rejectForeignKey(() =>
              tx.refreshTokenFamily.create({
                data: { ...bindings, [field]: missing },
              }),
            );
          await rejectForeignKey(() =>
            tx.user.delete({ where: { id: user.id } }),
          );
          await rejectForeignKey(() =>
            tx.client.delete({ where: { id: client.id } }),
          );
          await rejectForeignKey(() =>
            tx.session.delete({ where: { id: session.id } }),
          );
          assert.equal(
            await tx.refreshTokenFamily.count({ where: bindings }),
            3,
            'Rejected deletes must preserve all family records.',
          );
          completed = true;
          throw rollback;
        },
        { timeout: 15000 },
      );
    } catch (error) {
      if (error !== rollback) throw error;
    }
    assert.ok(completed, 'Family integrity probe did not complete.');
  } finally {
    try {
      if (before !== undefined)
        assert.ok(
          JSON.stringify(await snapshot(prisma)) === JSON.stringify(before),
          'Family fixtures must roll back; all nine table fingerprints must remain unchanged.',
        );
    } finally {
      await prisma.$disconnect();
    }
  }
  console.log(
    'M8.1 family persistence check passed: exact eight fields/enum/defaults/UUID PK/three nonunique FK-status indexes; three required restrictive FKs and parent back-relations; duplicate bindings allowed, nonexistent references and parent deletes rejected. Owned fixtures rolled back; nine table fingerprints unchanged; no individual tokens, runtime refresh behavior or sensitive values printed.',
  );
}

void checkFamilies().catch(() => {
  console.error(
    'Refresh-token family persistence check failed (private details suppressed). Verify local database configuration/migration; all fixtures use transaction rollback.',
  );
  process.exitCode = 1;
});
