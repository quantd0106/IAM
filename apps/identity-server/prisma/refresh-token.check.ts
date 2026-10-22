// Explicit local persistence probe, not token generation/issuance/rotation.
// All owned fixtures, including arbitrary tokenHash text, are rolled back.
import 'dotenv/config';
import assert from 'node:assert/strict';
import { PrismaPg } from '@prisma/adapter-pg';
import { z } from 'zod';
import {
  Prisma,
  PrismaClient,
  RefreshTokenStatus,
  type RefreshToken,
} from '../src/generated/prisma/client.js';

type Snapshot = { relation: string; count: number; fingerprint: string }[];
// Full-row fingerprints remain in memory; never output rows, IDs or hashes.
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
  UNION ALL SELECT 'refresh_tokens', COUNT(*)::int,
    md5(COALESCE(jsonb_agg(to_jsonb(t) ORDER BY id)::text, '[]')) FROM refresh_tokens t
  UNION ALL SELECT '_prisma_migrations', COUNT(*)::int,
    md5(COALESCE(jsonb_agg(to_jsonb(t) ORDER BY id)::text, '[]')) FROM _prisma_migrations t
  ORDER BY relation
`;

async function checkTokens(): Promise<void> {
  const connectionString = process.env.DATABASE_URL?.trim();
  if (!connectionString) throw new Error('DATABASE_URL is required.');
  const url = new URL(connectionString);
  assert.ok(
    ['development', 'test'].includes(process.env.NODE_ENV ?? 'development') &&
      ['postgres:', 'postgresql:'].includes(url.protocol) &&
      ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname),
    'Token persistence probe requires local development PostgreSQL.',
  );
  const prisma = new PrismaClient({
    adapter: new PrismaPg({ connectionString, connectionTimeoutMillis: 5000 }),
  });
  const rollback = new Error('Rollback owned token persistence fixtures.');
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
      WHERE table_schema='public' AND table_name='refresh_tokens'
      ORDER BY ordinal_position
    `;
    assert.deepEqual(columns, [
      { name: 'id', type: 'uuid', nullable: 'NO', defaultValue: null },
      { name: 'family_id', type: 'uuid', nullable: 'NO', defaultValue: null },
      { name: 'token_hash', type: 'text', nullable: 'NO', defaultValue: null },
      {
        name: 'parent_token_id',
        type: 'uuid',
        nullable: 'YES',
        defaultValue: null,
      },
      {
        name: 'status',
        type: 'RefreshTokenStatus',
        nullable: 'NO',
        defaultValue: '\'ACTIVE\'::"RefreshTokenStatus"',
      },
      {
        name: 'issued_at',
        type: 'timestamp',
        nullable: 'NO',
        defaultValue: 'CURRENT_TIMESTAMP',
      },
      {
        name: 'expires_at',
        type: 'timestamp',
        nullable: 'NO',
        defaultValue: null,
      },
      {
        name: 'consumed_at',
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
    ]);
    const forbidden = [
      'raw_token',
      'rawToken',
      'refresh_token',
      'refreshToken',
      'token',
      'secret',
      'plaintext_token',
      'user_id',
      'client_id',
      'session_id',
      'replaced_by_token_id',
    ];
    assert.ok(
      !columns.some((column) => forbidden.includes(column.name)),
      'No raw-token column, duplicated binding or redundant lineage is allowed.',
    );
    const enums = await prisma.$queryRaw<{ label: string }[]>`
      SELECT e.enumlabel::text AS label FROM pg_enum e
      JOIN pg_type t ON t.oid=e.enumtypid JOIN pg_namespace n ON n.oid=t.typnamespace
      WHERE n.nspname='public' AND t.typname='RefreshTokenStatus'
      ORDER BY e.enumsortorder
    `;
    assert.deepEqual(
      enums.map((row) => row.label),
      ['ACTIVE', 'CONSUMED', 'REVOKED'],
    );
    assert.deepEqual(Object.values(RefreshTokenStatus), [
      'ACTIVE',
      'CONSUMED',
      'REVOKED',
    ]);
    const constraints = await prisma.$queryRaw<{ definition: string }[]>`
      SELECT pg_get_constraintdef(oid) AS definition FROM pg_constraint
      WHERE conrelid='public.refresh_tokens'::regclass AND contype <> 'n'
      ORDER BY pg_get_constraintdef(oid)
    `;
    assert.deepEqual(
      constraints.map((row) => row.definition),
      [
        'FOREIGN KEY (family_id) REFERENCES refresh_token_families(id) ON UPDATE CASCADE ON DELETE RESTRICT',
        'FOREIGN KEY (parent_token_id) REFERENCES refresh_tokens(id) ON UPDATE CASCADE ON DELETE RESTRICT',
        'PRIMARY KEY (id)',
      ],
    );
    const indexes = await prisma.$queryRaw<{ definition: string }[]>`
      SELECT indexdef AS definition FROM pg_indexes
      WHERE schemaname='public' AND tablename='refresh_tokens' ORDER BY indexname
    `;
    assert.deepEqual(
      indexes.map((row) => row.definition),
      [
        'CREATE INDEX refresh_tokens_family_id_issued_at_idx ON public.refresh_tokens USING btree (family_id, issued_at)',
        'CREATE INDEX refresh_tokens_family_id_status_idx ON public.refresh_tokens USING btree (family_id, status)',
        'CREATE UNIQUE INDEX refresh_tokens_parent_token_id_key ON public.refresh_tokens USING btree (parent_token_id)',
        'CREATE UNIQUE INDEX refresh_tokens_pkey ON public.refresh_tokens USING btree (id)',
        'CREATE UNIQUE INDEX refresh_tokens_token_hash_key ON public.refresh_tokens USING btree (token_hash)',
      ],
    );
    before = await snapshot(prisma);
    try {
      await prisma.$transaction(
        async (tx) => {
          // Unique fixture label only, not a random credential or a hash encoding.
          const marker = 'm82-' + process.pid + '-' + Date.now();
          const user = await tx.user.create({
            data: { email: marker + '@example.invalid', username: marker },
          });
          const client = await tx.client.create({
            data: { clientId: marker, name: marker, clientType: 'PUBLIC' },
          });
          const expiresAt = new Date('2100-01-01T00:00:00.000Z');
          const session = await tx.session.create({
            data: { userId: user.id, expiresAt },
          });
          const bindings = {
            userId: user.id,
            clientId: client.id,
            sessionId: session.id,
          };
          const family = await tx.refreshTokenFamily.create({ data: bindings });
          const initial: RefreshToken = await tx.refreshToken.create({
            data: {
              familyId: family.id,
              tokenHash: marker + '-root',
              expiresAt,
            },
          });
          assert.deepEqual(Object.keys(initial).sort(), [
            'consumedAt',
            'expiresAt',
            'familyId',
            'id',
            'issuedAt',
            'parentTokenId',
            'revokedAt',
            'status',
            'tokenHash',
          ]);
          assert.ok(
            z.uuid().safeParse(initial.id).success &&
              initial.familyId === family.id &&
              initial.parentTokenId === null &&
              initial.status === RefreshTokenStatus.ACTIVE &&
              initial.consumedAt === null &&
              initial.revokedAt === null &&
              initial.issuedAt instanceof Date &&
              Number.isFinite(initial.issuedAt.getTime()) &&
              initial.expiresAt.getTime() === expiresAt.getTime(),
            'Initial token persistence defaults mismatch.',
          );
          // Direct state fixtures only: no transition, consumption or rotation service.
          const eventAt = new Date();
          const second = await tx.refreshToken.create({
            data: {
              familyId: family.id,
              tokenHash: marker + '-child',
              parentTokenId: initial.id,
              status: RefreshTokenStatus.CONSUMED,
              consumedAt: eventAt,
              expiresAt,
            },
          });
          const third = await tx.refreshToken.create({
            data: {
              familyId: family.id,
              tokenHash: marker + '-grandchild',
              parentTokenId: second.id,
              status: RefreshTokenStatus.REVOKED,
              revokedAt: eventAt,
              expiresAt,
            },
          });
          assert.ok(
            second.status === RefreshTokenStatus.CONSUMED &&
              second.consumedAt?.getTime() === eventAt.getTime() &&
              second.revokedAt === null &&
              third.status === RefreshTokenStatus.REVOKED &&
              third.consumedAt === null &&
              third.revokedAt?.getTime() === eventAt.getTime(),
          );
          // Read one relation per awaited query: no parallel relation queries on
          // the driver's single interactive-transaction connection.
          for (const link of [
            { id: initial.id, parent: null, child: second.id },
            { id: second.id, parent: initial.id, child: third.id },
            { id: third.id, parent: second.id, child: null },
          ]) {
            const parent = await tx.refreshToken.findUniqueOrThrow({
              where: { id: link.id },
              select: { parent: { select: { id: true } } },
            });
            const child = await tx.refreshToken.findUniqueOrThrow({
              where: { id: link.id },
              select: { child: { select: { id: true } } },
            });
            assert.ok(
              (parent.parent?.id ?? null) === link.parent &&
                (child.child?.id ?? null) === link.child,
              'Generated parent/child relations must match owned lineage.',
            );
          }
          const root = await tx.refreshToken.findUniqueOrThrow({
            where: { id: initial.id },
            select: { family: true },
          });
          assert.ok(
            root.family.id === family.id &&
              root.family.userId === user.id &&
              root.family.clientId === client.id &&
              root.family.sessionId === session.id,
            'Generated family and parent/child relations must match owned lineage.',
          );
          const withTokens = await tx.refreshTokenFamily.findUniqueOrThrow({
            where: { id: family.id },
            select: { tokens: { select: { id: true } } },
          });
          assert.ok(
            JSON.stringify(withTokens.tokens.map((row) => row.id).sort()) ===
              JSON.stringify([initial.id, second.id, third.id].sort()),
          );
          const otherFamily = await tx.refreshTokenFamily.create({
            data: bindings,
          });
          const otherRoot = await tx.refreshToken.create({
            data: {
              familyId: otherFamily.id,
              tokenHash: marker + '-other-root',
              expiresAt,
            },
          });
          const sameFamilyRoot = await tx.refreshToken.create({
            data: {
              familyId: family.id,
              tokenHash: marker + '-same-family-root',
              expiresAt,
            },
          });
          assert.ok(
            otherRoot.parentTokenId === null &&
              sameFamilyRoot.parentTokenId === null &&
              (await tx.refreshToken.count({
                where: {
                  familyId: { in: [family.id, otherFamily.id] },
                  parentTokenId: null,
                },
              })) === 3,
            'Nullable unique parent permits multiple roots, including in one family.',
          );
          const rejectConstraint = async (
            code: 'P2002' | 'P2003',
            operation: () => Promise<unknown>,
          ): Promise<void> => {
            await tx.$executeRaw`SAVEPOINT m82_expected_constraint`;
            let rejected = false;
            try {
              await operation();
            } catch (error) {
              await tx.$executeRaw`ROLLBACK TO SAVEPOINT m82_expected_constraint`;
              if (
                !(error instanceof Prisma.PrismaClientKnownRequestError) ||
                error.code !== code
              )
                throw error; // Suppressed by the fixed top-level failure boundary.
              rejected = true;
            } finally {
              await tx.$executeRaw`RELEASE SAVEPOINT m82_expected_constraint`;
            }
            assert.ok(rejected, 'Expected database constraint rejection.');
          };
          await rejectConstraint('P2002', () =>
            tx.refreshToken.create({
              data: {
                familyId: otherFamily.id,
                tokenHash: initial.tokenHash,
                expiresAt,
              },
            }),
          );
          await rejectConstraint('P2002', () =>
            tx.refreshToken.create({
              data: {
                familyId: family.id,
                tokenHash: marker + '-fork',
                parentTokenId: initial.id,
                expiresAt,
              },
            }),
          );
          // Fixed missing reference, verified absent before each negative FK test.
          const missing = '00000000-0000-4000-8000-000000000000';
          assert.ok(
            (await tx.refreshTokenFamily.count({ where: { id: missing } })) ===
              0 &&
              (await tx.refreshToken.count({ where: { id: missing } })) === 0,
          );
          await rejectConstraint('P2003', () =>
            tx.refreshToken.create({
              data: {
                familyId: missing,
                tokenHash: marker + '-missing-family',
                expiresAt,
              },
            }),
          );
          await rejectConstraint('P2003', () =>
            tx.refreshToken.create({
              data: {
                familyId: family.id,
                tokenHash: marker + '-missing-parent',
                parentTokenId: missing,
                expiresAt,
              },
            }),
          );
          await rejectConstraint('P2003', () =>
            tx.refreshTokenFamily.delete({ where: { id: family.id } }),
          );
          await rejectConstraint('P2003', () =>
            tx.refreshToken.delete({ where: { id: initial.id } }),
          );
          assert.ok(
            (await tx.refreshToken.count({
              where: { familyId: { in: [family.id, otherFamily.id] } },
            })) === 5 &&
              (await tx.refreshTokenFamily.count({
                where: { id: { in: [family.id, otherFamily.id] } },
              })) === 2,
            'Constraint failures must preserve owned families and lineage.',
          );
          completed = true;
          throw rollback;
        },
        { timeout: 15000 },
      );
    } catch (error) {
      if (error !== rollback) throw error;
    }
    assert.ok(completed, 'Token persistence probe did not complete.');
  } finally {
    try {
      if (before !== undefined)
        assert.ok(
          JSON.stringify(await snapshot(prisma)) === JSON.stringify(before),
          'All owned fixtures must roll back; ten table fingerprints must remain unchanged.',
        );
    } finally {
      await prisma.$disconnect();
    }
  }
  console.log(
    'M8.2 token persistence check passed: exact nine fields/enum/defaults/UUID/normalized family; no raw-token columns; family and three-token lineage relations; globally unique hash, one child per parent, multiple NULL roots; restrictive family/parent FKs and deletes; ACTIVE/CONSUMED/REVOKED persistence. All fixtures rolled back; ten table fingerprints unchanged; no token generation, hashing, runtime transitions or sensitive output.',
  );
}

void checkTokens().catch(() => {
  console.error(
    'Refresh-token persistence check failed (private details suppressed). Verify local database configuration/migration; all fixtures use transaction rollback.',
  );
  process.exitCode = 1;
});
