// Explicit local persistence verification, not part of seed/startup/unit tests.
// Run from this package: pnpm exec tsx prisma/session.check.ts
import 'dotenv/config';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { setTimeout } from 'node:timers/promises';
import { PrismaPg } from '@prisma/adapter-pg';
import { Prisma, PrismaClient } from '../src/generated/prisma/client.js';
import { PasswordService } from '../src/security/password/password.service.js';

async function checkSessions(): Promise<void> {
  const connectionString = process.env.DATABASE_URL?.trim();
  if (!connectionString) throw new Error('DATABASE_URL is required.');
  const prisma = new PrismaClient({
    adapter: new PrismaPg({ connectionString, connectionTimeoutMillis: 5000 }),
  });
  const userIds: string[] = [];
  const sessionIds: string[] = [];
  const marker = `m3.1-check-${randomUUID()}`;
  const expiresAt = new Date('2030-01-02T03:04:05.123Z');

  async function createUser(data: Prisma.UserCreateInput) {
    const user = await prisma.user.create({ data });
    userIds.push(user.id);
    return user;
  }
  async function createSession(data: Prisma.SessionUncheckedCreateInput) {
    const session = await prisma.session.create({ data });
    sessionIds.push(session.id);
    return session;
  }
  async function expectConstraint(
    operation: () => Promise<unknown>,
    code: 'P2002' | 'P2003',
  ): Promise<void> {
    let rejected = false;
    try {
      await operation();
    } catch (error) {
      assert.ok(error instanceof Prisma.PrismaClientKnownRequestError);
      assert.equal(error.code, code);
      rejected = true;
    }
    assert.ok(rejected, 'Expected database constraint rejection.');
  }

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
      SELECT column_name::text AS name, udt_name::text AS type, is_nullable::text AS nullable,
             column_default AS "defaultValue"
      FROM information_schema.columns
      WHERE table_schema = 'public' AND table_name = 'sessions'
      ORDER BY ordinal_position
    `;
    assert.deepEqual(
      columns.map((column) => column.name),
      [
        'id',
        'user_id',
        'status',
        'ip_address',
        'user_agent',
        'created_at',
        'last_activity_at',
        'expires_at',
      ],
    );
    for (const column of columns) {
      assert.equal(
        column.nullable,
        ['ip_address', 'user_agent'].includes(column.name) ? 'YES' : 'NO',
      );
      assert.equal(
        column.type,
        ['id', 'user_id'].includes(column.name)
          ? 'uuid'
          : ['ip_address', 'user_agent'].includes(column.name)
            ? 'text'
            : column.name === 'status'
              ? 'SessionStatus'
              : 'timestamp',
      );
    }
    assert.equal(
      columns.find((column) => column.name === 'expires_at')?.defaultValue,
      null,
    );
    assert.ok(
      columns
        .find((column) => column.name === 'status')
        ?.defaultValue?.includes('ACTIVE'),
    );
    for (const name of ['created_at', 'last_activity_at'])
      assert.equal(
        columns.find((column) => column.name === name)?.defaultValue,
        'CURRENT_TIMESTAMP',
      );

    const constraints = await prisma.$queryRaw<
      { kind: string; definition: string }[]
    >`
      SELECT contype::text AS kind, pg_get_constraintdef(oid) AS definition
      FROM pg_constraint WHERE conrelid = 'public.sessions'::regclass
        AND contype IN ('p', 'f', 'u')
    `;
    assert.deepEqual(constraints.map((item) => item.kind).sort(), ['f', 'p']);
    assert.ok(
      constraints.some((item) => item.definition === 'PRIMARY KEY (id)'),
    );
    assert.ok(
      constraints.some(
        (item) =>
          item.definition ===
          'FOREIGN KEY (user_id) REFERENCES users(id) ON UPDATE CASCADE ON DELETE RESTRICT',
      ),
    );
    const indexes = await prisma.$queryRaw<{ definition: string }[]>`
      SELECT indexdef AS definition FROM pg_indexes
      WHERE schemaname = 'public' AND tablename = 'sessions'
    `;
    assert.equal(indexes.length, 2);
    assert.ok(
      indexes.some((item) =>
        /^CREATE INDEX .*\(user_id\)$/.test(item.definition),
      ),
    );
    const statuses = await prisma.$queryRaw<{ label: string }[]>`
      SELECT e.enumlabel::text AS label FROM pg_enum e JOIN pg_type t ON t.oid = e.enumtypid
      JOIN pg_namespace n ON n.oid = t.typnamespace
      WHERE n.nspname = 'public' AND t.typname = 'SessionStatus'
      ORDER BY e.enumsortorder
    `;
    assert.deepEqual(
      statuses.map((item) => item.label),
      ['ACTIVE', 'REVOKED'],
    );
    console.log(
      'Session PostgreSQL columns/defaults/enum/PK/FK/non-unique user index passed.',
    );

    const user = await createUser({
      email: `${marker}@example.invalid`,
      username: marker,
    });
    assert.match(
      user.id,
      /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i,
    );
    assert.equal(user.status, 'ACTIVE');
    assert.equal(user.lockedUntil, null);
    assert.ok(user.createdAt instanceof Date && user.updatedAt instanceof Date);

    const first = await createSession({ userId: user.id, expiresAt });
    assert.match(
      first.id,
      /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i,
    );
    assert.equal(first.status, 'ACTIVE');
    assert.equal(first.ipAddress, null);
    assert.equal(first.userAgent, null);
    assert.ok(
      first.createdAt instanceof Date && first.lastActivityAt instanceof Date,
    );
    assert.equal(first.expiresAt.getTime(), expiresAt.getTime());
    const second = await createSession({
      userId: user.id,
      expiresAt,
      ipAddress: null,
      userAgent: null,
    });
    assert.notEqual(first.id, second.id);
    const third = await createSession({
      userId: user.id,
      expiresAt,
      status: 'REVOKED',
      ipAddress: '203.0.113.10',
      userAgent: 'iam-m3.1-test-agent',
    });
    assert.equal(third.status, 'REVOKED');
    assert.equal(third.ipAddress, '203.0.113.10');
    assert.equal(third.userAgent, 'iam-m3.1-test-agent');
    const relation = await prisma.session.findUniqueOrThrow({
      where: { id: first.id },
      include: { user: true },
    });
    assert.equal(relation.user.id, user.id);
    const owner = await prisma.user.findUniqueOrThrow({
      where: { id: user.id },
      include: { sessions: true },
    });
    assert.equal(owner.sessions.length, 3);
    await expectConstraint(
      () => createSession({ userId: randomUUID(), expiresAt }),
      'P2003',
    );

    let missingExpiryRejected = false;
    try {
      await createSession({
        userId: user.id,
      } as Prisma.SessionUncheckedCreateInput);
    } catch (error) {
      assert.ok(error instanceof Prisma.PrismaClientValidationError);
      missingExpiryRejected = true;
    }
    assert.ok(missingExpiryRejected, 'expiresAt must be supplied explicitly.');
    await setTimeout(10);
    const statusUpdate = await prisma.session.update({
      where: { id: first.id },
      data: { status: 'REVOKED' },
    });
    assert.equal(
      statusUpdate.lastActivityAt.getTime(),
      first.lastActivityAt.getTime(),
    );
    assert.equal(statusUpdate.createdAt.getTime(), first.createdAt.getTime());
    const lastActivityAt = new Date(first.lastActivityAt.getTime() + 1000);
    const activityUpdate = await prisma.session.update({
      where: { id: first.id },
      data: { lastActivityAt },
    });
    assert.equal(
      activityUpdate.lastActivityAt.getTime(),
      lastActivityAt.getTime(),
    );
    assert.equal(activityUpdate.expiresAt.getTime(), expiresAt.getTime());
    console.log(
      'Session UUID/default ACTIVE/multiple ownership/REVOKED/metadata/required expiry/explicit activity passed.',
    );

    // Existing User/Credential contract remains independent of Session persistence.
    await expectConstraint(
      () =>
        createUser({
          email: user.email,
          username: `${marker}-duplicate-email`,
        }),
      'P2002',
    );
    await expectConstraint(
      () =>
        createUser({
          email: `${marker}-duplicate-username@example.invalid`,
          username: user.username,
        }),
      'P2002',
    );
    const passwordHash = await new PasswordService().hash(
      'm3.1 test-only password',
    );
    const credential = await prisma.credential.create({
      data: { userId: user.id, passwordHash },
    });
    assert.ok(credential.passwordHash === passwordHash);
    assert.ok(credential.passwordUpdatedAt instanceof Date);
    await expectConstraint(
      () =>
        prisma.credential.create({ data: { userId: user.id, passwordHash } }),
      'P2002',
    );
    await expectConstraint(
      () =>
        prisma.credential.create({
          data: { userId: randomUUID(), passwordHash },
        }),
      'P2003',
    );
    const credentialUpdate = await prisma.credential.update({
      where: { id: credential.id },
      data: { passwordHash },
    });
    assert.equal(
      credentialUpdate.passwordUpdatedAt.getTime(),
      credential.passwordUpdatedAt.getTime(),
    );
    const passwordUpdatedAt = new Date(
      credential.passwordUpdatedAt.getTime() + 1000,
    );
    const timestampUpdate = await prisma.credential.update({
      where: { id: credential.id },
      data: { passwordUpdatedAt },
    });
    assert.equal(
      timestampUpdate.passwordUpdatedAt.getTime(),
      passwordUpdatedAt.getTime(),
    );
    const lockedUntil = new Date(Date.now() + 60000);
    const disabled = await prisma.user.update({
      where: { id: user.id },
      data: { status: 'DISABLED', lockedUntil },
    });
    assert.equal(disabled.status, 'DISABLED');
    assert.equal(disabled.lockedUntil?.getTime(), lockedUntil.getTime());
    assert.ok(disabled.updatedAt.getTime() > user.updatedAt.getTime());
    const ownerWithCredential = await prisma.user.findUniqueOrThrow({
      where: { id: user.id },
      include: { credential: true, sessions: true },
    });
    assert.equal(ownerWithCredential.credential?.id, credential.id);
    assert.equal(ownerWithCredential.sessions.length, 3);
    console.log(
      'User UUID/identity uniqueness/status/lock/timestamps and Credential uniqueness/FK/hash-only/timestamps passed.',
    );
  } finally {
    try {
      // Every successful create is recorded, including unexpected constraint successes.
      // Delete only this probe's rows, in FK-safe order; preserve all unrelated data.
      await prisma.session.deleteMany({
        where: {
          OR: [{ userId: { in: userIds } }, { id: { in: sessionIds } }],
        },
      });
      await prisma.credential.deleteMany({
        where: { userId: { in: userIds } },
      });
      await prisma.user.deleteMany({ where: { id: { in: userIds } } });
      assert.equal(
        await prisma.session.count({
          where: {
            OR: [{ userId: { in: userIds } }, { id: { in: sessionIds } }],
          },
        }),
        0,
      );
      assert.equal(
        await prisma.user.count({ where: { id: { in: userIds } } }),
        0,
      );
      const orphans = await prisma.$queryRaw<{ count: number }[]>`
        SELECT COUNT(*)::int AS count FROM sessions s LEFT JOIN users u ON s.user_id = u.id
        WHERE u.id IS NULL
      `;
      assert.equal(orphans[0].count, 0);
      console.log(
        'Session probe cleanup passed: no temporary Sessions/Users or orphan Sessions.',
      );
    } finally {
      await prisma.$disconnect();
    }
  }
}

void checkSessions().catch(() => {
  // Do not print driver errors, connection URLs or synthetic password hashes.
  console.error(
    'Session persistence verification failed; inspect local database availability/schema and rerun.',
  );
  process.exitCode = 1;
});
