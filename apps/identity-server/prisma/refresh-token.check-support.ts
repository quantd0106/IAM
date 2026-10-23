// Local probe assertions/owned teardown only; never used for presented-token lookup.
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import type { Pool, PoolClient } from 'pg';
import { RefreshTokenGeneratorService } from '../src/tokens/refresh-token-generator.service.js';

export function requireOpaqueRefreshToken(value: unknown): string {
  assert.ok(
    typeof value === 'string' && /^[A-Za-z0-9_-]{43}$/.test(value),
    'Expected canonical opaque refresh credential.',
  );
  const decoded = Buffer.from(value, 'base64url');
  assert.ok(
    decoded.length === 32 && decoded.toString('base64url') === value,
    'Expected canonical 256-bit refresh credential.',
  );
  return value;
}

export async function verifyInitialRefresh(
  db: Pool | PoolClient,
  raw: string,
  expected: {
    userId: string;
    clientId: string;
    sessionId: string;
    scopes: readonly string[];
    ttlSeconds: number;
  },
): Promise<void> {
  const tokenHash = new RefreshTokenGeneratorService().hash(
    requireOpaqueRefreshToken(raw),
  );
  const families = await db.query<{
    id: string;
    user_id: string;
    client_id: string;
    session_id: string;
    granted_scopes: string[];
    status: string;
    reuse_detected_at: unknown;
    revoked_at: unknown;
  }>(
    'SELECT * FROM refresh_token_families WHERE user_id=$1 AND client_id=$2 AND session_id=$3',
    [expected.userId, expected.clientId, expected.sessionId],
  );
  assert.equal(families.rowCount, 1, 'Expected one owned refresh family.');
  const family = families.rows[0];
  assert.ok(
    family.user_id === expected.userId &&
      family.client_id === expected.clientId &&
      family.session_id === expected.sessionId &&
      family.status === 'ACTIVE' &&
      family.reuse_detected_at === null &&
      family.revoked_at === null &&
      JSON.stringify(family.granted_scopes) === JSON.stringify(expected.scopes),
    'Invalid initial refresh family binding/snapshot/lifecycle.',
  );
  const tokens = await db.query<{
    family_id: string;
    token_hash: string;
    parent_token_id: string | null;
    status: string;
    consumed_at: unknown;
    revoked_at: unknown;
    ttl_ms: string;
    same_instant: boolean;
  }>(
    `SELECT t.*, (extract(epoch FROM (t.expires_at-t.issued_at))*1000)::bigint::text AS ttl_ms,
      t.issued_at=f.created_at AS same_instant
    FROM refresh_tokens t JOIN refresh_token_families f ON f.id=t.family_id WHERE t.family_id=$1`,
    [family.id],
  );
  assert.equal(tokens.rowCount, 1, 'Expected one owned initial root token.');
  const token = tokens.rows[0];
  assert.ok(
    token.family_id === family.id &&
      token.token_hash === tokenHash &&
      token.token_hash !== raw &&
      token.parent_token_id === null &&
      token.status === 'ACTIVE' &&
      token.consumed_at === null &&
      token.revoked_at === null &&
      token.same_instant &&
      Number(token.ttl_ms) === expected.ttlSeconds * 1000,
    'Invalid initial hash/root/lifetime/lifecycle.',
  );
  assert.ok(
    !JSON.stringify([families.rows, tokens.rows]).includes(raw),
    'Raw refresh credential must not be persisted.',
  );
}

// Caller must first prove/lock the uniquely owned User. Discover even a lost HTTP reply's
// family, prove every binding, then delete exact family IDs before Session/User/Client.
export async function deleteOwnedRefresh(
  db: PoolClient,
  userId: string,
  sessionIds: readonly string[],
  clientIds: readonly string[],
): Promise<void> {
  const families = await db.query<{
    id: string;
    session_id: string;
    client_id: string;
  }>(
    'SELECT id, session_id, client_id FROM refresh_token_families WHERE user_id=$1 FOR UPDATE',
    [userId],
  );
  assert.ok(
    families.rows.every(
      (row) =>
        sessionIds.includes(row.session_id) &&
        clientIds.includes(row.client_id),
    ),
    'Cannot prove refresh family ownership; refusing teardown.',
  );
  const ids = families.rows.map((row) => row.id);
  if (!ids.length) return;
  await db.query('DELETE FROM refresh_tokens WHERE family_id=ANY($1::uuid[])', [
    ids,
  ]);
  const removed = await db.query(
    `DELETE FROM refresh_token_families WHERE id=ANY($1::uuid[])
    AND user_id=$2 AND session_id=ANY($3::uuid[]) AND client_id=ANY($4::uuid[])`,
    [ids, userId, sessionIds, clientIds],
  );
  assert.equal(
    removed.rowCount,
    ids.length,
    'Owned family teardown incomplete.',
  );
}

// Synthetic M6 probes now need real FK parents. No credentials/login or Redis
// sessions are fabricated here; only their already-synthetic code fixtures use these IDs.
export function ownedRefreshIdentity(db: Pool, prefix: string) {
  const userId = randomUUID();
  const sessionId = randomUUID();
  const marker = prefix + '-' + randomUUID();
  const email = marker + '@example.invalid';
  const teardown = async (
    clientIds: readonly string[],
    removeIdentity: boolean,
  ): Promise<void> => {
    const connection = await db.connect();
    try {
      await connection.query('BEGIN');
      const user = await connection.query(
        'SELECT id FROM users WHERE id=$1 AND email=$2 AND username=$3 FOR UPDATE',
        [userId, email, marker],
      );
      if (user.rowCount === 0) {
        await connection.query('COMMIT');
        return;
      }
      assert.equal(
        user.rowCount,
        1,
        'Cannot prove synthetic identity ownership.',
      );
      const sessions = await connection.query<{ id: string }>(
        'SELECT id FROM sessions WHERE user_id=$1',
        [userId],
      );
      assert.ok(
        sessions.rows.every((row) => row.id === sessionId),
        'Cannot prove synthetic session ownership.',
      );
      await deleteOwnedRefresh(connection, userId, [sessionId], clientIds);
      if (removeIdentity) {
        await connection.query(
          'DELETE FROM sessions WHERE id=$1 AND user_id=$2',
          [sessionId, userId],
        );
        const removed = await connection.query(
          'DELETE FROM users WHERE id=$1 AND email=$2 AND username=$3',
          [userId, email, marker],
        );
        assert.equal(
          removed.rowCount,
          1,
          'Owned synthetic user teardown incomplete.',
        );
      }
      await connection.query('COMMIT');
    } catch {
      await connection.query('ROLLBACK');
      throw new Error('Owned refresh fixture teardown failed.');
    } finally {
      connection.release();
    }
  };
  return {
    userId,
    sessionId,
    async create(): Promise<void> {
      await db.query(
        'INSERT INTO users (id,email,username,updated_at) VALUES ($1,$2,$3,CURRENT_TIMESTAMP)',
        [userId, email, marker],
      );
      await db.query(
        "INSERT INTO sessions (id,user_id,expires_at) VALUES ($1,$2,CURRENT_TIMESTAMP + interval '1 hour')",
        [sessionId, userId],
      );
    },
    clearRefresh: (clientIds: readonly string[]) => teardown(clientIds, false),
    cleanup: (clientIds: readonly string[]) => teardown(clientIds, true),
  };
}
