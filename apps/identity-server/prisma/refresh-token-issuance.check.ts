// Real M8.4 issuer + PostgreSQL transactions, including root uniqueness rollback.
// Explicit local probe only. No presented refresh-token lookup or HTTP grant.
import 'reflect-metadata';
import 'dotenv/config';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { PrismaPg } from '@prisma/adapter-pg';
import { Pool } from 'pg';
import { PrismaClient } from '../src/generated/prisma/client.js';
import { RefreshTokenIssuerService } from '../src/tokens/refresh-token-issuer.service.js';
import { RefreshTokenGeneratorService } from '../src/tokens/refresh-token-generator.service.js';
import {
  ownedRefreshIdentity,
  verifyInitialRefresh,
} from './refresh-token.check-support.js';

let phase = 'preconditions';
async function checkIssuance(): Promise<void> {
  const connectionString = process.env.DATABASE_URL?.trim();
  assert.ok(connectionString, 'DATABASE_URL required.');
  const url = new URL(connectionString);
  assert.ok(
    ['development', 'test'].includes(process.env.NODE_ENV ?? 'development') &&
      ['postgres:', 'postgresql:'].includes(url.protocol) &&
      ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname),
    'Issuance probe requires local development PostgreSQL.',
  );
  const prisma = new PrismaClient({
    adapter: new PrismaPg({ connectionString, connectionTimeoutMillis: 5000 }),
  });
  const db = new Pool({ connectionString, connectionTimeoutMillis: 5000 });
  const identity = ownedRefreshIdentity(db, 'm84');
  const clientId = randomUUID();
  const protocolId = 'm84-' + randomUUID();
  let clientAttempted = false;
  const generator = new RefreshTokenGeneratorService();
  const issuer = new RefreshTokenIssuerService(prisma, generator);
  const snapshot = async (): Promise<string> => {
    const tables = [
      'users',
      'credentials',
      'sessions',
      'clients',
      'client_redirect_uris',
      'scopes',
      'client_scopes',
      'refresh_token_families',
      'refresh_tokens',
      '_prisma_migrations',
    ];
    return JSON.stringify(
      (
        await db.query(
          tables
            .map(
              (table) =>
                `SELECT '${table}' AS relation, COUNT(*)::int AS count, md5(COALESCE(jsonb_agg(to_jsonb(t) ORDER BY ${table === 'client_scopes' ? 'client_id, scope_id' : 'id'})::text, '[]')) AS fingerprint FROM ${table} t`,
            )
            .join(' UNION ALL ') + ' ORDER BY relation',
        )
      ).rows,
    );
  };
  const cleanup = async (): Promise<void> => {
    await identity.cleanup([clientId]);
    if (clientAttempted)
      await db.query('DELETE FROM clients WHERE id=$1 AND client_id=$2', [
        clientId,
        protocolId,
      ]);
  };
  try {
    await prisma.$connect();
    const before = await snapshot();
    try {
      phase = 'owned fixtures';
      await identity.create();
      clientAttempted = true;
      await prisma.client.create({
        data: {
          id: clientId,
          clientId: protocolId,
          name: protocolId,
          clientType: 'PUBLIC',
          refreshTokenTtl: 456,
          accessTokenTtl: 123,
        },
      });
      const input = {
        userId: identity.userId,
        clientRecordId: clientId,
        sessionId: identity.sessionId,
        grantedScopes: ['profile', 'Scope:Exact', 'openid'],
        ttlSeconds: 456,
      };
      phase = 'real initial issuer commit';
      const result = await issuer.issueInitial(input);
      assert.ok(
        Object.keys(result).join(',') === 'refreshToken',
        'Unexpected issuer result metadata.',
      );
      const expected = {
        userId: identity.userId,
        clientId,
        sessionId: identity.sessionId,
        scopes: input.grantedScopes,
        ttlSeconds: 456,
      };
      await verifyInitialRefresh(db, result.refreshToken, expected);
      const committed = await snapshot();
      const sanitized = async (
        operation: () => Promise<unknown>,
      ): Promise<void> => {
        const error: unknown = await operation().catch(
          (value: unknown) => value,
        );
        assert.ok(
          error instanceof Error &&
            error.message === 'Refresh token issuance failed.' &&
            error.cause === undefined,
          'Issuer failure must contain only the fixed error and no native cause.',
        );
        assert.ok(
          (await snapshot()) === committed,
          'Failed issuance left committed/changed database state.',
        );
      };
      phase = 'root uniqueness failure rollback';
      let generations = 0;
      const colliding = new RefreshTokenIssuerService(prisma, {
        generate: () => {
          generations++;
          return {
            rawToken: result.refreshToken,
            tokenHash: generator.hash(result.refreshToken),
          };
        },
      });
      await sanitized(() => colliding.issueInitial(input));
      assert.equal(generations, 1, 'M8.4 must not retry collisions.');
      phase = 'family FK failure rollback';
      const absentUser = randomUUID();
      assert.equal(
        await prisma.user.count({ where: { id: absentUser } }),
        0,
        'Absent FK fixture collision.',
      );
      await sanitized(() =>
        issuer.issueInitial({ ...input, userId: absentUser }),
      );
      await verifyInitialRefresh(db, result.refreshToken, expected);
    } finally {
      const flowPhase = phase;
      phase = 'strict FK-ordered cleanup';
      await cleanup();
      assert.ok(
        (await snapshot()) === before,
        'Ten fingerprints not restored after owned cleanup.',
      );
      phase = flowPhase;
    }
    console.log(
      'M8.4 real issuer passed: exact user/internal-client/session binding and scope snapshot; one ACTIVE family + parentless ACTIVE root; one instant/configured refresh TTL; canonical raw delivery/hash-only storage; real unique-root and family-FK failures roll back atomically without retry.',
    );
    console.log(
      'Owned RefreshToken -> RefreshTokenFamily -> Session/User/Client cleanup passed; all ten database fingerprints restored; no credential, hash or identifier printed.',
    );
  } finally {
    await prisma.$disconnect();
    await db.end();
  }
}
void checkIssuance().catch(() => {
  console.error(
    `Refresh-token issuance check failed at ${phase} (private details suppressed).`,
  );
  process.exitCode = 1;
});
