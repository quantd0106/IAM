// Explicit local real-stack M8.5 probe, not rotation/reuse enforcement.
import 'reflect-metadata';
import 'dotenv/config';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { PrismaPg } from '@prisma/adapter-pg';
import { Pool } from 'pg';
import * as argon2 from 'argon2';
import { createLocalJWKSet, jwtVerify, type JSONWebKeySet } from 'jose';
import { validateEnvironment } from '../src/config/env.schema.js';
import { PrismaClient } from '../src/generated/prisma/client.js';
import { RefreshTokenGeneratorService } from '../src/tokens/refresh-token-generator.service.js';
import { RefreshTokenIssuerService } from '../src/tokens/refresh-token-issuer.service.js';
import {
  ownedRefreshIdentity,
  verifyInitialRefresh,
} from './refresh-token.check-support.js';

let phase = 'preconditions';
async function checkRefreshGrant(): Promise<void> {
  const env = validateEnvironment(process.env);
  const local = (value: string, protocols: string[]): boolean => {
    const url = new URL(value);
    return (
      protocols.includes(url.protocol) &&
      ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname)
    );
  };
  assert.ok(
    env.NODE_ENV !== 'production' &&
      local(env.DATABASE_URL, ['postgres:', 'postgresql:']) &&
      local(env.ISSUER_URL, ['http:']),
    'Refresh probe requires local development HTTP/PostgreSQL.',
  );
  const db = new Pool({
    connectionString: env.DATABASE_URL,
    connectionTimeoutMillis: 5000,
  });
  const prisma = new PrismaClient({
    adapter: new PrismaPg({
      connectionString: env.DATABASE_URL,
      connectionTimeoutMillis: 5000,
    }),
  });
  const identity = ownedRefreshIdentity(db, 'm85');
  const marker = 'm85-' + randomUUID();
  const clients = [
    {
      id: randomUUID(),
      clientId: marker + '-public',
      clientType: 'PUBLIC' as const,
      audience: 'student-api',
      accessTtl: 123,
    },
    {
      id: randomUUID(),
      clientId: marker + '-other',
      clientType: 'PUBLIC' as const,
      audience: 'other-api',
      accessTtl: 321,
    },
    {
      id: randomUUID(),
      clientId: marker + '-confidential',
      clientType: 'CONFIDENTIAL' as const,
      audience: 'banking-api',
      accessTtl: 234,
    },
  ];
  const [student, other, banking] = clients;
  const attemptedClients = new Set<string>();
  const secret = randomBytes(32).toString('base64url');
  const generator = new RefreshTokenGeneratorService();
  const issuer = new RefreshTokenIssuerService(prisma, generator);
  const http = (path: string, options: RequestInit = {}) =>
    fetch(new URL(path, env.ISSUER_URL), {
      ...options,
      redirect: 'manual',
      credentials: 'omit',
      signal: AbortSignal.timeout(10000),
    });
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
    await identity.cleanup(clients.map((client) => client.id));
    for (const client of clients)
      if (attemptedClients.has(client.id))
        await db.query('DELETE FROM clients WHERE id=$1 AND client_id=$2', [
          client.id,
          client.clientId,
        ]);
  };
  try {
    await prisma.$connect();
    phase = 'live public verification metadata';
    const discovery = await http('/.well-known/openid-configuration');
    assert.equal(discovery.status, 200, 'Discovery prerequisite failed.');
    const metadata = (await discovery.json()) as Record<string, unknown>;
    assert.ok(
      JSON.stringify(metadata.grant_types_supported) ===
        '["authorization_code","refresh_token"]',
      'Unexpected grant advertisement.',
    );
    const jwksResponse = await http('/.well-known/jwks.json');
    assert.equal(
      jwksResponse.status,
      200,
      'Existing signing pair/JWKS required.',
    );
    const jwks = createLocalJWKSet(
      (await jwksResponse.json()) as JSONWebKeySet,
    );
    const before = await snapshot();
    let cases = 0;
    try {
      phase = 'owned initial refresh issuance';
      await identity.create();
      const secretHash = await argon2.hash(secret, { type: argon2.argon2id });
      for (const client of clients) {
        attemptedClients.add(client.id);
        await prisma.client.create({
          data: {
            id: client.id,
            clientId: client.clientId,
            name: client.clientId,
            clientType: client.clientType,
            clientSecretHash:
              client.clientType === 'CONFIDENTIAL' ? secretHash : null,
            accessTokenAudience: client.audience,
            accessTokenTtl: client.accessTtl,
            refreshTokenTtl: 456,
          },
        });
      }
      const scopes = ['openid', 'profile', 'email'];
      const initial = await issuer.issueInitial({
        userId: identity.userId,
        sessionId: identity.sessionId,
        clientRecordId: student.id,
        grantedScopes: scopes,
        ttlSeconds: 456,
      });
      const expected = {
        userId: identity.userId,
        sessionId: identity.sessionId,
        clientId: student.id,
        scopes,
        ttlSeconds: 456,
      };
      await verifyInitialRefresh(db, initial.refreshToken, expected);
      const post = async (
        client: typeof student,
        raw: string,
        status: number,
        scope?: string,
        authorization?: string,
        error?: string,
      ) => {
        const unchanged = await snapshot();
        const response = await http('/oauth/token', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            ...(authorization === undefined
              ? {}
              : { Authorization: authorization }),
          },
          body: new URLSearchParams({
            grant_type: 'refresh_token',
            client_id: client.clientId,
            refresh_token: raw,
            ...(scope === undefined ? {} : { scope }),
          }),
        });
        assert.equal(
          response.status,
          status,
          'Unexpected refresh HTTP status.',
        );
        assert.equal(response.headers.get('cache-control'), 'no-store');
        assert.equal(response.headers.get('pragma'), 'no-cache');
        assert.equal(response.headers.get('set-cookie'), null);
        assert.equal(response.headers.get('location'), null);
        assert.ok(
          response.headers.get('content-type')?.startsWith('application/json'),
          'Expected JSON.',
        );
        const text = await response.text();
        assert.ok(
          !text.includes(raw) &&
            !text.includes(secret) &&
            !text.includes(secretHash),
          'Refresh response leaked a credential.',
        );
        const body = JSON.parse(text) as Record<string, unknown>;
        if (status === 200) {
          assert.ok(
            JSON.stringify(Object.keys(body).sort()) ===
              '["access_token","expires_in","scope","token_type"]',
            'Refresh must have exactly four fields; no ID/replacement refresh credential.',
          );
          const effective = scope === undefined ? scopes : scope.split(' ');
          assert.ok(
            typeof body.access_token === 'string' &&
              body.token_type === 'Bearer' &&
              body.expires_in === client.accessTtl &&
              body.scope === effective.join(' '),
            'Unexpected refresh response metadata.',
          );
          const { payload, protectedHeader } = await jwtVerify(
            body.access_token,
            jwks,
            {
              algorithms: ['RS256'],
              issuer: env.ISSUER_URL,
              audience: client.audience,
            },
          );
          assert.ok(
            JSON.stringify(protectedHeader) ===
              JSON.stringify({ alg: 'RS256', kid: env.JWT_KEY_ID }) &&
              JSON.stringify(Object.keys(payload).sort()) ===
                '["aud","exp","iat","iss","permissions","roles","scope","sub"]' &&
              payload.sub === identity.userId &&
              payload.aud === client.audience &&
              payload.scope === effective.join(' ') &&
              Number.isSafeInteger(payload.iat) &&
              Number.isSafeInteger(payload.exp) &&
              payload.exp! - payload.iat! === client.accessTtl &&
              JSON.stringify(payload.roles) === '[]' &&
              JSON.stringify(payload.permissions) === '[]',
            'Invalid refresh-issued access JWT.',
          );
          if (effective.includes('openid')) {
            const userinfo = await http('/oidc/userinfo', {
              headers: { Authorization: 'Bearer ' + body.access_token },
            });
            assert.equal(
              userinfo.status,
              200,
              'Refresh-issued access token must work at unchanged UserInfo.',
            );
            const profile = (await userinfo.json()) as Record<string, unknown>;
            assert.ok(
              profile.sub === identity.userId,
              'Unexpected refresh/UserInfo subject.',
            );
          }
        } else {
          const description =
            error === 'invalid_client'
              ? 'Client authentication failed.'
              : error === 'invalid_scope'
                ? 'Invalid refresh scope.'
                : 'Invalid refresh token.';
          assert.ok(
            text === JSON.stringify({ error, error_description: description }),
            'Refresh failure must be fixed/sanitized.',
          );
          assert.equal(
            response.headers.get('www-authenticate'),
            status === 401 ? 'Basic realm="oauth/token"' : null,
          );
        }
        assert.ok(
          (await snapshot()) === unchanged,
          'Refresh request mutated database state (rotation/reuse/revocation must remain absent).',
        );
        cases++;
      };
      phase = 'PUBLIC repeated refresh and scope narrowing';
      await post(student, initial.refreshToken, 200);
      await post(student, initial.refreshToken, 200, 'email openid');
      await post(student, initial.refreshToken, 200);
      await post(student, initial.refreshToken, 200, 'openid profile email');
      await verifyInitialRefresh(db, initial.refreshToken, expected);
      phase = 'wrong authenticated client and invalid scopes';
      await post(
        other,
        initial.refreshToken,
        400,
        undefined,
        undefined,
        'invalid_grant',
      );
      for (const scope of [
        '',
        'profile profile',
        'openid admin',
        'OpenID',
        'openid  profile',
      ])
        await post(
          student,
          initial.refreshToken,
          400,
          scope,
          undefined,
          'invalid_scope',
        );
      await post(
        student,
        'A'.repeat(42) + '+',
        400,
        undefined,
        undefined,
        'invalid_grant',
      );
      await post(
        student,
        generator.generate().rawToken,
        400,
        undefined,
        undefined,
        'invalid_grant',
      );
      phase = 'owned expired credential';
      const ownedRoot = await prisma.refreshToken.findUniqueOrThrow({
        where: { tokenHash: generator.hash(initial.refreshToken) },
        select: { id: true, familyId: true },
      });
      const family = await prisma.refreshTokenFamily.findUniqueOrThrow({
        where: { id: ownedRoot.familyId },
        select: { userId: true, sessionId: true, clientId: true },
      });
      assert.ok(
        family.userId === identity.userId &&
          family.sessionId === identity.sessionId &&
          family.clientId === student.id,
        'Cannot prove expiry fixture ownership.',
      );
      phase = 'owned compatibility/corrupt scope snapshots';
      const setOwnedScopes = async (value: string[] | null): Promise<void> => {
        const changed = await db.query(
          `UPDATE refresh_token_families SET granted_scopes=$1::text[]
          WHERE id=$2 AND user_id=$3 AND session_id=$4 AND client_id=$5`,
          [
            value,
            ownedRoot.familyId,
            identity.userId,
            identity.sessionId,
            student.id,
          ],
        );
        assert.equal(changed.rowCount, 1, 'Owned scope fixture setup failed.');
      };
      for (const value of [[], ['profile', 'profile'], ['bad scope'], null]) {
        // Owned negative fixture only; each HTTP request must remain read-only.
        await setOwnedScopes(value);
        await post(
          student,
          initial.refreshToken,
          400,
          undefined,
          undefined,
          'invalid_grant',
        );
      }
      await setOwnedScopes(scopes);
      phase = 'owned expired credential';
      // Fixture setup only; the HTTP flow must not modify this expired record.
      await prisma.refreshToken.update({
        where: { id: ownedRoot.id },
        data: { expiresAt: new Date(Date.now() - 1000) },
      });
      await post(
        student,
        initial.refreshToken,
        400,
        undefined,
        undefined,
        'invalid_grant',
      );
      assert.equal(
        await prisma.refreshToken.count({
          where: { familyId: ownedRoot.familyId },
        }),
        1,
        'RT2 must not exist.',
      );
      const root = await prisma.refreshToken.findUniqueOrThrow({
        where: { id: ownedRoot.id },
      });
      assert.ok(
        root.status === 'ACTIVE' &&
          root.consumedAt === null &&
          root.revokedAt === null &&
          root.parentTokenId === null,
        'RT1 must remain unconsumed/parentless, even on expiry failure.',
      );
      phase = 'CONFIDENTIAL Basic refresh';
      const confidential = await issuer.issueInitial({
        userId: identity.userId,
        sessionId: identity.sessionId,
        clientRecordId: banking.id,
        grantedScopes: scopes,
        ttlSeconds: 456,
      });
      const basic = (value: string) =>
        'Basic ' +
        Buffer.from(
          `${encodeURIComponent(banking.clientId)}:${encodeURIComponent(value)}`,
        ).toString('base64');
      await post(
        banking,
        confidential.refreshToken,
        401,
        undefined,
        undefined,
        'invalid_client',
      );
      await post(
        banking,
        confidential.refreshToken,
        401,
        undefined,
        basic(secret + '-wrong'),
        'invalid_client',
      );
      await post(
        banking,
        confidential.refreshToken,
        200,
        'profile',
        basic(secret),
      );
      await verifyInitialRefresh(db, confidential.refreshToken, {
        ...expected,
        clientId: banking.id,
      });
    } finally {
      const flowPhase = phase;
      phase = 'strict owned FK cleanup';
      await cleanup();
      assert.ok(
        (await snapshot()) === before,
        'Ten database fingerprints not restored.',
      );
      phase = flowPhase;
    }
    console.log(
      `M8.5 real refresh grant passed (${cases} HTTP cases): real M8.4 RT1; PUBLIC/repeated/narrowed and confidential Basic access issuance; live-JWKS RS256/exact eight claims/resource audience/access TTL; wrong client/unknown/malformed/expired grants and invalid scopes rejected safely.`,
    );
    console.log(
      'Each refresh left all ten DB fingerprints unchanged; RT1 ACTIVE/parentless, no consumedAt, RT2, ID/replacement refresh token or expiry extension. Strict owned FK cleanup restored baseline; no credentials/hashes/identifiers printed. M8.6 rotation remains mandatory before production completeness.',
    );
  } finally {
    await prisma.$disconnect();
    await db.end();
  }
}
void checkRefreshGrant().catch(() => {
  console.error(
    `Refresh-token grant check failed at ${phase} (private details suppressed).`,
  );
  process.exitCode = 1;
});
