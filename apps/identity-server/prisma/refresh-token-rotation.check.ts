// Explicit local M8.6 transaction/HTTP/concurrency probe. No M8.7 revocation.
import 'reflect-metadata';
import 'dotenv/config';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { PrismaPg } from '@prisma/adapter-pg';
import { Pool } from 'pg';
import { createLocalJWKSet, jwtVerify, type JSONWebKeySet } from 'jose';
import { validateEnvironment } from '../src/config/env.schema.js';
import { PrismaClient } from '../src/generated/prisma/client.js';
import { RefreshTokenGeneratorService } from '../src/tokens/refresh-token-generator.service.js';
import { RefreshTokenIssuerService } from '../src/tokens/refresh-token-issuer.service.js';
import { RefreshTokenRotationService } from '../src/tokens/refresh-token-rotation.service.js';
import {
  ownedRefreshIdentity,
  requireOpaqueRefreshToken,
  verifyInitialRefresh,
} from './refresh-token.check-support.js';

let phase = 'preconditions';
async function checkRotation(): Promise<void> {
  const env = validateEnvironment(process.env);
  for (const value of [env.DATABASE_URL, env.ISSUER_URL]) {
    const url = new URL(value);
    assert.ok(
      env.NODE_ENV !== 'production' &&
        ['postgres:', 'postgresql:', 'http:'].includes(url.protocol) &&
        ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname),
      'Rotation probe requires local development HTTP/PostgreSQL.',
    );
  }
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
  const identity = ownedRefreshIdentity(db, 'm86');
  const clientId = randomUUID();
  const protocolId = 'm86-' + randomUUID();
  let clientAttempted = false;
  const scopes = ['openid', 'profile', 'email'];
  const generator = new RefreshTokenGeneratorService();
  const issuer = new RefreshTokenIssuerService(prisma, generator);
  const http = (path: string, options: RequestInit = {}) =>
    fetch(new URL(path, env.ISSUER_URL), {
      ...options,
      redirect: 'manual',
      credentials: 'omit',
      signal: AbortSignal.timeout(15000),
    });
  const snapshot = async (includeTokens = true): Promise<string> => {
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
            .filter((table) => includeTokens || table !== 'refresh_tokens')
            .map(
              (table) =>
                `SELECT '${table}' AS relation, COUNT(*)::int AS count, md5(COALESCE(jsonb_agg(to_jsonb(t) ORDER BY ${table === 'client_scopes' ? 'client_id, scope_id' : 'id'})::text, '[]')) AS fingerprint FROM ${table} t`,
            )
            .join(' UNION ALL ') + ' ORDER BY relation',
        )
      ).rows,
    );
  };
  const issueRoot = () =>
    issuer.issueInitial({
      userId: identity.userId,
      sessionId: identity.sessionId,
      clientRecordId: clientId,
      grantedScopes: scopes,
      ttlSeconds: 456,
    });
  const lookup = (raw: string) =>
    prisma.refreshToken.findUniqueOrThrow({
      where: { tokenHash: generator.hash(raw) },
    });
  const post = async (raw: string, scope?: string) => {
    const response = await http('/oauth/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'refresh_token',
        client_id: protocolId,
        refresh_token: raw,
        ...(scope === undefined ? {} : { scope }),
      }),
    });
    assert.equal(response.headers.get('cache-control'), 'no-store');
    assert.equal(response.headers.get('pragma'), 'no-cache');
    assert.equal(response.headers.get('set-cookie'), null);
    assert.equal(response.headers.get('location'), null);
    assert.ok(
      response.headers.get('content-type')?.startsWith('application/json'),
      'Expected JSON.',
    );
    const text = await response.text();
    assert.ok(!text.includes(raw), 'Presented credential leaked in response.');
    return {
      status: response.status,
      body: JSON.parse(text) as Record<string, unknown>,
    };
  };
  try {
    await prisma.$connect();
    phase = 'live Discovery/JWKS';
    const discovery = await http('/.well-known/openid-configuration');
    assert.equal(discovery.status, 200);
    const metadata = (await discovery.json()) as Record<string, unknown>;
    assert.ok(
      JSON.stringify(metadata.grant_types_supported) ===
        '["authorization_code","refresh_token"]',
      'Discovery changed.',
    );
    const keys = await http('/.well-known/jwks.json');
    assert.equal(keys.status, 200, 'Existing signing pair/JWKS required.');
    const jwks = createLocalJWKSet((await keys.json()) as JSONWebKeySet);
    const verifySuccess = async (
      result: Awaited<ReturnType<typeof post>>,
      previousRaw: string,
      scope: string,
    ) => {
      assert.equal(result.status, 200, 'Expected rotation success.');
      const body = result.body;
      assert.ok(
        JSON.stringify(Object.keys(body).sort()) ===
          '["access_token","expires_in","refresh_token","scope","token_type"]',
        'Expected exactly five refresh response fields.',
      );
      assert.ok(
        body.token_type === 'Bearer' &&
          body.expires_in === 123 &&
          body.scope === scope &&
          typeof body.access_token === 'string',
        'Invalid access response metadata.',
      );
      const raw = requireOpaqueRefreshToken(body.refresh_token);
      assert.ok(raw !== previousRaw, 'Rotation must replace the credential.');
      const { payload, protectedHeader } = await jwtVerify(
        body.access_token,
        jwks,
        {
          algorithms: ['RS256'],
          issuer: env.ISSUER_URL,
          audience: 'student-api',
        },
      );
      assert.ok(
        JSON.stringify(Object.keys(payload).sort()) ===
          '["aud","exp","iat","iss","permissions","roles","scope","sub"]' &&
          payload.sub === identity.userId &&
          payload.scope === scope &&
          payload.exp! - payload.iat! === 123 &&
          JSON.stringify(payload.roles) === '[]' &&
          JSON.stringify(payload.permissions) === '[]' &&
          JSON.stringify(protectedHeader) ===
            JSON.stringify({ alg: 'RS256', kid: env.JWT_KEY_ID }),
        'Invalid signed refresh access token.',
      );
      const parent = await lookup(previousRaw);
      const child = await lookup(raw);
      assert.ok(
        parent.status === 'CONSUMED' &&
          parent.consumedAt !== null &&
          parent.revokedAt === null &&
          child.status === 'ACTIVE' &&
          child.consumedAt === null &&
          child.revokedAt === null &&
          child.parentTokenId === parent.id &&
          child.familyId === parent.familyId &&
          child.issuedAt.getTime() === parent.consumedAt.getTime() &&
          child.expiresAt.getTime() === parent.expiresAt.getTime(),
        'Invalid lineage/state/absolute expiry.',
      );
      assert.equal(
        await prisma.refreshToken.count({
          where: { parentTokenId: parent.id },
        }),
        1,
        'Expected exactly one child.',
      );
      const family = await prisma.refreshTokenFamily.findUniqueOrThrow({
        where: { id: parent.familyId },
      });
      const tokens = await prisma.refreshToken.findMany({
        where: { familyId: family.id },
      });
      assert.ok(
        family.userId === identity.userId &&
          family.clientId === clientId &&
          family.sessionId === identity.sessionId &&
          family.status === 'ACTIVE' &&
          family.reuseDetectedAt === null &&
          family.revokedAt === null &&
          JSON.stringify(family.grantedScopes) === JSON.stringify(scopes),
        'Family binding/scopes/lifecycle must not change.',
      );
      for (const credential of [raw, previousRaw, body.access_token])
        assert.ok(
          !JSON.stringify([family, tokens]).includes(credential),
          'Raw credentials must never be persisted.',
        );
      return raw;
    };
    const verifyReplay = (result: Awaited<ReturnType<typeof post>>) => {
      assert.equal(result.status, 400, 'Expected replay/race invalid_grant.');
      assert.ok(
        JSON.stringify(result.body) ===
          '{"error":"invalid_grant","error_description":"Invalid refresh token."}',
        'Expected fixed sanitized invalid_grant without replacement.',
      );
    };
    const before = await snapshot();
    try {
      phase = 'owned fixtures and real M8.4 RT1';
      await identity.create();
      clientAttempted = true;
      await prisma.client.create({
        data: {
          id: clientId,
          clientId: protocolId,
          name: protocolId,
          clientType: 'PUBLIC',
          accessTokenAudience: 'student-api',
          accessTokenTtl: 123,
          refreshTokenTtl: 456,
        },
      });
      const initial = await issueRoot();
      await verifyInitialRefresh(db, initial.refreshToken, {
        userId: identity.userId,
        sessionId: identity.sessionId,
        clientId,
        scopes,
        ttlSeconds: 456,
      });
      const stable = await snapshot(false);
      phase = 'RT1 -> RT2 and narrowed access scope';
      const rt2 = await verifySuccess(
        await post(initial.refreshToken, 'profile'),
        initial.refreshToken,
        'profile',
      );
      phase = 'consumed RT1 replay without family/session revocation';
      const committed = await snapshot();
      verifyReplay(await post(initial.refreshToken));
      assert.ok(
        (await snapshot()) === committed,
        'Replay must leave all state unchanged in M8.6.',
      );
      phase = 'RT2 -> RT3 with original scopes and inherited absolute horizon';
      const rt3 = await verifySuccess(await post(rt2), rt2, scopes.join(' '));
      assert.ok(
        rt3 !== initial.refreshToken && rt3 !== rt2,
        'RT3 must be fresh.',
      );
      const root = await lookup(initial.refreshToken);
      assert.equal(
        await prisma.refreshToken.count({ where: { familyId: root.familyId } }),
        3,
        'Expected three-token lineage.',
      );
      assert.ok(
        (await snapshot(false)) === stable,
        'Normal rotation/replay modified family/session/registry.',
      );

      phase = 'two truly concurrent HTTP requests for one fresh RT1';
      const fresh = await issueRoot();
      const concurrentStable = await snapshot(false);
      const results = await Promise.all([
        post(fresh.refreshToken),
        post(fresh.refreshToken),
      ]);
      assert.ok(
        results.filter((result) => result.status === 200).length === 1 &&
          results.filter((result) => result.status === 400).length === 1,
        'Concurrent refresh must have exactly one 200 and one 400.',
      );
      await verifySuccess(
        results.find((result) => result.status === 200)!,
        fresh.refreshToken,
        scopes.join(' '),
      );
      verifyReplay(results.find((result) => result.status === 400)!);
      const racedRoot = await lookup(fresh.refreshToken);
      assert.equal(
        await prisma.refreshToken.count({
          where: { familyId: racedRoot.familyId },
        }),
        2,
        'Race must create only one child and no RT3.',
      );
      assert.ok(
        (await snapshot(false)) === concurrentStable,
        'Race changed family/session/registry state.',
      );

      phase = 'real PostgreSQL signing/generation/child-insert rollback';
      const rollbackRoot = await issueRoot();
      const rollbackBaseline = await snapshot();
      const rotationInput = {
        rawRefreshToken: rollbackRoot.refreshToken,
        clientRecordId: clientId,
        accessTokenAudience: 'student-api',
        accessTokenTtl: 123,
      };
      const transientAccess = {
        issue: () =>
          Promise.resolve({
            accessToken: 'never-delivered',
            expiresIn: 123,
            scope: scopes.join(' '),
          }),
      };
      const failures = [
        new RefreshTokenRotationService(prisma, generator, {
          issue: () => Promise.reject(new Error('private signing failure')),
        }),
        new RefreshTokenRotationService(
          prisma,
          {
            hash: generator.hash.bind(generator),
            generate: () => {
              throw new Error('private generator failure');
            },
          },
          transientAccess,
        ),
        // Root's existing unique hash forces child insertion to fail AFTER consume.
        new RefreshTokenRotationService(
          prisma,
          {
            hash: generator.hash.bind(generator),
            generate: () => ({
              rawToken: rollbackRoot.refreshToken,
              tokenHash: generator.hash(rollbackRoot.refreshToken),
            }),
          },
          transientAccess,
        ),
      ];
      for (const service of failures) {
        const error: unknown = await service
          .rotate(rotationInput)
          .catch((value: unknown) => value);
        assert.ok(
          error instanceof Error &&
            error.message === 'Refresh token rotation failed.' &&
            error.cause === undefined,
          'Expected fixed internal failure, not credentials or native cause.',
        );
        assert.ok(
          (await snapshot()) === rollbackBaseline,
          'Failed transaction left partial consume/replacement state.',
        );
      }
      const unchangedRoot = await lookup(rollbackRoot.refreshToken);
      assert.ok(
        unchangedRoot.status === 'ACTIVE' && unchangedRoot.consumedAt === null,
        'Rollback must keep RT1 ACTIVE.',
      );
    } finally {
      const flowPhase = phase;
      phase = 'strict owned FK cleanup and ten-table fingerprints';
      await identity.cleanup([clientId]);
      if (clientAttempted)
        await db.query('DELETE FROM clients WHERE id=$1 AND client_id=$2', [
          clientId,
          protocolId,
        ]);
      assert.ok(
        (await snapshot()) === before,
        'Ten database fingerprints not restored.',
      );
      phase = flowPhase;
    }
    console.log(
      'M8.6 real rotation passed: M8.4 RT1 -> RT2 -> RT3, exact five-field responses/live-JWKS access claims, inherited absolute expiry, original family scopes, hash-only persistence, RT1 replay invalid_grant without revocation.',
    );
    console.log(
      'Concurrent PostgreSQL-backed HTTP refresh: exactly one 200 + one 400 invalid_grant; one ACTIVE child, two family tokens, winner raw hashes to child. Real signing/generator/unique-child failures rolled back; strict owned cleanup restored ten fingerprints. No family/session/audit changes, credentials, hashes or IDs printed.',
    );
  } finally {
    await prisma.$disconnect();
    await db.end();
  }
}
void checkRotation().catch(() => {
  console.error(
    `Refresh-token rotation check failed at ${phase} (private details suppressed).`,
  );
  process.exitCode = 1;
});
