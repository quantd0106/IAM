// Explicit local PostgreSQL/HTTP verification; never startup/seed code.
import 'reflect-metadata';
import 'dotenv/config';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import type { Server } from 'node:http';
import type { INestApplication, LoggerService } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import { PrismaPg } from '@prisma/adapter-pg';
import { PrismaClient, type Prisma } from '../src/generated/prisma/client.js';
import { PrismaService } from '../src/prisma/prisma.service.js';
import { OAuthModule } from '../src/oauth/oauth.module.js';

const demos = [
  { clientId: 'student-spa', redirectUri: 'http://localhost:3200/callback' },
  {
    clientId: 'banking-web',
    redirectUri: 'http://localhost:3100/auth/callback',
  },
  {
    clientId: 'admin-portal',
    redirectUri: 'http://localhost:3300/auth/callback',
  },
];
const student = {
  response_type: 'code',
  client_id: 'student-spa',
  redirect_uri: demos[0].redirectUri,
  scope: 'openid profile email',
  state: 'm51-opaque-state',
  nonce: 'm51-opaque-nonce',
  code_challenge: 'm51-opaque-challenge',
  code_challenge_method: 'S256',
};
const invalid = {
  error: 'invalid_request',
  error_description: 'Invalid authorization request.',
};
type Snapshot = { relation: string; count: number; fingerprint: string }[];
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
  UNION ALL SELECT '_prisma_migrations', COUNT(*)::int,
    md5(COALESCE(jsonb_agg(to_jsonb(t) ORDER BY id)::text, '[]')) FROM _prisma_migrations t
  ORDER BY relation
`;
type Writes = {
  relation: string;
  inserted: bigint;
  updated: bigint;
  deleted: bigint;
}[];
const writes = (
  db: Prisma.TransactionClient,
): Promise<Writes> => db.$queryRaw<Writes>`
  SELECT relname::text AS relation, n_tup_ins AS inserted, n_tup_upd AS updated, n_tup_del AS deleted
  FROM pg_stat_xact_user_tables WHERE schemaname = 'public' ORDER BY relname
`;
function local(value: string, protocols: string[]): boolean {
  const url = new URL(value);
  return (
    protocols.includes(url.protocol) &&
    ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname)
  );
}
async function checkHttp(
  origin: string,
  query: Record<string, string> | URLSearchParams,
  status: number,
  body = invalid,
): Promise<void> {
  const url = new URL('/oauth/authorize', origin);
  url.search = new URLSearchParams(query).toString();
  const response = await fetch(url, {
    redirect: 'manual',
    signal: AbortSignal.timeout(5000),
  });
  assert.equal(response.status, status);
  assert.equal(response.headers.get('location'), null);
  assert.equal(response.headers.get('set-cookie'), null);
  assert.equal(response.headers.get('cache-control'), 'no-store');
  if (status === 204) assert.equal(await response.text(), '');
  else assert.deepEqual(await response.json(), body);
}
async function checkCanonicalHttp(origin: string): Promise<void> {
  for (const demo of demos) {
    const query: Record<string, string> = {
      ...student,
      client_id: demo.clientId,
      redirect_uri: demo.redirectUri,
    };
    if (demo.clientId !== 'student-spa') {
      delete query.code_challenge;
      delete query.code_challenge_method;
    }
    await checkHttp(origin, query, 204);
  }
  await checkHttp(
    origin,
    { ...student, client_id: `m5.1-unknown-${randomUUID()}` },
    400,
  );
  for (const redirect_uri of [
    'https://unregistered.example.invalid/callback',
    `${student.redirect_uri}/`,
    'http://localhost:3200/Callback',
    'http://localhost:3200/call%62ack',
    `${student.redirect_uri}?a=1`,
    `${student.redirect_uri}.evil`,
    'http://localhost:3200/prefix/callback',
    'http://localhost:3200/*',
  ])
    await checkHttp(origin, { ...student, redirect_uri }, 400);
  const withoutNonce: Record<string, string> = { ...student };
  delete withoutNonce.nonce;
  await checkHttp(origin, withoutNonce, 400);
  const withoutPkce: Record<string, string> = { ...student };
  delete withoutPkce.code_challenge;
  delete withoutPkce.code_challenge_method;
  await checkHttp(origin, withoutPkce, 400);
  await checkHttp(origin, { ...student, code_challenge_method: 'plain' }, 400);
  await checkHttp(
    origin,
    new URLSearchParams([
      ...Object.entries(student),
      ['state', 'duplicate-m51-state'],
    ]),
    400,
  );
  // M5.3 has not begun: syntax-valid unregistered scopes are not granted/rejected here.
  await checkHttp(origin, { ...student, scope: 'custom.scope OpenID' }, 204);
  await checkHttp(origin, { ...student, response_type: 'token' }, 400, {
    ...invalid,
    error: 'unsupported_response_type',
  });
}

async function checkAuthorizationRequests(): Promise<void> {
  const connectionString = process.env.DATABASE_URL?.trim();
  const origin = process.env.ISSUER_URL?.trim() || 'http://localhost:3000';
  if (
    !connectionString ||
    !['development', 'test'].includes(process.env.NODE_ENV ?? 'development') ||
    !local(connectionString, ['postgresql:', 'postgres:']) ||
    !local(origin, ['http:', 'https:'])
  )
    throw new Error(
      'Authorization probe requires local development PostgreSQL/HTTP.',
    );
  const prisma = new PrismaClient({
    adapter: new PrismaPg({ connectionString, connectionTimeoutMillis: 5000 }),
  });
  let capturedLogs = 0;
  const capture = (): void => {
    capturedLogs++;
  };
  const logger: LoggerService = {
    log: capture,
    error: capture,
    warn: capture,
    debug: capture,
    verbose: capture,
    fatal: capture,
  };
  const originals = {
    log: console.log,
    info: console.info,
    error: console.error,
    warn: console.warn,
    debug: console.debug,
  };
  const withHttp = async (
    tx: Prisma.TransactionClient,
    verify: (origin: string) => Promise<void>,
  ): Promise<void> => {
    const context = await Test.createTestingModule({ imports: [OAuthModule] })
      .overrideProvider(PrismaService)
      .useValue(tx)
      .setLogger(logger)
      .compile();
    const app: INestApplication<Server> = context.createNestApplication<
      INestApplication<Server>
    >({ logger });
    try {
      await app.listen(0, '127.0.0.1');
      capturedLogs = 0;
      await verify(await app.getUrl());
      assert.equal(capturedLogs, 0);
    } finally {
      await app.close();
    }
  };
  try {
    await prisma.$connect();
    const before = await snapshot(prisma);
    for (const method of ['log', 'info', 'error', 'warn', 'debug'] as const)
      console[method] = capture;
    await prisma.$transaction(
      async (tx) => {
        await tx.$executeRaw`SET TRANSACTION READ ONLY`;
        await withHttp(tx, checkCanonicalHttp);
        assert.ok(
          (await writes(tx)).every(
            (row) =>
              row.inserted === 0n && row.updated === 0n && row.deleted === 0n,
          ),
        );
      },
      { timeout: 15000 },
    );

    const rollback = new Error(
      'Rollback disabled authorization probe fixture.',
    );
    let completed = false;
    try {
      await prisma.$transaction(
        async (tx) => {
          const marker = `m5.1-disabled-${randomUUID()}`;
          const redirectUri = 'http://localhost:3100/m51-disabled-callback';
          await tx.client.create({
            data: {
              clientId: marker,
              name: marker,
              clientType: 'CONFIDENTIAL',
              enabled: false,
              redirectUris: { create: { redirectUri } },
            },
            select: { id: true },
          });
          const state = await snapshot(tx);
          const activity = await writes(tx);
          await withHttp(tx, (testOrigin) =>
            checkHttp(
              testOrigin,
              { ...student, client_id: marker, redirect_uri: redirectUri },
              400,
            ),
          );
          assert.deepEqual(await writes(tx), activity);
          assert.ok(
            JSON.stringify(await snapshot(tx)) === JSON.stringify(state),
          );
          completed = true;
          throw rollback;
        },
        { timeout: 15000 },
      );
    } catch (error) {
      if (error !== rollback) throw error;
    }
    assert.ok(completed);
    // Also exercise the rebuilt full application, including its unchanged global filters.
    await checkCanonicalHttp(origin);
    const health = await fetch(new URL('/health', origin), {
      signal: AbortSignal.timeout(5000),
    });
    assert.equal(health.status, 200);
    assert.deepEqual(await health.json(), { status: 'ok' });
    assert.ok(
      JSON.stringify(await snapshot(prisma)) === JSON.stringify(before),
    );
    Object.assign(console, originals);
    console.log(
      'M5.1 real PostgreSQL/HTTP passed: canonical 204, unknown/disabled rejected, exact URI/nonce/PUBLIC S256 checks, duplicate rejection, no Location or Set-Cookie, fixed OAuth errors.',
    );
    console.log(
      'Read-only transaction/zero-write counters/disabled fixture rollback/full-row fingerprints passed; canonical registry and all domain/migration rows unchanged.',
    );
    console.log(
      'Rebuilt application HTTP and /health passed; temporary HTTP servers closed; no session, code, token or grant behavior added.',
    );
  } finally {
    Object.assign(console, originals);
    await prisma.$disconnect();
  }
}

void checkAuthorizationRequests().catch(() => {
  console.error(
    'Authorization-request verification failed; inspect local development configuration, seeded registry and running application, then rerun.',
  );
  process.exitCode = 1;
});
