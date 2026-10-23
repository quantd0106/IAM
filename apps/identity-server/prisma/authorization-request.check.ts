// Explicit local PostgreSQL/HTTP verification; never startup/seed code.
import 'reflect-metadata';
import 'dotenv/config';
import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import { setTimeout } from 'node:timers/promises';
import type { Server } from 'node:http';
import type { INestApplication, LoggerService } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import { ConfigService } from '@nestjs/config';
import {
  validateEnvironment,
  type Environment,
} from '../src/config/env.schema.js';
import { PrismaPg } from '@prisma/adapter-pg';
import { createClient, RESP_TYPES } from 'redis';
import { PrismaClient, type Prisma } from '../src/generated/prisma/client.js';
import { PrismaService } from '../src/prisma/prisma.service.js';
import { OAuthModule } from '../src/oauth/oauth.module.js';
import { AuthorizationRequestService } from '../src/oauth/authorization-request.service.js';
import { AppModule } from '../src/app.module.js';
import { RedisService } from '../src/redis/redis.service.js';
import { IdpSessionStateService } from '../src/session/idp-session-state.service.js';
import { IdpSessionCookieService } from '../src/session/idp-session-cookie.service.js';
import { IdpSessionAuthenticationService } from '../src/session/idp-session-authentication.service.js';
import { PasswordService } from '../src/security/password/password.service.js';
import { buildRedisKey } from '../src/redis/redis-key.js';
import {
  AuthorizationCodeService,
  AUTHORIZATION_CODE_TTL_SECONDS,
} from '../src/oauth/authorization-code.service.js';
import {
  authorizationCodeStateSchema,
  type AuthorizationCodeInput,
} from '../src/oauth/authorization-code.state.js';

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
  code_challenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
  code_challenge_method: 'S256',
};
const invalid = {
  error: 'invalid_request',
  error_description: 'Invalid authorization request.',
};
const invalidScope = { ...invalid, error: 'invalid_scope' };
const unauthenticated = {
  statusCode: 401,
  error: 'Unauthorized',
  message: 'Authentication required.',
};
let verifiedHttpCases = 0;
let verifyCodeWrite:
  | ((
      origin: string,
      query: Record<string, string> | URLSearchParams,
      status: number,
      cookie?: string,
      code?: string,
    ) => Promise<void>)
  | undefined;
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
  UNION ALL SELECT 'refresh_token_families', COUNT(*)::int,
    md5(COALESCE(jsonb_agg(to_jsonb(t) ORDER BY id)::text, '[]')) FROM refresh_token_families t
  UNION ALL SELECT 'refresh_tokens', COUNT(*)::int,
    md5(COALESCE(jsonb_agg(to_jsonb(t) ORDER BY id)::text, '[]')) FROM refresh_tokens t
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
  cookie?: string,
): Promise<string | undefined> {
  const url = new URL('/oauth/authorize', origin);
  url.search = new URLSearchParams(query).toString();
  const response = await fetch(url, {
    headers: cookie === undefined ? {} : { Cookie: cookie },
    redirect: 'manual',
    signal: AbortSignal.timeout(5000),
  });
  assert.equal(response.status, status);
  assert.equal(response.headers.get('set-cookie'), null);
  assert.equal(response.headers.get('cache-control'), 'no-store');
  let returnedCode: string | undefined;
  if (status === 302) {
    assert.equal(await response.text(), '');
    const location = response.headers.get('location');
    assert.ok(location !== null);
    const parameters = new URLSearchParams(query);
    const redirectUri = parameters.get('redirect_uri')!;
    const state = parameters.get('state')!;
    const callback = new URL(location);
    const code = callback.searchParams.get('code');
    assert.ok(code !== null && /^[A-Za-z0-9_-]{43}$/.test(code));
    assert.equal(callback.searchParams.getAll('code').length, 1);
    assert.equal(callback.searchParams.getAll('state').length, 1);
    assert.ok(callback.searchParams.get('state') === state);
    const hashAt = redirectUri.indexOf('#');
    const base = hashAt < 0 ? redirectUri : redirectUri.slice(0, hashAt);
    const fragment = hashAt < 0 ? '' : redirectUri.slice(hashAt);
    const separator = base.includes('?')
      ? base.endsWith('?') || base.endsWith('&')
        ? ''
        : '&'
      : '?';
    assert.ok(
      location ===
        `${base}${separator}code=${encodeURIComponent(code)}&state=${encodeURIComponent(state)}${fragment}`,
    );
    returnedCode = code;
  } else {
    assert.equal(response.headers.get('location'), null);
    assert.deepEqual(
      await response.json(),
      status === 401 ? unauthenticated : body,
    );
  }
  verifiedHttpCases++;
  await verifyCodeWrite?.(origin, query, status, cookie, returnedCode);
  return returnedCode;
}
async function checkCanonicalHttp(
  origin: string,
  cookie?: string,
): Promise<void> {
  // M5.4 requires authentication; M5.6 changes authenticated success to 302 only.
  // All earlier 400 contracts stay unchanged, with or without a browser cookie.
  const check = (
    query: Record<string, string> | URLSearchParams,
    status: number,
    body = invalid,
  ): Promise<string | undefined> =>
    checkHttp(
      origin,
      query,
      status === 302 && cookie === undefined ? 401 : status,
      body,
      cookie,
    );
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
    await check(query, 302);
  }
  await check({ ...student, client_id: `m5.1-unknown-${randomUUID()}` }, 400);
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
    await check({ ...student, redirect_uri }, 400);
  const withoutNonce: Record<string, string> = { ...student };
  delete withoutNonce.nonce;
  await check(withoutNonce, 400);
  const withoutPkce: Record<string, string> = { ...student };
  delete withoutPkce.code_challenge;
  delete withoutPkce.code_challenge_method;
  await check(withoutPkce, 400);
  await check({ ...student, code_challenge_method: 'plain' }, 400);
  await check(
    new URLSearchParams([
      ...Object.entries(student),
      ['state', 'duplicate-m51-state'],
    ]),
    400,
  );
  // M5.3 supersedes syntax-only acceptance of unassigned scope tokens.
  await check({ ...student, scope: 'custom.scope OpenID' }, 400, invalidScope);
  await check({ ...student, response_type: 'token' }, 400, {
    ...invalid,
    error: 'unsupported_response_type',
  });

  // M5.2 extends, not replaces, every M5.1 regression above.
  for (const demo of demos) {
    const query: Record<string, string> = {
      ...student,
      client_id: demo.clientId,
      redirect_uri: demo.redirectUri,
    };
    await check(query, 302);
    const challengeOnly = { ...query };
    delete challengeOnly.code_challenge_method;
    await check(challengeOnly, 400);
    const methodOnly = { ...query };
    delete methodOnly.code_challenge;
    await check(methodOnly, 400);
    for (const code_challenge_method of ['plain', 's256', ' S256', 'S256 '])
      await check({ ...query, code_challenge_method }, 400);
    for (const code_challenge of [
      '',
      'x',
      'A'.repeat(42),
      'A'.repeat(44),
      `${student.code_challenge}=`,
      ...[
        '=',
        '+',
        '/',
        '.',
        '~',
        ' ',
        '\t',
        '\n',
        '\r',
        '\u2028',
        '\u00e9',
      ].map((character) => `${'A'.repeat(42)}${character}`),
      `${'A'.repeat(40)}%2D`,
    ])
      await check({ ...query, code_challenge }, 400);
  }

  // Canonical ClientScope assignments; no fixture/seed changes are needed.
  for (const [clientId, scope, status] of [
    ['student-spa', 'openid banking.transactions.read', 400],
    ['student-spa', 'openid definitely.unknown', 400],
    ['student-spa', 'OpenID', 400],
    ['student-spa', 'profile openid profile email openid', 302],
    ['student-spa', 'profile', 302],
    ['banking-web', 'openid banking.transactions.read', 302],
    ['banking-web', 'BANKING.TRANSACTIONS.READ', 400],
    ['admin-portal', 'openid banking.transactions.read', 400],
  ] as const) {
    const demo = demos.find((item) => item.clientId === clientId);
    assert.ok(demo);
    await check(
      {
        ...student,
        client_id: clientId,
        redirect_uri: demo.redirectUri,
        scope,
      },
      status,
      invalidScope,
    );
  }
}

async function checkAuthorizationRequests(): Promise<void> {
  const connectionString = process.env.DATABASE_URL?.trim();
  const redisUrl = process.env.REDIS_URL?.trim();
  const origin = process.env.ISSUER_URL?.trim() || 'http://localhost:3000';
  if (
    !connectionString ||
    !redisUrl ||
    !['development', 'test'].includes(process.env.NODE_ENV ?? 'development') ||
    !local(connectionString, ['postgresql:', 'postgres:']) ||
    !local(redisUrl, ['redis:', 'rediss:']) ||
    !local(origin, ['http:', 'https:'])
  )
    throw new Error(
      'Authorization probe requires local development PostgreSQL/Redis/HTTP.',
    );
  const prisma = new PrismaClient({
    adapter: new PrismaPg({ connectionString, connectionTimeoutMillis: 5000 }),
  });
  const config = new ConfigService<Environment, true>(
    validateEnvironment(process.env),
  );
  // Read-only observer, never injected into OAuthModule or used by the endpoint.
  const redis = createClient({
    url: redisUrl,
    disableOfflineQueue: true,
    socket: { connectTimeout: 5000, reconnectStrategy: false },
  });
  redis.on('error', () => undefined);
  const redisSnapshot = async (): Promise<[string, string][]> => {
    const reader = redis.withCommandOptions({
      abortSignal: AbortSignal.timeout(5000),
    });
    const binary = reader.withTypeMapping({ [RESP_TYPES.BLOB_STRING]: Buffer });
    const entries = new Map<string, string>();
    for await (const keys of reader.scanIterator({ COUNT: 100 })) {
      for (const key of keys) {
        assert.ok(
          entries.size < 1000,
          'Probe requires a bounded local Redis dataset.',
        );
        const value = await binary.dump(key);
        assert.ok(Buffer.isBuffer(value));
        entries.set(key, value.toString('hex'));
      }
    }
    // Keep opaque keys/values in memory only, never print them.
    return [...entries].sort(([left], [right]) =>
      left < right ? -1 : left > right ? 1 : 0,
    );
  };
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
      .overrideProvider(RedisService)
      .useValue({})
      .overrideProvider(IdpSessionStateService)
      .useValue({
        touch: () => {
          throw new Error('No-cookie regression must not touch Redis.');
        },
      })
      .useMocker((token) => (token === ConfigService ? config : undefined))
      .setLogger(logger)
      .compile();
    const app: INestApplication<Server> = context.createNestApplication<
      INestApplication<Server>
    >({ logger });
    try {
      await app.listen(0, '127.0.0.1');
      capturedLogs = 0;
      await verify(await app.getUrl());
      const grant = await app
        .get(AuthorizationRequestService)
        .validate({ ...student, scope: 'profile openid profile email openid' });
      assert.ok(grant.ok);
      assert.deepEqual(grant.request.scope, [
        'profile',
        'openid',
        'profile',
        'email',
        'openid',
      ]);
      assert.deepEqual(grant.grantedScopes, ['profile', 'openid', 'email']);
      assert.equal(capturedLogs, 0);
    } finally {
      await app.close();
    }
  };
  const checkSessionFlow = async (): Promise<void> => {
    const userId = randomUUID();
    const marker = `m5.6-${randomUUID()}`;
    const email = `${marker}@example.invalid`;
    const password = `temporary-${randomUUID()}`;
    const ids = new Set<string>();
    const key = (id: string): string => buildRedisKey('session', id);
    const rateKey = buildRedisKey('rate', userId, 'login-failure');
    let app: INestApplication<Server> | undefined;
    let redisFault = false;
    let prismaFault = false;
    let touches = 0;
    let persistentReads = 0;
    let createdUser = false;
    const callbackClientId = randomUUID();
    const callbackClientName = `${marker}-callbacks`;
    let createdClient = false;
    const codeKeys = new Set<string>();
    const collisionEntries = new Map<string, string>();
    const attempts: string[] = [];
    const reserved = new Map<string, { value: string; ttl: number }>();
    const issued: {
      code: string;
      input: AuthorizationCodeInput;
      before: number;
      after: number;
    }[] = [];
    let collisionsRemaining = 0;
    let codeFault = false;
    let reservationFailure = false;
    let expectedAttempts = 1;
    let unavailableRedis: RedisService | undefined;
    try {
      // Short idle TTL only in this temporary app; production/env defaults stay frozen.
      const probeConfig = new ConfigService<Environment, true>({
        ...validateEnvironment(process.env),
        SESSION_IDLE_TTL_SECONDS: 5,
      });
      const module = await Test.createTestingModule({ imports: [AppModule] })
        .setLogger(logger)
        .overrideProvider(ConfigService)
        .useValue(probeConfig)
        .overrideProvider(AuthorizationCodeService)
        .useFactory({
          inject: [RedisService],
          factory: (liveRedis: RedisService) => {
            const service = new AuthorizationCodeService({
              getAndDelete: () => {
                throw new Error('Authorization probe must not consume.');
              },
              setIfAbsentWithTtl: async (codeKey, serialized, ttl) => {
                attempts.push(codeKey);
                assert.ok(/^oauth:code:[0-9a-f]{64}$/.test(codeKey));
                assert.equal(ttl, 120);
                if (collisionsRemaining > 0) {
                  collisionsRemaining--;
                  const sentinel = 'probe-owned-collision-' + randomUUID();
                  assert.equal(
                    await redis.set(codeKey, sentinel, { NX: true, EX: 120 }),
                    'OK',
                  );
                  codeKeys.add(codeKey);
                  collisionEntries.set(codeKey, sentinel);
                  await redis.pExpire(codeKey, 30000);
                }
                const stored = await (
                  codeFault ? unavailableRedis! : liveRedis
                ).setIfAbsentWithTtl(codeKey, serialized, ttl);
                if (stored) {
                  codeKeys.add(codeKey);
                  reserved.set(codeKey, {
                    value: serialized,
                    ttl: await redis.pTTL(codeKey),
                  });
                }
                if (collisionEntries.has(codeKey)) {
                  assert.ok(
                    (await redis.get(codeKey)) ===
                      collisionEntries.get(codeKey),
                  );
                  const collisionTtl = await redis.pTTL(codeKey);
                  assert.ok(collisionTtl > 0 && collisionTtl <= 30000);
                }
                return stored;
              },
            });
            return {
              issue: async (input: AuthorizationCodeInput) => {
                const before = Date.now();
                const result = await service.issue(input);
                issued.push({ ...result, input, before, after: Date.now() });
                return result;
              },
            };
          },
        })
        .overrideProvider(IdpSessionAuthenticationService)
        .useFactory({
          inject: [
            IdpSessionStateService,
            PrismaService,
            IdpSessionCookieService,
          ],
          factory: (
            states: IdpSessionStateService,
            database: PrismaService,
            cookies: IdpSessionCookieService,
          ) =>
            new IdpSessionAuthenticationService(
              {
                touch: (id) => {
                  touches++;
                  if (redisFault)
                    throw new Error('Controlled private Redis probe fault.');
                  return states.touch(id);
                },
              },
              {
                session: {
                  findFirst: (input: Prisma.SessionFindFirstArgs) => {
                    persistentReads++;
                    if (prismaFault)
                      throw new Error(
                        'Controlled private PostgreSQL probe fault.',
                      );
                    return database.session.findFirst(input);
                  },
                },
              } as unknown as PrismaService,
              cookies,
            ),
        })
        .compile();
      app = module.createNestApplication<INestApplication<Server>>({ logger });
      await app.listen(0, '127.0.0.1');
      const temporaryOrigin = await app.getUrl();
      const runtime = app.get(IdpSessionStateService);
      const runtimeRedis = app.get(RedisService);
      const cookies = app.get(IdpSessionCookieService);
      let checkedIssues = 0;
      let checkedAttempts = 0;
      let checkedKeys = 0;
      verifyCodeWrite = async (
        targetOrigin,
        query,
        status,
        cookieHeader,
        returnedCode,
      ) => {
        if (targetOrigin !== temporaryOrigin) return;
        assert.equal(issued.length, checkedIssues + (status === 302 ? 1 : 0));
        if (status !== 302 && !codeFault && !reservationFailure)
          assert.equal(attempts.length, checkedAttempts);
        if (status === 302) {
          const latest = issued.at(-1)!;
          assert.ok(returnedCode !== undefined && returnedCode === latest.code);
          const codeKey = buildRedisKey(
            'oauth:code',
            createHash('sha256').update(returnedCode).digest('hex'),
          );
          assert.ok(codeKeys.has(codeKey));
          assert.ok(!codeKey.includes(latest.code));
          const value = await redis.get(codeKey);
          assert.ok(value !== null && !value.includes(latest.code));
          assert.ok(value === reserved.get(codeKey)?.value);
          const stored = authorizationCodeStateSchema.parse(JSON.parse(value));
          const parameters = new URLSearchParams(query);
          const id = cookies.parse(cookieHeader);
          assert.ok(id);
          const session = await runtime.read(id);
          assert.ok(session);
          assert.deepEqual(Object.keys(stored), [
            'clientId',
            'userId',
            'sessionId',
            'redirectUri',
            'grantedScopes',
            'codeChallenge',
            'nonce',
            'authTime',
            'expiresAt',
          ]);
          assert.deepEqual(stored, {
            clientId: parameters.get('client_id'),
            userId,
            sessionId: id,
            redirectUri: parameters.get('redirect_uri'),
            grantedScopes: [...new Set(parameters.get('scope')!.split(' '))],
            codeChallenge: parameters.get('code_challenge'),
            nonce: parameters.get('nonce'),
            authTime: session.authTime,
            expiresAt: stored.expiresAt,
          });
          assert.ok(
            stored.expiresAt >= latest.before + 120000 &&
              stored.expiresAt <= latest.after + 120000,
          );
          const ttl = await redis.pTTL(codeKey);
          assert.ok(ttl > 0 && ttl <= AUTHORIZATION_CODE_TTL_SECONDS * 1000);
          assert.ok(ttl <= reserved.get(codeKey)!.ttl);
          // Each no-collision success reserves exactly one remembered key.
          assert.equal(attempts.length, checkedAttempts + expectedAttempts);
          assert.equal(codeKeys.size, checkedKeys + expectedAttempts);
        }
        checkedIssues = issued.length;
        checkedAttempts = attempts.length;
        checkedKeys = codeKeys.size;
      };
      const deadline = Date.now() + 10000;
      for (;;) {
        try {
          await runtimeRedis.ttl(rateKey);
          break;
        } catch {
          if (Date.now() >= deadline)
            throw new Error('Authorization probe Redis readiness timeout.');
          await setTimeout(50);
        }
      }
      const passwordHash = await app.get(PasswordService).hash(password);
      assert.equal(await prisma.user.count({ where: { id: userId } }), 0);
      // Claim this absent UUID before the write so an uncertain create failure
      // still cleans only the exact fixture identity chosen by this probe.
      createdUser = true;
      await prisma.user.create({
        data: {
          id: userId,
          email,
          username: marker,
          credential: { create: { passwordHash } },
        },
      });
      capturedLogs = 0;
      const login = async (targetOrigin: string): Promise<string> => {
        const response = await fetch(new URL('/auth/login', targetOrigin), {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            identifier: { type: 'email', value: email },
            password,
          }),
          signal: AbortSignal.timeout(10000),
        });
        assert.equal(response.status, 204);
        assert.equal(await response.text(), '');
        const setCookies = response.headers.getSetCookie();
        assert.equal(setCookies.length, 1);
        const id = cookies.parse(setCookies[0].split(';')[0]);
        assert.ok(id);
        ids.add(id);
        assert.equal(setCookies[0], cookies.serialize(id));
        return id;
      };
      const cookie = (id: string): string =>
        cookies.serialize(id).split(';')[0];
      // The exact same query is resubmitted, not persisted/rewritten as a continuation.
      for (const targetOrigin of [temporaryOrigin, origin]) {
        await checkHttp(targetOrigin, student, 401);
        const id = await login(targetOrigin);
        const persistentBefore = await prisma.session.findUniqueOrThrow({
          where: { id },
        });
        const stateBefore = await runtime.read(id);
        assert.ok(stateBefore);
        assert.equal(stateBefore.userId, userId);
        assert.equal(
          stateBefore.createdAt,
          persistentBefore.createdAt.getTime(),
        );
        assert.equal(
          stateBefore.absoluteExpiresAt,
          persistentBefore.expiresAt.getTime(),
        );
        const keysBeforeCompose =
          targetOrigin === origin
            ? new Set((await redisSnapshot()).map(([redisKey]) => redisKey))
            : undefined;
        const returnedCode = await checkHttp(
          targetOrigin,
          student,
          302,
          invalid,
          cookie(id),
        );
        if (keysBeforeCompose) {
          // Compose is a black box: bounded local observer only; delete only state
          // belonging to this absent-before-run fixture UUID, never arbitrary keys.
          const created = (await redisSnapshot())
            .map(([redisKey]) => redisKey)
            .filter((redisKey) => !keysBeforeCompose.has(redisKey));
          assert.equal(created.length, 1);
          const codeKey = created[0];
          assert.ok(returnedCode !== undefined);
          assert.ok(
            codeKey ===
              buildRedisKey(
                'oauth:code',
                createHash('sha256').update(returnedCode).digest('hex'),
              ),
          );
          assert.ok(/^oauth:code:[0-9a-f]{64}$/.test(codeKey));
          const stored = authorizationCodeStateSchema.parse(
            JSON.parse((await redis.get(codeKey))!),
          );
          assert.equal(stored.userId, userId);
          assert.ok(!(await redis.get(codeKey))!.includes(returnedCode));
          codeKeys.add(codeKey);
          checkedKeys = codeKeys.size;
          assert.equal(stored.clientId, student.client_id);
          assert.equal(stored.authTime, stateBefore.authTime);
          assert.deepEqual(stored.grantedScopes, [
            'openid',
            'profile',
            'email',
          ]);
          assert.equal(stored.redirectUri, student.redirect_uri);
          assert.equal(stored.codeChallenge, student.code_challenge);
          assert.equal(stored.nonce, student.nonce);
          assert.ok(
            (await redis.ttl(codeKey)) > 0 && (await redis.ttl(codeKey)) <= 120,
          );
        }
        assert.deepEqual(
          await prisma.session.findUniqueOrThrow({ where: { id } }),
          persistentBefore,
        );
        const continued = await app
          .get(IdpSessionAuthenticationService)
          .authenticate(cookie(id));
        assert.ok(continued);
        assert.equal(continued.userId, userId);
        assert.equal(continued.sessionId, id);
        if (targetOrigin === temporaryOrigin) {
          await setTimeout(1100);
          const idleBefore = await redis.pTTL(key(id));
          await checkHttp(targetOrigin, student, 302, invalid, cookie(id));
          const idleAfter = await redis.pTTL(key(id));
          assert.ok(idleAfter > idleBefore + 500 && idleAfter <= 5000);
          const after = await runtime.read(id);
          assert.ok(after);
          assert.ok(after.lastActivityAt > stateBefore.lastActivityAt);
          assert.deepEqual(
            { ...after, lastActivityAt: stateBefore.lastActivityAt },
            stateBefore,
          );
          assert.deepEqual(
            await prisma.session.findUniqueOrThrow({ where: { id } }),
            persistentBefore,
          );
          // Existing M5.1-M5.3 matrix now also runs with a genuine central session.
          await checkCanonicalHttp(targetOrigin, cookie(id));
          // New exact registrations belong only to this probe, not the demo seed.
          const registeredCallbacks = [
            'http://localhost:3100/m56-call%62ack?tenant=a&mode=b',
            'HTTP://LOCALHOST:3100/m56-call%62ack?b=%2f&a=hello+world#opaque%2F?x=1#tail',
            'http://localhost:3100/m56-callback#opaque?x=1',
          ];
          assert.equal(
            await prisma.client.count({ where: { id: callbackClientId } }),
            0,
          );
          createdClient = true;
          const profile = await prisma.scope.findUniqueOrThrow({
            where: { name: 'profile' },
            select: { id: true },
          });
          await prisma.client.create({
            data: {
              id: callbackClientId,
              clientId: callbackClientName,
              name: callbackClientName,
              clientType: 'CONFIDENTIAL',
              redirectUris: {
                create: registeredCallbacks.map((redirectUri) => ({
                  redirectUri,
                })),
              },
              allowedScopes: { create: { scopeId: profile.id } },
            },
          });
          for (const redirectUri of registeredCallbacks)
            await checkHttp(
              targetOrigin,
              {
                response_type: 'code',
                client_id: callbackClientName,
                redirect_uri: redirectUri,
                scope: 'profile',
                state: ' M5.6 Tiếng Việt / 漢字 / 🙂 &+=?/#%\r\n e\u0301 ',
              },
              302,
              invalid,
              cookie(id),
            );
          await checkHttp(
            targetOrigin,
            {
              response_type: 'code',
              client_id: 'banking-web',
              redirect_uri: demos[1].redirectUri,
              scope: 'profile',
              state: student.state,
            },
            302,
            invalid,
            cookie(id),
          );
          const untouched = await redis.get(key(id));
          const touchCount = touches;
          await checkHttp(
            targetOrigin,
            { ...student, redirect_uri: 'https://invalid.example.invalid' },
            400,
            invalid,
            cookie(id),
          );
          await checkHttp(
            targetOrigin,
            { ...student, scope: 'definitely.unknown' },
            400,
            invalidScope,
            cookie(id),
          );
          assert.equal(touches, touchCount);
          assert.equal(await redis.get(key(id)), untouched);
          redisFault = true;
          const reads = persistentReads;
          await checkHttp(
            targetOrigin,
            student,
            500,
            {
              error: 'server_error',
              error_description: 'Authorization request failed.',
            },
            cookie(id),
          );
          assert.equal(persistentReads, reads);
          redisFault = false;
          prismaFault = true;
          await checkHttp(
            targetOrigin,
            student,
            500,
            {
              error: 'server_error',
              error_description: 'Authorization request failed.',
            },
            cookie(id),
          );
          prismaFault = false;
          await checkHttp(targetOrigin, student, 302, invalid, cookie(id));
          const firstCode = issued.at(-1)!.code;
          await checkHttp(targetOrigin, student, 302, invalid, cookie(id));
          assert.ok(firstCode !== issued.at(-1)!.code);
          // Occupy the first random candidate at the storage seam, then use
          // the real NX primitive. The collided value must remain untouched.
          collisionsRemaining = 1;
          expectedAttempts = 2;
          const attemptsBeforeCollision = attempts.length;
          await checkHttp(targetOrigin, student, 302, invalid, cookie(id));
          assert.equal(attempts.length, attemptsBeforeCollision + 2);
          assert.ok(attempts.at(-1) !== attempts.at(-2));
          expectedAttempts = 1;
          collisionsRemaining = 3;
          reservationFailure = true;
          const attemptsBeforeExhaustion = attempts.length;
          await checkHttp(
            targetOrigin,
            student,
            500,
            {
              error: 'server_error',
              error_description: 'Authorization request failed.',
            },
            cookie(id),
          );
          assert.equal(attempts.length, attemptsBeforeExhaustion + 3);
          reservationFailure = false;
          for (const [codeKey, sentinel] of collisionEntries)
            assert.ok((await redis.get(codeKey)) === sentinel);
          // Isolate a real disconnected Redis client at the code-write boundary:
          // session authentication still uses the healthy shared Redis client.
          unavailableRedis = new RedisService(probeConfig);
          unavailableRedis.onModuleInit();
          const codeRedisDeadline = Date.now() + 10000;
          for (;;) {
            try {
              await unavailableRedis.ttl(rateKey);
              break;
            } catch {
              if (Date.now() >= codeRedisDeadline)
                throw new Error('Code Redis readiness timeout.');
              await setTimeout(50);
            }
          }
          await unavailableRedis.onModuleDestroy();
          codeFault = true;
          const failedAttempt = attempts.length;
          await checkHttp(
            targetOrigin,
            student,
            500,
            {
              error: 'server_error',
              error_description: 'Authorization request failed.',
            },
            cookie(id),
          );
          assert.equal(attempts.length, failedAttempt + 1);
          assert.equal(await redis.get(attempts.at(-1)!), null);
          codeFault = false;
          await checkHttp(targetOrigin, student, 302, invalid, cookie(id));
        }
        const logout = await fetch(new URL('/auth/logout', targetOrigin), {
          method: 'POST',
          headers: { Cookie: cookie(id) },
          signal: AbortSignal.timeout(5000),
        });
        assert.equal(logout.status, 204);
        assert.equal(await logout.text(), '');
        assert.deepEqual(logout.headers.getSetCookie(), [cookies.clear()]);
        await checkHttp(targetOrigin, student, 401, invalid, cookie(id));
        assert.equal(await runtime.read(id), null);
        assert.equal(
          (await prisma.session.findUniqueOrThrow({ where: { id } })).status,
          'REVOKED',
        );
      }
      for (const invalidCookie of [
        '',
        'iam.sid=bad',
        `${config.getOrThrow('COOKIE_NAME', { infer: true })}=bad`,
        `${cookie([...ids][0])}; ${cookie([...ids][0])}`,
      ])
        await checkHttp(temporaryOrigin, student, 401, invalid, invalidCookie);
      await checkHttp(
        temporaryOrigin,
        { ...student, sessionId: [...ids][0], userId },
        401,
      );

      // All incoherent/expired fixtures are owned by this probe, never canonical data.
      for (const variant of [
        'missing runtime',
        'expired runtime',
        'corrupt runtime',
        'missing row',
        'revoked',
        'expired row',
        'wrong user',
        'createdAt',
        'absolute expiry',
      ]) {
        const id = randomUUID();
        ids.add(id);
        const now = Date.now();
        const expiresAt = now + 60000;
        if (variant !== 'missing row')
          await prisma.session.create({
            data: {
              id,
              userId,
              status: variant === 'revoked' ? 'REVOKED' : 'ACTIVE',
              createdAt: new Date(now),
              lastActivityAt: new Date(now),
              expiresAt: new Date(
                variant === 'expired row' ? now - 1 : expiresAt,
              ),
            },
          });
        if (variant !== 'missing runtime')
          await runtime.create(id, {
            userId: variant === 'wrong user' ? randomUUID() : userId,
            authTime: now,
            mfaLevel: 'password',
            createdAt: variant === 'createdAt' ? now - 1 : now,
            lastActivityAt: now,
            absoluteExpiresAt:
              variant === 'absolute expiry' ? expiresAt + 1 : expiresAt,
          });
        if (variant === 'corrupt runtime')
          await redis.set(key(id), '{', { PX: 5000 });
        if (variant === 'expired runtime') {
          await redis.pExpire(key(id), 1);
          await setTimeout(30);
        }
        const rowsBefore = await snapshot(prisma);
        await checkHttp(temporaryOrigin, student, 401, invalid, cookie(id));
        assert.deepEqual(await snapshot(prisma), rowsBefore);
        if (
          ['missing runtime', 'expired runtime', 'corrupt runtime'].includes(
            variant,
          )
        )
          assert.equal(await redis.get(key(id)), null);
      }
      const boundedId = randomUUID();
      ids.add(boundedId);
      const now = Date.now();
      const absolute = now + 2000;
      await prisma.session.create({
        data: {
          id: boundedId,
          userId,
          createdAt: new Date(now),
          lastActivityAt: new Date(now),
          expiresAt: new Date(absolute),
        },
      });
      await runtime.create(boundedId, {
        userId,
        authTime: now,
        mfaLevel: 'password',
        createdAt: now,
        lastActivityAt: now,
        absoluteExpiresAt: absolute,
      });
      await checkHttp(
        temporaryOrigin,
        student,
        302,
        invalid,
        cookie(boundedId),
      );
      const boundedTtl = await redis.pTTL(key(boundedId));
      assert.ok(boundedTtl > 0 && boundedTtl <= absolute - Date.now() + 50);
      await setTimeout(Math.max(0, absolute - Date.now()) + 50);
      await checkHttp(
        temporaryOrigin,
        student,
        401,
        invalid,
        cookie(boundedId),
      );
      assert.equal(await redis.get(key(boundedId)), null);
      assert.equal(
        (
          await prisma.session.findUniqueOrThrow({ where: { id: boundedId } })
        ).expiresAt.getTime(),
        absolute,
      );
      assert.equal(capturedLogs, 0);
    } finally {
      verifyCodeWrite = undefined;
      redisFault = false;
      prismaFault = false;
      try {
        try {
          await app?.close();
        } finally {
          await unavailableRedis?.onModuleDestroy();
        }
      } finally {
        if (createdUser) {
          // Recover even a code whose HTTP response/Redis reply was lost. This is
          // the existing bounded local snapshot convention, not runtime scanning.
          for (const [redisKey] of await redisSnapshot()) {
            if (!/^oauth:code:[0-9a-f]{64}$/.test(redisKey)) continue;
            const value = await redis.get(redisKey);
            if (value === null) continue;
            try {
              const stored = authorizationCodeStateSchema.safeParse(
                JSON.parse(value),
              );
              if (stored.success && stored.data.userId === userId)
                codeKeys.add(redisKey);
            } catch {
              /* Unrelated/collision values are never adopted by content. */
            }
          }
          for (const codeKey of codeKeys) {
            await redis.del(codeKey);
            assert.equal(await redis.get(codeKey), null);
          }
          const owned = await prisma.session.findMany({
            where: { userId },
            select: { id: true },
          });
          for (const row of owned) ids.add(row.id);
          for (const id of ids) {
            await redis.del(key(id));
            assert.equal(await redis.get(key(id)), null);
          }
          await redis.del(rateKey);
          assert.equal(await redis.get(rateKey), null);
          await prisma.$transaction([
            ...(createdClient
              ? [
                  prisma.clientScope.deleteMany({
                    where: { clientId: callbackClientId },
                  }),
                  prisma.clientRedirectUri.deleteMany({
                    where: { clientId: callbackClientId },
                  }),
                  prisma.client.deleteMany({
                    where: {
                      id: callbackClientId,
                      clientId: callbackClientName,
                    },
                  }),
                ]
              : []),
            prisma.session.deleteMany({ where: { userId } }),
            prisma.credential.deleteMany({ where: { userId } }),
            prisma.user.deleteMany({
              where: { id: userId, email, username: marker },
            }),
          ]);
          assert.equal(await prisma.user.count({ where: { id: userId } }), 0);
          assert.equal(await prisma.session.count({ where: { userId } }), 0);
          assert.equal(await prisma.credential.count({ where: { userId } }), 0);
          assert.equal(
            await prisma.client.count({ where: { id: callbackClientId } }),
            0,
          );
          assert.equal(
            await prisma.clientRedirectUri.count({
              where: { clientId: callbackClientId },
            }),
            0,
          );
          assert.equal(
            await prisma.clientScope.count({
              where: { clientId: callbackClientId },
            }),
            0,
          );
        }
      }
    }
  };
  try {
    await prisma.$connect();
    await redis.connect();
    const before = await snapshot(prisma);
    const redisBefore = await redisSnapshot();
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
          await withHttp(tx, async (testOrigin) => {
            await checkHttp(
              testOrigin,
              { ...student, client_id: marker, redirect_uri: redirectUri },
              400,
            );
          });
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
    await checkSessionFlow();
    const health = await fetch(new URL('/health', origin), {
      signal: AbortSignal.timeout(5000),
    });
    assert.equal(health.status, 200);
    assert.deepEqual(await health.json(), { status: 'ok' });
    assert.ok(
      JSON.stringify(await snapshot(prisma)) === JSON.stringify(before),
    );
    assert.deepEqual(await redisSnapshot(), redisBefore);
    Object.assign(console, originals);
    console.log(
      'M5.1-M5.6 real PostgreSQL/Redis/HTTP passed: unchanged validation/session/code pipeline, authenticated empty-body 302 callback with original state and exactly the issued code; errors keep fixed 400/401/500 without Location or Set-Cookie.',
    );
    console.log(
      'Read-only validation/counters/disabled fixture rollback passed; authorization performs no PostgreSQL writes; owned login/session/callback-registry fixtures cleaned; full-row fingerprints and canonical registry unchanged.',
    );
    console.log(
      'Real login -> cookie -> same authorization request -> logout passed on temporary and Compose apps; Redis idle touch/absolute cap, coherence and controlled Redis/Prisma faults passed; temporary server/clients closed.',
    );
    console.log(
      `M5.1-M5.6 passed ${verifiedHttpCases} real HTTP authorization cases; returned-code SHA-256/nine-field state including trusted sessionId/unchanged 120-second TTL/exact query-fragment and Unicode-state preservation/independent codes/NX collision retry and exhaustion/disconnected code Redis failure passed; all probe-owned code keys cleaned; no token/consume; ten DB fingerprints and Redis snapshot restored unchanged.`,
    );
  } finally {
    Object.assign(console, originals);
    try {
      await prisma.$disconnect();
    } finally {
      if (redis.isOpen) redis.destroy();
    }
  }
}

void checkAuthorizationRequests().catch(() => {
  console.error(
    'Authorization-request verification failed; inspect local development configuration, seeded registry and running application, then rerun.',
  );
  process.exitCode = 1;
});
