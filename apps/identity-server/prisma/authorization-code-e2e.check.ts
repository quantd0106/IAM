// Explicit real-stack HTTP E2E. DB/Redis writes below are owned teardown only.
import 'dotenv/config';
import assert from 'node:assert/strict';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { Pool } from 'pg';
import { createClient, RESP_TYPES } from 'redis';
import { z } from 'zod';
import { validateEnvironment } from '../src/config/env.schema.js';
import { authorizationCodeStateSchema } from '../src/oauth/authorization-code.state.js';
import { parseIdpSessionState } from '../src/session/idp-session-state.js';
import { buildRedisKey } from '../src/redis/redis-key.js';
import { accessTokenVerifier } from './access-token.check-support.js';

const publicKeyPrerequisite = new Error('Public signing key prerequisite.');
const clientId = 'student-spa';
const redirectUri = 'http://localhost:3200/callback';
const audience = 'student-api';
// Diagnostics use only fixed phase labels, never native error messages or inputs.
let phase = 'preconditions';

async function checkAuthorizationCodeE2e(): Promise<void> {
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
      local(env.ISSUER_URL, ['http:']) &&
      local(env.DATABASE_URL, ['postgres:', 'postgresql:']) &&
      local(env.REDIS_URL, ['redis:']),
    'E2E requires the local development HTTP/PostgreSQL/Redis stack.',
  );
  // Validate the existing PUBLIC key before creating any identity. Never generate keys.
  let verifyToken: Awaited<ReturnType<typeof accessTokenVerifier>>;
  try {
    verifyToken = await accessTokenVerifier(env);
  } catch {
    throw publicKeyPrerequisite;
  }

  const db = new Pool({
    connectionString: env.DATABASE_URL,
    connectionTimeoutMillis: 5000,
    query_timeout: 5000,
    statement_timeout: 5000,
  });
  const redis = createClient({
    url: env.REDIS_URL,
    disableOfflineQueue: true,
    socket: { connectTimeout: 5000, reconnectStrategy: false },
  }).withTypeMapping({ [RESP_TYPES.BLOB_STRING]: Buffer });
  redis.on('error', () => {
    /* Never print driver errors or private values. */
  });
  const tag = 'm68-' + randomUUID();
  const email = tag + '@example.invalid';
  const password = randomBytes(32).toString('base64url');
  const verifier = randomBytes(32).toString('base64url');
  const challenge = createHash('sha256')
    .update(verifier, 'ascii')
    .digest('base64url');
  const state = randomBytes(32).toString('base64url');
  const authorizeUrl = new URL('/oauth/authorize', env.ISSUER_URL);
  authorizeUrl.search = new URLSearchParams({
    response_type: 'code',
    client_id: clientId,
    redirect_uri: redirectUri,
    scope: 'profile',
    state,
    code_challenge: challenge,
    code_challenge_method: 'S256',
  }).toString();
  // Preserve exactly one serialized request for both authorization attempts.
  const authorizeRequest = authorizeUrl.href;
  const ownedKeys = new Set<string>();
  let registrationAttempted = false;
  let userId: string | undefined;
  let cookie: string | undefined;
  let sessionId: string | undefined;
  let redisBefore = new Map<string, { value: string; expires: number }>();

  const http = (path: string, options: RequestInit = {}): Promise<Response> =>
    fetch(new URL(path, env.ISSUER_URL), {
      ...options,
      redirect: 'manual',
      credentials: 'omit',
      signal: AbortSignal.timeout(10000),
    });
  const snapshotDb = async (): Promise<string> => {
    const tables = [
      ['users', 'id'],
      ['credentials', 'id'],
      ['sessions', 'id'],
      ['clients', 'id'],
      ['client_redirect_uris', 'id'],
      ['scopes', 'id'],
      ['client_scopes', 'client_id, scope_id'],
      ['_prisma_migrations', 'id'],
    ];
    return JSON.stringify(
      (
        await db.query(
          tables
            .map(
              ([table, order]) =>
                `SELECT '${table}' AS relation, COUNT(*)::int AS count, md5(COALESCE(jsonb_agg(to_jsonb(t) ORDER BY ${order})::text, '[]')) AS fingerprint FROM ${table} t`,
            )
            .join(' UNION ALL ') + ' ORDER BY relation',
        )
      ).rows,
    );
  };
  const snapshotRedis = async (requireStableExpiry = false) => {
    const values = new Map<string, { value: string; expires: number }>();
    let cursor = '0';
    let pages = 0;
    do {
      const page = await redis.scan(cursor, { COUNT: 100 });
      cursor = page.cursor.toString();
      assert.ok(
        ++pages <= 100 && values.size + page.keys.length <= 1000,
        'E2E requires a bounded local Redis dataset.',
      );
      for (const key of page.keys) {
        const value = await redis.dump(key);
        const expires = await redis.pExpireTime(key);
        assert.ok(
          value !== null && (expires === -1 || expires > Date.now()),
          'Redis key expired during snapshot; rerun on a quiet local stack.',
        );
        assert.ok(
          !requireStableExpiry ||
            expires === -1 ||
            expires > Date.now() + 30000,
          'Unrelated Redis key expires too soon; rerun after expiry.',
        );
        values.set(key.toString(), {
          value: value.toString('base64'),
          expires,
        });
      }
    } while (cursor !== '0');
    return values;
  };
  const sameRedis = (
    left: typeof redisBefore,
    right: typeof redisBefore,
  ): boolean =>
    left.size === right.size &&
    [...left].every(
      ([key, value]) =>
        right.get(key)?.value === value.value &&
        right.get(key)?.expires === value.expires,
    );

  const cleanup = async (): Promise<void> => {
    if (!registrationAttempted) return;
    let failed = false;
    const attempt = async (work: () => Promise<void>): Promise<void> => {
      try {
        await work();
      } catch {
        failed = true;
      }
    };
    // Also recover a committed registration whose HTTP response was lost.
    await attempt(async () => {
      const found = await db.query<{ id: string }>(
        'SELECT id FROM users WHERE email = $1 AND username = $2',
        [email, tag],
      );
      if (found.rows.length === 0) return;
      assert.ok(
        found.rows.length === 1 && z.uuid().safeParse(found.rows[0].id).success,
        'Cannot prove E2E identity ownership.',
      );
      const ownedId = found.rows[0].id;
      assert.ok(
        userId === undefined || userId === ownedId,
        'E2E identity ownership mismatch.',
      );
      const sessions = await db.query<{ id: string }>(
        'SELECT id FROM sessions WHERE user_id = $1',
        [ownedId],
      );
      for (const row of sessions.rows) {
        assert.ok(
          z.uuid().safeParse(row.id).success,
          'Invalid owned session identifier.',
        );
        ownedKeys.add(buildRedisKey('session', row.id));
      }
      // Only a cookie proven to belong to this newly registered user may be logged out.
      if (
        cookie !== undefined &&
        sessions.rows.some((row) => row.id === sessionId)
      ) {
        await attempt(async () => {
          const logout = await http('/auth/logout', {
            method: 'POST',
            headers: { Cookie: cookie! },
          });
          assert.equal(logout.status, 204, 'Owned logout failed.');
          assert.ok((await logout.text()) === '', 'Logout must have no body.');
          assert.ok(
            logout.headers.getSetCookie().length === 1 &&
              logout.headers.getSetCookie()[0] ===
                `${env.COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0${env.COOKIE_SECURE ? '; Secure' : ''}`,
            'Logout must clear the configured cookie.',
          );
          assert.equal(
            await redis.exists(buildRedisKey('session', sessionId!)),
            0,
            'Logout must remove owned runtime session.',
          );
        });
      }
      // Bounded read-only recovery for lost code/login replies, never adopt baseline keys.
      await attempt(async () => {
        for (const [key] of await snapshotRedis()) {
          if (redisBefore.has(key)) continue;
          if (
            !/^oauth:code:[0-9a-f]{64}$/.test(key) &&
            !(
              key.startsWith('session:') &&
              z.uuid().safeParse(key.slice(8)).success
            )
          )
            continue;
          const value = await redis.get(key);
          if (value === null) continue;
          if (key.startsWith('session:')) {
            if (parseIdpSessionState(value.toString())?.userId === ownedId)
              ownedKeys.add(key);
          } else {
            try {
              const stored = authorizationCodeStateSchema.safeParse(
                JSON.parse(value.toString()),
              );
              if (
                stored.success &&
                stored.data.userId === ownedId &&
                stored.data.clientId === clientId &&
                stored.data.redirectUri === redirectUri
              )
                ownedKeys.add(key);
            } catch {
              /* Never adopt malformed/unrelated code values. */
            }
          }
        }
      });
      ownedKeys.add(buildRedisKey('rate', ownedId, 'login-failure'));
      for (const key of ownedKeys)
        await attempt(async () => {
          assert.ok(
            !redisBefore.has(key),
            'Refusing to delete pre-existing Redis state.',
          );
          await redis.del(key);
          assert.equal(await redis.exists(key), 0, 'Owned Redis key remains.');
        });
      // FK order, transactional teardown, constrained again by the exact owned identity.
      const connection = await db.connect();
      try {
        await connection.query('BEGIN');
        const locked = await connection.query(
          'SELECT id FROM users WHERE id = $1 AND email = $2 AND username = $3 FOR UPDATE',
          [ownedId, email, tag],
        );
        assert.equal(
          locked.rowCount,
          1,
          'Owned identity changed before teardown.',
        );
        await connection.query('DELETE FROM sessions WHERE user_id = $1', [
          ownedId,
        ]);
        await connection.query('DELETE FROM credentials WHERE user_id = $1', [
          ownedId,
        ]);
        const removed = await connection.query(
          'DELETE FROM users WHERE id = $1 AND email = $2 AND username = $3',
          [ownedId, email, tag],
        );
        assert.equal(removed.rowCount, 1, 'Owned user was not removed.');
        await connection.query('COMMIT');
      } catch {
        await connection.query('ROLLBACK');
        throw new Error('Owned E2E teardown failed.');
      } finally {
        connection.release();
      }
    });
    assert.ok(!failed, 'Owned E2E cleanup failed; private details suppressed.');
  };

  try {
    phase = 'stack connection';
    await redis.connect();
    phase = 'registry preconditions';
    const metadata = await db.query<{
      client_type: string;
      enabled: boolean;
      access_token_audience: string | null;
      access_token_ttl: number;
      no_secret: boolean;
      redirect_registered: boolean;
      profile_allowed: boolean;
    }>(
      `
      SELECT c.client_type, c.enabled, c.access_token_audience, c.access_token_ttl,
        c.client_secret_hash IS NULL AS no_secret,
        EXISTS(SELECT 1 FROM client_redirect_uris r WHERE r.client_id=c.id AND r.redirect_uri=$2) AS redirect_registered,
        EXISTS(SELECT 1 FROM client_scopes cs JOIN scopes s ON s.id=cs.scope_id WHERE cs.client_id=c.id AND s.name='profile') AS profile_allowed
      FROM clients c WHERE c.client_id=$1`,
      [clientId, redirectUri],
    );
    const student = metadata.rows[0];
    assert.ok(
      metadata.rows.length === 1 &&
        student.client_type === 'PUBLIC' &&
        student.enabled &&
        student.no_secret &&
        student.redirect_registered &&
        student.profile_allowed &&
        student.access_token_audience === audience &&
        Number.isSafeInteger(student.access_token_ttl) &&
        student.access_token_ttl > 0,
      'E2E requires the canonical seeded PUBLIC Student SPA issuance configuration.',
    );
    assert.equal(
      (
        await db.query(
          'SELECT id FROM users WHERE email = $1 OR username = $2',
          [email, tag],
        )
      ).rowCount,
      0,
      'E2E identity collision; refusing to modify existing identity.',
    );
    const dbBefore = await snapshotDb();
    redisBefore = await snapshotRedis(true);
    try {
      phase = 'HTTP registration';
      registrationAttempted = true;
      const registration = await http('/auth/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, username: tag, password }),
      });
      assert.equal(registration.status, 201, 'HTTP registration failed.');
      assert.equal(registration.headers.get('set-cookie'), null);
      const registered: unknown = await registration.json();
      const parsed = z.object({ id: z.uuid() }).safeParse(registered);
      assert.ok(parsed.success, 'Registration must return a safe UUID.');
      userId = parsed.data.id; // Only the safe ID is retained from the registration result.
      const persisted = await db.query<{ argon2id: boolean }>(
        `
        SELECT EXISTS(SELECT 1 FROM credentials WHERE user_id=u.id AND password_hash LIKE '$argon2id$%') AS argon2id
        FROM users u WHERE u.id=$1 AND u.email=$2 AND u.username=$3`,
        [userId, email, tag],
      );
      assert.ok(
        persisted.rows.length === 1 && persisted.rows[0].argon2id,
        'HTTP registration must persist the owned User and Argon2id Credential.',
      );

      phase = 'authorize without session';
      const unauthenticated = await http(authorizeRequest);
      assert.equal(
        unauthenticated.status,
        401,
        'Authorize must require the central session.',
      );
      assert.equal(unauthenticated.headers.get('location'), null);
      assert.equal(unauthenticated.headers.get('set-cookie'), null);
      assert.equal(unauthenticated.headers.get('cache-control'), 'no-store');
      assert.ok(
        z
          .strictObject({
            statusCode: z.literal(401),
            error: z.literal('Unauthorized'),
            message: z.literal('Authentication required.'),
          })
          .safeParse(await unauthenticated.json()).success,
        'Expected existing login-required contract, not a login redirect.',
      );
      assert.ok(
        sameRedis(redisBefore, await snapshotRedis()),
        'Unauthenticated authorize must not issue a code or runtime state.',
      );

      phase = 'HTTP login and central session';
      const login = await http('/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          identifier: { type: 'username', value: tag },
          password,
        }),
      });
      assert.equal(login.status, 204, 'HTTP login failed.');
      assert.ok(
        (await login.text()) === '',
        'Login must not return OAuth tokens.',
      );
      phase = 'session cookie contract';
      const setCookies = login.headers.getSetCookie();
      assert.ok(
        setCookies.length === 1,
        'Login must issue one configured session cookie.',
      );
      const pair = setCookies[0].split(';')[0];
      assert.ok(
        pair.startsWith(env.COOKIE_NAME + '='),
        'Unexpected session cookie name.',
      );
      const parsedSession = z
        .uuid()
        .safeParse(pair.slice(env.COOKIE_NAME.length + 1));
      assert.ok(parsedSession.success, 'Cookie must contain only a UUID.');
      sessionId = parsedSession.data;
      cookie = pair;
      assert.ok(
        setCookies[0] ===
          `${env.COOKIE_NAME}=${sessionId}; Path=/; HttpOnly; SameSite=Lax${env.COOKIE_SECURE ? '; Secure' : ''}`,
        'Session cookie flags must match the frozen policy.',
      );
      phase = 'session persistence and coherence';
      // Prisma stores these timestamp-without-time-zone values as UTC. Read epoch
      // milliseconds in SQL, not pg's host-timezone-dependent Date parser.
      const row = (
        await db.query<{ created_ms: string; expires_ms: string }>(
          "SELECT (extract(epoch FROM created_at)*1000)::bigint::text AS created_ms, (extract(epoch FROM expires_at)*1000)::bigint::text AS expires_ms FROM sessions WHERE id=$1 AND user_id=$2 AND status='ACTIVE'",
          [sessionId, userId],
        )
      ).rows[0];
      const sessionKey = buildRedisKey('session', sessionId);
      const runtime = parseIdpSessionState(
        (await redis.get(sessionKey))?.toString() ?? null,
      );
      assert.ok(
        row &&
          runtime &&
          runtime.userId === userId &&
          runtime.createdAt === Number(row.created_ms) &&
          runtime.absoluteExpiresAt === Number(row.expires_ms) &&
          runtime.mfaLevel === 'password' &&
          (await redis.pTTL(sessionKey)) > 0,
        'Login must create coherent PostgreSQL and Redis central session state.',
      );
      ownedKeys.add(sessionKey);

      phase = 'authorize with session and callback';
      const authorized = await http(authorizeRequest, {
        headers: { Cookie: cookie },
      });
      assert.equal(
        authorized.status,
        302,
        'Same authorize request must resume after login.',
      );
      assert.equal(authorized.headers.get('cache-control'), 'no-store');
      assert.equal(authorized.headers.get('set-cookie'), null);
      assert.ok(
        (await authorized.text()) === '',
        'Authorization code must not appear in a response body.',
      );
      const location = authorized.headers.get('location');
      assert.ok(location !== null, 'Expected callback Location.');
      const callback = new URL(location);
      const code = callback.searchParams.get('code');
      assert.ok(
        code !== null && /^[A-Za-z0-9_-]{43}$/.test(code),
        'Expected one opaque callback code.',
      );
      assert.ok(
        callback.hash === '' &&
          callback.searchParams.getAll('code').length === 1 &&
          callback.searchParams.getAll('state').length === 1 &&
          callback.searchParams.get('state') === state &&
          location ===
            `${redirectUri}?code=${encodeURIComponent(code)}&state=${encodeURIComponent(state)}`,
        'Callback must preserve the exact registered URI and original state.',
      );
      const codeKey = buildRedisKey(
        'oauth:code',
        createHash('sha256').update(code).digest('hex'),
      );
      const value = await redis.get(codeKey);
      assert.ok(
        value !== null,
        'Callback code must have real hash-keyed Redis state.',
      );
      const stored = authorizationCodeStateSchema.parse(
        JSON.parse(value.toString()),
      );
      assert.ok(
        stored.userId === userId &&
          stored.clientId === clientId &&
          stored.redirectUri === redirectUri &&
          JSON.stringify(stored.grantedScopes) === '["profile"]' &&
          stored.codeChallenge === challenge &&
          stored.nonce === null &&
          stored.authTime === runtime.authTime &&
          (await redis.pTTL(codeKey)) > 0 &&
          !value.toString().includes(code) &&
          !value.toString().includes(verifier) &&
          !codeKey.includes(code),
        'Issued code must originate from the real logged-in session, with hashed storage and S256 context.',
      );
      ownedKeys.add(codeKey);

      const tokenBody = new URLSearchParams({
        grant_type: 'authorization_code',
        client_id: clientId,
        code,
        redirect_uri: redirectUri,
        code_verifier: verifier,
      });
      const exchange = (): Promise<Response> => {
        const input = new Request(new URL('/oauth/token', env.ISSUER_URL), {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: tokenBody.toString(),
          redirect: 'manual',
          credentials: 'omit',
          signal: AbortSignal.timeout(10000),
        });
        assert.ok(
          !input.headers.has('authorization') &&
            !input.headers.has('cookie') &&
            !tokenBody.has('client_secret'),
          'PUBLIC exchange must send no client secret or Authorization header.',
        );
        return fetch(input);
      };
      phase = 'token exchange and public-key verification';
      const token = await exchange();
      await verifyToken(token, await token.text(), {
        subject: userId,
        audience,
        ttlSeconds: student.access_token_ttl,
        scopes: ['profile'],
      });
      assert.equal(
        await redis.exists(codeKey),
        0,
        'Successful exchange must consume the real code.',
      );
      phase = 'code replay';
      const replay = await exchange();
      assert.equal(replay.status, 400, 'Replayed code must fail.');
      assert.ok(
        (await replay.text()) ===
          JSON.stringify({
            error: 'invalid_grant',
            error_description: 'Invalid authorization grant.',
          }),
        'Replay must return only the fixed invalid_grant error, not another token.',
      );
      assert.equal(replay.headers.get('cache-control'), 'no-store');
      assert.equal(replay.headers.get('pragma'), 'no-cache');
      assert.equal(replay.headers.get('location'), null);
      assert.equal(replay.headers.get('set-cookie'), null);
      assert.equal(
        await redis.exists(codeKey),
        0,
        'Replay must not restore authorization-code state.',
      );
      phase = 'unsupported HTTP endpoints';
      for (const path of [
        '/oauth/token',
        '/.well-known/jwks.json',
        '/.well-known/openid-configuration',
      ]) {
        const response = await http(path);
        assert.equal(
          response.status,
          path === '/oauth/token' ? 404 : 200,
          'HTTP endpoint status must match the current milestone staging.',
        );
        await response.arrayBuffer();
      }
    } finally {
      const flowPhase = phase;
      phase = 'owned cleanup';
      await cleanup();
      phase = 'non-mutation snapshots';
      // Boolean assertions never dump rows, hashes, cookies, codes or JWTs on failure.
      assert.ok(
        (await snapshotDb()) === dbBefore,
        'Eight database fingerprints must be restored, including the full canonical registry and unrelated identities/sessions.',
      );
      assert.ok(
        sameRedis(redisBefore, await snapshotRedis()),
        'Unrelated Redis values/absolute expiry must remain unchanged, with no owned keys left.',
      );
      phase = flowPhase;
    }
    console.log(
      'M6.8 real-stack OAuth E2E passed: canonical PUBLIC student-spa/profile; HTTP register -> authorize 401 -> login/session -> identical authorize 302/state -> S256 token 200 -> RS256 public-key/claims verification -> replay invalid_grant.',
    );
    console.log(
      'Owned logout and FK-ordered teardown passed; eight DB fingerprints and all unrelated Redis values/absolute expiry restored. Discovery/JWKS are 200; GET token remains 404; no ID/refresh token, client secret or private material printed.',
    );
  } finally {
    if (redis.isOpen) redis.destroy();
    await db.end();
  }
}

void checkAuthorizationCodeE2e().catch((error: unknown) => {
  console.error(
    error === publicKeyPrerequisite
      ? 'E2E prerequisite: provide a valid configured local public signing key. Use dev-keys:generate only if no keys exist; existing keys are never regenerated.'
      : `Authorization-code E2E check failed at ${phase} (private details suppressed). Check local stack, seeded registry and configuration, then rerun.`,
  );
  process.exitCode = 1;
});
