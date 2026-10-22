// Explicit M7.6 real-stack OIDC client check. Owned cleanup follows M6.8;
// keep the separate OAuth-only M6.8 check frozen. Never read signing PEM files.
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
import { createLocalJWKSet, errors, jwtVerify } from 'jose';

const publicKeyPrerequisite = new Error('Live Discovery/JWKS prerequisite.');
const nonceMismatch = new Error('Client ID Token nonce check failed.');
const clientId = 'student-spa';
const redirectUri = 'http://localhost:3200/callback';
const audience = 'student-api';
// Diagnostics use only fixed phase labels, never native error messages or inputs.
let phase = 'preconditions';

async function checkOidcE2e(): Promise<void> {
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
  // Client validation consumes only LIVE public Discovery + JWKS, never config PEM
  // paths, SigningKeyService, local files, token-supplied URLs or a private key.
  const publicGet = (url: string | URL): Promise<Response> =>
    fetch(url, {
      redirect: 'manual',
      credentials: 'omit',
      signal: AbortSignal.timeout(10000),
    });
  const metadataResponse = await publicGet(
    new URL('/.well-known/openid-configuration', env.ISSUER_URL),
  );
  assert.equal(metadataResponse.status, 200, 'Live Discovery must succeed.');
  assert.equal(metadataResponse.headers.get('cache-control'), 'no-store');
  assert.equal(metadataResponse.headers.get('set-cookie'), null);
  assert.equal(metadataResponse.headers.get('location'), null);
  const metadataResult = z
    .object({
      issuer: z.literal(env.ISSUER_URL),
      authorization_endpoint: z.literal(
        new URL('/oauth/authorize', env.ISSUER_URL).href,
      ),
      token_endpoint: z.literal(new URL('/oauth/token', env.ISSUER_URL).href),
      userinfo_endpoint: z.literal(
        new URL('/oidc/userinfo', env.ISSUER_URL).href,
      ),
      jwks_uri: z.literal(
        new URL('/.well-known/jwks.json', env.ISSUER_URL).href,
      ),
      response_types_supported: z.tuple([z.literal('code')]),
      id_token_signing_alg_values_supported: z.tuple([z.literal('RS256')]),
    })
    .safeParse(await metadataResponse.json());
  assert.ok(
    metadataResult.success,
    'Discovery must match the configured issuer/endpoints and code/RS256 support.',
  );
  const metadata = metadataResult.data;
  const jwksResponse = await publicGet(metadata.jwks_uri);
  if (jwksResponse.status !== 200) {
    await jwksResponse.arrayBuffer();
    throw publicKeyPrerequisite;
  }
  assert.equal(
    jwksResponse.headers.get('cache-control'),
    'public, max-age=300',
  );
  assert.equal(jwksResponse.headers.get('set-cookie'), null);
  assert.equal(jwksResponse.headers.get('location'), null);
  const jwksSchema = z.strictObject({
    keys: z.tuple([
      z.strictObject({
        kty: z.literal('RSA'),
        alg: z.literal('RS256'),
        use: z.literal('sig'),
        kid: z.string().min(1),
        n: z.string().regex(/^[A-Za-z0-9_-]+$/),
        e: z.string().regex(/^[A-Za-z0-9_-]+$/),
      }),
    ]),
  });
  const published = jwksSchema.safeParse(await jwksResponse.json());
  assert.ok(published.success, 'Expected the exact single public RS256 JWKS.');
  const jwks = createLocalJWKSet(published.data);
  const keyId = published.data.keys[0].kid;
  const publicSnapshot = JSON.stringify(published.data);
  const numericDate = z.number().int().min(0).max(Number.MAX_SAFE_INTEGER);
  const validateIdentity = async (
    compact: string,
    expectedNonce: string,
    expectedAudience: string,
  ) => {
    const verified = await jwtVerify(compact, jwks, {
      algorithms: ['RS256'],
      issuer: metadata.issuer,
      audience: expectedAudience,
      requiredClaims: ['iss', 'sub', 'aud', 'iat', 'exp', 'nonce'],
    });
    const result = z
      .strictObject({
        iss: z.literal(metadata.issuer),
        sub: z.uuid(),
        aud: z.literal(expectedAudience),
        iat: numericDate,
        exp: numericDate,
        nonce: z.string().min(1),
      })
      .safeParse(verified.payload);
    assert.ok(
      result.success,
      'ID Token must have exactly six valid canonical claims.',
    );
    assert.ok(
      JSON.stringify(verified.protectedHeader) ===
        JSON.stringify({ alg: 'RS256', kid: keyId }),
      'ID Token must use the published RS256 key identifier.',
    );
    // Explicit case-sensitive RP nonce check BEFORE accepting identity/profile data.
    if (result.data.nonce !== expectedNonce) throw nonceMismatch;
    return result.data;
  };
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
  const tag = 'm76-' + randomUUID();
  const email = tag + '@example.invalid';
  const password = randomBytes(32).toString('base64url');
  const verifier = randomBytes(32).toString('base64url');
  const challenge = createHash('sha256')
    .update(verifier, 'ascii')
    .digest('base64url');
  const state = randomBytes(32).toString('base64url');
  const nonce = randomBytes(32).toString('base64url');
  const authorizeUrl = new URL(metadata.authorization_endpoint);
  authorizeUrl.search = new URLSearchParams({
    response_type: 'code',
    client_id: clientId,
    redirect_uri: redirectUri,
    scope: 'openid profile email',
    state,
    nonce,
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
    const registryMetadata = await db.query<{
      client_type: string;
      enabled: boolean;
      access_token_audience: string | null;
      access_token_ttl: number;
      no_secret: boolean;
      redirect_registered: boolean;
      oidc_scopes_allowed: boolean;
    }>(
      `
      SELECT c.client_type, c.enabled, c.access_token_audience, c.access_token_ttl,
        c.client_secret_hash IS NULL AS no_secret,
        EXISTS(SELECT 1 FROM client_redirect_uris r WHERE r.client_id=c.id AND r.redirect_uri=$2) AS redirect_registered,
        (SELECT COUNT(DISTINCT s.name) FROM client_scopes cs JOIN scopes s ON s.id=cs.scope_id WHERE cs.client_id=c.id AND s.name IN ('openid','profile','email')) = 3 AS oidc_scopes_allowed
      FROM clients c WHERE c.client_id=$1`,
      [clientId, redirectUri],
    );
    const student = registryMetadata.rows[0];
    assert.ok(
      registryMetadata.rows.length === 1 &&
        student.client_type === 'PUBLIC' &&
        student.enabled &&
        student.no_secret &&
        student.redirect_registered &&
        student.oidc_scopes_allowed &&
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
          JSON.stringify(stored.grantedScopes) ===
            '["openid","profile","email"]' &&
          stored.codeChallenge === challenge &&
          stored.nonce === nonce &&
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
        const input = new Request(metadata.token_endpoint, {
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
      phase = 'OIDC token exchange and live-JWKS verification';
      const token = await exchange();
      assert.equal(token.status, 200, 'OIDC token exchange must succeed.');
      assert.equal(token.headers.get('cache-control'), 'no-store');
      assert.equal(token.headers.get('pragma'), 'no-cache');
      assert.equal(token.headers.get('set-cookie'), null);
      assert.equal(token.headers.get('location'), null);
      assert.ok(
        token.headers.get('content-type')?.startsWith('application/json'),
      );
      const tokenResult = z
        .strictObject({
          access_token: z.string().min(1),
          token_type: z.literal('Bearer'),
          expires_in: z.literal(student.access_token_ttl),
          scope: z.literal('openid profile email'),
          id_token: z.string().min(1),
        })
        .safeParse(await token.json());
      assert.ok(
        tokenResult.success,
        'OIDC exchange must return exactly five token fields, no refresh token.',
      );
      const tokens = tokenResult.data;
      const identity = await validateIdentity(tokens.id_token, nonce, clientId);
      assert.ok(
        identity.sub === userId &&
          identity.aud === clientId &&
          identity.exp > identity.iat &&
          identity.exp - identity.iat === student.access_token_ttl,
        'Invalid ID Token subject/client audience/lifetime.',
      );
      const access = await jwtVerify(tokens.access_token, jwks, {
        algorithms: ['RS256'],
        issuer: metadata.issuer,
        audience,
        requiredClaims: [
          'iss',
          'sub',
          'aud',
          'iat',
          'exp',
          'scope',
          'roles',
          'permissions',
        ],
      });
      assert.ok(
        JSON.stringify(access.protectedHeader) ===
          JSON.stringify({ alg: 'RS256', kid: keyId }),
        'Access token protected header mismatch.',
      );
      const accessResult = z
        .strictObject({
          iss: z.literal(metadata.issuer),
          sub: z.uuid(),
          aud: z.literal(audience),
          iat: numericDate,
          exp: numericDate,
          scope: z.literal('openid profile email'),
          roles: z.tuple([]),
          permissions: z.tuple([]),
        })
        .safeParse(access.payload);
      assert.ok(
        accessResult.success,
        'Expected the unchanged eight-claim access token.',
      );
      assert.ok(
        accessResult.data.sub === userId &&
          accessResult.data.exp > accessResult.data.iat &&
          accessResult.data.exp - accessResult.data.iat ===
            student.access_token_ttl &&
          !Object.is(identity.aud, accessResult.data.aud),
        'Access token must use the resource audience, not the ID Token client audience.',
      );

      phase = 'RP wrong nonce and audience rejection';
      let wrongNonceRejected = false;
      try {
        await validateIdentity(tokens.id_token, nonce + '-different', clientId);
      } catch (error) {
        wrongNonceRejected = error === nonceMismatch;
      }
      assert.ok(
        wrongNonceRejected,
        'Client must reject the same valid ID Token with a different expected nonce.',
      );
      let wrongAudienceRejected = false;
      try {
        await validateIdentity(tokens.id_token, nonce, audience);
      } catch (error) {
        wrongAudienceRejected =
          error instanceof errors.JWTClaimValidationFailed &&
          error.claim === 'aud';
      }
      assert.ok(
        wrongAudienceRejected,
        'JOSE audience validation must reject the resource audience for an ID Token.',
      );

      phase = 'live UserInfo and explicit ID Token subject match';
      const userinfo = await http(metadata.userinfo_endpoint, {
        headers: { Authorization: 'Bearer ' + tokens.access_token },
      });
      assert.equal(
        userinfo.status,
        200,
        'UserInfo must accept the access token.',
      );
      assert.equal(userinfo.headers.get('cache-control'), 'no-store');
      assert.equal(userinfo.headers.get('pragma'), 'no-cache');
      assert.equal(userinfo.headers.get('set-cookie'), null);
      assert.equal(userinfo.headers.get('location'), null);
      const userinfoResult = z
        .strictObject({
          sub: z.uuid(),
          preferred_username: z.string().min(1),
          email: z.email(),
        })
        .safeParse(await userinfo.json());
      assert.ok(
        userinfoResult.success,
        'UserInfo must return only sub/preferred_username/email.',
      );
      // This RP check is separate from fixture comparisons; profile claims cannot
      // be accepted unless UserInfo identifies the same subject as the ID Token.
      assert.ok(
        userinfoResult.data.sub === identity.sub,
        'UserInfo subject must match the validated ID Token subject.',
      );
      assert.ok(
        userinfoResult.data.sub === userId &&
          userinfoResult.data.preferred_username === tag &&
          userinfoResult.data.email === email,
        'Unexpected owned UserInfo identity claims.',
      );
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
      phase = 'published signing key non-mutation';
      const finalJwks = await publicGet(metadata.jwks_uri);
      assert.equal(finalJwks.status, 200);
      const finalPublished = jwksSchema.safeParse(await finalJwks.json());
      assert.ok(
        finalPublished.success &&
          JSON.stringify(finalPublished.data) === publicSnapshot,
        'Published signing key must remain unchanged.',
      );
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
      'M7.6 real-stack OIDC E2E passed: PUBLIC student-spa/openid profile email; register -> authorize 401 -> login/session -> identical authorize 302/state -> S256 token 200 with five fields -> live Discovery/JWKS RS256 issuer/client-audience/nonce validation -> access-token UserInfo with matching subject -> replay invalid_grant.',
    );
    console.log(
      'Wrong expected nonce and wrong ID-token resource audience rejected by client checks; ID Token has exactly six claims. Owned logout/FK-ordered teardown, eight DB fingerprints, unrelated Redis values/absolute expiry and public signing-key snapshot passed; no PEM reads, refresh token, registry mutations or sensitive values printed.',
    );
  } finally {
    if (redis.isOpen) redis.destroy();
    await db.end();
  }
}

void checkOidcE2e().catch((error: unknown) => {
  console.error(
    error === publicKeyPrerequisite
      ? 'OIDC E2E prerequisite: provide valid live Discovery/JWKS and a provisioned server signing pair; this client never reads, generates or replaces PEM files.'
      : `OIDC E2E check failed at ${phase} (private details suppressed). Check local stack, seeded registry and configuration, then rerun.`,
  );
  process.exitCode = 1;
});
