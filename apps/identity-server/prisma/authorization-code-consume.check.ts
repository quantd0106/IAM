// Destructive tests touch ONLY probe-owned synthetic code entries, never M5 codes.
import 'dotenv/config';
import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import { setTimeout } from 'node:timers/promises';
import { Pool } from 'pg';
import { createClient, RESP_TYPES } from 'redis';
import { validateEnvironment } from '../src/config/env.schema.js';
import { buildRedisKey } from '../src/redis/redis-key.js';
import {
  authorizationCodeStateSchema,
  type AuthorizationCodeState,
} from '../src/oauth/authorization-code.state.js';

const invalidGrant = {
  error: 'invalid_grant',
  error_description: 'Invalid authorization grant.',
};
const serverError = {
  error: 'server_error',
  error_description: 'Token request failed.',
};
const form = 'application/x-www-form-urlencoded';
const validVerifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
const validChallenge = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';

async function checkConsumption(): Promise<void> {
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
      local(env.REDIS_URL, ['redis:']) &&
      local(env.DATABASE_URL, ['postgres:', 'postgresql:']),
    'Consumption probe requires the local development stack.',
  );
  const redis = createClient({
    url: env.REDIS_URL,
    socket: { connectTimeout: 5000, reconnectStrategy: false },
  }).withTypeMapping({ [RESP_TYPES.BLOB_STRING]: Buffer });
  redis.on('error', () => {
    /* Never print driver causes, keys or state. */
  });
  const db = new Pool({
    connectionString: env.DATABASE_URL,
    connectionTimeoutMillis: 5000,
  });
  const owned = new Set<string>();
  let cases = 0;
  const keyFor = (code: string): string =>
    buildRedisKey(
      'oauth:code',
      createHash('sha256').update(code).digest('hex'),
    );
  const base = (): AuthorizationCodeState => ({
    clientId: 'student-spa',
    userId: randomUUID(),
    redirectUri: 'http://localhost:3200/callback',
    grantedScopes: ['profile', 'openid'],
    codeChallenge: null,
    nonce: 'probe-owned-nonce',
    authTime: Date.now() - 1000,
    expiresAt: Date.now() + 120000,
  });
  const fixture = async (
    state = base(),
    ttl = 120,
    serialized = JSON.stringify(authorizationCodeStateSchema.parse(state)),
    code = 'm62-owned-' + randomUUID(),
  ) => {
    const key = keyFor(code);
    assert.ok(/^oauth:code:[0-9a-f]{64}$/.test(key));
    assert.ok(
      (await redis.set(key, serialized, { EX: ttl, NX: true })) !== null,
      'Owned fixture collision.',
    );
    owned.add(key);
    return { code, key, state };
  };
  const post = async (
    code: string,
    clientId: string,
    redirectUri: string,
    verifier?: string,
  ): Promise<number> => {
    const response = await fetch(new URL('/oauth/token', env.ISSUER_URL), {
      method: 'POST',
      headers: { 'Content-Type': form, Authorization: 'not-even-basic' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        client_id: clientId,
        code,
        redirect_uri: redirectUri,
        ...(verifier === undefined ? {} : { code_verifier: verifier }),
      }),
      redirect: 'manual',
      signal: AbortSignal.timeout(5000),
    });
    assert.equal(response.headers.get('cache-control'), 'no-store');
    assert.equal(response.headers.get('set-cookie'), null);
    assert.equal(response.headers.get('location'), null);
    const text = await response.text();
    if (response.status === 204)
      assert.ok(text === '', 'Staged success must be empty.');
    else {
      assert.ok(
        response.status === 400 || response.status === 500,
        'Unexpected consume status.',
      );
      assert.ok(
        text ===
          JSON.stringify(response.status === 400 ? invalidGrant : serverError),
        'Grant failure must be fixed/sanitized.',
      );
    }
    cases++;
    return response.status;
  };
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
  const snapshotCodes = async (): Promise<string> => {
    let cursor = '0';
    let pages = 0;
    const values = new Map<string, { value: string; expires: number }>();
    do {
      const page = await redis.scan(cursor, {
        MATCH: 'oauth:code:*',
        COUNT: 100,
      });
      cursor = page.cursor.toString();
      assert.ok(
        ++pages <= 100 && values.size + page.keys.length <= 1000,
        'Local snapshot bound exceeded.',
      );
      for (const key of page.keys) {
        if (owned.has(key.toString())) continue;
        const value = await redis.dump(key);
        const expires = await redis.pExpireTime(key);
        assert.ok(
          value !== null && expires > Date.now() + 15000,
          'Existing code expires during probe; retry after expiry.',
        );
        values.set(key.toString(), {
          value: value.toString('base64'),
          expires,
        });
      }
    } while (cursor !== '0');
    return JSON.stringify(
      [...values].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)),
    );
  };
  try {
    await redis.connect();
    const dbBefore = await snapshotDb();
    const codesBefore = await snapshotCodes();
    const first = await fixture({ ...base(), codeChallenge: validChallenge });
    assert.equal(
      await post(
        first.code,
        first.state.clientId,
        first.state.redirectUri,
        validVerifier,
      ),
      204,
    );
    assert.equal(await redis.exists(first.key), 0);
    assert.equal(
      await post(first.code, first.state.clientId, first.state.redirectUri),
      400,
    );
    assert.equal(
      await post(
        'm62-unknown-' + randomUUID(),
        first.state.clientId,
        first.state.redirectUri,
      ),
      400,
    );

    const concurrent = await fixture({
      ...base(),
      codeChallenge: validChallenge,
    });
    const results = await Promise.all(
      Array.from({ length: 12 }, () =>
        post(
          concurrent.code,
          concurrent.state.clientId,
          concurrent.state.redirectUri,
          validVerifier,
        ),
      ),
    );
    assert.equal(results.filter((status) => status === 204).length, 1);
    assert.equal(results.filter((status) => status === 400).length, 11);
    assert.equal(await redis.exists(concurrent.key), 0);

    const expired = await fixture(base(), 1);
    const deadline = Date.now() + 5000;
    while (await redis.exists(expired.key)) {
      assert.ok(Date.now() < deadline, 'Owned TTL fixture did not expire.');
      await setTimeout(50);
    }
    assert.equal(
      await post(
        expired.code,
        expired.state.clientId,
        expired.state.redirectUri,
      ),
      400,
    );

    const logical = await fixture({ ...base(), expiresAt: Date.now() - 1 });
    assert.equal(await redis.exists(logical.key), 1);
    assert.equal(
      await post(
        logical.code,
        logical.state.clientId,
        logical.state.redirectUri,
      ),
      400,
    );
    assert.equal(await redis.exists(logical.key), 0);

    for (const change of [
      { clientId: 'other-client' },
      { redirectUri: 'http://LOCALHOST:3200/callback' },
      { redirectUri: 'http://localhost:3200/call%62ack' },
    ]) {
      const binding = await fixture();
      assert.equal(
        await post(
          binding.code,
          change.clientId ?? binding.state.clientId,
          change.redirectUri ?? binding.state.redirectUri,
        ),
        400,
      );
      assert.equal(await redis.exists(binding.key), 0);
      assert.equal(
        await post(
          binding.code,
          binding.state.clientId,
          binding.state.redirectUri,
        ),
        400,
      );
    }
    const exact = await fixture({
      ...base(),
      clientId: ' unknown e\u0301 CLIENT ',
      redirectUri: ' HTTPS://EXAMPLE.invalid:443/a/../%2f?b=2&a=%2520#frag ',
    });
    assert.equal(
      await post(
        exact.code,
        exact.state.clientId,
        exact.state.redirectUri,
        ' short wrong verifier ',
      ),
      204,
    );
    assert.equal(await redis.exists(exact.key), 0); // null challenge: no PKCE requirement or Basic auth
    const opaque = await fixture(
      base(),
      120,
      undefined,
      ' M62 e\u0301 +%2F / ' + randomUUID() + ' ',
    );
    assert.equal(
      await post(opaque.code, opaque.state.clientId, opaque.state.redirectUri),
      204,
    );
    assert.equal(await redis.exists(opaque.key), 0);

    for (const verifier of [
      undefined,
      '',
      'A'.repeat(42),
      'A'.repeat(129),
      'A'.repeat(43),
      'A'.repeat(42) + '+',
      'A'.repeat(42) + '/',
      'A'.repeat(42) + 'é',
      ' ' + validVerifier,
      validVerifier + '\n',
      '%64' + validVerifier.slice(1),
    ]) {
      const rejected = await fixture({
        ...base(),
        codeChallenge: validChallenge,
      });
      assert.equal(
        await post(
          rejected.code,
          rejected.state.clientId,
          rejected.state.redirectUri,
          verifier,
        ),
        400,
      );
      assert.equal(await redis.exists(rejected.key), 0);
      assert.equal(
        await post(
          rejected.code,
          rejected.state.clientId,
          rejected.state.redirectUri,
          validVerifier,
        ),
        400,
      );
    }
    const maxVerifier = 'Ab0-._~'.repeat(19).slice(0, 128);
    const max = await fixture({
      ...base(),
      codeChallenge: createHash('sha256')
        .update(maxVerifier, 'ascii')
        .digest('base64url'),
    });
    assert.equal(
      await post(
        max.code,
        max.state.clientId,
        max.state.redirectUri,
        maxVerifier,
      ),
      204,
    );
    assert.equal(await redis.exists(max.key), 0);
    for (const verifier of [undefined, '', ' malformed e\u0301 %2F+ ']) {
      const noPkce = await fixture();
      assert.equal(
        await post(
          noPkce.code,
          noPkce.state.clientId,
          noPkce.state.redirectUri,
          verifier,
        ),
        204,
      );
      assert.equal(await redis.exists(noPkce.key), 0);
    }

    for (const serialized of [
      'private-corrupt-canary{',
      JSON.stringify({ ...base(), userId: 'private-invalid-uuid' }),
      JSON.stringify({ ...base(), extra: true }),
    ]) {
      const corrupt = await fixture(base(), 120, serialized);
      assert.equal(
        await post(
          corrupt.code,
          corrupt.state.clientId,
          corrupt.state.redirectUri,
        ),
        500,
      );
      assert.equal(await redis.exists(corrupt.key), 0);
      assert.equal(
        await post(
          corrupt.code,
          corrupt.state.clientId,
          corrupt.state.redirectUri,
        ),
        400,
      );
    }
    assert.ok(
      (await snapshotDb()) === dbBefore,
      'Consumption mutated database fingerprints.',
    );
    assert.ok(
      (await snapshotCodes()) === codesBefore,
      'Unrelated authorization-code state changed.',
    );
    for (const key of owned)
      assert.equal(
        await redis.exists(key),
        0,
        'Owned code remains after consume/expiry.',
      );
    console.log(
      `M6.2/M6.3 consumption and PKCE check passed (${cases} HTTP cases): first/replay/unknown, 1-of-12 concurrent winner, Redis/logical expiry, exact bindings/burn, S256 43/128 verifiers, missing/empty/malformed/wrong verifier burn/replay, null-challenge bypass and corrupt-state fail-closed; no client auth/tokens; 8 DB fingerprints and unrelated code snapshots unchanged; zero owned keys remain.`,
    );
  } finally {
    try {
      if (redis.isReady) for (const key of owned) await redis.del(key);
    } finally {
      if (redis.isOpen) redis.destroy();
      await db.end();
    }
  }
}
void checkConsumption().catch(() => {
  console.error(
    'Authorization-code consumption check failed (private details suppressed).',
  );
  process.exitCode = 1;
});
