// Explicit local HTTP probe. Only observers/one owned sentinel touch storage;
// failed M6.1 validation must never reach M6.2. Well-shaped unknown codes now
// for enabled PUBLIC clients reach GETDEL and return invalid_grant.
import 'dotenv/config';
import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import { Pool } from 'pg';
import { createClient, RESP_TYPES } from 'redis';
import { validateEnvironment } from '../src/config/env.schema.js';

const invalid = {
  error: 'invalid_request',
  error_description: 'Invalid token request.',
};
const unsupported = {
  error: 'unsupported_grant_type',
  error_description: 'Unsupported grant type.',
};
const form = 'application/x-www-form-urlencoded';
const invalidGrant = {
  error: 'invalid_grant',
  error_description: 'Invalid authorization grant.',
};
const invalidClient = {
  error: 'invalid_client',
  error_description: 'Client authentication failed.',
};

async function checkTokenRequests(): Promise<void> {
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
    'Token probe requires the local development stack.',
  );
  const redis = createClient({
    url: env.REDIS_URL,
    socket: { connectTimeout: 5000, reconnectStrategy: false },
  }).withTypeMapping({ [RESP_TYPES.BLOB_STRING]: Buffer });
  redis.on('error', () => {
    /* Do not log driver causes or stored values. */
  });
  const db = new Pool({
    connectionString: env.DATABASE_URL,
    connectionTimeoutMillis: 5000,
  });
  const syntheticCode = 'm61-synthetic-code-' + randomUUID();
  const sentinel =
    'oauth:code:' + createHash('sha256').update(syntheticCode).digest('hex');
  let owned = false;
  let cases = 0;
  const snapshotCodes = async (): Promise<
    Map<string, { value: string; expires: number }>
  > => {
    const result = new Map<string, { value: string; expires: number }>();
    let cursor = '0';
    let pages = 0;
    do {
      const page = await redis.scan(cursor, {
        MATCH: 'oauth:code:*',
        COUNT: 100,
      });
      cursor = page.cursor.toString();
      assert.ok(
        ++pages <= 100 && result.size + page.keys.length <= 1000,
        'Local code snapshot bound exceeded.',
      );
      for (const key of page.keys) {
        const value = await redis.dump(key);
        const expires = await redis.pExpireTime(key);
        assert.ok(
          value !== null && expires > Date.now() + 10000,
          'Code snapshot contains an expiring key; retry after expiry.',
        );
        result.set(key.toString(), {
          value: value.toString('base64'),
          expires,
        });
      }
    } while (cursor !== '0');
    return result;
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
    const query =
      tables
        .map(
          ([table, order]) =>
            `SELECT '${table}' AS relation, COUNT(*)::int AS count, md5(COALESCE(jsonb_agg(to_jsonb(t) ORDER BY ${order})::text, '[]')) AS fingerprint FROM ${table} t`,
        )
        .join(' UNION ALL ') + ' ORDER BY relation';
    return JSON.stringify((await db.query(query)).rows);
  };
  const post = async (
    body: string,
    status = 400,
    expected = invalid,
    type = form,
  ): Promise<void> => {
    const response = await fetch(new URL('/oauth/token', env.ISSUER_URL), {
      method: 'POST',
      headers: { 'Content-Type': type },
      body,
      redirect: 'manual',
      signal: AbortSignal.timeout(5000),
    });
    assert.equal(response.status, status, 'Unexpected token response status.');
    assert.equal(response.headers.get('cache-control'), 'no-store');
    assert.equal(response.headers.get('location'), null);
    assert.equal(response.headers.get('set-cookie'), null);
    assert.equal(
      response.headers.get('www-authenticate'),
      status === 401 ? 'Basic realm="oauth/token"' : null,
    );
    const text = await response.text();
    assert.ok(
      text === JSON.stringify(expected),
      'Token error must be fixed and sanitized.',
    );
    cases++;
  };
  try {
    await redis.connect();
    const initial = await snapshotCodes();
    const beforeDb = await snapshotDb();
    assert.ok(
      (await redis.set(
        sentinel,
        JSON.stringify({
          clientId: 'student-spa',
          userId: randomUUID(),
          redirectUri: 'http://localhost:3200/callback',
          grantedScopes: ['openid', 'profile'],
          codeChallenge: 'A'.repeat(43),
          nonce: null,
          authTime: Date.now() - 1000,
          expiresAt: Date.now() + 120000,
        }),
        {
          EX: 120,
          NX: true,
        },
      )) !== null,
    );
    owned = true;
    const before = await snapshotCodes();
    const valid = {
      grant_type: 'authorization_code',
      client_id: 'student-spa',
      code: syntheticCode,
      redirect_uri: 'http://localhost:3200/callback',
      code_verifier: 'm61-synthetic-opaque-verifier',
    };
    const unknown = { ...valid, code: 'm62-unknown-' + randomUUID() };
    await post(new URLSearchParams(unknown).toString(), 400, invalidGrant);
    const withoutVerifier = new URLSearchParams(unknown);
    withoutVerifier.delete('code_verifier');
    await post(withoutVerifier.toString(), 400, invalidGrant);
    await post(
      new URLSearchParams({ ...unknown, code_verifier: '' }).toString(),
      400,
      invalidGrant,
    );
    await post(
      new URLSearchParams({
        ...unknown,
        client_id: 'unknown opaque client',
        redirect_uri: ' unregistered e\u0301 %2F+ ',
        code_verifier: ' short ',
      }).toString(),
      401,
      invalidClient,
    );
    for (const field of Object.keys(valid)) {
      const missing = new URLSearchParams(valid);
      missing.delete(field);
      if (field !== 'code_verifier') await post(missing.toString());
      if (field !== 'code_verifier') {
        const empty = new URLSearchParams(valid);
        empty.set(field, '');
        await post(empty.toString());
      }
      await post(`${new URLSearchParams(valid)}&${field}=duplicate`);
      await post(`${missing}&${field}[nested]=object`);
    }
    for (const grant_type of [
      'refresh_token',
      'Authorization_Code',
      'AUTHORIZATION_CODE',
      'authorization-code',
      ' authorization_code',
      'authorization_code ',
    ])
      await post(
        new URLSearchParams({ ...valid, grant_type }).toString(),
        400,
        unsupported,
      );
    await post(`${new URLSearchParams(valid)}&client_secret=synthetic-canary`);
    await post(JSON.stringify(valid), 400, invalid, 'application/json');
    await post(
      '{"private":"synthetic-body-canary",',
      400,
      invalid,
      'application/json',
    );
    await post('x=canary&'.repeat(1002));
    await post('code=' + 'synthetic-body-canary'.repeat(7000));
    await post(
      'code=synthetic-body-canary',
      400,
      invalid,
      `${form}; charset=unsupported-canary`,
    );
    const get = await fetch(new URL('/oauth/token', env.ISSUER_URL), {
      redirect: 'manual',
      signal: AbortSignal.timeout(5000),
    });
    assert.equal(get.status, 404);
    await get.arrayBuffer();
    cases++;
    for (const encoding of ['gzip', 'deflate', 'br']) {
      const response = await fetch(new URL('/oauth/token', env.ISSUER_URL), {
        method: 'POST',
        headers: { 'Content-Type': form, 'Content-Encoding': encoding },
        body: 'code=synthetic-compression-canary',
        redirect: 'manual',
        signal: AbortSignal.timeout(5000),
      });
      assert.equal(response.status, 400);
      assert.ok(
        (await response.text()) === JSON.stringify(invalid),
        'Compression error must be sanitized.',
      );
      assert.equal(response.headers.get('cache-control'), 'no-store');
      assert.equal(response.headers.get('location'), null);
      assert.equal(response.headers.get('set-cookie'), null);
      cases++;
    }
    const after = await snapshotCodes();
    assert.ok(
      before.size === after.size &&
        [...before].every(
          ([key, value]) =>
            value.value === after.get(key)?.value &&
            value.expires === after.get(key)?.expires,
        ),
      'Token requests changed code state or expiry.',
    );
    assert.ok(
      beforeDb === (await snapshotDb()),
      'Token requests changed database fingerprints.',
    );
    assert.equal(await redis.del(sentinel), 1);
    owned = false;
    const restored = await snapshotCodes();
    assert.ok(
      initial.size === restored.size &&
        [...initial].every(
          ([key, value]) =>
            value.value === restored.get(key)?.value &&
            value.expires === restored.get(key)?.expires,
        ),
      'Probe did not restore its owned sentinel.',
    );
    console.log(
      `M6.1-M6.4 token request check passed (${cases} HTTP cases); rejected forms/unsupported grants preserve the matching sentinel; enabled PUBLIC unknown codes return invalid_grant; unknown client returns invalid_client; code snapshots and 8 database fingerprints unchanged; owned sentinel removed.`,
    );
  } finally {
    try {
      if (owned && redis.isReady) await redis.del(sentinel);
    } finally {
      if (redis.isOpen) redis.destroy();
      await db.end();
    }
  }
}

void checkTokenRequests().catch(() => {
  console.error(
    'Token request check failed (details suppressed to protect protocol/storage values).',
  );
  process.exitCode = 1;
});
