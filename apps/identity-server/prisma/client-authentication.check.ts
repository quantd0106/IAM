// Local HTTP/DB/Redis probe. Only UUID-owned clients/codes are created/deleted.
import 'dotenv/config';
import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import * as argon2 from 'argon2';
import { Pool } from 'pg';
import { createClient, RESP_TYPES } from 'redis';
import { validateEnvironment } from '../src/config/env.schema.js';
import { authorizationCodeStateSchema } from '../src/oauth/authorization-code.state.js';
import { buildRedisKey } from '../src/redis/redis-key.js';

const invalidClient = {
  error: 'invalid_client',
  error_description: 'Client authentication failed.',
};
const invalidGrant = {
  error: 'invalid_grant',
  error_description: 'Invalid authorization grant.',
};
const verifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
const challenge = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';

async function checkClientAuthentication(): Promise<void> {
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
    'Client authentication probe requires the local development stack.',
  );
  const db = new Pool({
    connectionString: env.DATABASE_URL,
    connectionTimeoutMillis: 5000,
  });
  const redis = createClient({
    url: env.REDIS_URL,
    socket: { connectTimeout: 5000, reconnectStrategy: false },
  }).withTypeMapping({ [RESP_TYPES.BLOB_STRING]: Buffer });
  redis.on('error', () => {
    /* No driver/private values in logs. */
  });
  const tag = randomUUID();
  const secret = ' owned e\u0301 +%2F: ' + randomUUID() + ' ';
  const hash = await argon2.hash(secret, { type: argon2.argon2id });
  const clients = [
    'student',
    'banking',
    'admin',
    'disabled',
    'no-hash',
    'opaque',
  ].map((name) => ({
    id: randomUUID(),
    clientId:
      name === 'opaque'
        ? ' owned e\u0301 +%2F ' + tag + ' '
        : `m64-${name}-${tag}`,
    type: name === 'student' ? 'PUBLIC' : 'CONFIDENTIAL',
    enabled: name !== 'disabled',
    hasHash: !['student', 'no-hash'].includes(name),
  }));
  const [student, banking, admin, disabled, noHash, opaque] = clients;
  assert.ok(student && banking && admin && disabled && noHash && opaque);
  const created = new Set<string>();
  const ownedKeys = new Set<string>();
  let cases = 0;
  const basic = (clientId: string, value = secret): string =>
    'bAsIc ' +
    Buffer.from(
      `${encodeURIComponent(clientId)}:${encodeURIComponent(value)}`,
    ).toString('base64');
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
        'Snapshot bound exceeded.',
      );
      for (const key of page.keys) {
        if (ownedKeys.has(key.toString())) continue;
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
  const fixture = async (
    clientId: string,
    codeChallenge: string | null = challenge,
  ) => {
    const code = 'm64-owned-' + randomUUID();
    const key = buildRedisKey(
      'oauth:code',
      createHash('sha256').update(code).digest('hex'),
    );
    const body = {
      grant_type: 'authorization_code',
      client_id: clientId,
      code,
      redirect_uri: 'http://localhost/m64-owned-callback',
      code_verifier: verifier,
    };
    const value = JSON.stringify(
      authorizationCodeStateSchema.parse({
        clientId,
        userId: randomUUID(),
        redirectUri: body.redirect_uri,
        grantedScopes: ['openid', 'profile'],
        codeChallenge,
        nonce: null,
        authTime: Date.now() - 1000,
        expiresAt: Date.now() + 120000,
      }),
    );
    assert.ok(
      (await redis.set(key, value, { EX: 120, NX: true })) !== null,
      'Owned key collision.',
    );
    ownedKeys.add(key);
    return { body, key, value, expires: await redis.pExpireTime(key) };
  };
  const post = async (
    body: Record<string, string>,
    header: string | undefined,
    status: number,
  ): Promise<void> => {
    const response = await fetch(new URL('/oauth/token', env.ISSUER_URL), {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        ...(header === undefined ? {} : { Authorization: header }),
      },
      body: new URLSearchParams(body),
      redirect: 'manual',
      signal: AbortSignal.timeout(5000),
    });
    assert.equal(
      response.status,
      status,
      'Unexpected client authentication status.',
    );
    assert.equal(response.headers.get('cache-control'), 'no-store');
    assert.equal(response.headers.get('location'), null);
    assert.equal(response.headers.get('set-cookie'), null);
    assert.equal(
      response.headers.get('www-authenticate'),
      status === 401 ? 'Basic realm="oauth/token"' : null,
    );
    const text = await response.text();
    assert.ok(
      text ===
        (status === 204
          ? ''
          : JSON.stringify(status === 401 ? invalidClient : invalidGrant)),
      'Authentication/grant response must be fixed and sanitized.',
    );
    assert.ok(
      ![secret, hash, body.code, verifier, challenge].some((value) =>
        text.includes(value),
      ),
      'Response contains private material.',
    );
    cases++;
  };
  const cleanupClients = async (): Promise<void> => {
    for (const client of clients) {
      if (!created.has(client.id)) continue;
      await db.query('DELETE FROM clients WHERE id = $1 AND client_id = $2', [
        client.id,
        client.clientId,
      ]);
      created.delete(client.id);
    }
  };
  try {
    await redis.connect();
    const beforeDb = await snapshotDb();
    const beforeCodes = await snapshotCodes();
    for (const client of clients) {
      await db.query(
        'INSERT INTO clients (id, client_id, name, client_type, enabled, client_secret_hash) VALUES ($1, $2, $3, $4, $5, $6)',
        [
          client.id,
          client.clientId,
          'M6.4 probe owned client',
          client.type,
          client.enabled,
          client.hasHash ? hash : null,
        ],
      );
      created.add(client.id);
    }
    const fixtureDb = await snapshotDb();
    for (const client of [student, banking, admin, opaque]) {
      const item = await fixture(client.clientId);
      await post(
        item.body,
        client.type === 'PUBLIC' ? undefined : basic(client.clientId),
        204,
      );
      assert.equal(await redis.exists(item.key), 0);
      await post(
        item.body,
        client.type === 'PUBLIC' ? undefined : basic(client.clientId),
        400,
      );
    }
    for (const kind of [
      'wrong',
      'missing',
      'malformed',
      'unsupported',
      'mismatch',
      'unknown',
      'case',
      'space',
      'public-basic',
      'disabled',
      'no-hash',
    ]) {
      const publicCase = kind === 'public-basic';
      const item = await fixture(
        publicCase ? student.clientId : banking.clientId,
      );
      const body = { ...item.body };
      let header: string | undefined = basic(banking.clientId);
      if (kind === 'wrong')
        header = basic(banking.clientId, 'wrong-owned-secret');
      if (kind === 'missing') header = undefined;
      if (kind === 'malformed') header = 'Basic !!!!';
      if (kind === 'unsupported') header = 'Bearer owned-credential';
      if (kind === 'mismatch') header = basic(admin.clientId);
      if (kind === 'unknown') body.client_id = 'm64-unknown-' + tag;
      if (kind === 'case') body.client_id = banking.clientId.toUpperCase();
      if (kind === 'space') body.client_id = ' ' + banking.clientId + ' ';
      if (publicCase) header = basic(student.clientId);
      if (kind === 'disabled') {
        body.client_id = disabled.clientId;
        header = basic(disabled.clientId);
      }
      if (kind === 'no-hash') {
        body.client_id = noHash.clientId;
        header = basic(noHash.clientId);
      }
      await post(body, header, 401);
      assert.ok(
        (await redis.get(item.key))?.toString() === item.value,
        'Failed auth changed owned code.',
      );
      assert.equal(
        await redis.pExpireTime(item.key),
        item.expires,
        'Failed auth changed code expiry.',
      );
      await post(
        item.body,
        publicCase ? undefined : basic(banking.clientId),
        204,
      );
      assert.equal(await redis.exists(item.key), 0);
    }
    const pkce = await fixture(banking.clientId);
    await post(
      { ...pkce.body, code_verifier: '' },
      basic(banking.clientId),
      400,
    );
    assert.equal(await redis.exists(pkce.key), 0);
    await post(pkce.body, basic(banking.clientId), 400);
    const noPkce = await fixture(admin.clientId, null);
    await post(noPkce.body, undefined, 401);
    assert.ok(
      (await redis.get(noPkce.key))?.toString() === noPkce.value,
      'Missing auth burned null-challenge code.',
    );
    await post(
      { ...noPkce.body, code_verifier: 'not-required' },
      basic(admin.clientId),
      204,
    );
    assert.ok(
      (await snapshotDb()) === fixtureDb,
      'Runtime changed database/credential fingerprints.',
    );
    for (const key of ownedKeys)
      assert.equal(await redis.exists(key), 0, 'Owned code remains.');
    await cleanupClients();
    assert.ok(
      (await snapshotDb()) === beforeDb,
      'Database fingerprints not restored.',
    );
    assert.ok(
      (await snapshotCodes()) === beforeCodes,
      'Unrelated code state changed.',
    );
    console.log(
      `M6.4 client authentication check passed (${cases} HTTP cases): PUBLIC/Banking/Admin/opaque Basic success; wrong/missing/malformed/unsupported/mismatch/unknown/disabled/PUBLIC Basic retain code+expiry and valid retry succeeds; PKCE still burns; null challenge still requires confidential auth; 8 DB fingerprints restored, unrelated codes unchanged, owned fixtures removed. No secrets printed or canonical seed changed.`,
    );
  } finally {
    try {
      if (redis.isReady) for (const key of ownedKeys) await redis.del(key);
    } finally {
      if (redis.isOpen) redis.destroy();
      try {
        await cleanupClients();
      } finally {
        await db.end();
      }
    }
  }
}
void checkClientAuthentication().catch(() => {
  console.error(
    'Client authentication check failed (private details suppressed).',
  );
  process.exitCode = 1;
});
