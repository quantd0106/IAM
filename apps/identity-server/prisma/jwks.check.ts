// Explicit read-only HTTP check. Never loads/generates keys or connects to stores.
import 'dotenv/config';
import assert from 'node:assert/strict';
import { importJWK } from 'jose';

const keyPrerequisite = new Error('Signing pair prerequisite.');

async function checkJwks(): Promise<void> {
  const issuer = process.env.ISSUER_URL;
  const kid = process.env.JWT_KEY_ID?.trim(); // Match existing env validation, not a new kid policy.
  assert.ok(typeof issuer === 'string' && issuer.length > 0 && kid);
  const url = new URL(issuer);
  assert.ok(
    process.env.NODE_ENV !== 'production' &&
      ['http:', 'https:'].includes(url.protocol) &&
      ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname) &&
      url.username === '' &&
      url.password === '' &&
      !issuer.includes('?') &&
      !issuer.includes('#'),
    'JWKS check requires a local development issuer.',
  );
  const response = await fetch(new URL('/.well-known/jwks.json', url), {
    redirect: 'manual',
    credentials: 'omit',
    signal: AbortSignal.timeout(5000),
  });
  if (response.status === 500) {
    await response.arrayBuffer();
    throw keyPrerequisite;
  }
  assert.equal(response.status, 200, 'JWKS must return HTTP 200.');
  assert.ok(
    response.headers.get('content-type')?.startsWith('application/json'),
  );
  assert.equal(response.headers.get('cache-control'), 'public, max-age=300');
  for (const name of [
    'set-cookie',
    'location',
    'www-authenticate',
    'etag',
    'last-modified',
  ])
    assert.equal(response.headers.get(name), null);
  const document: unknown = await response.json();
  assert.ok(
    typeof document === 'object' &&
      document !== null &&
      !Array.isArray(document),
  );
  const fields = document as Record<string, unknown>;
  assert.ok(Object.keys(fields).length === 1 && Object.hasOwn(fields, 'keys'));
  assert.ok(Array.isArray(fields.keys) && fields.keys.length === 1);
  const key: unknown = fields.keys[0];
  assert.ok(typeof key === 'object' && key !== null && !Array.isArray(key));
  const jwk = key as Record<string, unknown>;
  // Boolean assertions never dump unexpected private/native/configuration values.
  assert.ok(
    JSON.stringify(Object.keys(jwk).sort()) ===
      '["alg","e","kid","kty","n","use"]' &&
      jwk.kty === 'RSA' &&
      jwk.alg === 'RS256' &&
      jwk.use === 'sig' &&
      jwk.kid === kid &&
      typeof jwk.n === 'string' &&
      /^[A-Za-z0-9_-]+$/.test(jwk.n) &&
      typeof jwk.e === 'string' &&
      /^[A-Za-z0-9_-]+$/.test(jwk.e),
    'JWKS must contain exactly one allowlisted public RS256 signing key.',
  );
  try {
    const imported = await importJWK(
      { kty: 'RSA', alg: 'RS256', use: 'sig', n: jwk.n, e: jwk.e },
      'RS256',
    );
    assert.ok(
      !(imported instanceof Uint8Array) &&
        imported.type === 'public' &&
        imported.algorithm.name === 'RSASSA-PKCS1-v1_5',
    );
  } catch {
    throw keyPrerequisite;
  }
  console.log(
    'M7.2 JWKS check passed: HTTP 200, exactly one public RSA/RS256/sig key, configured kid, usable JOSE verification key, cache 300 seconds; no cookie/redirect/challenge/private fields. No stores mutated or key material printed.',
  );
}
void checkJwks().catch((error: unknown) => {
  console.error(
    error === keyPrerequisite
      ? 'JWKS prerequisite: provide a valid configured local signing pair; this check never generates or replaces keys.'
      : 'JWKS check failed (private details suppressed). Verify the local server and configuration.',
  );
  process.exitCode = 1;
});
