// Explicit public-metadata HTTP check. No DB/Redis clients or key-file imports.
import 'dotenv/config';
import assert from 'node:assert/strict';

async function checkDiscovery(): Promise<void> {
  const issuer = process.env.ISSUER_URL;
  assert.ok(
    typeof issuer === 'string' && issuer.length > 0,
    'ISSUER_URL is required.',
  );
  const url = new URL(issuer);
  assert.ok(
    process.env.NODE_ENV !== 'production' &&
      ['http:', 'https:'].includes(url.protocol) &&
      ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname) &&
      url.username === '' &&
      url.password === '' &&
      !issuer.includes('?') &&
      !issuer.includes('#'),
    'Discovery check requires a local development issuer.',
  );
  const expected = {
    issuer,
    authorization_endpoint: new URL('/oauth/authorize', url).href,
    token_endpoint: new URL('/oauth/token', url).href,
    userinfo_endpoint: new URL('/oidc/userinfo', url).href,
    jwks_uri: new URL('/.well-known/jwks.json', url).href,
    scopes_supported: ['openid', 'profile', 'email'],
    response_types_supported: ['code'],
    response_modes_supported: ['query'],
    grant_types_supported: ['authorization_code'],
    subject_types_supported: ['public'],
    id_token_signing_alg_values_supported: ['RS256'],
    token_endpoint_auth_methods_supported: ['client_secret_basic', 'none'],
    code_challenge_methods_supported: ['S256'],
    claims_parameter_supported: false,
    request_parameter_supported: false,
    request_uri_parameter_supported: false,
  };
  const response = await fetch(
    new URL('/.well-known/openid-configuration', url),
    {
      redirect: 'manual',
      credentials: 'omit',
      signal: AbortSignal.timeout(5000),
    },
  );
  assert.equal(response.status, 200, 'Discovery must return HTTP 200.');
  assert.ok(
    response.headers.get('content-type')?.startsWith('application/json'),
    'Discovery must return JSON.',
  );
  assert.equal(response.headers.get('cache-control'), 'no-store');
  assert.equal(response.headers.get('set-cookie'), null);
  assert.equal(response.headers.get('location'), null);
  const metadata: unknown = await response.json();
  assert.ok(
    typeof metadata === 'object' &&
      metadata !== null &&
      !Array.isArray(metadata),
    'Invalid metadata object.',
  );
  const fields = metadata as Record<string, unknown>;
  // Boolean checks never dump unexpected server/configuration values.
  assert.ok(
    Object.keys(fields).length === Object.keys(expected).length &&
      Object.entries(expected).every(
        ([key, value]) => JSON.stringify(fields[key]) === JSON.stringify(value),
      ),
    'Discovery metadata does not match the exact public allowlist.',
  );
  const jwksUrl = new URL('/.well-known/jwks.json', url);
  assert.ok(
    fields.jwks_uri === jwksUrl.href,
    'Discovery must advertise the live JWKS URL exactly.',
  );
  const jwks = await fetch(jwksUrl, {
    redirect: 'manual',
    credentials: 'omit',
    signal: AbortSignal.timeout(5000),
  });
  assert.equal(
    jwks.status,
    200,
    'Advertised JWKS endpoint must return HTTP 200.',
  );
  assert.ok(jwks.headers.get('content-type')?.startsWith('application/json'));
  assert.equal(jwks.headers.get('set-cookie'), null);
  assert.equal(jwks.headers.get('location'), null);
  await jwks.arrayBuffer();
  for (const path of ['/oidc/userinfo', '/oauth/token']) {
    const staged = await fetch(new URL(path, url), {
      redirect: 'manual',
      signal: AbortSignal.timeout(5000),
    });
    assert.equal(
      staged.status,
      404,
      'Staged/unsupported route must remain absent.',
    );
    await staged.arrayBuffer();
  }
  console.log(
    'M7.1/M7.2 Discovery check passed: HTTP 200, exact 16 public metadata fields, no authentication/cookie/redirect; advertised JWKS URL returns 200; UserInfo/GET token remain 404. No store clients or direct key-file reads; server JWKS requires an existing valid signing pair.',
  );
}
void checkDiscovery().catch(() => {
  console.error(
    'Discovery check failed (private details suppressed). Verify the local server and ISSUER_URL.',
  );
  process.exitCode = 1;
});
