// Explicit focused HTTP probe: no DB/Redis clients, user rows, key generation or OIDC flow.
import 'dotenv/config';
import assert from 'node:assert/strict';
import { ConfigService } from '@nestjs/config';
import {
  validateEnvironment,
  type Environment,
} from '../src/config/env.schema.js';
import { SigningKeyService } from '../src/security/signing/signing-key.service.js';
import { AccessTokenClaimsService } from '../src/tokens/access-token-claims.service.js';
import { AccessTokenIssuerService } from '../src/tokens/access-token-issuer.service.js';
import { IdTokenClaimsService } from '../src/oidc/id-token-claims.service.js';
import { IdTokenIssuerService } from '../src/oidc/id-token-issuer.service.js';

const prerequisite = new Error('Signing pair prerequisite.');

async function checkUserInfo(): Promise<void> {
  const env = validateEnvironment(process.env);
  const url = new URL(env.ISSUER_URL);
  assert.ok(
    env.NODE_ENV !== 'production' &&
      ['http:', 'https:'].includes(url.protocol) &&
      ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname) &&
      url.username === '' &&
      url.password === '' &&
      !env.ISSUER_URL.includes('?') &&
      !env.ISSUER_URL.includes('#'),
    'UserInfo check requires a local development issuer.',
  );
  const config = new ConfigService<Environment, true>(env);
  const keys = new SigningKeyService(config);
  // Validate existing provisioned pair explicitly; never generate/replace keys.
  try {
    await keys.getPublicVerificationKey();
  } catch {
    throw prerequisite;
  }
  const issuer = new AccessTokenIssuerService(
    new AccessTokenClaimsService(config),
    keys,
  );
  const subject = 'c0e21e3f-d3ee-425c-a99f-c2e7a7cab53f';
  const token = async (audience: string, scopes: string[]): Promise<string> =>
    (
      await issuer.issue({
        subject,
        audience,
        scopes,
        roles: [],
        permissions: [],
        ttlSeconds: 600,
      })
    ).accessToken;
  const check = async (
    method: 'GET' | 'POST',
    bearer: string | undefined,
    status: number,
    expected: object | undefined,
    challenge: string | null,
  ): Promise<void> => {
    const response = await fetch(new URL('/oidc/userinfo', url), {
      method,
      headers:
        bearer === undefined
          ? undefined
          : { Authorization: 'Bearer ' + bearer },
      credentials: 'omit',
      redirect: 'manual',
      signal: AbortSignal.timeout(5000),
    });
    assert.equal(response.status, status, 'Unexpected UserInfo status.');
    assert.equal(response.headers.get('cache-control'), 'no-store');
    assert.equal(response.headers.get('pragma'), 'no-cache');
    assert.equal(response.headers.get('www-authenticate'), challenge);
    assert.equal(response.headers.get('set-cookie'), null);
    assert.equal(response.headers.get('location'), null);
    if (expected === undefined)
      assert.ok(
        (await response.text()) === '',
        'Missing credentials must have no claims.',
      );
    else {
      assert.ok(
        response.headers.get('content-type')?.startsWith('application/json'),
      );
      // Boolean assertion never prints a compact JWT, subject or unexpected body.
      assert.ok(
        JSON.stringify(await response.json()) === JSON.stringify(expected),
        'Unexpected UserInfo body.',
      );
    }
  };
  const student = await token('student-api', ['openid', 'profile', 'email']);
  const banking = await token('banking-api', ['openid']);
  const profileOnly = await token('student-api', ['profile']);
  const idToken = (
    await new IdTokenIssuerService(
      new IdTokenClaimsService(config),
      keys,
    ).issue({
      subject,
      audience: 'student-spa',
      nonce: 'opaque-probe-nonce',
      ttlSeconds: 600,
    })
  ).idToken;
  for (const method of ['GET', 'POST'] as const) {
    await check(method, undefined, 401, undefined, 'Bearer realm="userinfo"');
    await check(method, student, 200, { sub: subject }, null);
    await check(method, banking, 200, { sub: subject }, null);
    await check(
      method,
      profileOnly,
      403,
      {
        error: 'insufficient_scope',
        error_description: 'The access token does not grant UserInfo access.',
      },
      'Bearer realm="userinfo", error="insufficient_scope", scope="openid"',
    );
    await check(
      method,
      idToken,
      401,
      {
        error: 'invalid_token',
        error_description: 'Invalid access token.',
      },
      'Bearer realm="userinfo", error="invalid_token"',
    );
  }
  console.log(
    'M7.4 UserInfo check passed: GET/POST header-Bearer access token + openid -> exact sub; student/banking scalar audiences accepted; missing -> 401, profile-only -> 403, real ID Token -> 401; no profile claims, cookies, redirects, store writes or token/key material printed.',
  );
}
void checkUserInfo().catch((error: unknown) => {
  console.error(
    error === prerequisite
      ? 'UserInfo prerequisite: provide a valid configured local signing pair; this check never generates or replaces keys.'
      : 'UserInfo check failed (private details suppressed). Verify the local server, signing pair and configuration.',
  );
  process.exitCode = 1;
});
