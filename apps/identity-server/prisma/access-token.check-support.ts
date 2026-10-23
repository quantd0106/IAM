// Local probe verification only; no production resource-server middleware/JWKS.
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { importSPKI, jwtVerify } from 'jose';
import type { Environment } from '../src/config/env.schema.js';
import { requireOpaqueRefreshToken } from './refresh-token.check-support.js';

export async function accessTokenVerifier(env: Environment) {
  const publicKey = await importSPKI(
    await readFile(env.JWT_PUBLIC_KEY_PATH, 'utf8'),
    'RS256',
  );
  return async (
    response: Response,
    text: string,
    expected: {
      subject: string;
      audience: string;
      ttlSeconds: number;
      scopes: readonly string[];
    },
  ): Promise<{ refreshToken: string }> => {
    assert.equal(response.status, 200, 'Token success must be HTTP 200.');
    assert.equal(response.headers.get('cache-control'), 'no-store');
    assert.equal(response.headers.get('pragma'), 'no-cache');
    assert.equal(response.headers.get('location'), null);
    assert.equal(response.headers.get('set-cookie'), null);
    assert.ok(
      response.headers.get('content-type')?.startsWith('application/json'),
      'Expected JSON.',
    );
    const body = JSON.parse(text) as Record<string, unknown>;
    assert.ok(
      JSON.stringify(Object.keys(body).sort()) ===
        JSON.stringify([
          'access_token',
          'expires_in',
          'refresh_token',
          'scope',
          'token_type',
        ]),
      'Unexpected token response fields.',
    );
    assert.ok(
      typeof body.access_token === 'string',
      'Expected compact access token.',
    );
    assert.ok(
      body.token_type === 'Bearer' &&
        body.expires_in === expected.ttlSeconds &&
        body.scope === expected.scopes.join(' '),
      'Invalid token response metadata.',
    );
    const { payload, protectedHeader } = await jwtVerify(
      body.access_token,
      publicKey,
      {
        algorithms: ['RS256'],
        issuer: env.ISSUER_URL,
        audience: expected.audience,
      },
    );
    // Compare booleans: assertions must never print compact JWTs or private grant context.
    assert.ok(
      JSON.stringify(protectedHeader) ===
        JSON.stringify({ alg: 'RS256', kid: env.JWT_KEY_ID }),
      'Invalid protected header.',
    );
    assert.ok(
      JSON.stringify(Object.keys(payload).sort()) ===
        JSON.stringify([
          'aud',
          'exp',
          'iat',
          'iss',
          'permissions',
          'roles',
          'scope',
          'sub',
        ]),
      'Unexpected JWT claims.',
    );
    assert.ok(
      payload.sub === expected.subject &&
        payload.aud === expected.audience &&
        Number.isSafeInteger(payload.iat) &&
        Number.isSafeInteger(payload.exp) &&
        payload.exp! - payload.iat! === expected.ttlSeconds &&
        payload.scope === expected.scopes.join(' ') &&
        JSON.stringify(payload.roles) === '[]' &&
        JSON.stringify(payload.permissions) === '[]',
      'Invalid JWT claim values.',
    );
    return { refreshToken: requireOpaqueRefreshToken(body.refresh_token) };
  };
}
