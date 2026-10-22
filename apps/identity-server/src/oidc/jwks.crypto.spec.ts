import { ConfigService } from '@nestjs/config';
import { generateKeyPairSync } from 'node:crypto';
import { mkdtemp, realpath, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, dirname, join } from 'node:path';
import { importJWK, jwtVerify } from 'jose';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { SigningKeyService } from '../security/signing/signing-key.service.js';
import { AccessTokenClaimsService } from '../tokens/access-token-claims.service.js';
import { AccessTokenIssuerService } from '../tokens/access-token-issuer.service.js';
import { JwksService } from './jwks.service.js';

describe('M7.2 JWKS / M6.7 issuer cryptographic consistency', () => {
  let directory: string;
  let keys: SigningKeyService;
  let issuer: AccessTokenIssuerService;
  const kid = 'MiXeD-e\u0301-Key';
  beforeAll(async () => {
    directory = await mkdtemp(join(await realpath(tmpdir()), 'iam-m72-owned-'));
    const pair = generateKeyPairSync('rsa', {
      modulusLength: 2048,
      privateKeyEncoding: { format: 'pem', type: 'pkcs8' },
      publicKeyEncoding: { format: 'pem', type: 'spki' },
    });
    const privatePath = join(directory, 'private.pem');
    const publicPath = join(directory, 'public.pem');
    await Promise.all([
      writeFile(privatePath, pair.privateKey, { mode: 0o600 }),
      writeFile(publicPath, pair.publicKey, { mode: 0o644 }),
    ]);
    keys = new SigningKeyService(
      new ConfigService({
        JWT_PRIVATE_KEY_PATH: privatePath,
        JWT_PUBLIC_KEY_PATH: publicPath,
        JWT_KEY_ID: kid,
      }),
    );
    issuer = new AccessTokenIssuerService(
      new AccessTokenClaimsService(
        new ConfigService({
          ISSUER_URL: 'http://localhost:3000',
          ACCESS_TOKEN_TTL_SECONDS: 600,
        }),
      ),
      keys,
    );
  }, 30000);
  afterAll(async () => {
    // Bound the exact owned fixture directory before recursive Windows cleanup.
    const target = await realpath(directory);
    expect(dirname(target)).toBe(await realpath(tmpdir()));
    expect(basename(target).startsWith('iam-m72-owned-')).toBe(true);
    await rm(target, { recursive: true, force: true });
  });
  it('verifies an actual access token using the published RSA JWK and proves identical configured/header/public kid', async () => {
    const document = await new JwksService(keys).build();
    const publicJwk = await keys.getPublicJwk();
    expect(document).toEqual({ keys: [publicJwk] });
    expect(Object.keys(document.keys[0]).sort()).toEqual([
      'alg',
      'e',
      'kid',
      'kty',
      'n',
      'use',
    ]);
    const verificationKey = await importJWK(document.keys[0], 'RS256');
    const input = {
      subject: 'c0e21e3f-d3ee-425c-a99f-c2e7a7cab53f',
      audience: 'student-api',
      scopes: ['profile'],
      roles: [],
      permissions: [],
    };
    const token = await issuer.issue(input);
    const verified = await jwtVerify(token.accessToken, verificationKey, {
      algorithms: ['RS256'],
      issuer: 'http://localhost:3000',
      audience: input.audience,
    });
    expect(verified.protectedHeader).toEqual({ alg: 'RS256', kid });
    expect(verified.protectedHeader.kid).toBe(await keys.getKeyId());
    expect(verified.protectedHeader.kid).toBe(publicJwk.kid);
    expect(verified.protectedHeader.kid).toBe(document.keys[0].kid);
    expect(verified.payload.sub).toBe(input.subject);
    expect(verified.payload.scope).toBe('profile');
    expect(verified.payload.exp! - verified.payload.iat!).toBe(600);
  });
});
