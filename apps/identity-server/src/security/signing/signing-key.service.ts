import { Inject, Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { createPublicKey, KeyObject } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { exportJWK, importPKCS8, importSPKI, type CryptoKey } from 'jose';
import type { Environment } from '../../config/env.schema.js';

export type PublicSigningJwk = Readonly<{
  kty: 'RSA';
  kid: string;
  alg: 'RS256';
  use: 'sig';
  n: string;
  e: string;
}>;

type SigningKeys = {
  privateKey: CryptoKey;
  publicKey: CryptoKey;
  publicJwk: PublicSigningJwk;
};

@Injectable()
export class SigningKeyService {
  #initialization: Promise<SigningKeys> | undefined;

  constructor(
    @Inject(ConfigService)
    private readonly config: ConfigService<Environment, true>,
  ) {}

  /** Trusted in-process signing capability only; never serialize this key. */
  async getPrivateSigningKey(): Promise<CryptoKey> {
    return (await this.load()).privateKey;
  }

  async getPublicVerificationKey(): Promise<CryptoKey> {
    return (await this.load()).publicKey;
  }

  async getPublicJwk(): Promise<PublicSigningJwk> {
    // A caller cannot mutate the cached metadata used by other consumers.
    return { ...(await this.load()).publicJwk };
  }

  async getKeyId(): Promise<string> {
    return (await this.load()).publicJwk.kid;
  }

  private load(): Promise<SigningKeys> {
    // Publish only the in-flight promise, never a partially validated key set.
    this.#initialization ??= this.initialize().catch(() => {
      this.#initialization = undefined;
      // A later explicit access may retry; no native error/cause is retained.
      throw new Error('Signing key initialization failed.');
    });
    return this.#initialization;
  }

  private async initialize(): Promise<SigningKeys> {
    const kid = this.config.getOrThrow('JWT_KEY_ID', { infer: true });
    if (typeof kid !== 'string' || kid.trim().length === 0)
      throw new Error('Invalid key identifier.');
    const privatePath = this.config.getOrThrow('JWT_PRIVATE_KEY_PATH', {
      infer: true,
    });
    const publicPath = this.config.getOrThrow('JWT_PUBLIC_KEY_PATH', {
      infer: true,
    });
    // Relative paths follow the Identity Server process working directory.
    const [privatePem, publicPem] = await Promise.all([
      readFile(privatePath, 'utf8'),
      readFile(publicPath, 'utf8'),
    ]);
    const [privateKey, publicKey] = await Promise.all([
      importPKCS8(privatePem, 'RS256', { extractable: false }),
      importSPKI(publicPem, 'RS256', { extractable: true }),
    ]);
    // Node's established key APIs derive PUBLIC metadata without exporting a private JWK.
    const derivedPublic = createPublicKey(KeyObject.from(privateKey));
    if (
      derivedPublic.asymmetricKeyType !== 'rsa' ||
      (derivedPublic.asymmetricKeyDetails?.modulusLength ?? 0) < 2048
    )
      throw new Error('Invalid RSA signing key.');
    const derived = derivedPublic.export({ format: 'jwk' });
    const exported = await exportJWK(publicKey);
    if (
      exported.kty !== 'RSA' ||
      !exported.n ||
      !exported.e ||
      exported.n !== derived.n ||
      exported.e !== derived.e
    )
      throw new Error('Invalid RSA key pair.');
    return {
      privateKey,
      publicKey,
      // Explicit allowlist: never spread an arbitrary exported JWK into this boundary.
      publicJwk: Object.freeze({
        kty: 'RSA',
        kid,
        alg: 'RS256',
        use: 'sig',
        n: exported.n,
        e: exported.e,
      }),
    };
  }
}
