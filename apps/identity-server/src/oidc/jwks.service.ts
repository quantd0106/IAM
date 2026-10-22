import { Inject, Injectable } from '@nestjs/common';
import {
  SigningKeyService,
  type PublicSigningJwk,
} from '../security/signing/signing-key.service.js';

export type JwksDocument = { keys: PublicSigningJwk[] };

@Injectable()
export class JwksService {
  constructor(
    @Inject(SigningKeyService) private readonly keys: SigningKeyService,
  ) {}

  async build(): Promise<JwksDocument> {
    try {
      const key = await this.keys.getPublicJwk();
      // Public HTTP boundary: never spread an arbitrary key or cached object.
      return {
        keys: [
          {
            kty: key.kty,
            kid: key.kid,
            alg: key.alg,
            use: key.use,
            n: key.n,
            e: key.e,
          },
        ],
      };
    } catch {
      throw new Error('JWKS build failed.');
    }
  }
}
