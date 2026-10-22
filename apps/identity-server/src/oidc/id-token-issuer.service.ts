import { Inject, Injectable } from '@nestjs/common';
import { SignJWT } from 'jose';
import { SigningKeyService } from '../security/signing/signing-key.service.js';
import {
  IdTokenClaimsService,
  type IdTokenClaimsInput,
} from './id-token-claims.service.js';

export type IssuedIdToken = { idToken: string };

@Injectable()
export class IdTokenIssuerService {
  constructor(
    @Inject(IdTokenClaimsService) private readonly claims: IdTokenClaimsService,
    @Inject(SigningKeyService) private readonly keys: SigningKeyService,
  ) {}

  async issue(input: IdTokenClaimsInput): Promise<IssuedIdToken> {
    try {
      const claims = this.claims.build(input);
      const key = await this.keys.getPrivateSigningKey();
      const kid = await this.keys.getKeyId();
      const idToken = await new SignJWT(claims)
        .setProtectedHeader({ alg: 'RS256', kid })
        .sign(key);
      return { idToken };
    } catch {
      throw new Error('ID token issuance failed.');
    }
  }
}
