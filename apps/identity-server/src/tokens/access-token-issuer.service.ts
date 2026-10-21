import { Inject, Injectable } from '@nestjs/common';
import { SignJWT } from 'jose';
import { SigningKeyService } from '../security/signing/signing-key.service.js';
import {
  AccessTokenClaimsService,
  type AccessTokenClaimsInput,
} from './access-token-claims.service.js';

export type IssuedAccessToken = {
  accessToken: string;
  expiresIn: number;
  scope: string;
};

@Injectable()
export class AccessTokenIssuerService {
  constructor(
    @Inject(AccessTokenClaimsService)
    private readonly claims: AccessTokenClaimsService,
    @Inject(SigningKeyService) private readonly keys: SigningKeyService,
  ) {}

  async issue(input: AccessTokenClaimsInput): Promise<IssuedAccessToken> {
    try {
      const claims = this.claims.build(input);
      const key = await this.keys.getPrivateSigningKey();
      const kid = await this.keys.getKeyId();
      const accessToken = await new SignJWT(claims)
        .setProtectedHeader({ alg: 'RS256', kid })
        .sign(key);
      return {
        accessToken,
        expiresIn: claims.exp - claims.iat,
        scope: claims.scope,
      };
    } catch {
      throw new Error('Access token issuance failed.');
    }
  }
}
