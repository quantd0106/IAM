import { Injectable } from '@nestjs/common';
import { createHash, randomBytes } from 'node:crypto';

export type GeneratedRefreshToken = {
  rawToken: string;
  tokenHash: string;
};

const rawTokenPattern = /^[A-Za-z0-9_-]{43}$/;
const tokenHashPattern = /^[0-9a-f]{64}$/;

@Injectable()
export class RefreshTokenGeneratorService {
  /** Credential material only. No storage, expiry, collision lookup or retry. */
  generate(): GeneratedRefreshToken {
    try {
      const bytes = randomBytes(32);
      if (!Buffer.isBuffer(bytes) || bytes.length !== 32)
        throw new Error('Invalid random material.');
      const rawToken = bytes.toString('base64url');
      if (
        typeof rawToken !== 'string' ||
        rawToken.length !== 43 ||
        !rawTokenPattern.test(rawToken)
      )
        throw new Error('Invalid raw encoding.');
      const decoded = Buffer.from(rawToken, 'base64url');
      if (decoded.length !== 32 || decoded.toString('base64url') !== rawToken)
        throw new Error('Noncanonical raw encoding.');
      return { rawToken, tokenHash: this.hash(rawToken) };
    } catch {
      // Never retain native causes, random bytes, raw credentials or hashes.
      throw new Error('Refresh token generation failed.');
    }
  }

  /** Exact opaque presented string; future protocol validation is separate. */
  hash(rawToken: string): string {
    try {
      if (typeof rawToken !== 'string' || rawToken.length === 0)
        throw new Error('Invalid hash input.');
      const tokenHash = createHash('sha256')
        .update(rawToken, 'utf8')
        .digest('hex');
      if (
        typeof tokenHash !== 'string' ||
        tokenHash.length !== 64 ||
        !tokenHashPattern.test(tokenHash)
      )
        throw new Error('Invalid digest representation.');
      return tokenHash;
    } catch {
      throw new Error('Refresh token hashing failed.');
    }
  }
}
