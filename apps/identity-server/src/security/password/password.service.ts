import { Injectable } from '@nestjs/common';
import * as argon2 from 'argon2';

@Injectable()
export class PasswordService {
  async hash(rawPassword: string): Promise<string> {
    try {
      // Library defaults supply costs and a fresh random salt; input is opaque.
      return await argon2.hash(rawPassword, { type: argon2.argon2id });
    } catch {
      // Do not attach the original error/cause: it may contain sensitive input.
      throw new Error('Password hashing failed.');
    }
  }

  /**
   * Mismatches return false. Malformed hashes that throw in the library and
   * internal failures reject with a safe error, not a disguised mismatch.
   */
  async verify(encodedHash: string, rawPassword: string): Promise<boolean> {
    try {
      return await argon2.verify(encodedHash, rawPassword);
    } catch {
      throw new Error('Password verification failed.');
    }
  }
}
