import { Inject, Injectable } from '@nestjs/common';
import { randomBytes } from 'node:crypto';
import * as argon2 from 'argon2';
import { z } from 'zod';
import { PrismaService } from '../prisma/prisma.service.js';

const clientRecordIdSchema = z.uuid();

export type IssuedClientSecret = { clientSecret: string };

@Injectable()
export class ClientSecretService {
  constructor(
    @Inject(PrismaService)
    private readonly prisma: Pick<PrismaService, 'client'>,
  ) {}

  /**
   * Internal capability: the caller must authorize issuance/rotation beforehand.
   * Uses internal Client.id, NOT the OAuth client_id. NULL hash means first issue;
   * otherwise this replaces the hash. No raw-secret recovery/verification API.
   */
  async issueSecret(clientRecordId: string): Promise<IssuedClientSecret> {
    try {
      if (!clientRecordIdSchema.safeParse(clientRecordId).success)
        throw new Error('Invalid client record identifier.');
      const client = await this.prisma.client.findUnique({
        where: { id: clientRecordId },
        select: { id: true, clientType: true, clientSecretHash: true },
      });
      // Fail before randomness/hashing; never convert a PUBLIC client.
      if (!client || client.clientType !== 'CONFIDENTIAL')
        throw new Error('Confidential client required.');

      const clientSecret = randomBytes(32).toString('base64url');
      // Library defaults supply costs and an independent random salt.
      const clientSecretHash = await argon2.hash(clientSecret, {
        type: argon2.argon2id,
      });
      const updated = await this.prisma.client.updateMany({
        where: {
          id: client.id,
          clientType: 'CONFIDENTIAL',
          clientSecretHash: client.clientSecretHash,
        },
        data: { clientSecretHash },
      });
      // No retry: a stale candidate must never be returned as successful.
      if (updated.count !== 1)
        throw new Error('Client secret changed concurrently.');
      return { clientSecret };
    } catch {
      // Never expose native/driver causes, hashes, raw secrets or identifiers.
      throw new Error('Client secret issuance failed.');
    }
  }
}
