import { Inject, Injectable } from '@nestjs/common';
import * as argon2 from 'argon2';
import type { ClientType, Prisma } from '../generated/prisma/client.js';
import { PrismaService } from '../prisma/prisma.service.js';
import { parseClientSecretBasic } from './client-secret-basic.js';

export type TokenClientAuthenticationResult =
  | {
      ok: true;
      client: {
        id: string;
        clientId: string;
        clientType: ClientType;
        accessTokenTtl: number;
        accessTokenAudience: string | null;
        refreshTokenTtl: number;
      };
    }
  | { ok: false; error: 'invalid_client' };

const authenticationSelection = {
  id: true,
  clientId: true,
  clientType: true,
  enabled: true,
  clientSecretHash: true,
  accessTokenTtl: true,
  accessTokenAudience: true,
  refreshTokenTtl: true,
} as const satisfies Prisma.ClientSelect;
const invalidClient = { ok: false, error: 'invalid_client' } as const;

@Injectable()
export class ClientAuthenticationService {
  constructor(
    @Inject(PrismaService)
    private readonly prisma: Pick<PrismaService, 'client'>,
  ) {}

  /** Read-only capability. Secret/hash never leave this boundary. */
  async authenticateTokenClient(
    clientId: string,
    authorizationHeader: string | undefined,
  ): Promise<TokenClientAuthenticationResult> {
    try {
      const client = await this.prisma.client.findUnique({
        where: { clientId },
        select: authenticationSelection,
      });
      if (!client || !client.enabled) return invalidClient;
      if (client.clientType === 'PUBLIC') {
        if (authorizationHeader !== undefined) return invalidClient;
      } else {
        const credentials = parseClientSecretBasic(authorizationHeader);
        if (
          !credentials ||
          credentials.clientId !== clientId ||
          client.clientSecretHash === null
        )
          return invalidClient;
        if (!client.clientSecretHash.startsWith('$argon2id$'))
          throw new Error('Invalid stored client credential.');
        if (!(await argon2.verify(client.clientSecretHash, credentials.secret)))
          return invalidClient;
      }
      return {
        ok: true,
        client: {
          id: client.id,
          clientId: client.clientId,
          clientType: client.clientType,
          accessTokenTtl: client.accessTokenTtl,
          accessTokenAudience: client.accessTokenAudience,
          refreshTokenTtl: client.refreshTokenTtl,
        },
      };
    } catch {
      // Native database/Argon2 causes are never credential failures or log data.
      throw new Error('Token client authentication failed.');
    }
  }
}
