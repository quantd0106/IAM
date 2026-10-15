import { Inject, Injectable } from '@nestjs/common';
import type { ClientType, Prisma } from '../generated/prisma/client.js';
import { PrismaService } from '../prisma/prisma.service.js';

export type EnabledClient = {
  id: string;
  clientId: string;
  name: string;
  clientType: ClientType;
  accessTokenTtl: number;
  refreshTokenTtl: number;
  redirectUris: string[];
};

const metadataSelection = {
  id: true,
  clientId: true,
  name: true,
  clientType: true,
  enabled: true,
  accessTokenTtl: true,
  refreshTokenTtl: true,
  redirectUris: { select: { redirectUri: true } },
} as const satisfies Prisma.ClientSelect;

@Injectable()
export class ClientLookupService {
  constructor(
    @Inject(PrismaService)
    private readonly prisma: Pick<PrismaService, 'client'>,
  ) {}

  /** Exact OAuth client_id, not internal UUID. No authentication or URI policy. */
  async requireEnabledClient(clientId: string): Promise<EnabledClient> {
    let client: Prisma.ClientGetPayload<{
      select: typeof metadataSelection;
    }> | null;
    try {
      client = await this.prisma.client.findUnique({
        where: { clientId },
        select: metadataSelection,
      });
    } catch {
      throw new Error('Client lookup failed.');
    }
    if (!client || !client.enabled) throw new Error('Client unavailable.');

    // Explicit projection: never return unselected fields or secret material.
    return {
      id: client.id,
      clientId: client.clientId,
      name: client.name,
      clientType: client.clientType,
      accessTokenTtl: client.accessTokenTtl,
      refreshTokenTtl: client.refreshTokenTtl,
      redirectUris: client.redirectUris.map((row) => row.redirectUri).sort(),
    };
  }
}
