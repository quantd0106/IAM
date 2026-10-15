import { Inject, Injectable } from '@nestjs/common';
import { z } from 'zod';
import { PrismaService } from '../prisma/prisma.service.js';

const clientRecordIdSchema = z.uuid();

@Injectable()
export class ScopeLookupService {
  constructor(
    @Inject(PrismaService)
    private readonly prisma: Pick<PrismaService, 'clientScope'>,
  ) {}

  /** Caller first resolves an enabled client. UUID alone confers no authority. */
  async getAllowedScopeNames(clientRecordId: string): Promise<string[]> {
    if (!clientRecordIdSchema.safeParse(clientRecordId).success)
      throw new Error('Invalid client record identifier.');
    try {
      const assignments = await this.prisma.clientScope.findMany({
        where: { clientId: clientRecordId },
        select: { scope: { select: { name: true } } },
      });
      // Exact deduplication/code-unit order, independent of database/host locale.
      // Empty/unassigned/unknown UUID returns []; never invent default scopes.
      return [...new Set(assignments.map(({ scope }) => scope.name))].sort();
    } catch {
      throw new Error('Scope lookup failed.');
    }
  }
}
