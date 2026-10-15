import { Inject, Injectable } from '@nestjs/common';
import {
  ClientLookupService,
  type EnabledClient,
} from '../client-registry/client-lookup.service.js';
import {
  authorizationRequestSchema,
  type AuthorizationRequest,
} from './authorization-request.schema.js';

export type AuthorizationRequestResult =
  | {
      ok: true;
      client: EnabledClient;
      request: AuthorizationRequest & { response_type: 'code' };
    }
  | { ok: false; error: 'invalid_request' | 'unsupported_response_type' };

@Injectable()
export class AuthorizationRequestService {
  constructor(
    @Inject(ClientLookupService)
    private readonly clients: Pick<ClientLookupService, 'requireEnabledClient'>,
  ) {}

  async validate(query: unknown): Promise<AuthorizationRequestResult> {
    const input = authorizationRequestSchema.safeParse(query);
    if (!input.success) return { ok: false, error: 'invalid_request' };
    const request = input.data;
    if (request.response_type !== 'code')
      return { ok: false, error: 'unsupported_response_type' };

    let client: EnabledClient | null;
    try {
      client = await this.clients.requireEnabledClient(request.client_id);
    } catch (error) {
      // M4.6 documents this same fixed rejection for unknown/disabled clients.
      if (error instanceof Error && error.message === 'Client unavailable.')
        return { ok: false, error: 'invalid_request' };
      // Retain only the failure classification, never private driver causes.
      client = null;
    }
    if (client === null) throw new Error('Authorization request failed.');
    if (!client.redirectUris.includes(request.redirect_uri))
      return { ok: false, error: 'invalid_request' };
    // M5.1 minimum presence/method only; no challenge format/entropy/verifier work.
    if (
      client.clientType === 'PUBLIC' &&
      (request.code_challenge === undefined ||
        request.code_challenge_method !== 'S256')
    )
      return { ok: false, error: 'invalid_request' };
    return { ok: true, client, request: { ...request, response_type: 'code' } };
  }
}
