import { Inject, Injectable } from '@nestjs/common';
import {
  ClientLookupService,
  type EnabledClient,
} from '../client-registry/client-lookup.service.js';
import {
  authorizationRequestSchema,
  type AuthorizationRequest,
} from './authorization-request.schema.js';
import { validateAuthorizationPkce } from './authorization-pkce.policy.js';
import { ScopeLookupService } from '../client-registry/scope-lookup.service.js';
import { calculateGrantedScopes } from './authorization-scope.policy.js';

export type AuthorizationRequestResult =
  | {
      ok: true;
      client: EnabledClient;
      request: AuthorizationRequest & { response_type: 'code' };
      grantedScopes: string[];
    }
  | {
      ok: false;
      error: 'invalid_request' | 'unsupported_response_type' | 'invalid_scope';
    };

@Injectable()
export class AuthorizationRequestService {
  constructor(
    @Inject(ClientLookupService)
    private readonly clients: Pick<ClientLookupService, 'requireEnabledClient'>,
    @Inject(ScopeLookupService)
    private readonly scopes: Pick<ScopeLookupService, 'getAllowedScopeNames'>,
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
    if (
      !validateAuthorizationPkce(
        client.clientType,
        request.code_challenge,
        request.code_challenge_method,
      )
    )
      return { ok: false, error: 'invalid_request' };
    let allowedScopes: string[];
    try {
      allowedScopes = await this.scopes.getAllowedScopeNames(client.id);
    } catch {
      // A failed registry read is not a forbidden-scope policy decision.
      throw new Error('Authorization request failed.');
    }
    const grant = calculateGrantedScopes(request.scope, allowedScopes);
    if (!grant.ok) return { ok: false, error: 'invalid_scope' };
    return {
      ok: true,
      client,
      request: { ...request, response_type: 'code' },
      grantedScopes: grant.grantedScopes,
    };
  }
}
