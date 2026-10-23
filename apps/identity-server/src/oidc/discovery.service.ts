import { Inject, Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import type { Environment } from '../config/env.schema.js';

export type DiscoveryMetadata = {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  userinfo_endpoint: string;
  jwks_uri: string;
  scopes_supported: ['openid', 'profile', 'email'];
  response_types_supported: ['code'];
  response_modes_supported: ['query'];
  grant_types_supported: ['authorization_code', 'refresh_token'];
  subject_types_supported: ['public'];
  id_token_signing_alg_values_supported: ['RS256'];
  token_endpoint_auth_methods_supported: ['client_secret_basic', 'none'];
  code_challenge_methods_supported: ['S256'];
  claims_parameter_supported: false;
  request_parameter_supported: false;
  request_uri_parameter_supported: false;
};

@Injectable()
export class DiscoveryService {
  constructor(
    @Inject(ConfigService)
    private readonly config: ConfigService<Environment, true>,
  ) {}

  build(): DiscoveryMetadata {
    try {
      const issuer = this.config.getOrThrow('ISSUER_URL', { infer: true });
      if (typeof issuer !== 'string' || issuer.length === 0)
        throw new Error('Invalid issuer configuration.');
      const url = new URL(issuer);
      // A Discovery-only policy: never repair query/fragment or expose credentials.
      // Do not tighten global config or change M6's exact token-issuer semantics.
      if (
        !['http:', 'https:'].includes(url.protocol) ||
        !url.hostname ||
        url.username !== '' ||
        url.password !== '' ||
        issuer.includes('?') ||
        issuer.includes('#')
      )
        throw new Error('Invalid issuer configuration.');
      return {
        issuer,
        authorization_endpoint: new URL('/oauth/authorize', url).href,
        token_endpoint: new URL('/oauth/token', url).href,
        userinfo_endpoint: new URL('/oidc/userinfo', url).href,
        jwks_uri: new URL('/.well-known/jwks.json', url).href,
        scopes_supported: ['openid', 'profile', 'email'],
        response_types_supported: ['code'],
        response_modes_supported: ['query'],
        grant_types_supported: ['authorization_code', 'refresh_token'],
        subject_types_supported: ['public'],
        id_token_signing_alg_values_supported: ['RS256'],
        token_endpoint_auth_methods_supported: ['client_secret_basic', 'none'],
        code_challenge_methods_supported: ['S256'],
        claims_parameter_supported: false,
        request_parameter_supported: false,
        request_uri_parameter_supported: false,
      };
    } catch {
      throw new Error('Discovery metadata build failed.');
    }
  }
}
