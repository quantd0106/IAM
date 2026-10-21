import {
  Body,
  Controller,
  Get,
  Header,
  Headers,
  HttpCode,
  HttpException,
  HttpStatus,
  Inject,
  Post,
  Query,
  Res,
  UnauthorizedException,
} from '@nestjs/common';
import {
  AuthorizationService,
  type AuthorizationResult,
} from './authorization.service.js';
import { HttpAdapterHost } from '@nestjs/core';
import { buildAuthorizationSuccessLocation } from './authorization-response.js';
import {
  TokenRequestService,
  type TokenRequestResult,
} from './token-request.service.js';
import {
  AuthorizationCodeService,
  type AuthorizationCodeConsumeResult,
} from './authorization-code.service.js';
import { verifyTokenPkce } from './token-pkce.policy.js';
import {
  ClientAuthenticationService,
  type TokenClientAuthenticationResult,
} from '../client-registry/client-authentication.service.js';
import { AccessTokenIssuerService } from '../tokens/access-token-issuer.service.js';
import { requireAccessTokenIssuance } from '../tokens/access-token-issuance.policy.js';

@Controller('oauth')
export class OAuthController {
  constructor(
    @Inject(AuthorizationService)
    private readonly authorization: AuthorizationService,
    @Inject(HttpAdapterHost) private readonly adapterHost: HttpAdapterHost,
    @Inject(TokenRequestService)
    private readonly tokenRequests: TokenRequestService,
    @Inject(AuthorizationCodeService)
    private readonly codes: Pick<AuthorizationCodeService, 'consume'>,
    @Inject(ClientAuthenticationService)
    private readonly clients: ClientAuthenticationService,
    @Inject(AccessTokenIssuerService)
    private readonly tokens: AccessTokenIssuerService,
  ) {}

  @Post('token')
  @HttpCode(HttpStatus.OK)
  @Header('Cache-Control', 'no-store')
  @Header('Pragma', 'no-cache')
  async token(
    @Body() body: unknown,
    @Headers('content-type') contentType: string | undefined,
    @Headers('authorization') authorizationHeader: string | undefined,
    @Res({ passthrough: true }) response: unknown,
  ): Promise<{
    access_token: string;
    token_type: 'Bearer';
    expires_in: number;
    scope: string;
  }> {
    let result: TokenRequestResult;
    try {
      result = this.tokenRequests.validate(body, contentType);
    } catch {
      throw new HttpException(
        { error: 'server_error', error_description: 'Token request failed.' },
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
    if (!result.ok)
      throw new HttpException(
        {
          error: result.error,
          error_description:
            result.error === 'unsupported_grant_type'
              ? 'Unsupported grant type.'
              : 'Invalid token request.',
        },
        HttpStatus.BAD_REQUEST,
      );
    let authentication: TokenClientAuthenticationResult;
    try {
      authentication = await this.clients.authenticateTokenClient(
        result.request.client_id,
        authorizationHeader,
      );
    } catch {
      throw new HttpException(
        { error: 'server_error', error_description: 'Token request failed.' },
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
    if (!authentication.ok) {
      this.adapterHost.httpAdapter.setHeader(
        response,
        'WWW-Authenticate',
        'Basic realm="oauth/token"',
      );
      throw new HttpException(
        {
          error: 'invalid_client',
          error_description: 'Client authentication failed.',
        },
        HttpStatus.UNAUTHORIZED,
      );
    }
    let grant: AuthorizationCodeConsumeResult;
    let issuance: ReturnType<typeof requireAccessTokenIssuance>;
    let pkceValid = false;
    try {
      issuance = requireAccessTokenIssuance(authentication.client);
      grant = await this.codes.consume({
        code: result.request.code,
        clientId: result.request.client_id,
        redirectUri: result.request.redirect_uri,
      });
      if (grant.ok)
        pkceValid = verifyTokenPkce(
          grant.state.codeChallenge,
          result.request.code_verifier,
        );
    } catch {
      throw new HttpException(
        { error: 'server_error', error_description: 'Token request failed.' },
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
    if (!grant.ok || !pkceValid)
      throw new HttpException(
        {
          error: 'invalid_grant',
          error_description: 'Invalid authorization grant.',
        },
        HttpStatus.BAD_REQUEST,
      );
    try {
      const token = await this.tokens.issue({
        subject: grant.state.userId,
        audience: issuance.audience,
        scopes: grant.state.grantedScopes,
        ttlSeconds: issuance.ttlSeconds,
        roles: [],
        permissions: [],
      });
      return {
        access_token: token.accessToken,
        token_type: 'Bearer',
        expires_in: token.expiresIn,
        scope: token.scope,
      };
    } catch {
      throw new HttpException(
        { error: 'server_error', error_description: 'Token request failed.' },
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  @Get('authorize')
  @HttpCode(HttpStatus.FOUND)
  @Header('Cache-Control', 'no-store')
  async authorize(
    @Query() query: unknown,
    @Headers('cookie') cookieHeader: string | undefined,
    @Res({ passthrough: true }) response: unknown,
  ): Promise<void> {
    let result: AuthorizationResult;
    try {
      result = await this.authorization.authorize(query, cookieHeader);
      if (result.ok) {
        const location = buildAuthorizationSuccessLocation({
          redirectUri: result.request.redirect_uri,
          code: result.authorizationCode,
          state: result.request.state,
        });
        // Header only: redirect helpers may duplicate the bearer code in an HTML body.
        this.adapterHost.httpAdapter.setHeader(response, 'Location', location);
      }
    } catch {
      throw new HttpException(
        {
          error: 'server_error',
          error_description: 'Authorization request failed.',
        },
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
    if (!result.ok && result.error === 'authentication_required')
      throw new UnauthorizedException('Authentication required.');
    if (!result.ok)
      throw new HttpException(
        {
          error: result.error,
          error_description: 'Invalid authorization request.',
        },
        HttpStatus.BAD_REQUEST,
      );
    // Nest sends the configured 302 with an empty body. Never log the Location.
  }
}
