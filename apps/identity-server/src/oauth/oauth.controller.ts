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

@Controller('oauth')
export class OAuthController {
  constructor(
    @Inject(AuthorizationService)
    private readonly authorization: AuthorizationService,
    @Inject(HttpAdapterHost) private readonly adapterHost: HttpAdapterHost,
    @Inject(TokenRequestService)
    private readonly tokenRequests: TokenRequestService,
  ) {}

  @Post('token')
  @HttpCode(HttpStatus.NO_CONTENT)
  @Header('Cache-Control', 'no-store')
  token(
    @Body() body: unknown,
    @Headers('content-type') contentType: string | undefined,
  ): void {
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
    // Temporary M6.1 success only: never read/consume a code or issue a token.
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
