import {
  Controller,
  Get,
  Header,
  Headers,
  HttpCode,
  HttpException,
  HttpStatus,
  Inject,
  Query,
  UnauthorizedException,
} from '@nestjs/common';
import {
  AuthorizationService,
  type AuthorizationResult,
} from './authorization.service.js';

@Controller('oauth')
export class OAuthController {
  constructor(
    @Inject(AuthorizationService)
    private readonly authorization: AuthorizationService,
  ) {}

  @Get('authorize')
  @HttpCode(HttpStatus.NO_CONTENT)
  @Header('Cache-Control', 'no-store')
  async authorize(
    @Query() query: unknown,
    @Headers('cookie') cookieHeader: string | undefined,
  ): Promise<void> {
    let result: AuthorizationResult;
    try {
      result = await this.authorization.authorize(query, cookieHeader);
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
    // Code has been persisted by hash; discard the transient raw code until M5.6.
    // No redirect, cookie, session, authorization code or token response.
  }
}
