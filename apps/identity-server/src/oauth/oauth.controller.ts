import {
  Controller,
  Get,
  Header,
  HttpCode,
  HttpException,
  HttpStatus,
  Inject,
  Query,
} from '@nestjs/common';
import {
  AuthorizationRequestService,
  type AuthorizationRequestResult,
} from './authorization-request.service.js';

@Controller('oauth')
export class OAuthController {
  constructor(
    @Inject(AuthorizationRequestService)
    private readonly authorization: AuthorizationRequestService,
  ) {}

  @Get('authorize')
  @HttpCode(HttpStatus.NO_CONTENT)
  @Header('Cache-Control', 'no-store')
  async authorize(@Query() query: unknown): Promise<void> {
    let result: AuthorizationRequestResult;
    try {
      result = await this.authorization.validate(query);
    } catch {
      throw new HttpException(
        {
          error: 'server_error',
          error_description: 'Authorization request failed.',
        },
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
    if (!result.ok)
      throw new HttpException(
        {
          error: result.error,
          error_description: 'Invalid authorization request.',
        },
        HttpStatus.BAD_REQUEST,
      );
    // Interim validation-only success: discard transient request/grantedScopes.
    // No redirect, cookie, session, authorization code or token response.
  }
}
