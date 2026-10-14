import {
  BadRequestException,
  Controller,
  Delete,
  Get,
  Headers,
  HttpCode,
  HttpStatus,
  Inject,
  InternalServerErrorException,
  NotFoundException,
  Param,
  Res,
  UnauthorizedException,
} from '@nestjs/common';
import { HttpAdapterHost } from '@nestjs/core';
import { IdpSessionCookieService } from '../session/idp-session-cookie.service.js';
import { sessionIdSchema } from '../session/idp-session-state.js';
import {
  IdpOwnSessionService,
  type OwnSession,
  type OwnSessionListResult,
  type OwnSessionRevokeResult,
} from './idp-own-session.service.js';

@Controller('auth/sessions')
export class AuthSessionsController {
  constructor(
    @Inject(IdpOwnSessionService)
    private readonly sessions: IdpOwnSessionService,
    @Inject(IdpSessionCookieService)
    private readonly cookies: IdpSessionCookieService,
    @Inject(HttpAdapterHost) private readonly adapterHost: HttpAdapterHost,
  ) {}

  @Get()
  async list(
    @Headers('cookie') cookieHeader: string | undefined,
  ): Promise<{ sessions: OwnSession[] }> {
    const current = this.cookies.parse(cookieHeader);
    if (current === null)
      throw new UnauthorizedException('Authentication required.');
    let result: OwnSessionListResult;
    try {
      result = await this.sessions.list(current);
    } catch {
      throw new InternalServerErrorException('Session management failed.');
    }
    if (!result.ok) throw new UnauthorizedException('Authentication required.');
    return { sessions: result.sessions };
  }

  @Delete(':sessionId')
  @HttpCode(HttpStatus.NO_CONTENT)
  async revoke(
    @Headers('cookie') cookieHeader: string | undefined,
    @Param('sessionId') targetSessionId: string,
    @Res({ passthrough: true }) response: unknown,
  ): Promise<void> {
    if (!sessionIdSchema.safeParse(targetSessionId).success)
      throw new BadRequestException('Invalid session identifier.');
    const current = this.cookies.parse(cookieHeader);
    if (current === null)
      throw new UnauthorizedException('Authentication required.');
    let result: OwnSessionRevokeResult;
    try {
      result = await this.sessions.revoke(current, targetSessionId);
    } catch {
      throw new InternalServerErrorException('Session management failed.');
    }
    if (!result.ok) {
      if (result.reason === 'INVALID_IDENTIFIER')
        throw new BadRequestException('Invalid session identifier.');
      if (result.reason === 'NOT_FOUND')
        throw new NotFoundException('Session not found.');
      throw new UnauthorizedException('Authentication required.');
    }
    if (result.current) {
      try {
        this.adapterHost.httpAdapter.setHeader(
          response,
          'Set-Cookie',
          this.cookies.clear(),
        );
      } catch {
        throw new InternalServerErrorException('Session management failed.');
      }
    }
  }
}
