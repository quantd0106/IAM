import { Controller, Get, Inject, Post, Req, Res } from '@nestjs/common';
import type { IncomingMessage, ServerResponse } from 'node:http';
import { UserInfoAccessTokenService } from './userinfo-access-token.service.js';
import { UserInfoClaimsService } from './userinfo-claims.service.js';

@Controller('oidc')
export class UserInfoController {
  constructor(
    @Inject(UserInfoAccessTokenService)
    private readonly tokens: UserInfoAccessTokenService,
    @Inject(UserInfoClaimsService)
    private readonly claims: UserInfoClaimsService,
  ) {}

  @Get('userinfo')
  get(
    @Req() request: IncomingMessage,
    @Res() response: ServerResponse,
  ): Promise<void> {
    return this.userinfo(request, response);
  }

  @Post('userinfo')
  post(
    @Req() request: IncomingMessage,
    @Res() response: ServerResponse,
  ): Promise<void> {
    return this.userinfo(request, response);
  }

  private async userinfo(
    request: IncomingMessage,
    response: ServerResponse,
  ): Promise<void> {
    try {
      // Read only Authorization. Reject duplicate field lines instead of relying
      // on Node's default first-header-wins behavior. Never inspect cookies/body/query.
      const authorization = request.rawHeaders.flatMap((name, index) =>
        index % 2 === 0 && name.toLowerCase() === 'authorization'
          ? [request.rawHeaders[index + 1]]
          : [],
      );
      const result = await this.tokens.authenticate(
        authorization.length <= 1 ? authorization[0] : authorization,
      );
      if (result.ok) {
        const resolved = await this.claims.resolve({
          subject: result.subject,
          scopes: result.scopes,
        });
        if (resolved.ok) this.send(response, 200, resolved.claims);
        else this.invalidToken(response);
      } else if (result.error === 'missing_credentials') {
        this.send(response, 401, undefined, 'Bearer realm="userinfo"');
      } else if (result.error === 'insufficient_scope') {
        this.send(
          response,
          403,
          {
            error: 'insufficient_scope',
            error_description:
              'The access token does not grant UserInfo access.',
          },
          'Bearer realm="userinfo", error="insufficient_scope", scope="openid"',
        );
      } else {
        this.invalidToken(response);
      }
    } catch {
      this.send(response, 500, {
        error: 'server_error',
        error_description: 'UserInfo request failed.',
      });
    }
  }

  private invalidToken(response: ServerResponse): void {
    this.send(
      response,
      401,
      {
        error: 'invalid_token',
        error_description: 'Invalid access token.',
      },
      'Bearer realm="userinfo", error="invalid_token"',
    );
  }

  private send(
    response: ServerResponse,
    status: number,
    body?: Record<string, string>,
    challenge?: string,
  ): void {
    response.statusCode = status;
    response.setHeader('Cache-Control', 'no-store');
    response.setHeader('Pragma', 'no-cache');
    if (challenge !== undefined)
      response.setHeader('WWW-Authenticate', challenge);
    if (body !== undefined)
      response.setHeader('Content-Type', 'application/json');
    response.end(body === undefined ? undefined : JSON.stringify(body));
  }
}
