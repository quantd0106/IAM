import { Controller, Get, Header, Inject, Res } from '@nestjs/common';
import type { ServerResponse } from 'node:http';
import { JwksService } from './jwks.service.js';

@Controller('.well-known')
export class JwksController {
  constructor(@Inject(JwksService) private readonly jwks: JwksService) {}

  @Get('jwks.json')
  @Header('Content-Type', 'application/json')
  @Header('Cache-Control', 'no-store')
  async document(@Res() response: ServerResponse): Promise<void> {
    let body: string;
    try {
      body = JSON.stringify(await this.jwks.build());
    } catch {
      response.statusCode = 500;
      response.end(
        JSON.stringify({
          error: 'server_error',
          error_description: 'JWKS request failed.',
        }),
      );
      return;
    }
    response.setHeader('Cache-Control', 'public, max-age=300');
    // End only this route's JSON response directly: no adapter-generated ETag
    // or implicit conditional 304, and no application-wide HTTP setting change.
    response.end(body);
  }
}
