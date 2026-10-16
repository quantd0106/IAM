import {
  BadRequestException,
  Catch,
  Inject,
  HttpException,
  HttpStatus,
  type ArgumentsHost,
} from '@nestjs/common';
import { BaseExceptionFilter, HttpAdapterHost } from '@nestjs/core';

// Body-parser errors occur before controller filters. Register globally but
// sanitize only the explicitly listed routes, including Express variants.
// The token branch also handles body-parser's non-Nest 400/413/415 errors.
@Catch()
export class RegisterValidationFilter extends BaseExceptionFilter {
  constructor(
    @Inject(HttpAdapterHost) private readonly adapterHost: HttpAdapterHost,
  ) {
    super(adapterHost.httpAdapter);
  }

  override catch(exception: unknown, host: ArgumentsHost): void {
    const request: unknown = host.switchToHttp().getRequest<unknown>();
    const adapter = this.adapterHost.httpAdapter;
    const method: unknown = adapter.getRequestMethod(request);
    const path: unknown = adapter.getRequestUrl(request);
    if (
      method === 'POST' &&
      typeof path === 'string' &&
      /^\/oauth\/token\/?$/i.test(path.split('?')[0]) &&
      (exception instanceof BadRequestException || isBodyParserError(exception))
    ) {
      adapter.setHeader(
        host.switchToHttp().getResponse<unknown>(),
        'Cache-Control',
        'no-store',
      );
      super.catch(
        new HttpException(
          {
            error: 'invalid_request',
            error_description: 'Invalid token request.',
          },
          HttpStatus.BAD_REQUEST,
        ),
        host,
      );
      return;
    }
    // Preserve the existing behavior of every non-token route/exception.
    if (!(exception instanceof BadRequestException)) {
      super.catch(exception, host);
      return;
    }
    if (
      method === 'POST' &&
      typeof path === 'string' &&
      /^\/auth\/login\/?$/i.test(path.split('?')[0])
    ) {
      super.catch(new BadRequestException('Invalid login request.'), host);
      return;
    }
    if (
      method === 'POST' &&
      typeof path === 'string' &&
      /^\/auth\/register\/?$/i.test(path.split('?')[0])
    ) {
      super.catch(
        new BadRequestException('Invalid registration request.'),
        host,
      );
      return;
    }
    if (
      method === 'POST' &&
      typeof path === 'string' &&
      /^\/auth\/password-reset\/request\/?$/i.test(path.split('?')[0])
    ) {
      super.catch(
        new BadRequestException('Invalid password reset request.'),
        host,
      );
      return;
    }
    if (
      method === 'POST' &&
      typeof path === 'string' &&
      /^\/auth\/password-reset\/consume\/?$/i.test(path.split('?')[0])
    ) {
      // Preserve only the controller's fixed token-failure message; parser
      // errors can contain arbitrary body fragments and must stay sanitized.
      super.catch(
        new BadRequestException(
          exception.message === 'Invalid or expired password reset token.'
            ? 'Invalid or expired password reset token.'
            : 'Invalid password reset consume request.',
        ),
        host,
      );
      return;
    }
    super.catch(exception, host);
  }
}

function isBodyParserError(exception: unknown): boolean {
  // body-parser wraps input failures in http-errors. Decompression failures
  // also have this shape but need not carry a `type` field. Never remap the
  // controller's Nest HttpException (including unsupported_grant_type).
  return (
    exception instanceof Error &&
    !(exception instanceof HttpException) &&
    'expose' in exception &&
    exception.expose === true &&
    'status' in exception &&
    (exception.status === 400 ||
      exception.status === 413 ||
      exception.status === 415)
  );
}
