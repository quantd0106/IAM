import {
  BadRequestException,
  Catch,
  Inject,
  type ArgumentsHost,
} from '@nestjs/common';
import { BaseExceptionFilter, HttpAdapterHost } from '@nestjs/core';

// Body-parser errors occur before controller filters. Register globally but
// sanitize only registration/reset requests, including Express route variants.
@Catch(BadRequestException)
export class RegisterValidationFilter extends BaseExceptionFilter {
  constructor(
    @Inject(HttpAdapterHost) private readonly adapterHost: HttpAdapterHost,
  ) {
    super(adapterHost.httpAdapter);
  }

  override catch(exception: BadRequestException, host: ArgumentsHost): void {
    const request: unknown = host.switchToHttp().getRequest<unknown>();
    const adapter = this.adapterHost.httpAdapter;
    const method: unknown = adapter.getRequestMethod(request);
    const path: unknown = adapter.getRequestUrl(request);
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
    super.catch(exception, host);
  }
}
