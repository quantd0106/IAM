import {
  Controller,
  Get,
  Header,
  HttpException,
  HttpStatus,
  Inject,
} from '@nestjs/common';
import {
  DiscoveryService,
  type DiscoveryMetadata,
} from './discovery.service.js';

@Controller('.well-known')
export class DiscoveryController {
  constructor(
    @Inject(DiscoveryService) private readonly discovery: DiscoveryService,
  ) {}

  @Get('openid-configuration')
  @Header('Cache-Control', 'no-store')
  configuration(): DiscoveryMetadata {
    try {
      return this.discovery.build();
    } catch {
      throw new HttpException(
        {
          error: 'server_error',
          error_description: 'Discovery request failed.',
        },
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }
}
