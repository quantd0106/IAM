import {
  BadRequestException,
  Body,
  Controller,
  Inject,
  Post,
} from '@nestjs/common';
import { registerSchema } from './register.schema.js';
import {
  RegistrationService,
  type SafeRegisteredUser,
} from './registration.service.js';

@Controller('auth')
export class AuthController {
  constructor(
    @Inject(RegistrationService)
    private readonly registration: RegistrationService,
  ) {}

  @Post('register')
  register(@Body() body: unknown): Promise<SafeRegisteredUser> {
    const result = registerSchema.safeParse(body);
    if (!result.success)
      throw new BadRequestException('Invalid registration request.');
    return this.registration.register(result.data);
  }
}
