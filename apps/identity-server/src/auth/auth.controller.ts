import {
  BadRequestException,
  Body,
  Controller,
  HttpCode,
  HttpStatus,
  Inject,
  InternalServerErrorException,
  Post,
} from '@nestjs/common';
import { registerSchema } from './register.schema.js';
import {
  RegistrationService,
  type SafeRegisteredUser,
} from './registration.service.js';
import { passwordResetRequestSchema } from './password-reset-request.schema.js';
import { PasswordResetRequestService } from './password-reset-request.service.js';
import { passwordResetConsumeSchema } from './password-reset-consume.schema.js';
import {
  PasswordResetConsumeService,
  type PasswordResetConsumeResult,
} from './password-reset-consume.service.js';

@Controller('auth')
export class AuthController {
  constructor(
    @Inject(RegistrationService)
    private readonly registration: RegistrationService,
    @Inject(PasswordResetRequestService)
    private readonly passwordReset: PasswordResetRequestService,
    @Inject(PasswordResetConsumeService)
    private readonly passwordResetConsume: PasswordResetConsumeService,
  ) {}

  @Post('register')
  register(@Body() body: unknown): Promise<SafeRegisteredUser> {
    const result = registerSchema.safeParse(body);
    if (!result.success)
      throw new BadRequestException('Invalid registration request.');
    return this.registration.register(result.data);
  }

  @Post('password-reset/request')
  @HttpCode(HttpStatus.ACCEPTED)
  async requestPasswordReset(
    @Body() body: unknown,
  ): Promise<{ status: 'accepted' }> {
    const result = passwordResetRequestSchema.safeParse(body);
    if (!result.success)
      throw new BadRequestException('Invalid password reset request.');
    // The service handles operational failures; retain response equivalence even
    // if an unexpected implementation/provider failure rejects at this boundary.
    try {
      await this.passwordReset.request(result.data.email);
    } catch {
      // Never propagate internal account state or secret-bearing errors.
    }
    return { status: 'accepted' };
  }

  @Post('password-reset/consume')
  @HttpCode(HttpStatus.NO_CONTENT)
  async consumePasswordReset(@Body() body: unknown): Promise<void> {
    const input = passwordResetConsumeSchema.safeParse(body);
    if (!input.success)
      throw new BadRequestException('Invalid password reset consume request.');
    let result: PasswordResetConsumeResult;
    try {
      result = await this.passwordResetConsume.consume(
        input.data.token,
        input.data.newPassword,
      );
    } catch {
      throw new InternalServerErrorException('Password reset failed.');
    }
    if (!result.ok)
      throw new BadRequestException('Invalid or expired password reset token.');
  }
}
