import {
  BadRequestException,
  Body,
  Controller,
  Headers,
  HttpCode,
  HttpStatus,
  Inject,
  InternalServerErrorException,
  Post,
  Res,
  UnauthorizedException,
} from '@nestjs/common';
import { HttpAdapterHost } from '@nestjs/core';
import { IdpSessionCookieService } from '../session/idp-session-cookie.service.js';
import { IdpLoginService, type IdpLoginResult } from './idp-login.service.js';
import { IdpLogoutService } from './idp-logout.service.js';
import { loginSchema } from './login.schema.js';
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
    @Inject(IdpLoginService) private readonly loginService: IdpLoginService,
    @Inject(IdpLogoutService) private readonly logoutService: IdpLogoutService,
    @Inject(IdpSessionCookieService)
    private readonly sessionCookies: IdpSessionCookieService,
    @Inject(HttpAdapterHost) private readonly adapterHost: HttpAdapterHost,
  ) {}

  @Post('login')
  @HttpCode(HttpStatus.NO_CONTENT)
  async login(
    @Body() body: unknown,
    @Res({ passthrough: true }) response: unknown,
  ): Promise<void> {
    const input = loginSchema.safeParse(body);
    if (!input.success) throw new BadRequestException('Invalid login request.');
    let result: IdpLoginResult;
    try {
      result = await this.loginService.login(
        input.data.identifier,
        input.data.password,
      );
    } catch {
      throw new InternalServerErrorException('Login failed.');
    }
    if (!result.ok)
      throw new UnauthorizedException('Invalid login credentials.');
    try {
      const cookie = this.sessionCookies.serialize(result.sessionId);
      this.adapterHost.httpAdapter.setHeader(response, 'Set-Cookie', cookie);
    } catch {
      throw new InternalServerErrorException('Login failed.');
    }
  }

  @Post('logout')
  @HttpCode(HttpStatus.NO_CONTENT)
  async logout(
    @Headers('cookie') cookieHeader: string | undefined,
    @Res({ passthrough: true }) response: unknown,
  ): Promise<void> {
    try {
      const sessionId = this.sessionCookies.parse(cookieHeader);
      if (sessionId !== null) await this.logoutService.logout(sessionId);
      const cookie = this.sessionCookies.clear();
      this.adapterHost.httpAdapter.setHeader(response, 'Set-Cookie', cookie);
    } catch {
      throw new InternalServerErrorException('Logout failed.');
    }
  }

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
