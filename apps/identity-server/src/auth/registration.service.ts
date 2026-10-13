import {
  ConflictException,
  Inject,
  Injectable,
  InternalServerErrorException,
  Logger,
} from '@nestjs/common';
import { Prisma, type UserStatus } from '../generated/prisma/client.js';
import { PrismaService } from '../prisma/prisma.service.js';
import { PasswordService } from '../security/password/password.service.js';
import type { RegisterInput } from './register.schema.js';

export interface SafeRegisteredUser {
  id: string;
  email: string;
  username: string;
  status: UserStatus;
  createdAt: Date;
}

function isRegistrationDuplicate(error: unknown): boolean {
  if (
    !(error instanceof Prisma.PrismaClientKnownRequestError) ||
    error.code !== 'P2002' ||
    error.meta?.modelName !== 'User'
  )
    return false;

  // Prisma 7's pg adapter reports the violated index, not meta.target fields.
  const adapterError: unknown = error.meta.driverAdapterError;
  if (
    typeof adapterError !== 'object' ||
    adapterError === null ||
    !('cause' in adapterError)
  )
    return false;
  const cause: unknown = adapterError.cause;
  if (
    typeof cause !== 'object' ||
    cause === null ||
    !('kind' in cause) ||
    cause.kind !== 'UniqueConstraintViolation' ||
    !('constraint' in cause)
  )
    return false;
  const constraint: unknown = cause.constraint;
  if (
    typeof constraint !== 'object' ||
    constraint === null ||
    !('index' in constraint)
  )
    return false;
  // Only these existing User indexes represent a duplicate registration identity.
  return (
    constraint.index === 'users_email_key' ||
    constraint.index === 'users_username_key'
  );
}

@Injectable()
export class RegistrationService {
  private readonly logger = new Logger(RegistrationService.name);

  constructor(
    @Inject(PrismaService) private readonly prisma: PrismaService,
    @Inject(PasswordService) private readonly passwords: PasswordService,
  ) {}

  async register(input: RegisterInput): Promise<SafeRegisteredUser> {
    let user: SafeRegisteredUser;
    try {
      // Argon2 runs before the transaction so CPU work does not hold it open.
      const passwordHash = await this.passwords.hash(input.password);
      user = await this.prisma.$transaction(async (transaction) => {
        const created = await transaction.user.create({
          data: { email: input.email, username: input.username },
          select: {
            id: true,
            email: true,
            username: true,
            status: true,
            createdAt: true,
          },
        });
        await transaction.credential.create({
          data: { userId: created.id, passwordHash },
          select: { id: true },
        });
        return created;
      });
    } catch (error) {
      if (isRegistrationDuplicate(error)) {
        throw new ConflictException('Email or username is already registered.');
      }
      // Never forward/cause-chain raw Prisma errors (query details may be sensitive).
      throw new InternalServerErrorException('Registration failed.');
    }

    // Provisional M2.4 event only; M12 owns persistent audit infrastructure.
    this.logger.log({ event: 'USER_REGISTERED', userId: user.id });
    return {
      id: user.id,
      email: user.email,
      username: user.username,
      status: user.status,
      createdAt: user.createdAt,
    };
  }
}
