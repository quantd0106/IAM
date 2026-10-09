import { z } from 'zod';

const nonEmptyString = z.string().trim().min(1);
const positiveInteger = z
  .union([
    z.number(),
    z
      .string()
      .regex(/^[0-9]+$/)
      .transform(Number),
  ])
  .pipe(z.number().int().positive().max(Number.MAX_SAFE_INTEGER));

function connectionUrl(protocols: readonly string[]): z.ZodString {
  return nonEmptyString.refine((value) => {
    try {
      const url = new URL(value);
      return protocols.includes(url.protocol) && url.hostname.length > 0;
    } catch {
      return false;
    }
  });
}

export const environmentSchema = z
  .object({
    NODE_ENV: z
      .enum(['development', 'test', 'production'])
      .default('development'),
    IDENTITY_SERVER_PORT: positiveInteger
      .pipe(z.number().max(65535))
      .default(3000),
    DATABASE_URL: connectionUrl(['postgresql:', 'postgres:']),
    REDIS_URL: connectionUrl(['redis:', 'rediss:']),
    ISSUER_URL: connectionUrl(['http:', 'https:']),
    ACCESS_TOKEN_TTL_SECONDS: positiveInteger.default(600),
    AUTH_CODE_TTL_SECONDS: positiveInteger.default(120),
    REFRESH_TOKEN_TTL_SECONDS: positiveInteger.default(2592000),
    SESSION_IDLE_TTL_SECONDS: positiveInteger.default(1800),
    SESSION_ABSOLUTE_TTL_SECONDS: positiveInteger.default(28800),
    JWT_PRIVATE_KEY_PATH: nonEmptyString,
    JWT_PUBLIC_KEY_PATH: nonEmptyString,
    JWT_KEY_ID: nonEmptyString,
    // Encoding/strength and key-file existence belong to later cryptographic tasks.
    TOTP_ENCRYPTION_KEY: z.string().refine((value) => value.trim().length > 0),
    COOKIE_NAME: nonEmptyString.default('iam.sid'),
    COOKIE_SECURE: z
      .union([
        z.boolean(),
        z.enum(['true', 'false']).transform((value) => value === 'true'),
      ])
      .optional(),
    LOGIN_MAX_FAILURES: positiveInteger.default(5),
    LOGIN_LOCK_SECONDS: positiveInteger.default(900),
  })
  .superRefine((values, context) => {
    if (values.NODE_ENV !== 'production') return;
    if (values.COOKIE_SECURE === false) {
      context.addIssue({
        code: 'custom',
        path: ['COOKIE_SECURE'],
        message: 'Required in production.',
      });
    }
    if (!/^https:/i.test(values.ISSUER_URL)) {
      context.addIssue({
        code: 'custom',
        path: ['ISSUER_URL'],
        message: 'HTTPS required in production.',
      });
    }
  })
  .transform((values) => ({
    ...values,
    COOKIE_SECURE: values.COOKIE_SECURE ?? values.NODE_ENV === 'production',
  }));

export type Environment = z.infer<typeof environmentSchema>;

export function validateEnvironment(input: unknown): Environment {
  const result = environmentSchema.safeParse(input);
  if (!result.success) {
    const names = [
      ...new Set(
        result.error.issues.map((issue) =>
          String(issue.path[0] ?? 'environment'),
        ),
      ),
    ];
    // Never propagate Zod issues/input or URL/secret values into startup logs.
    throw new Error(`Invalid environment configuration: ${names.join(', ')}.`);
  }
  return result.data;
}
