import { z } from 'zod';

const opaque = z.string().min(1);
const timestamp = z.number().int().min(0).max(Number.MAX_SAFE_INTEGER);
const scope = opaque.refine(
  (value) => !/[^\x21\x23-\x5B\x5D-\x7E]/.test(value),
);

// Exact protocol values, no transformations. Absence is explicit JSON null.
export const authorizationCodeStateSchema = z.strictObject({
  clientId: opaque,
  userId: z.uuid(),
  redirectUri: opaque,
  grantedScopes: z.array(scope).min(1),
  codeChallenge: z
    .string()
    .length(43)
    .refine((value) => !/[^A-Za-z0-9_-]/.test(value))
    .nullable(),
  nonce: opaque.nullable(),
  authTime: timestamp,
  expiresAt: timestamp,
});

export type AuthorizationCodeState = z.infer<
  typeof authorizationCodeStateSchema
>;
export type AuthorizationCodeInput = Omit<AuthorizationCodeState, 'expiresAt'>;
