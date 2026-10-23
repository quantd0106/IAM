import { z } from 'zod';

// Opaque framework-decoded strings: no coercion, trimming or normalization.
const opaque = z.string().min(1);
const authorizationCodeTokenRequestSchema = z.strictObject({
  grant_type: z.literal('authorization_code'),
  client_id: opaque,
  code: opaque,
  redirect_uri: opaque,
  // Structural validation only. M6.3 classifies empty/malformed syntax after GETDEL.
  code_verifier: z.string().optional(),
});

const refreshTokenRequestSchema = z.strictObject({
  grant_type: z.literal('refresh_token'),
  client_id: opaque,
  refresh_token: opaque,
  // Scalar shape only. The valid-grant boundary classifies scope syntax/subset.
  scope: z.string().optional(),
});

export const tokenRequestSchema = z.discriminatedUnion('grant_type', [
  authorizationCodeTokenRequestSchema,
  refreshTokenRequestSchema,
]);

export type AuthorizationCodeTokenRequest = z.infer<
  typeof authorizationCodeTokenRequestSchema
>;
export type RefreshTokenRequest = z.infer<typeof refreshTokenRequestSchema>;
export type TokenRequest = z.infer<typeof tokenRequestSchema>;
