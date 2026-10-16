import { z } from 'zod';

// Opaque framework-decoded strings: no coercion, trimming or normalization.
const opaque = z.string().min(1);
export const tokenRequestSchema = z.strictObject({
  grant_type: opaque,
  client_id: opaque,
  code: opaque,
  redirect_uri: opaque,
  code_verifier: opaque.optional(),
});

export type TokenRequest = Omit<
  z.infer<typeof tokenRequestSchema>,
  'grant_type'
> & { grant_type: 'authorization_code' };
