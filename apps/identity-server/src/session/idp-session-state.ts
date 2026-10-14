import { z } from 'zod';

export const sessionIdSchema = z.uuid();
const timestamp = z.number().int().min(0).max(Number.MAX_SAFE_INTEGER);

export const idpSessionStateSchema = z
  .strictObject({
    userId: z.uuid(),
    authTime: timestamp,
    // Opaque metadata only: MFA assurance policy belongs to M10, not M3.2.
    mfaLevel: z.string().min(1),
    createdAt: timestamp,
    lastActivityAt: timestamp,
    absoluteExpiresAt: timestamp,
  })
  .refine(
    (state) =>
      state.absoluteExpiresAt > state.createdAt &&
      state.absoluteExpiresAt > state.authTime &&
      state.absoluteExpiresAt > state.lastActivityAt,
  );

/** All timestamps are non-negative safe-integer Unix epoch milliseconds. */
export type IdpSessionState = z.infer<typeof idpSessionStateSchema>;

export function parseIdpSessionState(
  raw: string | null,
): IdpSessionState | null {
  if (raw === null) return null;
  try {
    const input: unknown = JSON.parse(raw);
    const result = idpSessionStateSchema.safeParse(input);
    return result.success ? result.data : null;
  } catch {
    return null;
  }
}
