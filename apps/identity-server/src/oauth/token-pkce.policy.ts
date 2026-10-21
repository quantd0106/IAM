import { createHash, timingSafeEqual } from 'node:crypto';

/** Call only after successful authorization-code consumption. S256 only. */
export function verifyTokenPkce(
  codeChallenge: string | null,
  codeVerifier: string | undefined,
): boolean {
  if (codeChallenge === null) return true;
  if (
    codeVerifier === undefined ||
    codeVerifier.length < 43 ||
    codeVerifier.length > 128 ||
    /[^A-Za-z0-9._~-]/.test(codeVerifier)
  )
    return false;
  try {
    const calculated = createHash('sha256')
      .update(codeVerifier, 'ascii')
      .digest('base64url');
    const actual = Buffer.from(calculated, 'ascii');
    const expected = Buffer.from(codeChallenge, 'utf8');
    return (
      actual.length === expected.length && timingSafeEqual(actual, expected)
    );
  } catch {
    // No verifier, challenge or private crypto cause escapes this boundary.
    throw new Error('PKCE verification failed.');
  }
}
