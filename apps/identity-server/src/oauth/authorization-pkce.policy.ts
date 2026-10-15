import type { EnabledClient } from '../client-registry/client-lookup.service.js';

/** Authorization-request policy only. Verifier calculation/comparison is M6.3. */
export function validateAuthorizationPkce(
  clientType: EnabledClient['clientType'],
  codeChallenge: string | undefined,
  codeChallengeMethod: string | undefined,
): boolean {
  if (codeChallenge === undefined && codeChallengeMethod === undefined)
    return clientType === 'CONFIDENTIAL';

  return (
    codeChallengeMethod === 'S256' &&
    codeChallenge !== undefined &&
    codeChallenge.length === 43 &&
    !/[^A-Za-z0-9_-]/.test(codeChallenge)
  );
}
