/** Trusted registry configuration, checked before consuming any code. No defaults. */
export function requireAccessTokenIssuance(input: {
  accessTokenAudience: string | null;
  accessTokenTtl: number;
}): { audience: string; ttlSeconds: number } {
  if (
    typeof input.accessTokenAudience !== 'string' ||
    input.accessTokenAudience.length === 0 ||
    !Number.isSafeInteger(input.accessTokenTtl) ||
    input.accessTokenTtl <= 0
  )
    throw new Error('Access token issuance configuration unavailable.');
  return {
    audience: input.accessTokenAudience,
    ttlSeconds: input.accessTokenTtl,
  };
}
