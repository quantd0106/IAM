/** Trusted registry configuration, checked before GETDEL; never a fallback TTL. */
export function requireRefreshTokenIssuance(input: {
  refreshTokenTtl: number;
}): { ttlSeconds: number } {
  const ttl = input?.refreshTokenTtl;
  if (!Number.isSafeInteger(ttl) || ttl <= 0)
    throw new Error('Refresh token issuance configuration unavailable.');
  const milliseconds = ttl * 1000;
  if (
    !Number.isSafeInteger(milliseconds) ||
    !Number.isFinite(new Date(milliseconds).getTime())
  )
    throw new Error('Refresh token issuance configuration unavailable.');
  return { ttlSeconds: ttl };
}
