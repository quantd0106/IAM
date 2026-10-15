export type GrantedScopeResult =
  { ok: true; grantedScopes: string[] } | { ok: false };

/** Exact requested/allowed intersection; reject the entire request on any miss. */
export function calculateGrantedScopes(
  requestedScopes: readonly string[],
  allowedScopes: readonly string[],
): GrantedScopeResult {
  const allowed = new Set(allowedScopes);
  if (requestedScopes.some((scope) => !allowed.has(scope)))
    return { ok: false };
  // Set preserves first-request occurrence order without mutating either input.
  return { ok: true, grantedScopes: [...new Set(requestedScopes)] };
}
