// Prefixes may contain colons; no implicit namespace or normalization is added.
export function buildRedisKey(prefix: string, ...segments: string[]): string {
  const parts = [prefix, ...segments];

  if (parts.some((part) => part.trim().length === 0)) {
    throw new Error('Redis key prefix and segments must not be empty.');
  }

  return parts.join(':');
}
