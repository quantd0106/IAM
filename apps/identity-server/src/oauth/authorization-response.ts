/** Call only with the successful validated authorization result. No URI normalization. */
export function buildAuthorizationSuccessLocation(input: {
  redirectUri: string;
  code: string;
  state: string;
}): string {
  const fragmentAt = input.redirectUri.indexOf('#');
  const base =
    fragmentAt < 0 ? input.redirectUri : input.redirectUri.slice(0, fragmentAt);
  const fragment = fragmentAt < 0 ? '' : input.redirectUri.slice(fragmentAt);
  const separator = !base.includes('?')
    ? '?'
    : base.endsWith('?') || base.endsWith('&')
      ? ''
      : '&';
  return `${base}${separator}code=${encodeURIComponent(input.code)}&state=${encodeURIComponent(input.state)}${fragment}`;
}
