/** OAuth client_secret_basic: strict Base64, then form-decode each component once. */
export function parseClientSecretBasic(
  header: string | undefined,
): { clientId: string; secret: string } | null {
  if (header === undefined) return null;
  const match = /^Basic +([A-Za-z0-9+/]+={0,2})$/i.exec(header);
  if (!match || match[0] !== header) return null;
  try {
    const encoded = match[1];
    const bytes = Buffer.from(encoded, 'base64');
    // Buffer's decoder is permissive; do not silently repair malformed input.
    if (bytes.toString('base64') !== encoded) return null;
    const credentials = new TextDecoder('utf-8', {
      fatal: true,
      ignoreBOM: true,
    }).decode(bytes);
    if (
      [...credentials].some(
        (char) => char.charCodeAt(0) < 32 || char.charCodeAt(0) === 127,
      )
    )
      return null;
    const colon = credentials.indexOf(':');
    if (colon < 1) return null;
    const decode = (value: string): string =>
      decodeURIComponent(value.replace(/\+/g, ' '));
    const clientId = decode(credentials.slice(0, colon));
    const secret = decode(credentials.slice(colon + 1));
    if (!clientId || !secret) return null;
    return { clientId, secret };
  } catch {
    return null;
  }
}
