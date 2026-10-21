// Explicit local provisioning only. Never imported by application/startup/seed.
import 'dotenv/config';
import { generateKeyPairSync } from 'node:crypto';
import { mkdir, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';

async function generate(): Promise<void> {
  if (!['development', 'test'].includes(process.env.NODE_ENV ?? 'development'))
    throw new Error('Development provisioning is unavailable in production.');
  const directory = resolve(import.meta.dirname, '..', 'dev-keys');
  // Atomic exclusive directory creation refuses existing/partial provisioning.
  // Never overwrite keys or automatically delete an operator-owned directory.
  await mkdir(directory, { mode: 0o700 });
  const pair = generateKeyPairSync('rsa', {
    modulusLength: 2048,
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    publicKeyEncoding: { type: 'spki', format: 'pem' },
  });
  await writeFile(resolve(directory, 'private.pem'), pair.privateKey, {
    flag: 'wx',
    mode: 0o600,
  });
  await writeFile(resolve(directory, 'public.pem'), pair.publicKey, {
    flag: 'wx',
    mode: 0o644,
  });
  console.log(
    'Development signing pair provisioned (ignored, no overwrite). Protect the directory ACL on Windows.',
  );
}
void generate().catch(() => {
  console.error(
    'Development key provisioning failed; existing files were not overwritten. Private details suppressed.',
  );
  process.exitCode = 1;
});
