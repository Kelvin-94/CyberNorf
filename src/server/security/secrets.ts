import { createCipheriv, createDecipheriv, randomBytes, scryptSync } from 'node:crypto';

/**
 * Reversible secret storage for values the server must present in clear text
 * later, such as the HMAC key used to sign webhook deliveries. Irreversible
 * credentials (agent tokens, passwords) must be hashed instead.
 *
 * AES-256-GCM with a per-value random IV and an authentication tag: a modified
 * ciphertext decrypts to an error, not to attacker-chosen plaintext.
 */
const SALT = 'cybernorf:sealed-secret:v1';
const VERSION = 'v1';
const IV_BYTES = 12;

let cachedKey: Buffer | null = null;

function encryptionKey(): Buffer {
  if (cachedKey) {
    return cachedKey;
  }

  // BETTER_AUTH_SECRET is validated to 32+ characters outside development. A
  // short secret would make the derived key weak, so refuse rather than seal
  // webhook keys under a placeholder.
  const secret = process.env.BETTER_AUTH_SECRET ?? '';
  if (secret.length < 32) {
    throw new Error('BETTER_AUTH_SECRET must be at least 32 characters to seal secrets.');
  }

  cachedKey = scryptSync(secret, SALT, 32);
  return cachedKey;
}

export function sealSecret(plaintext: string): string {
  const iv = randomBytes(IV_BYTES);
  const cipher = createCipheriv('aes-256-gcm', encryptionKey(), iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return [
    VERSION,
    iv.toString('base64url'),
    tag.toString('base64url'),
    ciphertext.toString('base64url'),
  ].join('.');
}

export function openSecret(sealed: string): string {
  const [version, ivPart, tagPart, dataPart] = sealed.split('.');
  if (version !== VERSION || !ivPart || !tagPart || !dataPart) {
    throw new Error('Unsupported sealed secret format.');
  }

  const decipher = createDecipheriv(
    'aes-256-gcm',
    encryptionKey(),
    Buffer.from(ivPart, 'base64url'),
  );
  decipher.setAuthTag(Buffer.from(tagPart, 'base64url'));
  return Buffer.concat([
    decipher.update(Buffer.from(dataPart, 'base64url')),
    decipher.final(),
  ]).toString('utf8');
}

/** Test hook: forget the derived key after changing the environment. */
export function resetSecretKeyCache(): void {
  cachedKey = null;
}
