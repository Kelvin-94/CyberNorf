import assert from 'node:assert/strict';
import { test } from 'node:test';
import { openSecret, resetSecretKeyCache, sealSecret } from './secrets.ts';

/**
 * These tests pin the consequence documented in docs/SECRETS.md: the key that
 * seals webhook signing secrets is derived from BETTER_AUTH_SECRET, so rotating
 * that variable makes every previously sealed value unreadable. The rotation
 * procedure exists because of this behaviour, so it must not change silently.
 */

const ORIGINAL = process.env.BETTER_AUTH_SECRET;
const FIRST = 'first-secret-value-long-enough-for-aes';
const SECOND = 'second-secret-value-long-enough-for-aes';

function withSecret<T>(value: string, run: () => T): T {
  process.env.BETTER_AUTH_SECRET = value;
  resetSecretKeyCache();
  try {
    return run();
  } finally {
    resetSecretKeyCache();
  }
}

test.afterEach(() => {
  if (ORIGINAL === undefined) {
    delete process.env.BETTER_AUTH_SECRET;
  } else {
    process.env.BETTER_AUTH_SECRET = ORIGINAL;
  }
  resetSecretKeyCache();
});

test('a sealed value opens with the secret that sealed it', () => {
  const sealed = withSecret(FIRST, () => sealSecret('webhook-signing-key'));

  assert.equal(
    withSecret(FIRST, () => openSecret(sealed)),
    'webhook-signing-key',
  );
});

test('a sealed value is unreadable after the auth secret is rotated', () => {
  const sealed = withSecret(FIRST, () => sealSecret('webhook-signing-key'));

  assert.throws(
    () => withSecret(SECOND, () => openSecret(sealed)),
    'rotation must invalidate previously sealed values rather than return garbage',
  );
});

test('a tampered ciphertext is rejected by the authentication tag', () => {
  const sealed = withSecret(FIRST, () => sealSecret('webhook-signing-key'));
  const parts = sealed.split('.');
  assert.equal(parts.length, 4);

  // Tamper the decoded bytes and re-encode, rather than editing a base64url
  // character. A base64url group carries padding bits, so changing the final
  // character can decode to exactly the same bytes: the value is then unmodified
  // and GCM is right to accept it, which made this test fail about a quarter of
  // the time for a reason unrelated to authentication.
  const ciphertext = Buffer.from(parts[3] ?? '', 'base64url');
  const modified = Buffer.from(ciphertext);
  modified[0] = (modified[0] as number) ^ 0x01;
  assert.ok(!modified.equals(ciphertext), 'the tampered bytes must actually differ');

  const tampered = [parts[0], parts[1], parts[2], modified.toString('base64url')].join('.');

  assert.throws(() => withSecret(FIRST, () => openSecret(tampered)));
});

test('a tampered authentication tag is rejected', () => {
  const sealed = withSecret(FIRST, () => sealSecret('webhook-signing-key'));
  const parts = sealed.split('.');

  // Same reasoning as above: change a decoded byte of the tag itself, so the edit
  // cannot be absorbed by base64url padding.
  const tag = Buffer.from(parts[2] ?? '', 'base64url');
  const modifiedTag = Buffer.from(tag);
  modifiedTag[0] = (modifiedTag[0] as number) ^ 0x80;
  assert.ok(!modifiedTag.equals(tag), 'the tampered tag must actually differ');

  const tampered = [parts[0], parts[1], modifiedTag.toString('base64url'), parts[3]].join('.');

  assert.throws(() => withSecret(FIRST, () => openSecret(tampered)));
});

test('sealing refuses a secret shorter than the derivation minimum', () => {
  withSecret('too-short', () => {
    assert.throws(() => sealSecret('value'), /at least 32 characters/);
  });
});

test('sealing the same plaintext twice produces different ciphertext', () => {
  const [first, second] = withSecret(FIRST, () => [sealSecret('same'), sealSecret('same')]);

  assert.notEqual(first, second, 'a repeated IV would leak that two values are identical');
  assert.equal(
    withSecret(FIRST, () => openSecret(first)),
    'same',
  );
  assert.equal(
    withSecret(FIRST, () => openSecret(second)),
    'same',
  );
});
