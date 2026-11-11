import assert from 'node:assert/strict';
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, test } from 'node:test';
import { loadFileSecrets } from './secrets-file.ts';

const directories: string[] = [];

function directory(): string {
  const path = mkdtempSync(join(tmpdir(), 'cn-secrets-'));
  directories.push(path);
  return path;
}

/** Writes a secret file with the restrictive mode the loader requires. */
function secret(dir: string, name: string, value: string, mode = 0o400): string {
  const path = join(dir, name);
  writeFileSync(path, value, { mode });
  // writeFileSync applies mode only on creation, and umask can loosen it, so the
  // mode is set again explicitly. The test asserts the loader rejects a loose
  // mode separately.
  chmodSync(path, mode);
  return path;
}

after(() => {
  for (const path of directories) {
    rmSync(path, { recursive: true, force: true });
  }
});

test('a mounted file overrides the environment', () => {
  const dir = directory();
  secret(dir, 'BETTER_AUTH_SECRET', 'from-the-file');
  const env: Record<string, string | undefined> = { BETTER_AUTH_SECRET: 'from-the-environment' };

  const result = loadFileSecrets(env, dir);

  assert.deepEqual(result.errors, []);
  assert.equal(env.BETTER_AUTH_SECRET, 'from-the-file');
  assert.deepEqual(result.loaded, ['BETTER_AUTH_SECRET']);
});

test('a file supplies a variable the environment does not set', () => {
  const dir = directory();
  secret(dir, 'CRON_SECRET', 'mounted-sweep-token');
  const env: Record<string, string | undefined> = {};

  loadFileSecrets(env, dir);

  assert.equal(env.CRON_SECRET, 'mounted-sweep-token');
});

test('one trailing newline and surrounding whitespace are stripped', () => {
  const dir = directory();
  secret(dir, 'CRON_SECRET', '  padded-secret\n');
  const env: Record<string, string | undefined> = {};

  loadFileSecrets(env, dir);

  // A secret that kept the newline would break an Authorization header in a way
  // that is almost invisible in a log.
  assert.equal(env.CRON_SECRET, 'padded-secret');
});

test('an empty secret file is an error, not an empty value', () => {
  const dir = directory();
  secret(dir, 'CRON_SECRET', '\n');
  const env: Record<string, string | undefined> = {};

  const result = loadFileSecrets(env, dir);

  assert.equal(result.errors.length, 1);
  assert.match(result.errors[0] as string, /empty/);
  assert.equal(env.CRON_SECRET, undefined);
});

test('a file readable by group or others is refused', () => {
  const dir = directory();
  secret(dir, 'CRON_SECRET', 'world-readable', 0o644);
  const env: Record<string, string | undefined> = {};

  const result = loadFileSecrets(env, dir);

  assert.equal(result.errors.length, 1);
  assert.match(result.errors[0] as string, /accessible by group or others/);
  // Refused means not applied: a loose mode must not quietly take effect.
  assert.equal(env.CRON_SECRET, undefined);
});

test('an unknown file name is ignored and named, never applied', () => {
  const dir = directory();
  secret(dir, 'NOT_A_REAL_VARIABLE', 'surprise');
  const env: Record<string, string | undefined> = {};

  const result = loadFileSecrets(env, dir);

  assert.deepEqual(result.errors, []);
  assert.deepEqual(result.ignored, ['NOT_A_REAL_VARIABLE']);
  assert.equal(env.NOT_A_REAL_VARIABLE, undefined);
});

test('dot-files are skipped without being reported as unknown', () => {
  const dir = directory();
  secret(dir, '.hidden', 'sidecar-remnant', 0o600);
  const env: Record<string, string | undefined> = {};

  const result = loadFileSecrets(env, dir);

  assert.deepEqual(result.errors, []);
  assert.deepEqual(result.ignored, []);
  assert.equal(env['.hidden'], undefined);
});

test('a missing directory is an error rather than a silent no-op', () => {
  const env: Record<string, string | undefined> = {};
  const result = loadFileSecrets(env, join(tmpdir(), 'cn-secrets-does-not-exist-xyz'));

  assert.equal(result.errors.length, 1);
  assert.match(result.errors[0] as string, /cannot be read/);
});

test('a path that is a file rather than a directory is an error', () => {
  const dir = directory();
  const filePath = secret(dir, 'CRON_SECRET', 'value', 0o600);
  const env: Record<string, string | undefined> = {};

  const result = loadFileSecrets(env, filePath);

  assert.equal(result.errors.length, 1);
  assert.match(result.errors[0] as string, /not a directory/);
});

test('error messages never contain the secret value', () => {
  const dir = directory();
  secret(dir, 'CRON_SECRET', 'super-secret-value-12345', 0o644);
  const env: Record<string, string | undefined> = {};

  const result = loadFileSecrets(env, dir);

  const joined = result.errors.join('\n');
  assert.ok(!joined.includes('super-secret-value-12345'));
  assert.ok(joined.includes('CRON_SECRET'));
});
