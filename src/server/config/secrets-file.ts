import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';

/**
 * Reads secrets that a deployment mounts as files instead of environment
 * variables.
 *
 * Environment variables are visible to anything that can read
 * `/proc/<pid>/environ`, are inherited by every child process, and end up in
 * `docker inspect` output and crash dumps. A file mount (Docker secrets,
 * Kubernetes secret volumes, Vault agent templates, systemd `LoadCredential`) is
 * the same secret with a narrower blast radius: it can be owned by one uid with
 * mode 0400 and it never appears in the process table.
 *
 * The contract, deliberately simple so it is easy to reason about:
 *
 * - `SECRETS_DIR` names one absolute directory. Each variable is one file whose
 *   name is the variable name.
 * - **A file wins over the environment.** If both are present the file is used,
 *   because the mounted file is the managed one and the environment is the
 *   leftover. This also makes migration orderly: mount the file, leave the old
 *   variable in place, restart, then remove it.
 * - Surrounding whitespace and one trailing newline are stripped. A secret with
 *   an intentional trailing space cannot be represented, which is the right
 *   trade for not silently failing to authenticate because an editor added `\n`.
 * - A file that cannot be read is an error, not a fallback. Silently using the
 *   environment after a failed mount read is how a deployment ends up running
 *   with the old credential while the operator believes it rotated.
 *
 * This module must not log values, and does not: the only output it produces is
 * the list of variable names it resolved.
 */

/** Variables that may be supplied as files. Anything else is ignored, so a stray
 * file in the directory cannot become configuration. */
export const FILE_SECRET_VARIABLES = [
  'DATABASE_URL',
  'BETTER_AUTH_SECRET',
  'BETTER_AUTH_URL',
  'CRON_SECRET',
  'OIDC_CLIENT_SECRET',
  'OIDC_ISSUER',
  'OIDC_CLIENT_ID',
  'EVIDENCE_DIR',
] as const;

export type FileSecretVariable = (typeof FILE_SECRET_VARIABLES)[number];

export interface SecretsFileResult {
  /** Variables successfully read from a file, in the order they were applied. */
  loaded: FileSecretVariable[];
  /** Variables present in the directory but not in the allow-list. */
  ignored: string[];
  /** Problems that must stop startup. Names only; never values. */
  errors: string[];
}

const ALLOWED = new Set<string>(FILE_SECRET_VARIABLES);

/**
 * Applies file-backed secrets to `env` in place and reports what happened.
 *
 * Injected rather than reaching for `process.env` so a test can pass a plain
 * object and a temporary directory, and so the startup hook stays the only place
 * that mutates the real environment.
 */
export function loadFileSecrets(
  env: Record<string, string | undefined>,
  directory: string,
): SecretsFileResult {
  const result: SecretsFileResult = { loaded: [], ignored: [], errors: [] };

  let entries: string[];
  try {
    if (!statSync(directory).isDirectory()) {
      result.errors.push(`SECRETS_DIR is not a directory: ${directory}`);
      return result;
    }
    entries = readdirSync(directory);
  } catch {
    result.errors.push(`SECRETS_DIR cannot be read: ${directory}`);
    return result;
  }

  for (const name of entries) {
    // Dot-files are the atomic-write remnants of a secret-injection sidecar
    // (`..data`, `.tmp-123`) and are never meant to be read as a variable.
    if (name.startsWith('.')) {
      continue;
    }
    if (!ALLOWED.has(name)) {
      result.ignored.push(name);
      continue;
    }

    const path = join(directory, name);
    try {
      const stat = statSync(path);
      if (!stat.isFile()) {
        result.errors.push(`${name}: SECRETS_DIR entry is not a regular file.`);
        continue;
      }
      // 0o077: no group or world permission. A world-readable secret on a shared
      // host is readable by every local user, which defeats the point of the
      // mount, so it is refused instead of quietly used.
      if ((stat.mode & 0o077) !== 0o000) {
        result.errors.push(
          `${name}: secret file is accessible by group or others (mode ${(stat.mode & 0o777).toString(8)}); restrict it to the service account.`,
        );
        continue;
      }

      const raw = readFileSync(path, 'utf8');
      // Strip one trailing newline, then surrounding whitespace. A secret is
      // never legitimately padded, and a stray newline breaks a bearer header in
      // a way that is very hard to see.
      const value = raw.replace(/\r?\n$/, '').trim();
      if (value.length === 0) {
        result.errors.push(`${name}: secret file is empty.`);
        continue;
      }
      env[name] = value;
      result.loaded.push(name as FileSecretVariable);
    } catch {
      result.errors.push(`${name}: secret file could not be read.`);
    }
  }

  result.loaded.sort();
  result.ignored.sort();
  return result;
}

/**
 * Describes a secret's source for the startup log, without the value. Used to
 * answer "did the new secret actually get picked up" during a rotation, which is
 * the question an operator has at the moment they most need it.
 */
export function describeSecretSources(result: SecretsFileResult): {
  fromFiles: string[];
  ignoredFiles: string[];
} {
  return { fromFiles: result.loaded, ignoredFiles: result.ignored };
}
