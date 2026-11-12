import { createHash, randomBytes } from 'node:crypto';
import { chmodSync, existsSync, renameSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { isAbsolute, join, resolve } from 'node:path';

/**
 * Writes one rotatable secret to a mounted file, atomically, without printing it.
 *
 * Rotating a secret by hand is where it usually goes wrong: the value is echoed
 * into a shell, the file is left group-readable, or the old file is overwritten
 * in place so a half-written secret is read by a restart. This command generates
 * the value, writes it to a temporary file with mode 0600 in the same directory,
 * and renames it over the target, which is atomic on a single filesystem. The
 * value never reaches stdout.
 *
 * The consequences of each rotation are printed, because they are not
 * interchangeable — rotating BETTER_AUTH_SECRET signs everyone out and makes
 * existing second factors undecryptable, and an operator should read that before
 * typing `--apply`, not afterwards. `docs/SECRETS.md` is the reference for the
 * full procedure; this prints the mechanical steps and points at it.
 */

const ROTATABLE = {
  BETTER_AUTH_SECRET: {
    bytes: 48,
    consequence:
      'Ends every session, invalidates every enrolled second factor, and makes stored webhook signing secrets unreadable. Users must re-enrol MFA through the recovery path.',
  },
  CRON_SECRET: {
    bytes: 32,
    consequence: 'Invalidates the scheduler bearer token. Update the scheduler in the same change.',
  },
  OIDC_CLIENT_SECRET: {
    bytes: 32,
    consequence:
      'Invalidates the provider client secret. Rotate it at the identity provider first, then restart; keep password sign-in available in case of a mismatch.',
  },
  EVIDENCE_SIGNING_KEY: {
    bytes: 32,
    consequence:
      'Packages issued with the old key must be verified with that key and its key id. Change EVIDENCE_SIGNING_KEY_ID with the key so each manifest names the key that signed it.',
  },
} as const;

type RotatableName = keyof typeof ROTATABLE;

function usage(message?: string): never {
  if (message) {
    console.error(`Error: ${message}`);
  }
  console.error(
    'Usage: npm run secrets:rotate -- --name <variable> --dir <SECRETS_DIR> [--apply] [--force]\n' +
      `       rotatable: ${Object.keys(ROTATABLE).join(', ')}\n` +
      '       Without --apply the command validates and prints the plan only.',
  );
  process.exit(1);
}

function parseArgs(argv: string[]): {
  name: RotatableName;
  dir: string;
  apply: boolean;
  force: boolean;
} {
  let name: string | null = null;
  // Deliberately not defaulted from SECRETS_DIR: a command that can overwrite a
  // mounted secret should name its target explicitly rather than inherit an
  // ambient directory, and the path it prints then cannot be mistaken for a
  // value that came from the environment.
  let dir: string | null = null;
  let apply = false;
  let force = false;

  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === '--apply') {
      apply = true;
      continue;
    }
    if (argument === '--force') {
      force = true;
      continue;
    }
    if (argument === '--name' || argument === '--dir') {
      const value = argv[index + 1];
      if (!value || value.startsWith('--')) {
        usage(`${argument} needs a value.`);
      }
      index += 1;
      if (argument === '--name') {
        name = value;
      } else {
        dir = value;
      }
      continue;
    }
    usage(`unknown argument "${argument}".`);
  }

  if (!name) {
    usage('--name is required.');
  }
  if (!(name in ROTATABLE)) {
    usage(
      name === 'DATABASE_URL'
        ? 'DATABASE_URL is not generated here: rotate the password in PostgreSQL and update the file in the same step.'
        : `"${name}" is not a rotatable secret.`,
    );
  }
  if (!dir) {
    usage('--dir is required: name the directory that holds the secret files.');
  }
  if (!isAbsolute(dir)) {
    usage('--dir must be an absolute path.');
  }

  return { name: name as RotatableName, dir: resolve(dir), apply, force };
}

function digest(value: string): string {
  return createHash('sha256').update(value).digest('hex').slice(0, 12);
}

function main(): void {
  const options = parseArgs(process.argv.slice(2));
  const target = join(options.dir, options.name);
  const bytes = ROTATABLE[options.name].bytes;

  if (!existsSync(options.dir) || !statSync(options.dir).isDirectory()) {
    usage(`"${options.dir}" is not a directory. Create the mount point before rotating.`);
  }

  if (existsSync(target) && !options.force) {
    usage(
      `${options.name} already exists at ${target}. Re-run with --force once you have confirmed the drill in docs/SECRETS.md.`,
    );
  }

  // base64url has no characters that need quoting and survives a copy/paste
  // through YAML, JSON and shell without escaping.
  const value = randomBytes(bytes).toString('base64url');

  console.log(`${options.name} -> ${target}`);
  console.log(`  mode:      0600`);
  console.log(`  length:    ${value.length} characters`);
  console.log(`  digest:    sha256:${digest(value)} (first 12 hex, safe to record)`);
  console.log(`  effect:    ${ROTATABLE[options.name].consequence}`);

  if (!options.apply) {
    console.log('Dry run. Nothing was written. Re-run with --apply to replace the file.');
    return;
  }

  const temporary = join(options.dir, `.tmp-${options.name}-${process.pid}`);
  try {
    writeFileSync(temporary, `${value}\n`, { mode: 0o600, flag: 'wx' });
    chmodSync(temporary, 0o600);
    renameSync(temporary, target);
  } catch (error) {
    rmSync(temporary, { force: true });
    throw error;
  }

  console.log('');
  console.log('Written. The value is not shown and cannot be recovered from this command.');
  console.log('Drill:');
  console.log('  1. npm run config:check -- --env-file <production env file>');
  console.log('  2. restart the service and confirm startup logs:');
  console.log(`     - secretsFromFiles includes "${options.name}"`);
  console.log('     - configFingerprint.status is "CHANGED" (or "NEW" on first boot)');
  console.log(
    '  3. exercise the affected path end to end (sign-in, scheduler call, provider login)',
  );
  console.log(
    '  4. record what changed and when in the change log; docs/SECRETS.md lists the blast radius',
  );
}

try {
  main();
} catch (error) {
  console.error(error instanceof Error ? error.message : error);
  process.exitCode = 1;
}
