/**
 * Pre-flight configuration check.
 *
 *   npm run config:check
 *
 * Loads `.env` the same way the app does, validates every variable the app
 * reads, and prints a report that names variables and rules but never values.
 * Exits 1 when the configuration cannot work, so it can gate a deployment
 * before a restart is attempted (and before a bad image reaches the proxy).
 *
 * `--env-file <path>` checks a specific file instead, which is how the
 * production `.env.production` is verified from a checkout:
 *
 *   npm run config:check -- --env-file .env.production
 */
import { existsSync } from 'node:fs';
import { config as loadEnv } from 'dotenv';
import { formatEnvReport, validateEnvironment } from '../src/server/config/env.ts';
import { loadFileSecrets } from '../src/server/config/secrets-file.ts';

function argument(name: string): string | undefined {
  const index = process.argv.indexOf(name);
  return index === -1 ? undefined : process.argv[index + 1];
}

const explicitFile = argument('--env-file');
const envFile = explicitFile ?? (existsSync('.env') ? '.env' : undefined);

if (explicitFile && !existsSync(explicitFile)) {
  console.error(`config:check: ${explicitFile} does not exist.`);
  process.exit(1);
}

if (envFile) {
  // `override: false` keeps variables already exported in the shell authoritative,
  // matching how Docker Compose and systemd inject configuration.
  loadEnv({ path: envFile, quiet: true, override: false });
  console.log(`Checked ${envFile} (with the current environment taking precedence).`);
} else {
  console.log('Checked the current environment (.env not found).');
}

// Mounted secret files are applied exactly as the server applies them at boot.
// Reporting on the environment alone would let `config:check` pass for a
// configuration the server would refuse, which defeats the point of a pre-flight
// check.
const secretsDir = process.env.SECRETS_DIR?.trim();
if (secretsDir) {
  const fileSecrets = loadFileSecrets(process.env, secretsDir);
  if (fileSecrets.errors.length > 0) {
    console.error('Secret files could not be loaded:');
    for (const error of fileSecrets.errors) {
      console.error(`  ${error}`);
    }
    process.exit(1);
  }
  console.log(`Applied ${fileSecrets.loaded.length} secret(s) from ${secretsDir}.`);
  if (fileSecrets.ignored.length > 0) {
    // Named, not read: a file whose name is not a known variable is a mistake
    // worth showing, but it must not become configuration.
    console.warn(`Ignored unrecognised entries: ${fileSecrets.ignored.join(', ')}`);
  }
}

const report = validateEnvironment();
console.log(formatEnvReport(report));

// Warnings are printed but do not fail the check: they describe intent, not a
// broken deployment. Errors do, because the app will refuse to boot or will
// silently disable a control.
process.exit(report.ok ? 0 : 1);
