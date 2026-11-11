import { isAbsolute } from 'node:path';
import { assertSecureDatabase, assertSecureOrigin, isLoopbackHost } from '@/server/config';

/**
 * Startup validation for every environment variable the application reads.
 *
 * Two properties matter more than breadth here:
 *
 * 1. **All problems are reported at once.** An operator fixing a deployment
 *    should not discover a second mistake only after restarting to fix the
 *    first. The report collects every issue, then the caller decides to stop.
 * 2. **Values never appear in messages.** A validator that echoes what it
 *    parsed turns a startup log into a credential leak. Issues name the
 *    variable and the rule, never the value.
 *
 * `error` means the deployment cannot work correctly and must not serve
 * traffic. `warning` means it will run, but with a behaviour the operator
 * probably did not intend, so it is logged loudly and allowed through.
 */

export type EnvSeverity = 'error' | 'warning';

export interface EnvIssue {
  variable: string;
  message: string;
  severity: EnvSeverity;
}

export interface EnvReport {
  ok: boolean;
  /** Variables that were present and valid. */
  accepted: string[];
  errors: EnvIssue[];
  warnings: EnvIssue[];
}

type Env = Record<string, string | undefined>;

export interface ValidateOptions {
  production?: boolean;
}

/** Secrets shorter than this are a password guess away; matches cron-auth. */
const MIN_CRON_SECRET = 24;
const MIN_AUTH_SECRET = 32;

const LOG_LEVELS = new Set(['debug', 'info', 'warn', 'error']);

/**
 * Variables that switch a control on or off. The application compares them to
 * the exact string `'true'`; anything else reads as "off". That makes a typo
 * such as `AGENT_REQUIRE_SIGNED_RUNS=1` a silent downgrade of a security
 * control, so an unrecognised value is an error rather than a warning.
 */
const BOOLEAN_VARIABLES = ['AGENT_REQUIRE_SIGNED_RUNS', 'NOTIFY_ALLOW_PRIVATE_WEBHOOKS'] as const;

function read(env: Env, name: string): string {
  return (env[name] ?? '').trim();
}

function parseAbsoluteUrl(name: string, value: string, errors: EnvIssue[]): URL | null {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    errors.push({ variable: name, message: 'must be an absolute URL.', severity: 'error' });
    return null;
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') {
    errors.push({ variable: name, message: 'must use http:// or https://.', severity: 'error' });
    return null;
  }
  if (url.username || url.password) {
    errors.push({ variable: name, message: 'must not embed credentials.', severity: 'error' });
  }
  return url;
}

function checkDatabaseUrl(value: string, errors: EnvIssue[]): void {
  if (value.length === 0) {
    errors.push({
      variable: 'DATABASE_URL',
      message: 'is required: PostgreSQL connection string for the application database.',
      severity: 'error',
    });
    return;
  }

  // libpq socket form has an empty host, which WHATWG URL rejects.
  if (/[?&]host=(?:%2f|\/)/i.test(value)) {
    return;
  }

  let url: URL;
  try {
    url = new URL(value);
  } catch {
    errors.push({
      variable: 'DATABASE_URL',
      message: 'is not a valid connection URL.',
      severity: 'error',
    });
    return;
  }

  if (url.protocol !== 'postgresql:' && url.protocol !== 'postgres:') {
    errors.push({
      variable: 'DATABASE_URL',
      message: 'must use the postgresql:// scheme.',
      severity: 'error',
    });
  }
  if (!url.hostname) {
    errors.push({
      variable: 'DATABASE_URL',
      message: 'must name a database host.',
      severity: 'error',
    });
  }
  if (url.pathname.replace(/^\//, '').length === 0) {
    errors.push({ variable: 'DATABASE_URL', message: 'must name a database.', severity: 'error' });
  }
}

function checkBoolean(env: Env, name: string, errors: EnvIssue[]): void {
  const raw = read(env, name);
  if (raw.length === 0) {
    return;
  }
  const normalised = raw.toLowerCase();
  if (normalised !== 'true' && normalised !== 'false') {
    errors.push({
      variable: name,
      message: "must be exactly 'true' or 'false'; any other value is read as false.",
      severity: 'error',
    });
  }
}

/**
 * Validates the environment and returns a complete report. Pure: it reads the
 * object it is given, never the live process environment unless asked to.
 */
export function validateEnvironment(
  env: Env = process.env,
  options: ValidateOptions = {},
): EnvReport {
  const production = options.production ?? env.NODE_ENV === 'production';
  const errors: EnvIssue[] = [];
  const warnings: EnvIssue[] = [];
  const accepted: string[] = [];

  // --- NODE_ENV -----------------------------------------------------------
  const nodeEnv = read(env, 'NODE_ENV');
  if (nodeEnv.length === 0) {
    warnings.push({
      variable: 'NODE_ENV',
      message: "is unset; the app behaves as development. Set 'production' on a real deployment.",
      severity: 'warning',
    });
  } else if (!['development', 'test', 'production'].includes(nodeEnv)) {
    warnings.push({
      variable: 'NODE_ENV',
      message: 'is not one of development, test or production; production safeguards are off.',
      severity: 'warning',
    });
  } else {
    accepted.push('NODE_ENV');
  }

  // --- DATABASE_URL -------------------------------------------------------
  const databaseUrl = read(env, 'DATABASE_URL');
  checkDatabaseUrl(databaseUrl, errors);
  if (databaseUrl.length > 0 && !errors.some((issue) => issue.variable === 'DATABASE_URL')) {
    accepted.push('DATABASE_URL');
  }

  // --- BETTER_AUTH_URL ----------------------------------------------------
  const authUrl = read(env, 'BETTER_AUTH_URL');
  if (authUrl.length === 0) {
    errors.push({
      variable: 'BETTER_AUTH_URL',
      message: 'is required: the public origin used for cookies and the same-origin check.',
      severity: 'error',
    });
  } else {
    const parsed = parseAbsoluteUrl('BETTER_AUTH_URL', authUrl, errors);
    if (parsed) {
      accepted.push('BETTER_AUTH_URL');
      if (production && parsed.protocol !== 'https:' && !isLoopbackHost(parsed.hostname)) {
        errors.push({
          variable: 'BETTER_AUTH_URL',
          message: 'must be an https:// origin in production.',
          severity: 'error',
        });
      }
    }
  }

  // --- BETTER_AUTH_SECRET -------------------------------------------------
  const authSecret = read(env, 'BETTER_AUTH_SECRET');
  if (authSecret.length === 0) {
    if (production) {
      errors.push({
        variable: 'BETTER_AUTH_SECRET',
        message: `is required in production: at least ${MIN_AUTH_SECRET} characters.`,
        severity: 'error',
      });
    } else {
      warnings.push({
        variable: 'BETTER_AUTH_SECRET',
        message:
          'is unset; development falls back to a well-known placeholder. Never deploy without a real value.',
        severity: 'warning',
      });
    }
  } else if (authSecret.length < MIN_AUTH_SECRET) {
    errors.push({
      variable: 'BETTER_AUTH_SECRET',
      message: `must be at least ${MIN_AUTH_SECRET} characters: it signs sessions and encrypts second-factor secrets and webhook signing keys.`,
      severity: 'error',
    });
  } else {
    accepted.push('BETTER_AUTH_SECRET');
  }

  // --- CRON_SECRET --------------------------------------------------------
  const cronSecret = read(env, 'CRON_SECRET');
  if (cronSecret.length === 0) {
    warnings.push({
      variable: 'CRON_SECRET',
      message: 'is unset; the alert sweep route answers 503 and no notifications are delivered.',
      severity: 'warning',
    });
  } else if (cronSecret.length < MIN_CRON_SECRET) {
    errors.push({
      variable: 'CRON_SECRET',
      message: `must be at least ${MIN_CRON_SECRET} characters; shorter values are refused by the sweep route, so alerting would silently stop.`,
      severity: 'error',
    });
  } else {
    accepted.push('CRON_SECRET');
  }

  // --- LOG_LEVEL ----------------------------------------------------------
  const logLevel = read(env, 'LOG_LEVEL');
  if (logLevel.length > 0) {
    if (!LOG_LEVELS.has(logLevel.toLowerCase())) {
      warnings.push({
        variable: 'LOG_LEVEL',
        message: "is not one of debug, info, warn or error; the logger falls back to 'info'.",
        severity: 'warning',
      });
    } else {
      accepted.push('LOG_LEVEL');
    }
  }

  // --- boolean flags ------------------------------------------------------
  for (const name of BOOLEAN_VARIABLES) {
    checkBoolean(env, name, errors);
    if (read(env, name).length > 0 && !errors.some((issue) => issue.variable === name)) {
      accepted.push(name);
    }
  }

  if (production && read(env, 'NOTIFY_ALLOW_PRIVATE_WEBHOOKS').toLowerCase() === 'true') {
    warnings.push({
      variable: 'NOTIFY_ALLOW_PRIVATE_WEBHOOKS',
      message:
        'is enabled in production: alert destinations may target loopback or private addresses. Intended only for an internal collector.',
      severity: 'warning',
    });
  }

  // --- single sign-on -----------------------------------------------------
  // The provider reader already enforces the all-or-none rule and https for a
  // non-loopback issuer; reuse it so there is one definition of "valid SSO".
  const oidcNames = ['OIDC_ISSUER', 'OIDC_CLIENT_ID', 'OIDC_CLIENT_SECRET'];
  const oidcSet = oidcNames.filter((name) => read(env, name).length > 0);
  if (oidcSet.length > 0 && oidcSet.length < oidcNames.length) {
    const missing = oidcNames.filter((name) => !oidcSet.includes(name));
    for (const name of missing) {
      errors.push({
        variable: name,
        message: 'must also be set for single sign-on; set all three OIDC_* values or none.',
        severity: 'error',
      });
    }
  } else if (oidcSet.length === oidcNames.length) {
    const issuer = read(env, 'OIDC_ISSUER');
    const parsed = parseAbsoluteUrl('OIDC_ISSUER', issuer, errors);
    if (parsed) {
      if (parsed.protocol !== 'https:' && !isLoopbackHost(parsed.hostname)) {
        errors.push({
          variable: 'OIDC_ISSUER',
          message: 'must use https://; plain http is only accepted for a loopback provider.',
          severity: 'error',
        });
      } else {
        accepted.push('OIDC_ISSUER', 'OIDC_CLIENT_ID', 'OIDC_CLIENT_SECRET');
      }
    }
  }

  const redirectUri = read(env, 'OIDC_REDIRECT_URI');
  if (redirectUri.length > 0) {
    if (oidcSet.length === 0) {
      errors.push({
        variable: 'OIDC_REDIRECT_URI',
        message:
          'is set but single sign-on is not configured; set the three OIDC_* values or remove it.',
        severity: 'error',
      });
    } else {
      parseAbsoluteUrl('OIDC_REDIRECT_URI', redirectUri, errors);
    }
  }

  // --- secrets manager ------------------------------------------------
  // A deployment may mount secrets as files (Docker/Swarm secrets, Kubernetes
  // secret volumes, Vault agent templates) instead of injecting them as
  // environment variables. `SECRETS_DIR` names the directory that holds one file
  // per variable; a file whose name matches an allow-listed variable is read at
  // startup and takes precedence over the environment, so the operator has one
  // obvious place a secret can come from.
  //
  // Validated here rather than only at read time so a misconfigured mount is a
  // startup failure with a clear message, not a partially working deployment.
  const secretsDir = read(env, 'SECRETS_DIR');
  if (secretsDir.length > 0) {
    if (!isAbsolute(secretsDir)) {
      errors.push({
        variable: 'SECRETS_DIR',
        message:
          'must be an absolute path; a relative path resolves against the process working directory, which differs between runtimes.',
        severity: 'error',
      });
    } else {
      accepted.push('SECRETS_DIR');
    }
  }

  // --- evidence storage ------------------------------------------------
  // Uploaded evidence is written to disk, so the target has to be configured
  // explicitly and has to be somewhere the operator can back up. Defaulting
  // silently into the source tree is how evidence ends up inside a container
  // layer that is thrown away on redeploy.
  const evidenceDir = read(env, 'EVIDENCE_DIR');
  if (evidenceDir.length > 0) {
    if (!isAbsolute(evidenceDir)) {
      errors.push({
        variable: 'EVIDENCE_DIR',
        message: 'must be an absolute path so the location does not depend on the working directory.',
        severity: 'error',
      });
    } else {
      accepted.push('EVIDENCE_DIR');
    }
  }
  // Unset is a valid production state: file evidence is then unavailable (the
  // upload route answers 503) rather than misconfigured. A permanent warning for
  // an optional feature is noise, and noise is what trains operators to ignore
  // warnings that do matter. The startup log states `evidenceUpload: false`
  // explicitly, so the state is discoverable without being framed as a fault.

  // --- transport policy ---------------------------------------------------
  // Delegated so the rule lives in one place, but each leg is checked on its
  // own: a bad origin must not hide a cleartext database, or the operator fixes
  // one problem and meets the next on the following restart.
  if (authUrl.length > 0) {
    try {
      assertSecureOrigin({ production, origin: authUrl });
    } catch (error) {
      // The structural check above already covers a malformed or non-http URL;
      // only add this one when it says something new.
      if (!errors.some((issue) => issue.variable === 'BETTER_AUTH_URL')) {
        errors.push({
          variable: 'BETTER_AUTH_URL',
          message: error instanceof Error ? error.message : 'failed the transport policy check.',
          severity: 'error',
        });
      }
    }
  }

  if (databaseUrl.length > 0) {
    try {
      assertSecureDatabase({ production, databaseUrl });
    } catch (error) {
      if (!errors.some((issue) => issue.variable === 'DATABASE_URL')) {
        errors.push({
          variable: 'DATABASE_URL',
          message: error instanceof Error ? error.message : 'failed the transport policy check.',
          severity: 'error',
        });
      }
    }
  }

  return {
    ok: errors.length === 0,
    accepted: [...new Set(accepted)].sort(),
    errors,
    warnings,
  };
}

/** Renders a report for a human, never including a value. */
export function formatEnvReport(report: EnvReport): string {
  const lines: string[] = [];
  lines.push(
    `Configuration check: ${report.accepted.length} variable(s) accepted, ${report.errors.length} error(s), ${report.warnings.length} warning(s).`,
  );
  for (const issue of report.errors) {
    lines.push(`  ERROR   ${issue.variable}: ${issue.message}`);
  }
  for (const issue of report.warnings) {
    lines.push(`  WARNING ${issue.variable}: ${issue.message}`);
  }
  if (report.ok) {
    lines.push('The configuration is usable.');
  } else {
    lines.push('The configuration is not usable; fix the errors above before starting the app.');
  }
  return lines.join('\n');
}
