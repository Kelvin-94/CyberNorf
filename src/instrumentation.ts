/**
 * Runs once when the Next.js server starts. Configuration problems that would
 * silently weaken a deployment fail here instead of at the first sign-in
 * attempt, and every problem is reported at once so an operator fixes them in
 * one pass rather than one restart per mistake.
 */
export async function register(): Promise<void> {
  if (process.env.NEXT_RUNTIME !== 'nodejs') {
    return;
  }

  const { formatEnvReport, validateEnvironment } = await import('@/server/config/env');
  const { fingerprintConfiguration, recordConfigurationFingerprint } =
    await import('@/server/config/fingerprint');
  const { describeSecretSources, loadFileSecrets } = await import('@/server/config/secrets-file');
  const { logger, resolveLogLevel } = await import('@/server/logging/logger');
  const { hasEvidenceSigningKey } = await import('@/server/config');

  // Mounted secrets are applied before validation, so the validator sees the
  // effective configuration rather than the environment alone. A failed read is
  // fatal: continuing would run with whatever the environment happened to hold.
  const secretsDir = process.env.SECRETS_DIR?.trim();
  let secretSources: ReturnType<typeof describeSecretSources> = {
    fromFiles: [],
    ignoredFiles: [],
  };
  if (secretsDir) {
    const fileSecrets = loadFileSecrets(process.env, secretsDir);
    if (fileSecrets.errors.length > 0) {
      // Names and rules only; no value is included in the message.
      throw new Error(`Secret files could not be loaded:\n${fileSecrets.errors.join('\n')}`);
    }
    secretSources = describeSecretSources(fileSecrets);
  }

  const report = validateEnvironment();

  // Warnings do not stop the process: they describe behaviour the operator
  // probably did not intend, so they are logged loudly and allowed through.
  for (const warning of report.warnings) {
    logger.warn('config.warning', { variable: warning.variable, reason: warning.message });
  }

  if (!report.ok) {
    // The message names variables and rules only; values are never included.
    logger.error('config.invalid', { errors: report.errors });
    throw new Error(`Invalid configuration:\n${formatEnvReport(report)}`);
  }

  // Compare the effective configuration with the one this deployment last
  // started with. The digest is keyed, so a changed value is visible without
  // the value — or a crackable hash of it — being stored. A database that is
  // not reachable yet is not a startup failure; it is reported as UNAVAILABLE.
  const fingerprint = await recordConfigurationFingerprint(fingerprintConfiguration());
  if (fingerprint.status === 'CHANGED') {
    logger.warn('config.changed', {
      digest: fingerprint.digest,
      reason: 'The effective configuration differs from the previous start.',
    });
  }

  // One parseable line that answers "which build booted, with which features,
  // and at which log level" without recording a single secret.
  logger.info('server.started', {
    nodeVersion: process.version,
    // Report the level the logger actually applied, not the raw variable, so an
    // unrecognised value is visibly resolved instead of echoed back.
    logLevel: resolveLogLevel(process.env.LOG_LEVEL),
    features: {
      oidc: Boolean(process.env.OIDC_ISSUER),
      signedAgentRunsRequired: process.env.AGENT_REQUIRE_SIGNED_RUNS === 'true',
      alertSweep: Boolean(process.env.CRON_SECRET),
      evidenceUpload: Boolean(process.env.EVIDENCE_DIR),
      evidencePackages: hasEvidenceSigningKey(),
    },
    // Variable names only, so an operator can confirm a rotation was picked up
    // without any value being written to the log.
    secretsFromFiles: secretSources.fromFiles,
    configFingerprint: { status: fingerprint.status, digest: fingerprint.digest },
  });
}
