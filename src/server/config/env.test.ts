import assert from 'node:assert/strict';
import { test } from 'node:test';
import { formatEnvReport, validateEnvironment } from './env.ts';

const VALID_SECRET = 'a'.repeat(48);
const VALID_CRON = 'c'.repeat(32);

/** A configuration that passes in production. */
function productionEnv(overrides: Record<string, string | undefined> = {}) {
  return {
    NODE_ENV: 'production',
    DATABASE_URL: 'postgresql://app:pw@db.internal:5432/cybernorf?sslmode=verify-full',
    BETTER_AUTH_URL: 'https://cybernorf.example.com',
    BETTER_AUTH_SECRET: VALID_SECRET,
    CRON_SECRET: VALID_CRON,
    ...overrides,
  };
}

function variables(report: ReturnType<typeof validateEnvironment>): string[] {
  return [...report.errors, ...report.warnings].map((issue) => issue.variable);
}

test('a complete production configuration passes with no issues', () => {
  const report = validateEnvironment(productionEnv(), { production: true });

  assert.equal(report.ok, true);
  assert.deepEqual(report.errors, []);
  assert.deepEqual(report.warnings, []);
  assert.ok(report.accepted.includes('DATABASE_URL'));
  assert.ok(report.accepted.includes('BETTER_AUTH_SECRET'));
});

test('every problem is reported at once, not just the first', () => {
  const report = validateEnvironment(
    { NODE_ENV: 'production', DATABASE_URL: '', BETTER_AUTH_URL: '' },
    { production: true },
  );

  assert.equal(report.ok, false);
  const names = report.errors.map((issue) => issue.variable);
  for (const expected of ['DATABASE_URL', 'BETTER_AUTH_URL', 'BETTER_AUTH_SECRET']) {
    assert.ok(names.includes(expected), `expected an error for ${expected}`);
  }
});

test('a missing auth secret fails in production and warns in development', () => {
  const production = validateEnvironment(productionEnv({ BETTER_AUTH_SECRET: undefined }), {
    production: true,
  });
  assert.equal(production.ok, false);
  assert.ok(production.errors.some((issue) => issue.variable === 'BETTER_AUTH_SECRET'));

  const development = validateEnvironment(
    {
      DATABASE_URL: 'postgresql://app:pw@127.0.0.1:5432/cybernorf',
      BETTER_AUTH_URL: 'http://localhost:3000',
    },
    { production: false },
  );
  assert.equal(development.ok, true);
  assert.deepEqual(development.warnings.map((issue) => issue.variable).sort(), [
    'BETTER_AUTH_SECRET',
    'CRON_SECRET',
    'NODE_ENV',
  ]);
});

test('a short auth secret is refused: it also derives the webhook sealing key', () => {
  const report = validateEnvironment(productionEnv({ BETTER_AUTH_SECRET: 'a'.repeat(31) }), {
    production: true,
  });

  assert.equal(report.ok, false);
  const issue = report.errors.find((entry) => entry.variable === 'BETTER_AUTH_SECRET');
  assert.match(issue?.message ?? '', /at least 32/);
});

test('a short CRON_SECRET is an error, because the route would silently refuse', () => {
  const report = validateEnvironment(productionEnv({ CRON_SECRET: 'too-short' }), {
    production: true,
  });

  assert.equal(report.ok, false);
  const issue = report.errors.find((entry) => entry.variable === 'CRON_SECRET');
  assert.match(issue?.message ?? '', /at least 24/);
});

test('a security flag set to a non-boolean value is an error, not a silent downgrade', () => {
  // Surrounding whitespace is trimmed, so ' TRUE ' is a deliberate 'true'.
  for (const value of ['1', 'yes', 'on', 'y']) {
    const report = validateEnvironment(productionEnv({ AGENT_REQUIRE_SIGNED_RUNS: value }), {
      production: true,
    });
    assert.equal(report.ok, false, `'${value}' should be rejected`);
    assert.ok(
      report.errors.some((issue) => issue.variable === 'AGENT_REQUIRE_SIGNED_RUNS'),
      `'${value}' should name the variable`,
    );
  }

  // The two exact spellings the application reads are accepted, case-insensitively.
  for (const value of ['true', 'false', 'True']) {
    const report = validateEnvironment(productionEnv({ AGENT_REQUIRE_SIGNED_RUNS: value }), {
      production: true,
    });
    assert.equal(report.ok, true, `'${value}' should be accepted`);
  }
});

test('enabling private webhook targets in production warns but does not block', () => {
  const report = validateEnvironment(productionEnv({ NOTIFY_ALLOW_PRIVATE_WEBHOOKS: 'true' }), {
    production: true,
  });

  assert.equal(report.ok, true);
  assert.ok(report.warnings.some((issue) => issue.variable === 'NOTIFY_ALLOW_PRIVATE_WEBHOOKS'));
});

test('plain http and a remote cleartext database are refused in production', () => {
  const report = validateEnvironment(
    productionEnv({
      BETTER_AUTH_URL: 'http://cybernorf.example.com',
      DATABASE_URL: 'postgresql://app:pw@db.internal:5432/cybernorf',
    }),
    { production: true },
  );

  assert.equal(report.ok, false);
  const names = variables(report);
  assert.ok(names.includes('BETTER_AUTH_URL'));
  assert.ok(names.includes('DATABASE_URL'));
});

test('a loopback deployment may use plain http, as the transport policy allows', () => {
  const report = validateEnvironment(
    productionEnv({
      BETTER_AUTH_URL: 'http://127.0.0.1:3000',
      DATABASE_URL: 'postgresql://app:pw@127.0.0.1:5432/cybernorf',
    }),
    { production: true },
  );

  assert.equal(report.ok, true);
  assert.deepEqual(report.errors, []);
});

test('a malformed or non-postgres database URL is refused', () => {
  for (const value of [
    'not a url',
    'mysql://app:pw@db:3306/cybernorf',
    'postgresql://db.internal/cybernorf',
  ]) {
    const report = validateEnvironment(productionEnv({ DATABASE_URL: value }), {
      production: true,
    });
    assert.equal(report.ok, false, `'${value}' should be rejected`);
    assert.ok(report.errors.some((issue) => issue.variable === 'DATABASE_URL'));
  }
});

test('a partially configured identity provider is refused', () => {
  const report = validateEnvironment(productionEnv({ OIDC_ISSUER: 'https://idp.example.com' }), {
    production: true,
  });

  assert.equal(report.ok, false);
  const names = report.errors.map((issue) => issue.variable);
  assert.ok(names.includes('OIDC_CLIENT_ID'));
  assert.ok(names.includes('OIDC_CLIENT_SECRET'));
});

test('a complete identity provider configuration is accepted', () => {
  const report = validateEnvironment(
    productionEnv({
      OIDC_ISSUER: 'https://idp.example.com/realms/cybernorf',
      OIDC_CLIENT_ID: 'cybernorf',
      OIDC_CLIENT_SECRET: 'provider-secret',
    }),
    { production: true },
  );

  assert.equal(report.ok, true);
  assert.ok(report.accepted.includes('OIDC_ISSUER'));
});

test('a plain-http identity provider is refused outside loopback', () => {
  const report = validateEnvironment(
    productionEnv({
      OIDC_ISSUER: 'http://idp.example.com',
      OIDC_CLIENT_ID: 'cybernorf',
      OIDC_CLIENT_SECRET: 'provider-secret',
    }),
    { production: true },
  );

  assert.equal(report.ok, false);
  assert.ok(report.errors.some((issue) => issue.variable === 'OIDC_ISSUER'));
});

test('an unknown LOG_LEVEL warns and keeps the documented fallback', () => {
  const report = validateEnvironment(productionEnv({ LOG_LEVEL: 'verbose' }), {
    production: true,
  });

  assert.equal(report.ok, true);
  assert.ok(report.warnings.some((issue) => issue.variable === 'LOG_LEVEL'));

  const accepted = validateEnvironment(productionEnv({ LOG_LEVEL: 'debug' }), {
    production: true,
  });
  assert.ok(accepted.accepted.includes('LOG_LEVEL'));
});

test('an absent evidence signing key is allowed, a short one is refused', () => {
  const absent = validateEnvironment(productionEnv(), { production: true });
  assert.equal(absent.ok, true);
  assert.ok(!variables(absent).includes('EVIDENCE_SIGNING_KEY'));

  const short = validateEnvironment(productionEnv({ EVIDENCE_SIGNING_KEY: 'a'.repeat(31) }), {
    production: true,
  });
  assert.equal(short.ok, false);
  const issue = short.errors.find((entry) => entry.variable === 'EVIDENCE_SIGNING_KEY');
  assert.match(issue?.message ?? '', /at least 32/);

  const complete = validateEnvironment(productionEnv({ EVIDENCE_SIGNING_KEY: 'a'.repeat(32) }), {
    production: true,
  });
  assert.equal(complete.ok, true);
  assert.ok(complete.accepted.includes('EVIDENCE_SIGNING_KEY'));
});

test('a malformed evidence key id is refused, because it travels in every manifest', () => {
  const bad = validateEnvironment(
    productionEnv({ EVIDENCE_SIGNING_KEY: 'a'.repeat(32), EVIDENCE_SIGNING_KEY_ID: 'bad id!' }),
    { production: true },
  );
  assert.equal(bad.ok, false);
  assert.ok(bad.errors.some((entry) => entry.variable === 'EVIDENCE_SIGNING_KEY_ID'));

  const good = validateEnvironment(
    productionEnv({ EVIDENCE_SIGNING_KEY: 'a'.repeat(32), EVIDENCE_SIGNING_KEY_ID: 'pkg-2026.11' }),
    { production: true },
  );
  assert.equal(good.ok, true);
  assert.ok(good.accepted.includes('EVIDENCE_SIGNING_KEY_ID'));
});

test('no message ever contains a configured value', () => {
  const secret = 'super-secret-auth-value-that-must-not-be-printed';
  const cron = 'cron-secret-value-that-must-not-be-printed';
  const report = validateEnvironment(
    productionEnv({
      BETTER_AUTH_SECRET: 'short', // deliberately invalid
      CRON_SECRET: cron,
      OIDC_ISSUER: 'http://idp.example.com',
      OIDC_CLIENT_ID: 'client-id-value',
      OIDC_CLIENT_SECRET: 'client-secret-value',
      DATABASE_URL: `postgresql://app:${secret}@db.internal:5432/cybernorf`,
    }),
    { production: true },
  );

  const rendered = formatEnvReport(report);
  for (const value of [secret, cron, 'client-secret-value', 'client-id-value']) {
    assert.ok(!rendered.includes(value), `the report leaked ${value}`);
  }
});
