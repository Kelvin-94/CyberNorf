import { createHmac } from 'node:crypto';
import { prisma } from '@/lib/prisma';
import type { Prisma } from '@/generated/prisma/client';

/**
 * A record of "what this deployment was configured with", not the configuration.
 *
 * The process environment is not auditable: a restart replaces it and leaves no
 * trace, so an operator cannot answer "did anything change since the last start,
 * and when?" after a rotation or an incident. On every boot the effective
 * configuration is reduced to a keyed digest and compared with the digest from
 * the previous boot. A change is reported; the values themselves are never
 * stored, logged or returned.
 *
 * The digest is an HMAC keyed with BETTER_AUTH_SECRET rather than a plain hash.
 * A plain hash over environment variables would be a guessing oracle for a
 * database-only attacker: most values are short and known-shaped, so an
 * unkeyed digest of "everything else plus the secret" can be brute-forced.
 * Keying it with a secret that never leaves the process removes that.
 */

/**
 * Variables that change on every start, every shell or every CI runner and carry
 * no configuration meaning. Including them would report a change on every boot
 * and train the operator to ignore the warning.
 */
const VOLATILE_KEYS = new Set([
  'HOSTNAME',
  'PWD',
  'OLDPWD',
  'SHLVL',
  '_',
  'TMPDIR',
  'INIT_CWD',
  'TERM',
  'COLORTERM',
  'NEXT_RUNTIME',
]);

const VOLATILE_PREFIXES = ['npm_', 'NEXT_PRIVATE_'];

function isVolatile(key: string): boolean {
  return VOLATILE_KEYS.has(key) || VOLATILE_PREFIXES.some((prefix) => key.startsWith(prefix));
}

/** The settings key that holds the fingerprint of the last completed start. */
export const CONFIG_FINGERPRINT_KEY = 'config.fingerprint';

/**
 * Pure digest of the effective configuration. Exported for tests: the same input
 * always produces the same digest, and the digest reveals nothing about values.
 */
export function fingerprintConfiguration(
  env: NodeJS.ProcessEnv = process.env,
  key: string | undefined = env.BETTER_AUTH_SECRET,
): string {
  const lines = Object.keys(env)
    .filter((name) => !isVolatile(name))
    .sort()
    .map((name) => `${name}=${env[name] ?? ''}`)
    .join('\n');

  // An unkeyed digest is accepted only when no auth secret exists, which the
  // environment validator already refuses in production. It is still better than
  // no record at all, and the caller reports which mode was used.
  return key
    ? createHmac('sha256', key).update(lines).digest('hex')
    : createHmac('sha256', 'cybernorf-unkeyed-config').update(lines).digest('hex');
}

export type FingerprintStatus = 'NEW' | 'UNCHANGED' | 'CHANGED' | 'UNAVAILABLE';

export interface FingerprintRecord {
  status: FingerprintStatus;
  /** First 12 hex characters, safe to log and enough to compare by eye. */
  digest: string;
  /** How the previous start's digest differed, when there was one. */
  changed: boolean;
}

/**
 * Stores the digest for the next start to compare against. Failure to write is
 * reported as UNAVAILABLE rather than thrown: the database may legitimately be
 * down while the process starts (the readiness probe is what reports that), and
 * a missing audit convenience must not stop the server from serving.
 */
export async function recordConfigurationFingerprint(
  fingerprint: string,
  options: { key?: string } = {},
): Promise<FingerprintRecord> {
  const key = options.key ?? CONFIG_FINGERPRINT_KEY;
  const digest = fingerprint.slice(0, 12);

  try {
    const previous = await prisma.systemSetting.findUnique({
      where: { key },
      select: { value: true },
    });
    const previousDigest =
      previous && typeof previous.value === 'object' && previous.value !== null
        ? (previous.value as { fingerprint?: unknown }).fingerprint
        : undefined;

    const value = {
      fingerprint,
      digest,
      recordedAt: new Date().toISOString(),
    } satisfies Prisma.InputJsonObject;

    await prisma.systemSetting.upsert({
      where: { key },
      create: { key, value },
      update: { value },
    });

    if (typeof previousDigest !== 'string') {
      return { status: 'NEW', digest, changed: false };
    }
    const changed = previousDigest !== fingerprint;
    return { status: changed ? 'CHANGED' : 'UNCHANGED', digest, changed };
  } catch {
    return { status: 'UNAVAILABLE', digest, changed: false };
  }
}
