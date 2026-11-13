import { createHash, createPublicKey, randomBytes, timingSafeEqual } from 'node:crypto';
import { Prisma } from '@/generated/prisma/client';
import { prisma } from '@/lib/prisma';
import {
  computeTrustState,
  POSTURE_CHECK_STATUSES,
  ZeroTrustError,
  type PostureCheck,
  type TrustAssessment,
  type TrustState,
} from '@/server/domain/zero-trust';
import { badRequest, conflict } from '@/server/errors';

/**
 * Plumbing shared by the Zero Trust services: error mapping, connector
 * credentials, posture parsing and the one place that turns stored device rows
 * into a trust assessment.
 *
 * Trust is derived on read from the stored posture report rather than trusted
 * from the device row. The row carries an assessment for filtering and
 * dashboards, but a caller that needs to make a decision recomputes it, so an
 * expired report degrades the device even if nothing wrote to the row since.
 */

export type Db = Prisma.TransactionClient | typeof prisma;

/** Maps a domain failure to an API error, and rethrows anything else untouched. */
export function mapZeroTrustFailure(error: unknown): never {
  if (error instanceof ZeroTrustError) {
    switch (error.code) {
      case 'invalid_transition':
      case 'self_approval':
        throw conflict(error.message);
      case 'rollback_blocked':
      case 'version_not_newer':
      case 'publisher_key_unknown':
      case 'invalid_public_key':
      case 'signature_invalid':
      case 'invalid_manifest':
        throw badRequest(error.message);
      case 'invalid_version':
      case 'invalid_conditions':
        throw badRequest(error.message);
    }
  }
  throw error;
}

export function hashToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}

/**
 * Connector credentials are shown once and stored as a hash. The prefix makes a
 * leaked token recognisable to secret scanners without making it guessable.
 */
export function generateConnectorToken(): { token: string; hash: string } {
  const token = `cnf_${randomBytes(32).toString('base64url')}`;
  return { token, hash: hashToken(token) };
}

export function tokenMatches(token: string, expectedHash: string): boolean {
  const actual = Buffer.from(hashToken(token), 'hex');
  const expected = Buffer.from(expectedHash, 'hex');
  if (actual.length !== expected.length) return false;
  return timingSafeEqual(actual, expected);
}

export function asRecord(value: Prisma.JsonValue | null | undefined): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return {};
  return value as Record<string, unknown>;
}

/**
 * Posture checks arrive as JSON. Anything that does not look like a check is
 * dropped rather than interpreted; a malformed report therefore cannot raise a
 * device's trust by smuggling an unknown status.
 */
export function parsePostureChecks(value: Prisma.JsonValue | null | undefined): PostureCheck[] {
  if (!Array.isArray(value)) return [];
  const checks: PostureCheck[] = [];
  for (const item of value) {
    if (typeof item !== 'object' || item === null || Array.isArray(item)) continue;
    const record = item as Record<string, unknown>;
    const id = record['id'];
    const status = record['status'];
    if (typeof id !== 'string' || id.length === 0 || id.length > 120) continue;
    if (typeof status !== 'string') continue;
    if (!(POSTURE_CHECK_STATUSES as readonly string[]).includes(status)) continue;
    const detail = record['detail'];
    checks.push({
      id,
      status: status as PostureCheck['status'],
      ...(typeof detail === 'string' && detail.length > 0 ? { detail: detail.slice(0, 500) } : {}),
    });
  }
  return checks;
}

export interface PostureRow {
  id: string;
  collectedAt: Date;
  expiresAt: Date;
  signatureVerified: boolean;
  checks: Prisma.JsonValue;
}

export interface DeviceTrustSnapshot extends TrustAssessment {
  postureReportId: string | null;
  collectedAt: Date | null;
  expiresAt: Date | null;
  passedChecks: string[];
  failingChecks: string[];
  unknownChecks: string[];
}

export function assessDeviceTrust(input: {
  status: 'PENDING' | 'ACTIVE' | 'SUSPENDED' | 'RETIRED';
  managed: boolean;
  attestationVerified: boolean;
  posture: PostureRow | null;
  now: Date;
}): DeviceTrustSnapshot {
  const checks = parsePostureChecks(input.posture?.checks);
  const assessment = computeTrustState({
    status: input.status,
    managed: input.managed,
    attestationVerified: input.attestationVerified,
    posture:
      input.posture === null
        ? null
        : {
            collectedAt: input.posture.collectedAt,
            expiresAt: input.posture.expiresAt,
            signatureVerified: input.posture.signatureVerified,
            checks,
          },
    now: input.now,
  });

  return {
    ...assessment,
    postureReportId: input.posture?.id ?? null,
    collectedAt: input.posture?.collectedAt ?? null,
    expiresAt: input.posture?.expiresAt ?? null,
    passedChecks: checks.filter((check) => check.status === 'PASS').map((check) => check.id),
    failingChecks: checks.filter((check) => check.status === 'FAIL').map((check) => check.id),
    unknownChecks: checks.filter((check) => check.status === 'UNKNOWN').map((check) => check.id),
  };
}

const LATEST_POSTURE_SELECT = {
  orderBy: { collectedAt: 'desc' },
  take: 1,
  select: {
    id: true,
    collectedAt: true,
    expiresAt: true,
    signatureVerified: true,
    checks: true,
  },
} as const;

export interface DeviceRecordForTrust {
  id: string;
  status: 'PENDING' | 'ACTIVE' | 'SUSPENDED' | 'RETIRED';
  managed: boolean;
  attestationVerified: boolean;
  postureReports?: readonly PostureRow[];
}

/** Recomputes trust for a loaded device. `postureReports` must be newest-first. */
export function trustForDevice(
  device: DeviceRecordForTrust,
  now = new Date(),
): DeviceTrustSnapshot {
  return assessDeviceTrust({
    status: device.status,
    managed: device.managed,
    attestationVerified: device.attestationVerified,
    posture: device.postureReports?.[0] ?? null,
    now,
  });
}

/** The exact object a device signs when it submits posture. */
export function postureSignaturePayload(
  deviceId: string,
  collectedAt: Date,
  checks: readonly PostureCheck[],
): Record<string, unknown> {
  return {
    deviceId,
    collectedAt: collectedAt.toISOString(),
    checks: checks.map((check) => ({
      id: check.id,
      status: check.status,
      ...(check.detail !== undefined ? { detail: check.detail } : {}),
    })),
  };
}

/**
 * Only Ed25519 device keys are accepted. A device that registers an RSA key
 * would otherwise be able to choose a weaker verification story than the one
 * the platform documents, so the algorithm is fixed here.
 */
export function assertEd25519PublicKey(material: string): void {
  let type: string | undefined;
  try {
    const key = material.includes('BEGIN PUBLIC KEY')
      ? createPublicKey({ key: material, format: 'pem' })
      : createPublicKey({ key: Buffer.from(material, 'base64'), format: 'der', type: 'spki' });
    type = key.asymmetricKeyType;
  } catch {
    throw badRequest('The device public key is not a valid PEM or base64 SPKI key.');
  }
  if (type !== 'ed25519') {
    throw badRequest('Device identity keys must be Ed25519.');
  }
}

export function isTrustState(value: unknown): value is TrustState {
  return (
    typeof value === 'string' && ['UNTRUSTED', 'UNKNOWN', 'PARTIAL', 'TRUSTED'].includes(value)
  );
}

export function isoOrNull(value: Date | null | undefined): string | null {
  return value === null || value === undefined ? null : value.toISOString();
}

export function clampTtlSeconds(value: number, min: number, max: number): number {
  return Math.min(max, Math.max(min, Math.round(value)));
}

export { LATEST_POSTURE_SELECT };
