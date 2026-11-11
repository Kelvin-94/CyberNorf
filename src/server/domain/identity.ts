import { createHash, randomBytes } from 'node:crypto';
import type {
  AccessReviewStatus,
  IdentityKind,
  IdentityStatus,
  IdentityType,
} from '@/generated/prisma/client';

/**
 * Identity governance domain rules.
 *
 * The inventory is a governance record, not an authentication store: Better Auth
 * remains the source of truth for console users, sessions and second factors.
 * These rules decide what may be recorded, which lifecycle moves are legal, how
 * a machine credential is minted and how attention is prioritized. They are pure
 * so the service layer stays about persistence and audit.
 */

/** Humans are people; every other type is a workload, device or service. */
export const HUMAN_IDENTITY_TYPES = ['USER'] as const;
export const MACHINE_IDENTITY_TYPES = [
  'SERVICE_ACCOUNT',
  'MONITORING_AGENT',
  'API_CLIENT',
  'SERVER',
  'NETWORK_DEVICE',
  'IOT_DEVICE',
  'CONTAINER',
  'OTHER',
] as const;

export const IDENTITY_TYPES = [...HUMAN_IDENTITY_TYPES, ...MACHINE_IDENTITY_TYPES] as const;
export type IdentityTypeName = (typeof IDENTITY_TYPES)[number];

export const IDENTITY_TYPE_DETAILS: Readonly<Record<IdentityTypeName, string>> = {
  USER: 'A person recorded in the inventory, optionally linked to a console account.',
  SERVICE_ACCOUNT: 'A non-interactive account used by software or automation.',
  MONITORING_AGENT: 'A monitoring agent credential or sensor identity.',
  API_CLIENT: 'An application registered to call an API.',
  SERVER: 'A server workload with its own credential or certificate.',
  NETWORK_DEVICE: 'A switch, router, firewall or other network appliance.',
  IOT_DEVICE: 'An operational or building device with network access.',
  CONTAINER: 'A container or orchestration workload identity.',
  OTHER: 'A non-human identity that does not fit another category.',
};

export const IDENTITY_STATUSES = [
  'PENDING_APPROVAL',
  'ACTIVE',
  'SUSPENDED',
  'DEPROVISIONED',
] as const satisfies readonly IdentityStatus[];

/**
 * Lifecycle moves. Approval is the only way out of PENDING_APPROVAL, and
 * DEPROVISIONED is terminal so a decommissioned identity cannot be revived by a
 * later edit or a connector replay.
 */
export const IDENTITY_STATUS_TRANSITIONS: Readonly<
  Record<IdentityStatus, readonly IdentityStatus[]>
> = {
  PENDING_APPROVAL: ['ACTIVE', 'DEPROVISIONED'],
  ACTIVE: ['SUSPENDED', 'DEPROVISIONED'],
  SUSPENDED: ['ACTIVE', 'DEPROVISIONED'],
  DEPROVISIONED: [],
};

export function canTransitionIdentity(from: IdentityStatus, to: IdentityStatus): boolean {
  return IDENTITY_STATUS_TRANSITIONS[from].includes(to);
}

/** Machine identities start inert; only an owner may approve them for use. */
export function initialIdentityStatus(kind: IdentityKind): IdentityStatus {
  return kind === 'MACHINE' ? 'PENDING_APPROVAL' : 'ACTIVE';
}

/**
 * Identifiers are canonicalized before they are stored. Human identifiers are
 * normally email addresses and machine identifiers are account or workload
 * names; both are case-insensitive in practice. The database check constraint
 * enforces the same rule for any writer that bypasses this function.
 */
export function normalizeIdentityIdentifier(value: string): string {
  return value.trim().toLowerCase();
}

export function isHumanType(type: IdentityType): boolean {
  return type === 'USER';
}

export function typeMatchesKind(kind: IdentityKind, type: IdentityType): boolean {
  return kind === 'HUMAN' ? type === 'USER' : type !== 'USER';
}

// ---------------------------------------------------------------------------
// Machine credentials
// ---------------------------------------------------------------------------

export const IDENTITY_CREDENTIAL_PREFIX = 'cnid_';
const CREDENTIAL_RANDOM_BYTES = 32;
const CREDENTIAL_DISPLAY_CHARS = 6;

/** The only scope a machine credential can carry in this release. */
export const IDENTITY_CREDENTIAL_SCOPES = ['identity.self.read'] as const;
export type IdentityCredentialScope = (typeof IDENTITY_CREDENTIAL_SCOPES)[number];

export const IDENTITY_CREDENTIAL_SCOPE_DETAILS: Readonly<Record<IdentityCredentialScope, string>> =
  {
    'identity.self.read': 'Read this machine identity and its own credential metadata.',
  };

export const CREDENTIAL_TTL_MIN_DAYS = 1;
export const CREDENTIAL_TTL_MAX_DAYS = 365;
export const CREDENTIAL_TTL_DEFAULT_DAYS = 90;

export interface IssuedIdentityCredential {
  /** Plaintext credential. Returned to the caller exactly once, never stored. */
  token: string;
  /** SHA-256 of the token, which is what the database keeps. */
  hash: string;
  /** Short clear-text display prefix, e.g. `cnid_8Kd2xQ`. */
  prefix: string;
  expiresAt: Date;
}

export function hashIdentityCredential(token: string): string {
  return createHash('sha256').update(token, 'utf8').digest('hex');
}

/** Cheap shape check so malformed bearer headers never touch the database. */
export function isIdentityCredentialShape(token: string): boolean {
  return /^cnid_[A-Za-z0-9_-]{40,64}$/.test(token);
}

export function issueIdentityCredential(options: {
  ttlDays: number;
  now?: Date;
}): IssuedIdentityCredential {
  const now = options.now ?? new Date();
  const token = `${IDENTITY_CREDENTIAL_PREFIX}${randomBytes(CREDENTIAL_RANDOM_BYTES).toString('base64url')}`;
  const ttlDays = Math.min(
    Math.max(Math.trunc(options.ttlDays), CREDENTIAL_TTL_MIN_DAYS),
    CREDENTIAL_TTL_MAX_DAYS,
  );

  return {
    token,
    hash: hashIdentityCredential(token),
    prefix: token.slice(0, IDENTITY_CREDENTIAL_PREFIX.length + CREDENTIAL_DISPLAY_CHARS),
    expiresAt: new Date(now.getTime() + ttlDays * 24 * 60 * 60 * 1000),
  };
}

export function isIdentityCredentialScope(value: string): value is IdentityCredentialScope {
  return (IDENTITY_CREDENTIAL_SCOPES as readonly string[]).includes(value);
}

// ---------------------------------------------------------------------------
// Attention and risk
// ---------------------------------------------------------------------------

export type IdentitySignalCode =
  | 'UNOWNED_MACHINE'
  | 'ORPHANED_ACCOUNT'
  | 'UNLINKED_HUMAN'
  | 'DORMANT'
  | 'FAILED_AUTH_BURST'
  | 'EXCESSIVE_SESSIONS'
  | 'CREDENTIAL_EXPIRED'
  | 'CREDENTIAL_EXPIRING'
  | 'NO_ACTIVE_CREDENTIAL'
  | 'PENDING_APPROVAL';

export type IdentitySignalSeverity = 'LOW' | 'MEDIUM' | 'HIGH';

export interface IdentitySignal {
  code: IdentitySignalCode;
  severity: IdentitySignalSeverity;
  detail: string;
  score: number;
}

export type IdentityRiskLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export interface IdentityRiskInput {
  kind: IdentityKind;
  status: IdentityStatus;
  createdAt: Date;
  ownerUserId: string | null;
  linkedUserId: string | null;
  /** ACTIVE, DISABLED or null when the linked account is not a member. */
  linkedMembershipStatus: string | null;
  /** Most recent sign-in, session or credential use; null when never observed. */
  lastActivityAt: Date | null;
  failedAuthLast24h: number;
  activeSessions: number;
  /** Unrevoked credentials only. */
  credentials: ReadonlyArray<{ expiresAt: Date }>;
  now?: Date;
}

export interface IdentityRisk {
  score: number;
  level: IdentityRiskLevel;
  signals: IdentitySignal[];
}

const DORMANT_AFTER_DAYS = 90;
const CREDENTIAL_WARNING_DAYS = 30;
const FAILED_AUTH_BURST = 5;
const EXCESSIVE_SESSIONS = 3;

function daysBetween(earlier: Date, later: Date): number {
  return (later.getTime() - earlier.getTime()) / (24 * 60 * 60 * 1000);
}

/**
 * Deterministic, explainable prioritization. It is not a trained model and does
 * not claim to detect account takeover: each signal is a fact the console can
 * point at, and the weights are deliberately conservative.
 */
export function evaluateIdentityRisk(input: IdentityRiskInput): IdentityRisk {
  const now = input.now ?? new Date();
  const signals: IdentitySignal[] = [];

  if (input.status === 'DEPROVISIONED') {
    return { score: 0, level: 'LOW', signals };
  }

  if (input.kind === 'MACHINE' && input.ownerUserId === null) {
    signals.push({
      code: 'UNOWNED_MACHINE',
      severity: 'HIGH',
      detail: 'No accountable owner is assigned to this non-human identity.',
      score: 40,
    });
  }

  if (input.kind === 'HUMAN') {
    if (input.linkedUserId === null) {
      signals.push({
        code: 'UNLINKED_HUMAN',
        severity: 'MEDIUM',
        detail: 'The person is inventoried but has no console account in this organization.',
        score: 15,
      });
    } else if (input.linkedMembershipStatus !== 'ACTIVE') {
      signals.push({
        code: 'ORPHANED_ACCOUNT',
        severity: 'HIGH',
        detail: 'The linked console account no longer has active access to this organization.',
        score: 30,
      });
    }
  }

  if (input.status === 'PENDING_APPROVAL') {
    signals.push({
      code: 'PENDING_APPROVAL',
      severity: 'LOW',
      detail: 'The identity is waiting for owner approval and cannot authenticate.',
      score: 10,
    });
  }

  const lastActivityAt = input.lastActivityAt;
  if (lastActivityAt === null) {
    if (daysBetween(input.createdAt, now) >= DORMANT_AFTER_DAYS) {
      signals.push({
        code: 'DORMANT',
        severity: 'MEDIUM',
        detail: 'No sign-in or credential use has been observed since the identity was recorded.',
        score: 20,
      });
    }
  } else if (daysBetween(lastActivityAt, now) >= DORMANT_AFTER_DAYS) {
    signals.push({
      code: 'DORMANT',
      severity: 'MEDIUM',
      detail: `No sign-in or credential use in ${Math.floor(daysBetween(lastActivityAt, now))} days.`,
      score: 20,
    });
  }

  if (input.failedAuthLast24h >= FAILED_AUTH_BURST) {
    signals.push({
      code: 'FAILED_AUTH_BURST',
      severity: 'MEDIUM',
      detail: `${input.failedAuthLast24h} failed authentication attempts in the last 24 hours.`,
      score: 15,
    });
  }

  if (input.activeSessions > EXCESSIVE_SESSIONS) {
    signals.push({
      code: 'EXCESSIVE_SESSIONS',
      severity: 'LOW',
      detail: `${input.activeSessions} concurrent console sessions are active.`,
      score: 10,
    });
  }

  if (input.kind === 'MACHINE') {
    const active = input.credentials;
    if (input.status === 'ACTIVE' && active.length === 0) {
      signals.push({
        code: 'NO_ACTIVE_CREDENTIAL',
        severity: 'MEDIUM',
        detail: 'The identity is marked active but has no usable credential.',
        score: 15,
      });
    }

    const expired = active.filter((credential) => credential.expiresAt.getTime() <= now.getTime());
    if (expired.length > 0) {
      signals.push({
        code: 'CREDENTIAL_EXPIRED',
        severity: 'HIGH',
        detail: `${expired.length} unrevoked credential(s) have expired.`,
        score: 20,
      });
    } else if (
      active.some(
        (credential) =>
          daysBetween(now, credential.expiresAt) <= CREDENTIAL_WARNING_DAYS &&
          credential.expiresAt.getTime() > now.getTime(),
      )
    ) {
      signals.push({
        code: 'CREDENTIAL_EXPIRING',
        severity: 'MEDIUM',
        detail: `A usable credential expires within ${CREDENTIAL_WARNING_DAYS} days.`,
        score: 10,
      });
    }
  }

  const score = Math.min(
    100,
    signals.reduce((total, signal) => total + signal.score, 0),
  );

  return { score, level: riskLevelForScore(score), signals };
}

export function riskLevelForScore(score: number): IdentityRiskLevel {
  if (score >= 80) {
    return 'CRITICAL';
  }
  if (score >= 50) {
    return 'HIGH';
  }
  if (score >= 20) {
    return 'MEDIUM';
  }
  return 'LOW';
}

// ---------------------------------------------------------------------------
// Access reviews
// ---------------------------------------------------------------------------

export const ACCESS_REVIEW_STATUS_TRANSITIONS: Readonly<
  Record<AccessReviewStatus, readonly AccessReviewStatus[]>
> = {
  ACTIVE: ['COMPLETED', 'CANCELLED'],
  COMPLETED: [],
  CANCELLED: [],
};

export function canTransitionAccessReview(
  from: AccessReviewStatus,
  to: AccessReviewStatus,
): boolean {
  return ACCESS_REVIEW_STATUS_TRANSITIONS[from].includes(to);
}
