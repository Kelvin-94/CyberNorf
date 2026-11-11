import type { AssetCriticality, FindingSeverity, FindingStatus } from '@/generated/prisma/client';

/**
 * Remediation windows, in days, measured from the moment the exposure was first
 * observed. These are deliberately conservative defaults for a small team and
 * are documented in docs/FINDINGS.md; they are policy, not a security control,
 * so changing them does not weaken authorization or data protection.
 */
export const REMEDIATION_SLA_DAYS: Record<FindingSeverity, number> = {
  CRITICAL: 7,
  HIGH: 30,
  MEDIUM: 90,
  LOW: 180,
  INFO: 365,
};

/** A finding in one of these states no longer consumes remediation time. */
export const CLOSED_FINDING_STATUSES: FindingStatus[] = [
  'RESOLVED',
  'ACCEPTED_RISK',
  'FALSE_POSITIVE',
];

const SEVERITY_BASE: Record<FindingSeverity, number> = {
  CRITICAL: 90,
  HIGH: 70,
  MEDIUM: 45,
  LOW: 20,
  INFO: 5,
};

/**
 * Exposure multipliers. A critical vulnerability on a critical asset should
 * sort above the same vulnerability on a low-value host, but criticality must
 * never lift an INFO finding into the critical band.
 */
const CRITICALITY_FACTOR: Record<AssetCriticality, number> = {
  CRITICAL: 1.25,
  HIGH: 1.15,
  MEDIUM: 1,
  LOW: 0.85,
};

/** Weight of a supplied CVSS vector relative to the declared severity. */
const CVSS_WEIGHT = 0.4;

const DAY_MS = 86_400_000;

export interface RiskInput {
  severity: FindingSeverity;
  cvssScore?: number | null;
  assetCriticality?: AssetCriticality | null;
}

/**
 * Deterministic 0–100 risk score used for ordering and dashboards.
 *
 * It is intentionally simple and explainable: severity sets the base, a real
 * CVSS vector pulls the base toward its own scale, and asset criticality
 * applies a bounded multiplier. The score is a prioritisation aid, not a
 * compliance judgement.
 */
export function computeRiskScore(input: RiskInput): number {
  const base = SEVERITY_BASE[input.severity];
  const cvss = input.cvssScore;

  const blended =
    typeof cvss === 'number' && Number.isFinite(cvss)
      ? base * (1 - CVSS_WEIGHT) + Math.min(Math.max(cvss, 0), 10) * 10 * CVSS_WEIGHT
      : base;

  const factor = input.assetCriticality ? CRITICALITY_FACTOR[input.assetCriticality] : 1;
  return clampScore(Math.round(blended * factor));
}

function clampScore(value: number): number {
  if (!Number.isFinite(value)) {
    return 0;
  }
  return Math.min(100, Math.max(0, value));
}

/**
 * Due date for a finding. The clock starts when the exposure was first
 * observed, so importing an old finding does not grant a fresh remediation
 * window.
 */
export function remediationDueAt(input: { severity: FindingSeverity; firstSeenAt: Date }): Date {
  const days = REMEDIATION_SLA_DAYS[input.severity];
  return new Date(input.firstSeenAt.getTime() + days * DAY_MS);
}

export type RemediationState = 'OVERDUE' | 'DUE_SOON' | 'ON_TRACK' | 'CLOSED' | 'UNSCHEDULED';

/** A finding is "due soon" inside this window. */
export const DUE_SOON_DAYS = 7;

export function remediationState(input: {
  dueAt: Date | null;
  status: FindingStatus;
  now?: Date;
}): RemediationState {
  if (CLOSED_FINDING_STATUSES.includes(input.status)) {
    return 'CLOSED';
  }
  if (!input.dueAt) {
    return 'UNSCHEDULED';
  }
  const now = input.now ?? new Date();
  if (input.dueAt.getTime() < now.getTime()) {
    return 'OVERDUE';
  }
  if (input.dueAt.getTime() - now.getTime() <= DUE_SOON_DAYS * DAY_MS) {
    return 'DUE_SOON';
  }
  return 'ON_TRACK';
}

export interface RemediationMetrics {
  overdue: number;
  dueSoon: number;
  open: number;
  /** Percentage of findings resolved within their SLA, 0–100, or null with no data. */
  slaCompliance: number | null;
  /** Mean days from creation to resolution, or null with no data. */
  meanTimeToResolveDays: number | null;
}

export interface ResolutionMetrics {
  /** Percentage of resolutions that met their deadline, 0–100, or null with no data. */
  slaCompliance: number | null;
  /** Mean days from creation to resolution, or null with no data. */
  meanTimeToResolveDays: number | null;
  /** Number of resolved findings the figures are based on. */
  sampleSize: number;
}

interface ResolvableRow {
  status: FindingStatus;
  dueAt: Date | null;
  resolvedAt: Date | null;
  createdAt: Date;
}

/**
 * Resolution-only view of the remediation figures. The dashboard counts open
 * work with SQL aggregates (exact regardless of table size) and feeds only the
 * resolved window here, so the maths must stand on its own.
 */
export function summarizeResolutions(rows: ResolvableRow[]): ResolutionMetrics {
  let resolvedWithinSla = 0;
  let resolvedWithDueDate = 0;
  let resolutionDaysTotal = 0;
  let resolvedWithTimes = 0;

  for (const row of rows) {
    if (row.status !== 'RESOLVED' || !row.resolvedAt) {
      continue;
    }
    resolutionDaysTotal += (row.resolvedAt.getTime() - row.createdAt.getTime()) / DAY_MS;
    resolvedWithTimes += 1;

    if (row.dueAt) {
      resolvedWithDueDate += 1;
      if (row.resolvedAt.getTime() <= row.dueAt.getTime()) {
        resolvedWithinSla += 1;
      }
    }
  }

  return {
    slaCompliance:
      resolvedWithDueDate === 0
        ? null
        : Math.round((resolvedWithinSla / resolvedWithDueDate) * 1000) / 10,
    meanTimeToResolveDays:
      resolvedWithTimes === 0
        ? null
        : Math.round((resolutionDaysTotal / resolvedWithTimes) * 10) / 10,
    sampleSize: resolvedWithTimes,
  };
}

/**
 * Aggregates remediation health from already-fetched rows. Keeping this pure
 * makes the dashboard maths testable without a database and keeps the query
 * layer free of business rules.
 */
export function summarizeRemediation(
  rows: ResolvableRow[],
  now: Date = new Date(),
): RemediationMetrics {
  let overdue = 0;
  let dueSoon = 0;
  let open = 0;

  for (const row of rows) {
    if (CLOSED_FINDING_STATUSES.includes(row.status)) {
      continue;
    }

    open += 1;
    const state = remediationState({ dueAt: row.dueAt, status: row.status, now });
    if (state === 'OVERDUE') {
      overdue += 1;
    } else if (state === 'DUE_SOON') {
      dueSoon += 1;
    }
  }

  const resolutions = summarizeResolutions(rows);
  return {
    overdue,
    dueSoon,
    open,
    slaCompliance: resolutions.slaCompliance,
    meanTimeToResolveDays: resolutions.meanTimeToResolveDays,
  };
}
