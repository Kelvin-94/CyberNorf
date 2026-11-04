import type { ControlStatus } from '@/generated/prisma/client';

/**
 * Compliance posture rules. Kept free of database access so the scoring model
 * and the attestation invariants can be tested directly.
 *
 * The score is weighted, never a simple count of green rows: a CRITICAL-weight
 * control left unattested hurts more than a low-weight one, and a control that
 * does not apply to the tenant is removed from the denominator instead of
 * being counted as a pass.
 */

export const CONTROL_STATUSES: readonly ControlStatus[] = [
  'NOT_STARTED',
  'IN_PROGRESS',
  'PARTIAL',
  'IMPLEMENTED',
  'NOT_APPLICABLE',
];

/** Credit earned toward the score. NOT_APPLICABLE is handled separately. */
const STATUS_CREDIT: Readonly<Record<ControlStatus, number>> = {
  NOT_STARTED: 0,
  IN_PROGRESS: 0.25,
  PARTIAL: 0.5,
  IMPLEMENTED: 1,
  NOT_APPLICABLE: 0,
};

export type PostureBand = 'READY' | 'PROGRESSING' | 'AT_RISK' | 'NOT_ASSESSED';

export interface ControlPostureInput {
  status: ControlStatus;
  weight: number;
}

export type ControlCounts = Record<ControlStatus, number>;

export interface Posture {
  /** 0-100, one decimal. Weighted credit divided by applicable weight. */
  score: number;
  band: PostureBand;
  /** Weight of every control that counts toward the score. */
  applicableWeight: number;
  /** Weighted credit earned, before conversion to a percentage. */
  creditedWeight: number;
  total: number;
  counts: ControlCounts;
}

export function emptyCounts(): ControlCounts {
  return {
    NOT_STARTED: 0,
    IN_PROGRESS: 0,
    PARTIAL: 0,
    IMPLEMENTED: 0,
    NOT_APPLICABLE: 0,
  };
}

export function postureBand(score: number, applicableWeight: number): PostureBand {
  if (applicableWeight <= 0) {
    return 'NOT_ASSESSED';
  }
  if (score >= 90) {
    return 'READY';
  }
  if (score >= 60) {
    return 'PROGRESSING';
  }
  return 'AT_RISK';
}

export function computePosture(controls: readonly ControlPostureInput[]): Posture {
  const counts = emptyCounts();
  let applicableWeight = 0;
  let creditedWeight = 0;

  for (const control of controls) {
    // A negative or zero weight would let a control erase another's credit, so
    // the effective weight is floored at 1 the same way the schema does.
    const weight = Number.isFinite(control.weight) && control.weight > 0 ? control.weight : 1;
    counts[control.status] += 1;

    if (control.status === 'NOT_APPLICABLE') {
      continue;
    }

    applicableWeight += weight;
    creditedWeight += weight * STATUS_CREDIT[control.status];
  }

  const score =
    applicableWeight === 0 ? 0 : Math.round((creditedWeight / applicableWeight) * 1000) / 10;

  return {
    score,
    band: postureBand(score, applicableWeight),
    applicableWeight,
    creditedWeight,
    total: controls.length,
    counts,
  };
}

/** Statuses that represent a reviewed attestation rather than a plan. */
export function isAttested(status: ControlStatus): boolean {
  return status === 'IMPLEMENTED' || status === 'PARTIAL';
}

/**
 * A control may only be marked fully implemented when at least one piece of
 * evidence backs it. Without this rule the posture score is self-asserted.
 */
export function requiresEvidence(status: ControlStatus): boolean {
  return status === 'IMPLEMENTED';
}

export interface AttestationCheck {
  status: ControlStatus;
  evidenceCount: number;
}

/** Returns a human-readable reason when the attestation must be refused. */
export function attestationIssue({ status, evidenceCount }: AttestationCheck): string | null {
  if (requiresEvidence(status) && evidenceCount === 0) {
    return 'Attach at least one piece of evidence before marking a control as implemented.';
  }
  return null;
}
