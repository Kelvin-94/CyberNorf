import { createHash, createPublicKey, verify as verifySignature } from 'node:crypto';
import { canonicalize } from '../audit/canonical';

/**
 * Zero Trust decision, trust, admission, detection, enforcement and update
 * semantics.
 *
 * Nothing here touches the database or the clock it was not given: every
 * function is a pure transformation of its input, so a verdict recorded six
 * months ago can be recomputed from the facts that were stored with it and a
 * test can pin `at` instead of waiting for a particular hour. Services own
 * persistence, authorization and audit; this module owns the rules.
 *
 * Two invariants are load-bearing and are asserted by the unit tests:
 *
 * 1. The decision point fails closed. A request that matches no rule is denied,
 *    and an enabled rule whose conditions cannot be interpreted denies before
 *    any later rule can allow it.
 * 2. Risk is computed from the fact bundle before rule matching, so a rule that
 *    keys on `riskAtLeast` sees the same number the decision records.
 */

// ---------------------------------------------------------------------------
// Vocabulary
//
// These mirror the Prisma enums in prisma/schema.prisma. They are redeclared as
// literal unions so this module stays free of generated code and can be tested
// without a database; the enum values are structurally assignable to them.
// ---------------------------------------------------------------------------

export const DEVICE_STATUSES = ['PENDING', 'ACTIVE', 'SUSPENDED', 'RETIRED'] as const;
export type DeviceStatusValue = (typeof DEVICE_STATUSES)[number];

/** Ordered worst to best. A device that failed a check ranks below an unknown one. */
export const TRUST_STATES = ['UNTRUSTED', 'UNKNOWN', 'PARTIAL', 'TRUSTED'] as const;
export type TrustState = (typeof TRUST_STATES)[number];

export const POLICY_EFFECTS = ['ALLOW', 'DENY', 'STEP_UP', 'QUARANTINE'] as const;
export type PolicyEffectValue = (typeof POLICY_EFFECTS)[number];

export const SUBJECT_KINDS = ['USER', 'DEVICE', 'IDENTITY'] as const;
export type SubjectKindValue = (typeof SUBJECT_KINDS)[number];

export const SENSITIVITIES = ['PUBLIC', 'INTERNAL', 'CONFIDENTIAL', 'RESTRICTED'] as const;
export type SensitivityValue = (typeof SENSITIVITIES)[number];

export const ZONES = ['CORPORATE', 'GUEST', 'OT', 'QUARANTINE', 'EXTERNAL'] as const;
export type ZoneValue = (typeof ZONES)[number];

export const CONNECTOR_KINDS = ['RADIUS', 'GATEWAY', 'FIREWALL', 'EDR', 'SWITCH'] as const;
export type ConnectorKindValue = (typeof CONNECTOR_KINDS)[number];

export const CONNECTOR_STATUSES = ['ONLINE', 'DEGRADED', 'OFFLINE'] as const;
export type ConnectorStatusValue = (typeof CONNECTOR_STATUSES)[number];

export const CONNECTOR_FAIL_MODES = ['CLOSED', 'OPEN'] as const;
export type ConnectorFailModeValue = (typeof CONNECTOR_FAIL_MODES)[number];

export const DETECTION_SEVERITIES = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'] as const;
export type DetectionSeverityValue = (typeof DETECTION_SEVERITIES)[number];

export const DETECTION_STATUSES = ['OPEN', 'ACKNOWLEDGED', 'CLOSED'] as const;
export type DetectionStatusValue = (typeof DETECTION_STATUSES)[number];

export const ENFORCEMENT_KINDS = [
  'SESSION_REVOKE',
  'ENDPOINT_ISOLATE',
  'NETWORK_QUARANTINE',
  'FIREWALL_BLOCK',
  'CERT_REVOKE',
] as const;
export type EnforcementKindValue = (typeof ENFORCEMENT_KINDS)[number];

export const ENFORCEMENT_STATES = [
  'REQUESTED',
  'APPROVED',
  'REJECTED',
  'DISPATCHED',
  'ACKNOWLEDGED',
  'VERIFIED',
  'FAILED',
  'EXPIRED',
] as const;
export type EnforcementStateValue = (typeof ENFORCEMENT_STATES)[number];

export const RELEASE_STATUSES = ['DRAFT', 'CANARY', 'ROLLING', 'RELEASED', 'ROLLED_BACK'] as const;
export type ReleaseStatusValue = (typeof RELEASE_STATUSES)[number];

export const DEVICE_UPDATE_STATES = [
  'OFFERED',
  'DOWNLOADING',
  'INSTALLING',
  'INSTALLED',
  'FAILED',
  'ROLLED_BACK',
] as const;
export type DeviceUpdateStateValue = (typeof DEVICE_UPDATE_STATES)[number];

export const APPROVAL_STATES = ['NONE', 'PENDING', 'APPROVED', 'REJECTED'] as const;
export type ApprovalStateValue = (typeof APPROVAL_STATES)[number];

export const POSTURE_CHECK_STATUSES = ['PASS', 'FAIL', 'UNKNOWN'] as const;
export type PostureCheckStatus = (typeof POSTURE_CHECK_STATUSES)[number];

const TRUST_RANK: Readonly<Record<TrustState, number>> = {
  UNTRUSTED: 0,
  UNKNOWN: 1,
  PARTIAL: 2,
  TRUSTED: 3,
};

const SENSITIVITY_RANK: Readonly<Record<SensitivityValue, number>> = {
  PUBLIC: 0,
  INTERNAL: 1,
  CONFIDENTIAL: 2,
  RESTRICTED: 3,
};

const SEVERITY_RANK: Readonly<Record<DetectionSeverityValue, number>> = {
  LOW: 0,
  MEDIUM: 1,
  HIGH: 2,
  CRITICAL: 3,
};

/** Business hours are evaluated in UTC. No tenant timezone exists yet, so the
 * window is explicit rather than an implicit guess at local time. */
export const BUSINESS_HOURS_START_UTC = 6;
export const BUSINESS_HOURS_END_UTC = 20;

export type ZeroTrustErrorCode =
  | 'invalid_conditions'
  | 'invalid_transition'
  | 'self_approval'
  | 'invalid_version'
  | 'rollback_blocked'
  | 'version_not_newer'
  | 'invalid_manifest'
  | 'publisher_key_unknown'
  | 'invalid_public_key'
  | 'signature_invalid';

export class ZeroTrustError extends Error {
  constructor(
    readonly code: ZeroTrustErrorCode,
    message: string,
  ) {
    super(message);
    this.name = 'ZeroTrustError';
  }
}

// ---------------------------------------------------------------------------
// Policy facts
// ---------------------------------------------------------------------------

export type PolicyAttributeValue = string | number | boolean;

export interface PolicySubject {
  kind: SubjectKindValue;
  id: string;
  label: string;
  role: string | null;
  attributes: Readonly<Record<string, PolicyAttributeValue>>;
}

export interface PolicyDeviceFacts {
  id: string;
  managed: boolean;
  attestationVerified: boolean;
  trustState: TrustState;
  postureFresh: boolean;
  passedChecks: readonly string[];
  failingChecks: readonly string[];
  unknownChecks: readonly string[];
}

export interface PolicyNetworkFacts {
  zone: ZoneValue;
  connectorStatus: ConnectorStatusValue | null;
  connectorFailMode: ConnectorFailModeValue | null;
}

export interface PolicyRequestFacts {
  /** Evaluation instant. Passed in so recorded decisions are reproducible. */
  at: Date;
  mfaSatisfied: boolean;
  approvalState: ApprovalStateValue;
  correlationId: string;
  sourceIp: string | null;
}

export interface PolicyResourceFacts {
  type: string;
  id: string | null;
  sensitivity: SensitivityValue;
}

export interface PolicyFactBundle {
  subject: PolicySubject;
  /** Absent for a request that did not come from an enrolled device. */
  device: PolicyDeviceFacts | null;
  network: PolicyNetworkFacts;
  resource: PolicyResourceFacts;
  action: string;
  request: PolicyRequestFacts;
}

// ---------------------------------------------------------------------------
// Risk
// ---------------------------------------------------------------------------

export interface RiskFactor {
  code: string;
  weight: number;
  detail: string;
}

export interface RiskAssessment {
  score: number;
  factors: readonly RiskFactor[];
}

/**
 * Scores the request from its facts only. Each factor is recorded so the
 * verdict can say *why* a request was risky instead of only how risky it was.
 * The score saturates at 100.
 */
export function computeRisk(facts: PolicyFactBundle): RiskAssessment {
  const factors: RiskFactor[] = [];
  const add = (code: string, weight: number, detail: string) => {
    factors.push({ code, weight, detail });
  };

  const device = facts.device;
  if (device === null) {
    add('device_missing', 10, 'Request did not come from an enrolled device');
  } else {
    if (device.trustState === 'UNTRUSTED') {
      add('device_untrusted', 30, 'Device trust state is UNTRUSTED');
    } else if (device.trustState === 'UNKNOWN') {
      add('device_unknown_trust', 20, 'Device trust state is UNKNOWN');
    } else if (device.trustState === 'PARTIAL') {
      add('device_partial_trust', 10, 'Device trust state is PARTIAL');
    }
    if (!device.postureFresh) {
      add('posture_stale', 15, 'Latest posture report is missing, unverified or expired');
    }
    if (!device.managed) {
      add('device_unmanaged', 10, 'Device is not under management');
    }
  }

  if (!facts.request.mfaSatisfied) {
    add('mfa_not_satisfied', 15, 'Request was not backed by a second factor');
  }

  if (facts.network.zone === 'EXTERNAL') {
    add('zone_external', 15, 'Request originates outside the estate');
  } else if (facts.network.zone === 'GUEST') {
    add('zone_guest', 10, 'Request originates on the guest network');
  } else if (facts.network.zone === 'QUARANTINE') {
    add('zone_quarantine', 25, 'Request originates from a quarantined segment');
  }

  if (facts.resource.sensitivity === 'RESTRICTED') {
    add('sensitivity_restricted', 20, 'Resource is classified RESTRICTED');
  } else if (facts.resource.sensitivity === 'CONFIDENTIAL') {
    add('sensitivity_confidential', 10, 'Resource is classified CONFIDENTIAL');
  }

  const hour = facts.request.at.getUTCHours();
  if (hour < BUSINESS_HOURS_START_UTC || hour >= BUSINESS_HOURS_END_UTC) {
    add('outside_business_hours', 5, `Request at ${String(hour).padStart(2, '0')}:xx UTC`);
  }

  const total = factors.reduce((sum, factor) => sum + factor.weight, 0);
  return { score: Math.min(100, total), factors };
}

// ---------------------------------------------------------------------------
// Policy conditions and evaluation
// ---------------------------------------------------------------------------

export interface PolicyConditionSet {
  roleIn?: readonly string[];
  attributeEquals?: Readonly<Record<string, PolicyAttributeValue>>;
  attributeIn?: Readonly<Record<string, readonly PolicyAttributeValue[]>>;
  deviceTrustAtLeast?: TrustState;
  deviceManaged?: boolean;
  postureFresh?: boolean;
  postureCheckPassed?: readonly string[];
  postureCheckFailed?: readonly string[];
  mfaSatisfied?: boolean;
  zoneIn?: readonly ZoneValue[];
  connectorStatusIn?: readonly ConnectorStatusValue[];
  sensitivityAtLeast?: SensitivityValue;
  riskAtLeast?: number;
  resourceTypeIn?: readonly string[];
  actionIn?: readonly string[];
  approvalStateIn?: readonly ApprovalStateValue[];
  outsideBusinessHours?: boolean;
}

export interface PolicyRuleDefinition {
  id: string;
  name: string;
  priority: number;
  effect: PolicyEffectValue;
  enabled: boolean;
  /** Untrusted on purpose: rows are validated on write but the engine must not
   * assume that any stored value still satisfies today's schema. */
  conditions: unknown;
}

export interface PolicyEvaluationStep {
  ruleId: string;
  ruleName: string;
  priority: number;
  effect: PolicyEffectValue;
  matched: boolean;
  failedConditions: readonly string[];
}

export interface PolicyExplanation {
  summary: string;
  defaulted: boolean;
  steps: readonly PolicyEvaluationStep[];
  riskFactors: readonly RiskFactor[];
  /** Rules skipped because they demanded a step-up the request already satisfied. */
  stepUpAlreadySatisfied: readonly string[];
  invalidRule?: { ruleId: string; ruleName: string; reason: string };
}

export interface PolicyOutcome {
  verdict: PolicyEffectValue;
  reason: 'matched_rule' | 'default_deny' | 'invalid_rule';
  matchedRuleId: string | null;
  matchedRuleName: string | null;
  riskScore: number;
  riskFactors: readonly RiskFactor[];
  obligations: readonly string[];
  explanation: PolicyExplanation;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isPrimitive(value: unknown): value is PolicyAttributeValue {
  return typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean';
}

function isStringArray(value: unknown): value is readonly string[] {
  return Array.isArray(value) && value.every((item) => typeof item === 'string');
}

function isPrimitiveArray(value: unknown): value is readonly PolicyAttributeValue[] {
  return Array.isArray(value) && value.every(isPrimitive);
}

function oneOf<T extends string>(allowed: readonly T[], value: unknown): value is T {
  return typeof value === 'string' && (allowed as readonly string[]).includes(value);
}

/** Condition keys the engine understands. Anything else makes the rule invalid. */
export const POLICY_CONDITION_KEYS = [
  'roleIn',
  'attributeEquals',
  'attributeIn',
  'deviceTrustAtLeast',
  'deviceManaged',
  'postureFresh',
  'postureCheckPassed',
  'postureCheckFailed',
  'mfaSatisfied',
  'zoneIn',
  'connectorStatusIn',
  'sensitivityAtLeast',
  'riskAtLeast',
  'resourceTypeIn',
  'actionIn',
  'approvalStateIn',
  'outsideBusinessHours',
] as const;

export type PolicyConditionKey = (typeof POLICY_CONDITION_KEYS)[number];

/**
 * Interprets a stored condition set. Returns the names of conditions that did
 * not pass, or an `invalid` reason when a value cannot be understood. An empty
 * object matches everything and is allowed, though the API warns about it.
 */
export function evaluateConditions(
  conditions: unknown,
  facts: PolicyFactBundle,
  riskScore: number,
): { matched: boolean; failed: readonly string[]; invalid?: string } {
  if (!isRecord(conditions)) {
    return { matched: false, failed: [], invalid: 'conditions must be an object' };
  }

  const failed: string[] = [];
  for (const key of Object.keys(conditions)) {
    if (!(POLICY_CONDITION_KEYS as readonly string[]).includes(key)) {
      return { matched: false, failed, invalid: `unknown condition "${key}"` };
    }
  }

  const check = (name: string, passed: boolean) => {
    if (!passed) failed.push(name);
  };

  const value = (key: PolicyConditionKey): unknown => conditions[key];
  const device = facts.device;

  if (value('roleIn') !== undefined) {
    const allowed = value('roleIn');
    if (!isStringArray(allowed))
      return { matched: false, failed, invalid: 'roleIn must be strings' };
    check('roleIn', facts.subject.role !== null && allowed.includes(facts.subject.role));
  }

  if (value('attributeEquals') !== undefined) {
    const expected = value('attributeEquals');
    if (!isRecord(expected) || !Object.values(expected).every(isPrimitive)) {
      return { matched: false, failed, invalid: 'attributeEquals must map to primitives' };
    }
    for (const [attribute, expectedValue] of Object.entries(expected)) {
      check(`attributeEquals.${attribute}`, facts.subject.attributes[attribute] === expectedValue);
    }
  }

  if (value('attributeIn') !== undefined) {
    const expected = value('attributeIn');
    if (!isRecord(expected) || !Object.values(expected).every(isPrimitiveArray)) {
      return { matched: false, failed, invalid: 'attributeIn must map to primitive arrays' };
    }
    for (const [attribute, allowed] of Object.entries(expected)) {
      const actual = facts.subject.attributes[attribute];
      const allowedValues = allowed as readonly PolicyAttributeValue[];
      check(`attributeIn.${attribute}`, actual !== undefined && allowedValues.includes(actual));
    }
  }

  if (value('deviceTrustAtLeast') !== undefined) {
    const minimum = value('deviceTrustAtLeast');
    if (!oneOf(TRUST_STATES, minimum)) {
      return { matched: false, failed, invalid: 'deviceTrustAtLeast is not a trust state' };
    }
    check(
      'deviceTrustAtLeast',
      device !== null && TRUST_RANK[device.trustState] >= TRUST_RANK[minimum],
    );
  }

  if (value('deviceManaged') !== undefined) {
    const expected = value('deviceManaged');
    if (typeof expected !== 'boolean') {
      return { matched: false, failed, invalid: 'deviceManaged must be a boolean' };
    }
    check('deviceManaged', device !== null && device.managed === expected);
  }

  if (value('postureFresh') !== undefined) {
    const expected = value('postureFresh');
    if (typeof expected !== 'boolean') {
      return { matched: false, failed, invalid: 'postureFresh must be a boolean' };
    }
    check('postureFresh', device !== null && device.postureFresh === expected);
  }

  if (value('postureCheckPassed') !== undefined) {
    const required = value('postureCheckPassed');
    if (!isStringArray(required)) {
      return { matched: false, failed, invalid: 'postureCheckPassed must be strings' };
    }
    const passed = new Set(device?.passedChecks ?? []);
    check(
      'postureCheckPassed',
      required.every((id) => passed.has(id)),
    );
  }

  if (value('postureCheckFailed') !== undefined) {
    const forbidden = value('postureCheckFailed');
    if (!isStringArray(forbidden)) {
      return { matched: false, failed, invalid: 'postureCheckFailed must be strings' };
    }
    const failing = new Set(device?.failingChecks ?? []);
    check(
      'postureCheckFailed',
      forbidden.some((id) => failing.has(id)),
    );
  }

  if (value('mfaSatisfied') !== undefined) {
    const expected = value('mfaSatisfied');
    if (typeof expected !== 'boolean') {
      return { matched: false, failed, invalid: 'mfaSatisfied must be a boolean' };
    }
    check('mfaSatisfied', facts.request.mfaSatisfied === expected);
  }

  if (value('zoneIn') !== undefined) {
    const allowed = value('zoneIn');
    if (!Array.isArray(allowed) || !allowed.every((zone) => oneOf(ZONES, zone))) {
      return { matched: false, failed, invalid: 'zoneIn contains an unknown zone' };
    }
    check('zoneIn', allowed.includes(facts.network.zone));
  }

  if (value('connectorStatusIn') !== undefined) {
    const allowed = value('connectorStatusIn');
    if (!Array.isArray(allowed) || !allowed.every((status) => oneOf(CONNECTOR_STATUSES, status))) {
      return { matched: false, failed, invalid: 'connectorStatusIn contains an unknown status' };
    }
    check(
      'connectorStatusIn',
      facts.network.connectorStatus !== null && allowed.includes(facts.network.connectorStatus),
    );
  }

  if (value('sensitivityAtLeast') !== undefined) {
    const minimum = value('sensitivityAtLeast');
    if (!oneOf(SENSITIVITIES, minimum)) {
      return { matched: false, failed, invalid: 'sensitivityAtLeast is not a sensitivity' };
    }
    check(
      'sensitivityAtLeast',
      SENSITIVITY_RANK[facts.resource.sensitivity] >= SENSITIVITY_RANK[minimum],
    );
  }

  if (value('riskAtLeast') !== undefined) {
    const minimum = value('riskAtLeast');
    if (typeof minimum !== 'number' || !Number.isFinite(minimum)) {
      return { matched: false, failed, invalid: 'riskAtLeast must be a number' };
    }
    check('riskAtLeast', riskScore >= minimum);
  }

  if (value('resourceTypeIn') !== undefined) {
    const allowed = value('resourceTypeIn');
    if (!isStringArray(allowed)) {
      return { matched: false, failed, invalid: 'resourceTypeIn must be strings' };
    }
    check('resourceTypeIn', allowed.includes(facts.resource.type));
  }

  if (value('actionIn') !== undefined) {
    const allowed = value('actionIn');
    if (!isStringArray(allowed)) {
      return { matched: false, failed, invalid: 'actionIn must be strings' };
    }
    check('actionIn', allowed.includes(facts.action));
  }

  if (value('approvalStateIn') !== undefined) {
    const allowed = value('approvalStateIn');
    if (!Array.isArray(allowed) || !allowed.every((state) => oneOf(APPROVAL_STATES, state))) {
      return { matched: false, failed, invalid: 'approvalStateIn contains an unknown state' };
    }
    check('approvalStateIn', allowed.includes(facts.request.approvalState));
  }

  if (value('outsideBusinessHours') !== undefined) {
    const expected = value('outsideBusinessHours');
    if (typeof expected !== 'boolean') {
      return { matched: false, failed, invalid: 'outsideBusinessHours must be a boolean' };
    }
    const hour = facts.request.at.getUTCHours();
    const outside = hour < BUSINESS_HOURS_START_UTC || hour >= BUSINESS_HOURS_END_UTC;
    check('outsideBusinessHours', outside === expected);
  }

  return { matched: failed.length === 0, failed };
}

function compareStrings(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

function obligationsFor(effect: PolicyEffectValue, riskScore: number): readonly string[] {
  switch (effect) {
    case 'ALLOW':
      return riskScore >= 70 ? ['admit', 'monitor'] : ['admit'];
    case 'DENY':
      return ['block'];
    case 'STEP_UP':
      return ['require_mfa'];
    case 'QUARANTINE':
      return ['quarantine_device'];
  }
}

/**
 * Evaluates one request. Rules are considered in ascending priority with a
 * deterministic name/id tie-break; the first rule whose conditions all pass
 * decides the verdict.
 *
 * - No matching rule denies (`default_deny`).
 * - An enabled rule whose conditions cannot be interpreted denies immediately
 *   (`invalid_rule`), because skipping it could let a later ALLOW through a
 *   deny the author intended.
 * - A STEP_UP rule whose requirement the request already satisfies is skipped
 *   rather than returned, so a caller cannot loop on a satisfied step-up.
 */
export function evaluatePolicy(input: {
  facts: PolicyFactBundle;
  rules: readonly PolicyRuleDefinition[];
}): PolicyOutcome {
  const risk = computeRisk(input.facts);
  const considered = input.rules
    .filter((rule) => rule.enabled)
    .slice()
    .sort(
      (a, b) =>
        a.priority - b.priority || compareStrings(a.name, b.name) || compareStrings(a.id, b.id),
    );

  const steps: PolicyEvaluationStep[] = [];
  const stepUpAlreadySatisfied: string[] = [];

  for (const rule of considered) {
    const result = evaluateConditions(rule.conditions, input.facts, risk.score);
    if (result.invalid !== undefined) {
      steps.push({
        ruleId: rule.id,
        ruleName: rule.name,
        priority: rule.priority,
        effect: rule.effect,
        matched: false,
        failedConditions: result.failed,
      });
      const explanation: PolicyExplanation = {
        summary: `Denied: enabled rule "${rule.name}" has invalid conditions (${result.invalid}).`,
        defaulted: false,
        steps,
        riskFactors: risk.factors,
        stepUpAlreadySatisfied,
        invalidRule: { ruleId: rule.id, ruleName: rule.name, reason: result.invalid },
      };
      return {
        verdict: 'DENY',
        reason: 'invalid_rule',
        matchedRuleId: null,
        matchedRuleName: null,
        riskScore: risk.score,
        riskFactors: risk.factors,
        obligations: ['block', 'fix_policy_rule'],
        explanation,
      };
    }

    if (!result.matched) {
      steps.push({
        ruleId: rule.id,
        ruleName: rule.name,
        priority: rule.priority,
        effect: rule.effect,
        matched: false,
        failedConditions: result.failed,
      });
      continue;
    }

    if (rule.effect === 'STEP_UP' && input.facts.request.mfaSatisfied) {
      stepUpAlreadySatisfied.push(rule.name);
      steps.push({
        ruleId: rule.id,
        ruleName: rule.name,
        priority: rule.priority,
        effect: rule.effect,
        matched: false,
        failedConditions: [],
      });
      continue;
    }

    steps.push({
      ruleId: rule.id,
      ruleName: rule.name,
      priority: rule.priority,
      effect: rule.effect,
      matched: true,
      failedConditions: [],
    });

    return {
      verdict: rule.effect,
      reason: 'matched_rule',
      matchedRuleId: rule.id,
      matchedRuleName: rule.name,
      riskScore: risk.score,
      riskFactors: risk.factors,
      obligations: obligationsFor(rule.effect, risk.score),
      explanation: {
        summary: `${rule.effect} by rule "${rule.name}" (priority ${rule.priority}); risk ${risk.score}/100.`,
        defaulted: false,
        steps,
        riskFactors: risk.factors,
        stepUpAlreadySatisfied,
      },
    };
  }

  return {
    verdict: 'DENY',
    reason: 'default_deny',
    matchedRuleId: null,
    matchedRuleName: null,
    riskScore: risk.score,
    riskFactors: risk.factors,
    obligations: ['block'],
    explanation: {
      summary: `Denied by default: no enabled rule matched; risk ${risk.score}/100.`,
      defaulted: true,
      steps,
      riskFactors: risk.factors,
      stepUpAlreadySatisfied,
    },
  };
}

// ---------------------------------------------------------------------------
// Device trust
// ---------------------------------------------------------------------------

export interface PostureCheck {
  id: string;
  status: PostureCheckStatus;
  detail?: string;
}

export interface PostureReportFacts {
  collectedAt: Date;
  expiresAt: Date;
  signatureVerified: boolean;
  checks: readonly PostureCheck[];
}

export interface TrustAssessment {
  state: TrustState;
  score: number;
  reasons: readonly string[];
  verifiedPosture: boolean;
  freshPosture: boolean;
  passRatio: number;
}

export interface TrustInput {
  status: DeviceStatusValue;
  managed: boolean;
  attestationVerified: boolean;
  posture: PostureReportFacts | null;
  now: Date;
}

/**
 * Derives the trust state a device is allowed to advertise. Only a verified,
 * fresh, fully passing posture report from a managed device with a verified
 * hardware identity reaches TRUSTED; anything less degrades by exactly one
 * named reason so the console can say what to fix.
 *
 * The numeric score is a posture-completeness measure and is capped to the band
 * of the state it accompanies, so a device cannot look healthy while being
 * untrusted.
 */
export function computeTrustState(input: TrustInput): TrustAssessment {
  if (input.status === 'SUSPENDED') {
    return {
      state: 'UNTRUSTED',
      score: 0,
      reasons: ['device_suspended'],
      verifiedPosture: false,
      freshPosture: false,
      passRatio: 0,
    };
  }
  if (input.status === 'RETIRED') {
    return {
      state: 'UNTRUSTED',
      score: 0,
      reasons: ['device_retired'],
      verifiedPosture: false,
      freshPosture: false,
      passRatio: 0,
    };
  }
  if (input.status === 'PENDING') {
    return {
      state: 'UNKNOWN',
      score: 0,
      reasons: ['awaiting_activation'],
      verifiedPosture: false,
      freshPosture: false,
      passRatio: 0,
    };
  }

  const posture = input.posture;
  const verifiedPosture = posture !== null && posture.signatureVerified;
  const freshPosture =
    posture !== null &&
    posture.signatureVerified &&
    posture.collectedAt.getTime() <= input.now.getTime() &&
    posture.expiresAt.getTime() > input.now.getTime();

  const checks = posture?.checks ?? [];
  const passed = checks.filter((check) => check.status === 'PASS').length;
  const failed = checks.filter((check) => check.status === 'FAIL');
  const unknown = checks.filter((check) => check.status === 'UNKNOWN');
  const passRatio = checks.length === 0 ? 0 : passed / checks.length;

  let score = 0;
  if (verifiedPosture) score += freshPosture ? 40 : 10;
  score += Math.round(30 * passRatio);
  if (input.managed) score += 15;
  if (input.attestationVerified) score += 15;
  score = Math.min(100, score);

  const reasons: string[] = [];
  let state: TrustState;

  if (posture === null) {
    reasons.push('posture_missing');
    state = 'UNKNOWN';
  } else if (!posture.signatureVerified) {
    reasons.push('posture_unverified');
    state = 'UNKNOWN';
  } else if (!freshPosture) {
    reasons.push('posture_stale');
    state = 'UNKNOWN';
  } else if (failed.length > 0) {
    reasons.push('posture_failed');
    state = 'UNTRUSTED';
  } else if (unknown.length > 0) {
    reasons.push('posture_incomplete');
    state = 'PARTIAL';
  } else if (!input.managed) {
    reasons.push('device_unmanaged');
    state = 'PARTIAL';
  } else if (!input.attestationVerified) {
    reasons.push('attestation_unverified');
    state = 'PARTIAL';
  } else {
    state = 'TRUSTED';
  }

  const ceiling: Record<TrustState, number> = {
    UNTRUSTED: 39,
    UNKNOWN: 49,
    PARTIAL: 74,
    TRUSTED: 100,
  };
  score = Math.min(score, ceiling[state]);

  return { state, score, reasons, verifiedPosture, freshPosture, passRatio };
}

/** Maps trust to the zone a device may occupy when admitted without policy. */
export function zoneForTrust(state: TrustState): ZoneValue {
  switch (state) {
    case 'TRUSTED':
      return 'CORPORATE';
    case 'PARTIAL':
      return 'CORPORATE';
    case 'UNKNOWN':
      return 'GUEST';
    case 'UNTRUSTED':
      return 'QUARANTINE';
  }
}

// ---------------------------------------------------------------------------
// Admission
// ---------------------------------------------------------------------------

export interface AdmissionInput {
  verdict: PolicyEffectValue;
  requestedZone: ZoneValue;
  connector: {
    status: ConnectorStatusValue;
    failMode: ConnectorFailModeValue;
  } | null;
}

export interface AdmissionOutcome {
  admitted: boolean;
  /** Zone the connector should place the device in; null when it stays off. */
  assignedZone: ZoneValue | null;
  quarantine: boolean;
  reason:
    | 'allowed'
    | 'allowed_degraded'
    | 'policy_denied'
    | 'policy_quarantine'
    | 'step_up_required'
    | 'connector_unreachable_fail_closed'
    | 'connector_unreachable_fail_open';
  restrictions: readonly string[];
}

/**
 * Turns a verdict into a network decision. A connector that cannot be reached
 * is itself an input: with `CLOSED` the device is quarantined regardless of the
 * verdict, and with `OPEN` the stored policy decides but the admission is
 * marked degraded so the gap is visible in the console.
 */
export function mapAdmission(input: AdmissionInput): AdmissionOutcome {
  const connectorOffline = input.connector === null || input.connector.status === 'OFFLINE';

  if (connectorOffline) {
    const failMode = input.connector?.failMode ?? 'CLOSED';
    if (failMode === 'CLOSED') {
      return {
        admitted: false,
        assignedZone: 'QUARANTINE',
        quarantine: true,
        reason: 'connector_unreachable_fail_closed',
        restrictions: ['no_network_access'],
      };
    }
    if (input.verdict === 'ALLOW') {
      return {
        admitted: true,
        assignedZone: input.requestedZone,
        quarantine: false,
        reason: 'connector_unreachable_fail_open',
        restrictions: ['degraded_admission', 'connector_unreachable'],
      };
    }
    return denyForVerdict(input.verdict, input.requestedZone, 'connector_unreachable_fail_open');
  }

  if (input.verdict === 'ALLOW') {
    const degraded = input.connector?.status === 'DEGRADED';
    return {
      admitted: true,
      assignedZone: input.requestedZone,
      quarantine: false,
      reason: degraded ? 'allowed_degraded' : 'allowed',
      restrictions: degraded ? ['connector_degraded'] : [],
    };
  }

  return denyForVerdict(input.verdict, input.requestedZone, 'policy');
}

function denyForVerdict(
  verdict: PolicyEffectValue,
  requestedZone: ZoneValue,
  cause: 'policy' | 'connector_unreachable_fail_open',
): AdmissionOutcome {
  const suffix = cause === 'policy' ? [] : ['connector_unreachable'];
  switch (verdict) {
    case 'DENY':
      return {
        admitted: false,
        assignedZone: null,
        quarantine: false,
        reason: 'policy_denied',
        restrictions: ['block', ...suffix],
      };
    case 'QUARANTINE':
      return {
        admitted: false,
        assignedZone: 'QUARANTINE',
        quarantine: true,
        reason: 'policy_quarantine',
        restrictions: ['no_network_access', ...suffix],
      };
    case 'STEP_UP':
      return {
        admitted: false,
        assignedZone: null,
        quarantine: false,
        reason: 'step_up_required',
        restrictions: ['require_mfa', ...suffix],
      };
    case 'ALLOW':
      // Unreachable: the caller only reaches here from the fail-open branch.
      return {
        admitted: true,
        assignedZone: requestedZone,
        quarantine: false,
        reason: 'connector_unreachable_fail_open',
        restrictions: ['degraded_admission', ...suffix],
      };
  }
}

// ---------------------------------------------------------------------------
// Network visibility and detection
// ---------------------------------------------------------------------------

export interface DetectionThresholds {
  /** Distinct destination ports from one source to one host in a batch. */
  portScanDistinctPorts: number;
  /** Single-flow volume that counts as a bulk transfer. */
  bulkTransferBytes: number;
  /** How long a detection stays fresh after its newest supporting observation. */
  telemetryTtlMs: number;
}

export const DETECTION_DEFAULTS: DetectionThresholds = {
  portScanDistinctPorts: 12,
  bulkTransferBytes: 50 * 1024 * 1024,
  telemetryTtlMs: 60 * 60 * 1000,
};

export interface NetworkFlowFact {
  id: string;
  sourceAddress: string;
  sourcePort: number | null;
  destinationAddress: string;
  destinationPort: number | null;
  protocol: string;
  bytes: number;
  observedAt: Date;
  segmentId: string | null;
}

export interface NetworkSegmentFact {
  id: string;
  cidr: string;
  zone: ZoneValue;
  sensitivity: SensitivityValue;
}

export interface DetectionCandidate {
  ruleKey: string;
  subjectKey: string;
  title: string;
  description: string;
  severity: DetectionSeverityValue;
  observations: { flowIds: readonly string[]; facts: Record<string, unknown> };
  freshUntil: Date;
  firstSeenAt: Date;
  lastSeenAt: Date;
}

export interface DetectionInput {
  flows: readonly NetworkFlowFact[];
  segments: readonly NetworkSegmentFact[];
  now: Date;
  thresholds?: Partial<DetectionThresholds>;
}

function ipv4ToInt(address: string): number | null {
  const parts = address.split('.');
  if (parts.length !== 4) return null;
  let value = 0;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    const octet = Number(part);
    if (octet > 255) return null;
    value = (value << 8) + octet;
  }
  return value >>> 0;
}

/** True when a value is an IPv4 CIDR (or bare address) the platform can map. */
export function isValidCidr(cidr: string): boolean {
  const [network, prefixText, extra] = cidr.split('/');
  if (network === undefined || extra !== undefined) return false;
  if (ipv4ToInt(network) === null) return false;
  if (prefixText === undefined) return true;
  if (!/^\d{1,2}$/.test(prefixText)) return false;
  const prefix = Number(prefixText);
  return prefix >= 0 && prefix <= 32;
}

/** True when `address` falls inside `cidr`. Only IPv4 is parsed; anything else
 * (including IPv6) is reported as unmapped rather than guessed at. */
export function cidrContains(cidr: string, address: string): boolean {
  const [network, prefixText] = cidr.split('/');
  if (network === undefined) return false;
  const target = ipv4ToInt(address);
  const base = ipv4ToInt(network);
  if (target === null || base === null) return false;
  const prefix = prefixText === undefined ? 32 : Number(prefixText);
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > 32) return false;
  if (prefix === 0) return true;
  const mask = (0xffffffff << (32 - prefix)) >>> 0;
  return (target & mask) === (base & mask);
}

function segmentForAddress(
  segments: readonly NetworkSegmentFact[],
  address: string,
): NetworkSegmentFact | null {
  // Longest prefix wins so a /24 carved out of a /16 is not shadowed by it.
  let best: NetworkSegmentFact | null = null;
  let bestPrefix = -1;
  for (const segment of segments) {
    if (!cidrContains(segment.cidr, address)) continue;
    const prefixText = segment.cidr.split('/')[1];
    const prefix = prefixText === undefined ? 32 : Number(prefixText);
    if (prefix > bestPrefix) {
      best = segment;
      bestPrefix = prefix;
    }
  }
  return best;
}

interface DetectionAccumulator {
  ruleKey: string;
  subjectKey: string;
  title: string;
  description: string;
  severity: DetectionSeverityValue;
  facts: Record<string, unknown>;
  flows: NetworkFlowFact[];
}

function addCandidate(
  acc: Map<string, DetectionAccumulator>,
  candidate: DetectionAccumulator,
): void {
  const key = `${candidate.ruleKey}::${candidate.subjectKey}`;
  const existing = acc.get(key);
  if (existing === undefined) {
    acc.set(key, candidate);
    return;
  }
  existing.flows.push(...candidate.flows);
  existing.facts = { ...existing.facts, ...candidate.facts };
  if (SEVERITY_RANK[candidate.severity] > SEVERITY_RANK[existing.severity]) {
    existing.severity = candidate.severity;
  }
}

/**
 * Correlates a batch of flows into detection candidates. Rules are intentionally
 * few and explainable: each candidate carries the ids of the flows that justify
 * it plus the measured facts, and a `freshUntil` derived from its newest
 * observation so a stale detection is visibly stale instead of silently trusted.
 */
export function deriveDetections(input: DetectionInput): readonly DetectionCandidate[] {
  const thresholds = { ...DETECTION_DEFAULTS, ...input.thresholds };
  const segments = input.segments;
  const candidates = new Map<string, DetectionAccumulator>();

  const zoneOf = (flow: NetworkFlowFact, which: 'source' | 'destination'): ZoneValue | null => {
    if (which === 'source' && flow.segmentId !== null) {
      const byId = segments.find((segment) => segment.id === flow.segmentId);
      if (byId !== undefined) return byId.zone;
    }
    const address = which === 'source' ? flow.sourceAddress : flow.destinationAddress;
    return segmentForAddress(segments, address)?.zone ?? null;
  };

  // Port scan: one source touching many ports on one destination in the batch.
  const portGroups = new Map<string, NetworkFlowFact[]>();
  for (const flow of input.flows) {
    if (flow.destinationPort === null) continue;
    const key = `${flow.sourceAddress}|${flow.destinationAddress}|${flow.protocol}`;
    const group = portGroups.get(key);
    if (group === undefined) portGroups.set(key, [flow]);
    else group.push(flow);
  }
  for (const [key, flows] of portGroups) {
    const distinctPorts = new Set(flows.map((flow) => flow.destinationPort));
    if (distinctPorts.size < thresholds.portScanDistinctPorts) continue;
    const first = flows[0];
    if (first === undefined) continue;
    const [source, destination] = key.split('|');
    addCandidate(candidates, {
      ruleKey: 'port_scan',
      subjectKey: `${source}|${destination}`,
      title: 'Port scan from a single source',
      description: `One source contacted ${distinctPorts.size} distinct ports on ${destination}.`,
      severity: 'HIGH',
      facts: {
        sourceAddress: source ?? '',
        destinationAddress: destination ?? '',
        distinctPorts: distinctPorts.size,
        protocols: [...new Set(flows.map((flow) => flow.protocol))].sort(),
        sourceZone: zoneOf(first, 'source'),
      },
      flows,
    });
  }

  for (const flow of input.flows) {
    const sourceZone = zoneOf(flow, 'source');
    const destinationZone = zoneOf(flow, 'destination');

    if (
      sourceZone === 'QUARANTINE' &&
      destinationZone !== null &&
      destinationZone !== 'QUARANTINE'
    ) {
      addCandidate(candidates, {
        ruleKey: 'quarantine_egress',
        subjectKey: flow.sourceAddress,
        title: 'Traffic from a quarantined segment',
        description: `Quarantined host ${flow.sourceAddress} sent traffic to the ${destinationZone} zone.`,
        severity: 'CRITICAL',
        facts: {
          sourceAddress: flow.sourceAddress,
          destinationAddress: flow.destinationAddress,
          destinationZone,
          destinationPort: flow.destinationPort,
        },
        flows: [flow],
      });
    }

    if (destinationZone === 'OT' && sourceZone === 'EXTERNAL') {
      addCandidate(candidates, {
        ruleKey: 'ot_external_inbound',
        subjectKey: flow.destinationAddress,
        title: 'External traffic into an OT segment',
        description: `${flow.sourceAddress} reached OT host ${flow.destinationAddress}:${flow.destinationPort ?? '?'} .`,
        severity: 'CRITICAL',
        facts: {
          sourceAddress: flow.sourceAddress,
          destinationAddress: flow.destinationAddress,
          destinationPort: flow.destinationPort,
        },
        flows: [flow],
      });
    } else if (
      destinationZone === 'EXTERNAL' &&
      (sourceZone === 'CORPORATE' || sourceZone === 'OT')
    ) {
      addCandidate(candidates, {
        ruleKey: 'external_egress',
        subjectKey: `${flow.sourceAddress}|${flow.destinationAddress}`,
        title: 'Egress to an external address',
        description: `${sourceZone} host ${flow.sourceAddress} sent ${flow.bytes} bytes to ${flow.destinationAddress}.`,
        severity: sourceZone === 'OT' ? 'CRITICAL' : 'MEDIUM',
        facts: {
          sourceAddress: flow.sourceAddress,
          destinationAddress: flow.destinationAddress,
          sourceZone,
          bytes: flow.bytes,
        },
        flows: [flow],
      });
    }

    if (flow.bytes >= thresholds.bulkTransferBytes) {
      addCandidate(candidates, {
        ruleKey: 'bulk_transfer',
        subjectKey: flow.sourceAddress,
        title: 'Large outbound transfer',
        description: `${flow.sourceAddress} transferred ${flow.bytes} bytes to ${flow.destinationAddress}.`,
        severity: flow.bytes >= thresholds.bulkTransferBytes * 5 ? 'HIGH' : 'MEDIUM',
        facts: {
          sourceAddress: flow.sourceAddress,
          destinationAddress: flow.destinationAddress,
          bytes: flow.bytes,
          sourceZone,
          destinationZone,
        },
        flows: [flow],
      });
    }
  }

  return [...candidates.values()].map((candidate) => {
    const times = candidate.flows.map((flow) => flow.observedAt.getTime());
    const firstSeenAt = new Date(Math.min(...times));
    const lastSeenAt = new Date(Math.max(...times));
    return {
      ruleKey: candidate.ruleKey,
      subjectKey: candidate.subjectKey,
      title: candidate.title,
      description: candidate.description,
      severity: candidate.severity,
      observations: {
        flowIds: [...new Set(candidate.flows.map((flow) => flow.id))].slice(0, 100),
        facts: candidate.facts,
      },
      freshUntil: new Date(lastSeenAt.getTime() + thresholds.telemetryTtlMs),
      firstSeenAt,
      lastSeenAt,
    };
  });
}

export function isDetectionFresh(freshUntil: Date, now: Date): boolean {
  return freshUntil.getTime() > now.getTime();
}

// ---------------------------------------------------------------------------
// Enforcement
// ---------------------------------------------------------------------------

const ENFORCEMENT_TRANSITIONS: Readonly<
  Record<EnforcementStateValue, readonly EnforcementStateValue[]>
> = {
  REQUESTED: ['APPROVED', 'REJECTED', 'EXPIRED'],
  APPROVED: ['DISPATCHED', 'FAILED', 'EXPIRED'],
  DISPATCHED: ['ACKNOWLEDGED', 'FAILED', 'EXPIRED'],
  ACKNOWLEDGED: ['VERIFIED', 'FAILED'],
  VERIFIED: [],
  REJECTED: [],
  FAILED: [],
  EXPIRED: [],
};

export function enforcementTransitions(
  state: EnforcementStateValue,
): readonly EnforcementStateValue[] {
  return ENFORCEMENT_TRANSITIONS[state];
}

export function isTerminalEnforcementState(state: EnforcementStateValue): boolean {
  return ENFORCEMENT_TRANSITIONS[state].length === 0;
}

export function assertEnforcementTransition(
  from: EnforcementStateValue,
  to: EnforcementStateValue,
): void {
  if (!ENFORCEMENT_TRANSITIONS[from].includes(to)) {
    throw new ZeroTrustError(
      'invalid_transition',
      `Enforcement action cannot move from ${from} to ${to}`,
    );
  }
}

/**
 * Kinds that cut a device or identity off the network need a second person.
 * Revoking a session is recoverable by signing in again, so one administrator
 * can do it during an incident without waiting for a peer.
 */
const SECOND_APPROVER_KINDS: ReadonlySet<EnforcementKindValue> = new Set<EnforcementKindValue>([
  'ENDPOINT_ISOLATE',
  'NETWORK_QUARANTINE',
  'FIREWALL_BLOCK',
  'CERT_REVOKE',
]);

export function requiresSecondApprover(kind: EnforcementKindValue): boolean {
  return SECOND_APPROVER_KINDS.has(kind);
}

export function assertDistinctApprover(requestedById: string, approvedById: string): void {
  if (requestedById === approvedById) {
    throw new ZeroTrustError(
      'self_approval',
      'An enforcement action cannot be approved by its requester',
    );
  }
}

// ---------------------------------------------------------------------------
// Updates and certificate trust
// ---------------------------------------------------------------------------

const SEMVER = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z.-]+))?$/;
const NUMERIC_DOTTED = /^\d+(?:\.\d+)*$/;

export function isSemver(value: string): boolean {
  return SEMVER.test(value);
}

function parsePrerelease(value: string | undefined): readonly string[] {
  if (value === undefined || value === '') return [];
  return value.split('.');
}

function comparePrerelease(a: string, b: string): number {
  const left = parsePrerelease(a);
  const right = parsePrerelease(b);
  if (left.length === 0 && right.length === 0) return 0;
  // A release without a prerelease outranks one with it.
  if (left.length === 0) return 1;
  if (right.length === 0) return -1;
  const length = Math.max(left.length, right.length);
  for (let index = 0; index < length; index += 1) {
    const l = left[index];
    const r = right[index];
    if (l === undefined) return -1;
    if (r === undefined) return 1;
    const lNumeric = /^\d+$/.test(l);
    const rNumeric = /^\d+$/.test(r);
    if (lNumeric && rNumeric) {
      const diff = Number(l) - Number(r);
      if (diff !== 0) return diff < 0 ? -1 : 1;
    } else if (lNumeric !== rNumeric) {
      return lNumeric ? -1 : 1;
    } else if (l !== r) {
      return compareStrings(l, r);
    }
  }
  return 0;
}

/**
 * Compares dotted versions. Release versions must be strict semver; operating
 * system versions such as `14.5` are accepted leniently because vendors do not
 * agree on a format. Throws rather than guessing when either side is not a
 * version at all.
 */
export function compareVersions(a: string, b: string): -1 | 0 | 1 {
  const aMatch = SEMVER.exec(a);
  const bMatch = SEMVER.exec(b);
  if (aMatch !== null && bMatch !== null) {
    for (const index of [1, 2, 3]) {
      const left = Number(aMatch[index] ?? 0);
      const right = Number(bMatch[index] ?? 0);
      if (left !== right) return left < right ? -1 : 1;
    }
    const pre = comparePrerelease(aMatch[4] ?? '', bMatch[4] ?? '');
    return pre === 0 ? 0 : pre < 0 ? -1 : 1;
  }
  if (!NUMERIC_DOTTED.test(a) || !NUMERIC_DOTTED.test(b)) {
    throw new ZeroTrustError('invalid_version', `Cannot compare "${a}" with "${b}"`);
  }
  const left = a.split('.').map(Number);
  const right = b.split('.').map(Number);
  const length = Math.max(left.length, right.length);
  for (let index = 0; index < length; index += 1) {
    const l = left[index] ?? 0;
    const r = right[index] ?? 0;
    if (l !== r) return l < r ? -1 : 1;
  }
  return 0;
}

/**
 * Anti-rollback: the target must be newer than what the device runs and must
 * not be older than the release's declared floor. The floor exists so a
 * compromised device cannot be talked down to a version with a known flaw.
 */
export function assertAntiRollback(input: {
  currentVersion: string | null;
  targetVersion: string;
  minVersion: string | null;
}): void {
  if (!isSemver(input.targetVersion)) {
    throw new ZeroTrustError(
      'invalid_version',
      `Target version "${input.targetVersion}" is not semver`,
    );
  }
  if (input.minVersion !== null && compareVersions(input.targetVersion, input.minVersion) < 0) {
    throw new ZeroTrustError(
      'rollback_blocked',
      `Target ${input.targetVersion} is below the release floor ${input.minVersion}`,
    );
  }
  if (
    input.currentVersion !== null &&
    compareVersions(input.targetVersion, input.currentVersion) <= 0
  ) {
    throw new ZeroTrustError(
      'version_not_newer',
      `Target ${input.targetVersion} is not newer than ${input.currentVersion}`,
    );
  }
}

export interface CompatibilitySpec {
  os?: readonly string[];
  minOsVersion?: string;
  maxOsVersion?: string;
}

function safeCompareVersions(a: string, b: string): -1 | 0 | 1 | null {
  try {
    return compareVersions(a, b);
  } catch {
    return null;
  }
}

export function checkCompatibility(
  spec: CompatibilitySpec,
  device: { os: string | null; osVersion: string | null },
): { compatible: boolean; reasons: readonly string[] } {
  const reasons: string[] = [];
  const os = device.os?.toLowerCase() ?? null;

  if (spec.os !== undefined && spec.os.length > 0) {
    const allowed = spec.os.map((value) => value.toLowerCase());
    if (os === null || !allowed.includes(os)) reasons.push('os_not_supported');
  }

  const bounded = spec.minOsVersion !== undefined || spec.maxOsVersion !== undefined;
  if (bounded) {
    if (device.osVersion === null) {
      reasons.push('os_version_unknown');
    } else {
      const version = safeCompareVersions(
        device.osVersion,
        spec.minOsVersion ?? spec.maxOsVersion ?? '0',
      );
      if (version === null) {
        reasons.push('os_version_unparseable');
      } else {
        if (
          spec.minOsVersion !== undefined &&
          safeCompareVersions(device.osVersion, spec.minOsVersion) === -1
        ) {
          reasons.push('os_too_old');
        }
        if (
          spec.maxOsVersion !== undefined &&
          safeCompareVersions(device.osVersion, spec.maxOsVersion) === 1
        ) {
          reasons.push('os_too_new');
        }
      }
    }
  }

  return { compatible: reasons.length === 0, reasons };
}

/**
 * Deterministic canary selection: a device's bucket is derived from its id, so
 * widening the percentage only ever adds devices and a retry offers the same
 * set. The server never picks a random sample it cannot reproduce.
 */
export function assignCanary(deviceIds: readonly string[], percent: number): readonly string[] {
  const clamped = Math.max(0, Math.min(100, Math.round(percent)));
  const sorted = [...deviceIds].sort(compareStrings);
  if (clamped === 0) return [];
  if (clamped === 100) return sorted;
  return sorted.filter((deviceId) => {
    const digest = createHash('sha256').update(`${deviceId}:canary`).digest();
    const bucket = ((digest[0] ?? 0) / 256) * 100;
    return bucket < clamped;
  });
}

export function sha256Hex(data: string | Buffer): string {
  return createHash('sha256').update(data).digest('hex');
}

/** Parses `keyId:base64(spki der)` pairs. Keys live in the environment, never
 * in the database, so a database compromise cannot mint a valid release. */
export function parsePublisherKeys(raw: string | undefined): ReadonlyMap<string, string> {
  const keys = new Map<string, string>();
  if (raw === undefined) return keys;
  for (const entry of raw.split(',')) {
    const trimmed = entry.trim();
    if (trimmed === '') continue;
    const separator = trimmed.indexOf(':');
    if (separator <= 0) continue;
    const keyId = trimmed.slice(0, separator).trim();
    const material = trimmed.slice(separator + 1).trim();
    if (keyId !== '' && material !== '') keys.set(keyId, material);
  }
  return keys;
}

export function loadPublisherPublicKey(material: string) {
  try {
    if (material.includes('BEGIN PUBLIC KEY')) {
      return createPublicKey({ key: material, format: 'pem' });
    }
    return createPublicKey({
      key: Buffer.from(material, 'base64'),
      format: 'der',
      type: 'spki',
    });
  } catch {
    return null;
  }
}

/**
 * Verifies a detached Ed25519 signature over the canonical JSON of a value.
 * Only Ed25519 is accepted: signing keys are meant to live in an HSM or an
 * offline publisher host, and accepting a second algorithm would widen what a
 * stolen key can do for no operational gain.
 */
export function verifyDetachedSignature(input: {
  payload: unknown;
  signatureBase64: string;
  publicKey: string;
}): {
  valid: boolean;
  reason?: 'invalid_public_key' | 'unsupported_key_type' | 'signature_invalid';
} {
  const key = loadPublisherPublicKey(input.publicKey);
  if (key === null) return { valid: false, reason: 'invalid_public_key' };
  if (key.asymmetricKeyType !== 'ed25519') {
    return { valid: false, reason: 'unsupported_key_type' };
  }
  const signature = Buffer.from(input.signatureBase64, 'base64');
  if (signature.length === 0) return { valid: false, reason: 'signature_invalid' };
  const payload = Buffer.from(canonicalize(input.payload), 'utf8');
  const valid = verifySignature(null, payload, key, signature);
  return valid ? { valid: true } : { valid: false, reason: 'signature_invalid' };
}

/** Verifies a release manifest. Kept as a named wrapper so call sites read as
 * what they are checking. */
export function verifyManifestSignature(input: {
  manifest: unknown;
  signatureBase64: string;
  publicKey: string;
}): {
  valid: boolean;
  reason?: 'invalid_public_key' | 'unsupported_key_type' | 'signature_invalid';
} {
  return verifyDetachedSignature({
    payload: input.manifest,
    signatureBase64: input.signatureBase64,
    publicKey: input.publicKey,
  });
}

/** The exact object a publisher signs. Kept in one place so the server and the
 * publisher cannot drift into signing slightly different manifests. */
export interface ReleaseManifestInput {
  product: string;
  version: string;
  channel: string;
  artifactUrl: string;
  sha256: string;
  minVersion: string | null;
  compatibility: CompatibilitySpec;
}

export function releaseManifest(input: ReleaseManifestInput): Record<string, unknown> {
  return {
    product: input.product,
    version: input.version,
    channel: input.channel,
    artifactUrl: input.artifactUrl,
    sha256: input.sha256,
    minVersion: input.minVersion,
    compatibility: {
      os: input.compatibility.os ?? [],
      minOsVersion: input.compatibility.minOsVersion ?? null,
      maxOsVersion: input.compatibility.maxOsVersion ?? null,
    },
  };
}

/**
 * Checks that a stored release is internally consistent before it is offered:
 * the manifest must match the row, the digest must cover the artifact the row
 * names, and the signature must verify under a configured publisher key.
 */
export function verifyRelease(input: {
  manifest: unknown;
  signatureBase64: string;
  publisherKey: string | null;
  artifactSha256: string;
}): { valid: boolean; reason?: string } {
  if (input.publisherKey === null) return { valid: false, reason: 'publisher_key_unknown' };
  const verification = verifyManifestSignature({
    manifest: input.manifest,
    signatureBase64: input.signatureBase64,
    publicKey: input.publisherKey,
  });
  if (!verification.valid) {
    return { valid: false, reason: verification.reason ?? 'signature_invalid' };
  }
  if (!isRecord(input.manifest)) return { valid: false, reason: 'invalid_manifest' };
  const manifestSha = input.manifest['sha256'];
  if (
    typeof manifestSha !== 'string' ||
    manifestSha.toLowerCase() !== input.artifactSha256.toLowerCase()
  ) {
    return { valid: false, reason: 'digest_mismatch' };
  }
  return { valid: true };
}
