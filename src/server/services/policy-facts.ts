import { Prisma } from '@/generated/prisma/client';
import {
  POLICY_CONDITION_KEYS,
  cidrContains,
  type ConnectorFailModeValue,
  type ConnectorStatusValue,
  type PolicyAttributeValue,
  type PolicyDeviceFacts,
  type PolicyNetworkFacts,
  type PolicyRuleDefinition,
  type PolicySubject,
  type SensitivityValue,
  type SubjectKindValue,
  type ZoneValue,
} from '@/server/domain/zero-trust';
import { notFound } from '@/server/errors';
import { LATEST_POSTURE_SELECT, asRecord, trustForDevice, type Db } from './zero-trust-support';

/**
 * Turns stored rows into the facts the decision point evaluates.
 *
 * Everything that a caller could otherwise assert about itself — role,
 * attributes, device trust, the zone an address sits in — is resolved here from
 * the database. The request body only contributes the observations only it can
 * know: the source address, whether the session carried a second factor, and
 * which subject and resource the action concerns.
 */

export interface NetworkFacts extends PolicyNetworkFacts {
  /** Segment the source address falls in, when one covers it. */
  segmentId: string | null;
  segmentSensitivity: SensitivityValue | null;
}

function toAttributes(
  value: Prisma.JsonValue | null | undefined,
): Record<string, PolicyAttributeValue> {
  const record = asRecord(value);
  const attributes: Record<string, PolicyAttributeValue> = {};
  for (const [key, entry] of Object.entries(record)) {
    if (typeof entry === 'string' || typeof entry === 'number' || typeof entry === 'boolean') {
      attributes[key] = entry;
    }
  }
  return attributes;
}

export async function resolveSubject(
  db: Db,
  organizationId: string,
  kind: SubjectKindValue,
  id: string,
): Promise<PolicySubject> {
  if (kind === 'USER') {
    const membership = await db.membership.findFirst({
      where: { organizationId, userId: id, status: 'ACTIVE' },
      select: {
        role: true,
        attributes: true,
        user: { select: { name: true, email: true, twoFactorEnabled: true } },
      },
    });
    if (!membership) {
      throw notFound('The subject is not an active member of this organization.');
    }
    return {
      kind,
      id,
      label: membership.user.name.length > 0 ? membership.user.name : membership.user.email,
      role: membership.role,
      attributes: {
        ...toAttributes(membership.attributes),
        twoFactorEnabled: membership.user.twoFactorEnabled === true,
      },
    };
  }

  if (kind === 'IDENTITY') {
    const identity = await db.identity.findFirst({
      where: { id, organizationId },
      select: {
        id: true,
        displayName: true,
        type: true,
        status: true,
        criticality: true,
        department: true,
      },
    });
    if (!identity) {
      throw notFound('The subject identity was not found in this organization.');
    }
    return {
      kind,
      id: identity.id,
      label: identity.displayName,
      role: null,
      attributes: {
        type: identity.type,
        status: identity.status,
        criticality: identity.criticality,
        ...(identity.department !== null ? { department: identity.department } : {}),
      },
    };
  }

  const device = await db.device.findFirst({
    where: { id, organizationId },
    select: {
      id: true,
      name: true,
      managed: true,
      attestationKind: true,
      attestationVerified: true,
      os: true,
      status: true,
      trustState: true,
    },
  });
  if (!device) {
    throw notFound('The subject device was not found in this organization.');
  }
  return {
    kind,
    id: device.id,
    label: device.name,
    role: null,
    attributes: {
      managed: device.managed,
      attestationKind: device.attestationKind,
      attestationVerified: device.attestationVerified,
      status: device.status,
      trustState: device.trustState,
      ...(device.os !== null ? { os: device.os } : {}),
    },
  };
}

/**
 * Device facts are recomputed from the stored posture report rather than read
 * from the device row, so a report that expired since the last write still
 * lowers trust at decision time.
 */
export async function resolveDeviceFacts(
  db: Db,
  organizationId: string,
  deviceId: string,
  now: Date,
): Promise<PolicyDeviceFacts> {
  const device = await db.device.findFirst({
    where: { id: deviceId, organizationId },
    select: {
      id: true,
      status: true,
      managed: true,
      attestationVerified: true,
      postureReports: LATEST_POSTURE_SELECT,
    },
  });
  if (!device) {
    throw notFound('The device was not found in this organization.');
  }
  const trust = trustForDevice(device, now);
  return {
    id: device.id,
    managed: device.managed,
    attestationVerified: device.attestationVerified,
    trustState: trust.state,
    postureFresh: trust.freshPosture,
    passedChecks: trust.passedChecks,
    failingChecks: trust.failingChecks,
    unknownChecks: trust.unknownChecks,
  };
}

function prefixLength(cidr: string): number {
  const [, prefix] = cidr.split('/');
  if (prefix === undefined) return 32;
  const parsed = Number(prefix);
  return Number.isInteger(parsed) && parsed >= 0 && parsed <= 32 ? parsed : 32;
}

/**
 * Resolves the zone from the most specific segment that covers the address. A
 * shorter prefix is a broader network, so the longest match wins; an address
 * outside every segment is external.
 */
export async function resolveNetworkFacts(
  db: Db,
  organizationId: string,
  sourceAddress: string | null,
  connectorId: string | null,
): Promise<NetworkFacts> {
  let connector: {
    status: ConnectorStatusValue;
    failMode: ConnectorFailModeValue;
  } | null = null;

  if (connectorId !== null) {
    const row = await db.networkConnector.findFirst({
      where: { id: connectorId, organizationId },
      select: { status: true, failMode: true },
    });
    if (!row) {
      throw notFound('The network connector was not found in this organization.');
    }
    connector = { status: row.status, failMode: row.failMode };
  }

  if (sourceAddress === null) {
    return {
      zone: 'EXTERNAL',
      connectorStatus: connector?.status ?? null,
      connectorFailMode: connector?.failMode ?? null,
      segmentId: null,
      segmentSensitivity: null,
    };
  }

  const segments = await db.networkSegment.findMany({
    where: { organizationId },
    select: { id: true, cidr: true, zone: true, sensitivity: true },
  });

  let best: { id: string; zone: ZoneValue; sensitivity: SensitivityValue; prefix: number } | null =
    null;
  for (const segment of segments) {
    if (!cidrContains(segment.cidr, sourceAddress)) continue;
    const prefix = prefixLength(segment.cidr);
    if (best === null || prefix > best.prefix) {
      best = { id: segment.id, zone: segment.zone, sensitivity: segment.sensitivity, prefix };
    }
  }

  return {
    zone: best?.zone ?? 'EXTERNAL',
    connectorStatus: connector?.status ?? null,
    connectorFailMode: connector?.failMode ?? null,
    segmentId: best?.id ?? null,
    segmentSensitivity: best?.sensitivity ?? null,
  };
}

/**
 * Loads enabled rules as the engine's input. Conditions are passed through as
 * `unknown`: rows were validated on write, but the engine still has to cope
 * with a value that no longer satisfies today's schema.
 */
export async function loadPolicyRules(
  db: Db,
  organizationId: string,
): Promise<PolicyRuleDefinition[]> {
  const rows = await db.policyRule.findMany({
    where: { organizationId, enabled: true },
    orderBy: [{ priority: 'asc' }, { name: 'asc' }],
    select: { id: true, name: true, priority: true, effect: true, enabled: true, conditions: true },
  });
  return rows.map((row) => ({
    id: row.id,
    name: row.name,
    priority: row.priority,
    effect: row.effect,
    enabled: row.enabled,
    conditions: row.conditions,
  }));
}

/** Condition keys an operator may set, re-exported for the console's editor. */
export const POLICY_CONDITION_KEYS_FOR_UI = POLICY_CONDITION_KEYS;
