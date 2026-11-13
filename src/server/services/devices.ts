import { Prisma } from '@/generated/prisma/client';
import { prisma } from '@/lib/prisma';
import { AuditActions, appendAuditEvent } from '@/server/audit/audit';
import type { TenantContext } from '@/server/authz/context';
import { verifyDetachedSignature, type PostureCheck } from '@/server/domain/zero-trust';
import { badRequest, conflict, notFound } from '@/server/errors';
import type {
  DeviceListQuery,
  RegisterDeviceInput,
  SubmitPostureInput,
  UpdateDeviceInput,
} from '@/server/validation/zero-trust';
import { assertActiveMember, isUniqueConstraintError, paginationMeta } from './shared';
import {
  LATEST_POSTURE_SELECT,
  assertEd25519PublicKey,
  clampTtlSeconds,
  isoOrNull,
  parsePostureChecks,
  postureSignaturePayload,
  trustForDevice,
  type Db,
  type DeviceRecordForTrust,
} from './zero-trust-support';

/**
 * Device registry and posture.
 *
 * A device is registered with a hardware identifier and an Ed25519 public key.
 * Posture arrives from a connector that relays a device-signed report; the
 * signature is verified against the registered key, and an unverified or stale
 * report can never raise trust. The row stores the latest assessment so lists
 * and dashboards can filter without recomputing every device, while every
 * decision recomputes from the report it reads.
 */

const MAX_POSTURE_AGE_MS = 7 * 24 * 60 * 60 * 1000;
const MAX_CLOCK_SKEW_MS = 5 * 60 * 1000;
const DEFAULT_POSTURE_TTL_SECONDS = 24 * 60 * 60;
const MIN_POSTURE_TTL_SECONDS = 5 * 60;
const MAX_POSTURE_TTL_SECONDS = 7 * 24 * 60 * 60;

const DEVICE_SELECT = {
  id: true,
  name: true,
  hardwareId: true,
  keyAlgorithm: true,
  attestationKind: true,
  attestationVerified: true,
  managed: true,
  os: true,
  osVersion: true,
  status: true,
  trustState: true,
  trustScore: true,
  ownerUserId: true,
  lastSeenAt: true,
  createdAt: true,
  updatedAt: true,
  postureReports: LATEST_POSTURE_SELECT,
} satisfies Prisma.DeviceSelect;

type DeviceRow = Prisma.DeviceGetPayload<{ select: typeof DEVICE_SELECT }>;

export interface DeviceTrustView {
  state: 'UNTRUSTED' | 'UNKNOWN' | 'PARTIAL' | 'TRUSTED';
  score: number;
  reasons: string[];
  postureFresh: boolean;
  postureReportId: string | null;
  collectedAt: string | null;
  expiresAt: string | null;
  failingChecks: string[];
  unknownChecks: string[];
  passedChecks: string[];
}

export interface DeviceSummary {
  id: string;
  name: string;
  hardwareId: string;
  keyAlgorithm: string;
  attestationKind: string;
  attestationVerified: boolean;
  managed: boolean;
  os: string | null;
  osVersion: string | null;
  status: 'PENDING' | 'ACTIVE' | 'SUSPENDED' | 'RETIRED';
  trustState: 'UNTRUSTED' | 'UNKNOWN' | 'PARTIAL' | 'TRUSTED';
  trustScore: number;
  ownerUserId: string | null;
  lastSeenAt: string | null;
  createdAt: string;
  updatedAt: string;
  trust: DeviceTrustView;
}

function toSummary(row: DeviceRow, now: Date): DeviceSummary {
  const trust = trustForDevice(row, now);
  return {
    id: row.id,
    name: row.name,
    hardwareId: row.hardwareId,
    keyAlgorithm: row.keyAlgorithm,
    attestationKind: row.attestationKind,
    attestationVerified: row.attestationVerified,
    managed: row.managed,
    os: row.os,
    osVersion: row.osVersion,
    status: row.status,
    trustState: trust.state,
    trustScore: trust.score,
    ownerUserId: row.ownerUserId,
    lastSeenAt: isoOrNull(row.lastSeenAt),
    createdAt: row.createdAt.toISOString(),
    updatedAt: row.updatedAt.toISOString(),
    trust: {
      state: trust.state,
      score: trust.score,
      reasons: [...trust.reasons],
      postureFresh: trust.freshPosture,
      postureReportId: trust.postureReportId,
      collectedAt: isoOrNull(trust.collectedAt),
      expiresAt: isoOrNull(trust.expiresAt),
      failingChecks: trust.failingChecks,
      unknownChecks: trust.unknownChecks,
      passedChecks: trust.passedChecks,
    },
  };
}

async function loadDeviceRow(db: Db, organizationId: string, deviceId: string): Promise<DeviceRow> {
  const device = await db.device.findFirst({
    where: { id: deviceId, organizationId },
    select: DEVICE_SELECT,
  });
  if (!device) throw notFound('Device not found in this organization.');
  return device;
}

async function persistTrust(
  tx: Prisma.TransactionClient,
  device: DeviceRecordForTrust,
  now: Date,
): Promise<ReturnType<typeof trustForDevice>> {
  const trust = trustForDevice(device, now);
  await tx.device.update({
    where: { id: device.id },
    data: { trustState: trust.state, trustScore: trust.score },
  });
  return trust;
}

export async function listDevices(
  organizationId: string,
  query: DeviceListQuery,
): Promise<{ devices: DeviceSummary[]; page: ReturnType<typeof paginationMeta> }> {
  const where: Prisma.DeviceWhereInput = {
    organizationId,
    ...(query.status ? { status: query.status } : {}),
    ...(query.trustState ? { trustState: query.trustState } : {}),
    ...(query.managed !== undefined ? { managed: query.managed } : {}),
    ...(query.q
      ? {
          OR: [
            { name: { contains: query.q, mode: 'insensitive' } },
            { hardwareId: { contains: query.q, mode: 'insensitive' } },
            { os: { contains: query.q, mode: 'insensitive' } },
          ],
        }
      : {}),
  };

  const [total, rows] = await Promise.all([
    prisma.device.count({ where }),
    prisma.device.findMany({
      where,
      select: DEVICE_SELECT,
      orderBy: [{ lastSeenAt: 'desc' }, { createdAt: 'desc' }],
      skip: (query.page - 1) * query.pageSize,
      take: query.pageSize,
    }),
  ]);

  const now = new Date();
  return {
    devices: rows.map((row) => toSummary(row, now)),
    page: paginationMeta(query.page, query.pageSize, total),
  };
}

export async function getDeviceDetail(
  organizationId: string,
  deviceId: string,
): Promise<{
  device: DeviceSummary;
  postureReports: Array<{
    id: string;
    collectedAt: string;
    expiresAt: string;
    signatureVerified: boolean;
    source: string;
    checks: PostureCheck[];
    createdAt: string;
  }>;
  updates: Array<{
    id: string;
    state: string;
    offeredAt: string;
    installedAt: string | null;
    product: string;
    version: string;
  }>;
  enforcementActions: Array<{
    id: string;
    kind: string;
    state: string;
    createdAt: string;
    targetLabel: string;
  }>;
}> {
  const row = await loadDeviceRow(prisma, organizationId, deviceId);

  const [reports, updates, actions] = await Promise.all([
    prisma.devicePostureReport.findMany({
      where: { organizationId, deviceId },
      orderBy: { collectedAt: 'desc' },
      take: 20,
      select: {
        id: true,
        collectedAt: true,
        expiresAt: true,
        signatureVerified: true,
        source: true,
        checks: true,
        createdAt: true,
      },
    }),
    prisma.deviceUpdate.findMany({
      where: { organizationId, deviceId },
      orderBy: { offeredAt: 'desc' },
      take: 10,
      select: {
        id: true,
        state: true,
        offeredAt: true,
        installedAt: true,
        release: { select: { product: true, version: true } },
      },
    }),
    prisma.enforcementAction.findMany({
      where: { organizationId, targetType: 'DEVICE', targetId: deviceId },
      orderBy: { createdAt: 'desc' },
      take: 10,
      select: { id: true, kind: true, state: true, createdAt: true, targetLabel: true },
    }),
  ]);

  return {
    device: toSummary(row, new Date()),
    postureReports: reports.map((report) => ({
      id: report.id,
      collectedAt: report.collectedAt.toISOString(),
      expiresAt: report.expiresAt.toISOString(),
      signatureVerified: report.signatureVerified,
      source: report.source,
      checks: parsePostureChecks(report.checks),
      createdAt: report.createdAt.toISOString(),
    })),
    updates: updates.map((update) => ({
      id: update.id,
      state: update.state,
      offeredAt: update.offeredAt.toISOString(),
      installedAt: isoOrNull(update.installedAt),
      product: update.release.product,
      version: update.release.version,
    })),
    enforcementActions: actions.map((action) => ({
      id: action.id,
      kind: action.kind,
      state: action.state,
      createdAt: action.createdAt.toISOString(),
      targetLabel: action.targetLabel,
    })),
  };
}

export async function getDeviceOverview(organizationId: string): Promise<{
  counts: {
    total: number;
    active: number;
    pending: number;
    suspended: number;
    retired: number;
    trusted: number;
    partial: number;
    unknown: number;
    untrusted: number;
    unmanaged: number;
  };
}> {
  const [byStatus, byTrust, unmanaged] = await Promise.all([
    prisma.device.groupBy({
      by: ['status'],
      where: { organizationId },
      _count: { _all: true },
    }),
    prisma.device.groupBy({
      by: ['trustState'],
      where: { organizationId },
      _count: { _all: true },
    }),
    prisma.device.count({ where: { organizationId, managed: false, status: { not: 'RETIRED' } } }),
  ]);

  const statusCount = (status: string) =>
    byStatus.find((entry) => entry.status === status)?._count._all ?? 0;
  const trustCount = (state: string) =>
    byTrust.find((entry) => entry.trustState === state)?._count._all ?? 0;

  return {
    counts: {
      total: byStatus.reduce((sum, entry) => sum + entry._count._all, 0),
      active: statusCount('ACTIVE'),
      pending: statusCount('PENDING'),
      suspended: statusCount('SUSPENDED'),
      retired: statusCount('RETIRED'),
      trusted: trustCount('TRUSTED'),
      partial: trustCount('PARTIAL'),
      unknown: trustCount('UNKNOWN'),
      untrusted: trustCount('UNTRUSTED'),
      unmanaged,
    },
  };
}

export async function registerDevice(
  ctx: TenantContext,
  input: RegisterDeviceInput,
): Promise<DeviceSummary> {
  const organizationId = ctx.organization.id;
  assertEd25519PublicKey(input.publicKey);
  if (input.ownerUserId) {
    await assertActiveMember(organizationId, input.ownerUserId);
  }

  try {
    const created = await prisma.$transaction(async (tx) => {
      const device = await tx.device.create({
        data: {
          organizationId,
          name: input.name,
          hardwareId: input.hardwareId,
          publicKey: input.publicKey,
          attestationKind: input.attestationKind,
          attestationVerified: input.attestationVerified,
          managed: input.managed,
          status: 'PENDING',
          createdById: ctx.user.id,
          ...(input.os !== undefined ? { os: input.os } : {}),
          ...(input.osVersion !== undefined ? { osVersion: input.osVersion } : {}),
          ...(input.ownerUserId ? { ownerUserId: input.ownerUserId } : {}),
        },
        select: DEVICE_SELECT,
      });

      await appendAuditEvent(tx, {
        organizationId,
        actorType: 'USER',
        actorId: ctx.user.id,
        action: AuditActions.DEVICE_REGISTERED,
        outcome: 'SUCCESS',
        targetType: 'device',
        targetId: device.id,
        summary: `Registered device "${input.name}"`,
        metadata: {
          hardwareId: input.hardwareId,
          attestationKind: input.attestationKind,
          attestationVerified: input.attestationVerified,
          managed: input.managed,
          ownerAssigned: Boolean(input.ownerUserId),
        },
        ipAddress: ctx.meta.ipAddress,
        userAgent: ctx.meta.userAgent,
        requestId: ctx.meta.requestId,
      });

      return device;
    });

    return toSummary(created, new Date());
  } catch (error) {
    if (isUniqueConstraintError(error)) {
      throw conflict(`A device with hardware id "${input.hardwareId}" is already registered.`);
    }
    throw error;
  }
}

async function transitionDevice(
  ctx: TenantContext,
  deviceId: string,
  next: 'ACTIVE' | 'SUSPENDED' | 'RETIRED',
  reason: string,
  action: (typeof AuditActions)[keyof typeof AuditActions],
): Promise<DeviceSummary> {
  const organizationId = ctx.organization.id;
  const existing = await prisma.device.findFirst({
    where: { id: deviceId, organizationId },
    select: { id: true, status: true, name: true },
  });
  if (!existing) throw notFound('Device not found in this organization.');
  if (existing.status === 'RETIRED') {
    throw conflict('A retired device cannot change state.');
  }
  if (existing.status === next) {
    throw conflict(`Device is already ${next.toLowerCase()}.`);
  }
  if (next === 'ACTIVE' && existing.status === 'SUSPENDED') {
    // Reactivation is allowed; the audit entry records who restored access.
  }

  const updated = await prisma.$transaction(async (tx) => {
    const device = await tx.device.update({
      where: { id: deviceId },
      data: {
        status: next,
        ...(next === 'ACTIVE' ? {} : { trustState: 'UNTRUSTED' as const }),
      },
      select: DEVICE_SELECT,
    });
    const trust = await persistTrust(tx, device, new Date());

    await appendAuditEvent(tx, {
      organizationId,
      actorType: 'USER',
      actorId: ctx.user.id,
      action,
      outcome: 'SUCCESS',
      targetType: 'device',
      targetId: deviceId,
      summary: `Device "${existing.name}" moved to ${next}`,
      metadata: { from: existing.status, to: next, reason, trustState: trust.state },
      ipAddress: ctx.meta.ipAddress,
      userAgent: ctx.meta.userAgent,
      requestId: ctx.meta.requestId,
    });

    return device;
  });

  return toSummary(updated, new Date());
}

export async function activateDevice(ctx: TenantContext, deviceId: string): Promise<DeviceSummary> {
  return transitionDevice(
    ctx,
    deviceId,
    'ACTIVE',
    'Activated for policy evaluation',
    AuditActions.DEVICE_UPDATED,
  );
}

export async function suspendDevice(
  ctx: TenantContext,
  deviceId: string,
  reason: string,
): Promise<DeviceSummary> {
  return transitionDevice(ctx, deviceId, 'SUSPENDED', reason, AuditActions.DEVICE_SUSPENDED);
}

export async function retireDevice(
  ctx: TenantContext,
  deviceId: string,
  reason: string,
): Promise<DeviceSummary> {
  return transitionDevice(ctx, deviceId, 'RETIRED', reason, AuditActions.DEVICE_RETIRED);
}

export async function updateDevice(
  ctx: TenantContext,
  deviceId: string,
  input: UpdateDeviceInput,
): Promise<DeviceSummary> {
  const organizationId = ctx.organization.id;
  const existing = await prisma.device.findFirst({
    where: { id: deviceId, organizationId },
    select: { id: true, name: true, publicKey: true, managed: true },
  });
  if (!existing) throw notFound('Device not found in this organization.');
  if (input.publicKey !== undefined) {
    assertEd25519PublicKey(input.publicKey);
  }
  if (input.ownerUserId) {
    await assertActiveMember(organizationId, input.ownerUserId);
  }

  const updated = await prisma.$transaction(async (tx) => {
    const device = await tx.device.update({
      where: { id: deviceId },
      data: {
        ...(input.name !== undefined ? { name: input.name } : {}),
        ...(input.os !== undefined ? { os: input.os } : {}),
        ...(input.osVersion !== undefined ? { osVersion: input.osVersion } : {}),
        ...(input.managed !== undefined ? { managed: input.managed } : {}),
        ...(input.ownerUserId !== undefined ? { ownerUserId: input.ownerUserId } : {}),
        ...(input.publicKey !== undefined ? { publicKey: input.publicKey } : {}),
      },
      select: DEVICE_SELECT,
    });

    await appendAuditEvent(tx, {
      organizationId,
      actorType: 'USER',
      actorId: ctx.user.id,
      action: AuditActions.DEVICE_UPDATED,
      outcome: 'SUCCESS',
      targetType: 'device',
      targetId: deviceId,
      summary: `Updated device "${device.name}"`,
      metadata: {
        fields: Object.keys(input),
        keyRotated: input.publicKey !== undefined,
        managedChanged: input.managed !== undefined && input.managed !== existing.managed,
      },
      ipAddress: ctx.meta.ipAddress,
      userAgent: ctx.meta.userAgent,
      requestId: ctx.meta.requestId,
    });

    return device;
  });

  return toSummary(updated, new Date());
}

/**
 * Records a posture report and recomputes trust in the same transaction.
 *
 * The signature covers `{ deviceId, collectedAt, checks }` in the order the
 * checks were submitted. A report that fails verification is still stored, so
 * the console can show that a device tried and failed to prove its state, but it
 * cannot raise trust.
 */
export async function recordPosture(input: {
  organizationId: string;
  deviceId: string;
  collectedAt: Date;
  ttlSeconds?: number;
  checks: PostureCheck[];
  signature?: string;
  source: 'AGENT' | 'CONNECTOR' | 'MANUAL';
  actor: {
    type: 'USER' | 'SYSTEM';
    id: string | null;
    ipAddress?: string | null;
    userAgent?: string | null;
    requestId?: string | null;
  };
}): Promise<{ device: DeviceSummary; signatureVerified: boolean; reportId: string }> {
  const now = new Date();
  if (input.collectedAt.getTime() > now.getTime() + MAX_CLOCK_SKEW_MS) {
    throw badRequest('Posture collection time cannot be in the future.');
  }
  if (input.collectedAt.getTime() < now.getTime() - MAX_POSTURE_AGE_MS) {
    throw badRequest('Posture reports older than seven days are not accepted.');
  }

  const device = await prisma.device.findFirst({
    where: { id: input.deviceId, organizationId: input.organizationId },
    select: { id: true, name: true, publicKey: true, status: true },
  });
  if (!device) throw notFound('Device not found in this organization.');
  if (device.status === 'RETIRED') throw conflict('A retired device cannot submit posture.');

  const ttl = clampTtlSeconds(
    input.ttlSeconds ?? DEFAULT_POSTURE_TTL_SECONDS,
    MIN_POSTURE_TTL_SECONDS,
    MAX_POSTURE_TTL_SECONDS,
  );
  const expiresAt = new Date(input.collectedAt.getTime() + ttl * 1000);

  let signatureVerified = false;
  if (input.signature !== undefined) {
    const verification = verifyDetachedSignature({
      payload: postureSignaturePayload(device.id, input.collectedAt, input.checks),
      signatureBase64: input.signature,
      publicKey: device.publicKey,
    });
    signatureVerified = verification.valid;
  }

  const result = await prisma.$transaction(async (tx) => {
    const report = await tx.devicePostureReport.create({
      data: {
        organizationId: input.organizationId,
        deviceId: device.id,
        collectedAt: input.collectedAt,
        expiresAt,
        signature: input.signature ?? null,
        signatureVerified,
        checks: input.checks as unknown as Prisma.InputJsonValue,
        source: input.source,
      },
      select: {
        id: true,
        collectedAt: true,
        expiresAt: true,
        signatureVerified: true,
        checks: true,
      },
    });

    const updated = await tx.device.update({
      where: { id: device.id },
      data: { lastSeenAt: input.collectedAt },
      select: DEVICE_SELECT,
    });
    const trust = await persistTrust(tx, { ...updated, postureReports: [report] }, now);

    await appendAuditEvent(tx, {
      organizationId: input.organizationId,
      actorType: input.actor.type,
      actorId: input.actor.id,
      action: AuditActions.DEVICE_POSTURE_RECORDED,
      outcome: signatureVerified ? 'SUCCESS' : 'FAILURE',
      targetType: 'device',
      targetId: device.id,
      summary: signatureVerified
        ? `Verified posture report for "${device.name}"`
        : `Unverified posture report for "${device.name}"`,
      metadata: {
        reportId: report.id,
        signatureProvided: input.signature !== undefined,
        signatureVerified,
        source: input.source,
        trustState: trust.state,
        failingChecks: trust.failingChecks,
        checkCount: input.checks.length,
      },
      ipAddress: input.actor.ipAddress ?? null,
      userAgent: input.actor.userAgent ?? null,
      requestId: input.actor.requestId ?? null,
    });

    return { device: toSummary(updated, now), reportId: report.id, trust };
  });

  return {
    device: result.device,
    signatureVerified,
    reportId: result.reportId,
  };
}

export async function submitPosture(
  ctx: TenantContext,
  deviceId: string,
  input: SubmitPostureInput,
): Promise<{ device: DeviceSummary; signatureVerified: boolean; reportId: string }> {
  return recordPosture({
    organizationId: ctx.organization.id,
    deviceId,
    collectedAt: new Date(input.collectedAt),
    ...(input.ttlSeconds !== undefined ? { ttlSeconds: input.ttlSeconds } : {}),
    checks: input.checks.map((check) =>
      check.detail === undefined
        ? { id: check.id, status: check.status }
        : { id: check.id, status: check.status, detail: check.detail },
    ),
    ...(input.signature !== undefined ? { signature: input.signature } : {}),
    source: 'MANUAL',
    actor: {
      type: 'USER',
      id: ctx.user.id,
      ipAddress: ctx.meta.ipAddress,
      userAgent: ctx.meta.userAgent,
      requestId: ctx.meta.requestId,
    },
  });
}
