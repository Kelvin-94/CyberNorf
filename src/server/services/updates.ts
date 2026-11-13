import { Prisma } from '@/generated/prisma/client';
import { prisma } from '@/lib/prisma';
import { AuditActions, appendAuditEvent } from '@/server/audit/audit';
import type { TenantContext } from '@/server/authz/context';
import { getPublisherKeyMaterial } from '@/server/config';
import {
  assertAntiRollback,
  assignCanary,
  checkCompatibility,
  compareVersions,
  isSemver,
  parsePublisherKeys,
  releaseManifest,
  verifyRelease,
  type CompatibilitySpec,
  type ReleaseStatusValue,
} from '@/server/domain/zero-trust';
import { badRequest, conflict, notFound } from '@/server/errors';
import type {
  AdvanceReleaseInput,
  CheckUpdateInput,
  OfferUpdateInput,
  PublishReleaseInput,
  RecordUpdateResultInput,
  ReleaseListQuery,
  UpdateListQuery,
} from '@/server/validation/zero-trust';
import { paginationMeta } from './shared';
import { asRecord, isoOrNull, mapZeroTrustFailure } from './zero-trust-support';

/**
 * Signed software updates.
 *
 * A release is stored only if its manifest signature verifies under a publisher
 * key the operator configured outside the database, and the digest in the
 * manifest matches the artifact the row names. What the server stores is what
 * was signed, so a later comparison cannot drift.
 *
 * Distribution is staged: DRAFT → CANARY → ROLLING → RELEASED, and only a
 * release that has reached one of the last three is offered. The canary cohort
 * is derived from the device id, so widening the percentage only ever adds
 * devices and a retry offers the same set.
 */

const RELEASE_TRANSITIONS: Readonly<Record<ReleaseStatusValue, readonly ReleaseStatusValue[]>> = {
  DRAFT: ['CANARY'],
  CANARY: ['ROLLING', 'ROLLED_BACK'],
  ROLLING: ['RELEASED', 'ROLLED_BACK'],
  RELEASED: ['ROLLED_BACK'],
  ROLLED_BACK: [],
};

const OFFERABLE: ReadonlySet<ReleaseStatusValue> = new Set<ReleaseStatusValue>([
  'CANARY',
  'ROLLING',
  'RELEASED',
]);

const DEVICE_UPDATE_TRANSITIONS: Readonly<Record<string, readonly string[]>> = {
  OFFERED: ['DOWNLOADING', 'INSTALLING', 'FAILED'],
  DOWNLOADING: ['INSTALLING', 'FAILED'],
  INSTALLING: ['INSTALLED', 'FAILED'],
  INSTALLED: ['ROLLED_BACK'],
  FAILED: [],
  ROLLED_BACK: [],
};

function parseCompatibility(value: Prisma.JsonValue): CompatibilitySpec {
  const record = asRecord(value);
  const os = Array.isArray(record['os'])
    ? record['os'].filter((entry): entry is string => typeof entry === 'string')
    : [];
  const minOsVersion = record['minOsVersion'];
  const maxOsVersion = record['maxOsVersion'];
  return {
    os,
    ...(typeof minOsVersion === 'string' ? { minOsVersion } : {}),
    ...(typeof maxOsVersion === 'string' ? { maxOsVersion } : {}),
  };
}

const RELEASE_SELECT = {
  id: true,
  product: true,
  version: true,
  channel: true,
  artifactUrl: true,
  sha256: true,
  manifest: true,
  manifestSignature: true,
  publisherKeyId: true,
  minVersion: true,
  compatibility: true,
  status: true,
  canaryPercent: true,
  createdById: true,
  releasedAt: true,
  rolledBackAt: true,
  createdAt: true,
  updatedAt: true,
} satisfies Prisma.SoftwareReleaseSelect;

type ReleaseRow = Prisma.SoftwareReleaseGetPayload<{ select: typeof RELEASE_SELECT }>;

export interface ReleaseView {
  id: string;
  product: string;
  version: string;
  channel: string;
  artifactUrl: string;
  sha256: string;
  publisherKeyId: string;
  minVersion: string | null;
  compatibility: CompatibilitySpec;
  status: ReleaseStatusValue;
  canaryPercent: number;
  offerable: boolean;
  transitions: ReleaseStatusValue[];
  createdById: string | null;
  releasedAt: string | null;
  rolledBackAt: string | null;
  createdAt: string;
  updatedAt: string;
}

function toReleaseView(row: ReleaseRow): ReleaseView {
  return {
    id: row.id,
    product: row.product,
    version: row.version,
    channel: row.channel,
    artifactUrl: row.artifactUrl,
    sha256: row.sha256,
    publisherKeyId: row.publisherKeyId,
    minVersion: row.minVersion,
    compatibility: parseCompatibility(row.compatibility),
    status: row.status,
    canaryPercent: row.canaryPercent,
    offerable: OFFERABLE.has(row.status),
    transitions: [...RELEASE_TRANSITIONS[row.status]],
    createdById: row.createdById,
    releasedAt: isoOrNull(row.releasedAt),
    rolledBackAt: isoOrNull(row.rolledBackAt),
    createdAt: row.createdAt.toISOString(),
    updatedAt: row.updatedAt.toISOString(),
  };
}

function publisherKeyFor(keyId: string): string {
  const keys = parsePublisherKeys(getPublisherKeyMaterial());
  const material = keys.get(keyId);
  if (material === undefined) {
    throw badRequest(
      `No publisher key "${keyId}" is configured. Add it to ZERO_TRUST_PUBLISHER_KEYS before publishing.`,
    );
  }
  return material;
}

export async function publishRelease(
  ctx: TenantContext,
  input: PublishReleaseInput,
): Promise<ReleaseView> {
  const organizationId = ctx.organization.id;
  const sha256 = input.sha256.toLowerCase();
  const publicKey = publisherKeyFor(input.publisherKeyId);

  const compatibility: CompatibilitySpec = {
    os: input.compatibility.os,
    ...(typeof input.compatibility.minOsVersion === 'string'
      ? { minOsVersion: input.compatibility.minOsVersion }
      : {}),
    ...(typeof input.compatibility.maxOsVersion === 'string'
      ? { maxOsVersion: input.compatibility.maxOsVersion }
      : {}),
  };

  const manifest = releaseManifest({
    product: input.product,
    version: input.version,
    channel: input.channel,
    artifactUrl: input.artifactUrl,
    sha256,
    minVersion: input.minVersion ?? null,
    compatibility,
  });

  const verification = verifyRelease({
    manifest,
    signatureBase64: input.manifestSignature,
    publisherKey: publicKey,
    artifactSha256: sha256,
  });
  if (!verification.valid) {
    throw badRequest(
      `The release manifest did not verify: ${verification.reason ?? 'signature_invalid'}.`,
    );
  }

  if (input.minVersion != null && compareVersions(input.version, input.minVersion) < 0) {
    throw badRequest('The release floor cannot be newer than the release itself.');
  }

  try {
    const row = await prisma.$transaction(async (tx) => {
      const created = await tx.softwareRelease.create({
        data: {
          organizationId,
          product: input.product,
          version: input.version,
          channel: input.channel,
          artifactUrl: input.artifactUrl,
          sha256,
          manifest: manifest as Prisma.InputJsonValue,
          manifestSignature: input.manifestSignature,
          publisherKeyId: input.publisherKeyId,
          minVersion: input.minVersion ?? null,
          compatibility: {
            os: compatibility.os,
            minOsVersion: compatibility.minOsVersion ?? null,
            maxOsVersion: compatibility.maxOsVersion ?? null,
          } as Prisma.InputJsonValue,
          status: 'DRAFT',
          canaryPercent: input.canaryPercent,
          createdById: ctx.user.id,
        },
        select: RELEASE_SELECT,
      });

      await appendAuditEvent(tx, {
        organizationId,
        actorType: 'USER',
        actorId: ctx.user.id,
        action: AuditActions.RELEASE_PUBLISHED,
        outcome: 'SUCCESS',
        targetType: 'software_release',
        targetId: created.id,
        summary: `Published draft ${created.product} ${created.version} (${created.channel})`,
        metadata: {
          product: created.product,
          version: created.version,
          channel: created.channel,
          sha256: created.sha256,
          publisherKeyId: created.publisherKeyId,
          minVersion: created.minVersion,
        },
        ipAddress: ctx.meta.ipAddress,
        userAgent: ctx.meta.userAgent,
        requestId: ctx.meta.requestId,
      });

      return created;
    });
    return toReleaseView(row);
  } catch (error) {
    if (
      typeof error === 'object' &&
      error !== null &&
      (error as { code?: unknown }).code === 'P2002'
    ) {
      throw conflict(`${input.product} ${input.version} is already published in this channel.`);
    }
    throw error;
  }
}

export async function advanceRelease(
  ctx: TenantContext,
  releaseId: string,
  input: AdvanceReleaseInput,
): Promise<ReleaseView> {
  const organizationId = ctx.organization.id;
  const existing = await prisma.softwareRelease.findFirst({
    where: { id: releaseId, organizationId },
    select: RELEASE_SELECT,
  });
  if (!existing) throw notFound('Release not found in this organization.');
  if (!RELEASE_TRANSITIONS[existing.status].includes(input.to)) {
    throw conflict(`A release cannot move from ${existing.status} to ${input.to}.`);
  }

  const now = new Date();
  const row = await prisma.$transaction(async (tx) => {
    const applied = await tx.softwareRelease.updateMany({
      where: { id: releaseId, organizationId, status: existing.status },
      data: {
        status: input.to,
        ...(input.canaryPercent !== undefined ? { canaryPercent: input.canaryPercent } : {}),
        ...(input.to === 'RELEASED' ? { releasedAt: now } : {}),
      },
    });
    if (applied.count !== 1) throw conflict('The release changed while it was being advanced.');

    await appendAuditEvent(tx, {
      organizationId,
      actorType: 'USER',
      actorId: ctx.user.id,
      action: AuditActions.RELEASE_ADVANCED,
      outcome: 'SUCCESS',
      targetType: 'software_release',
      targetId: releaseId,
      summary: `Advanced ${existing.product} ${existing.version} from ${existing.status} to ${input.to}`,
      metadata: {
        from: existing.status,
        to: input.to,
        canaryPercent: input.canaryPercent ?? existing.canaryPercent,
      },
      ipAddress: ctx.meta.ipAddress,
      userAgent: ctx.meta.userAgent,
      requestId: ctx.meta.requestId,
    });

    return tx.softwareRelease.findUniqueOrThrow({
      where: { id: releaseId },
      select: RELEASE_SELECT,
    });
  });

  return toReleaseView(row);
}

/**
 * Rolling a release back also rolls back every device update for it that has
 * not already failed: leaving installed rows as INSTALLED would claim devices
 * still run a release the operator withdrew.
 */
export async function rollbackRelease(
  ctx: TenantContext,
  releaseId: string,
  reason: string,
): Promise<{ release: ReleaseView; devicesRolledBack: number }> {
  const organizationId = ctx.organization.id;
  const existing = await prisma.softwareRelease.findFirst({
    where: { id: releaseId, organizationId },
    select: RELEASE_SELECT,
  });
  if (!existing) throw notFound('Release not found in this organization.');
  if (!RELEASE_TRANSITIONS[existing.status].includes('ROLLED_BACK')) {
    throw conflict(`A release in ${existing.status} cannot be rolled back.`);
  }

  const now = new Date();
  const result = await prisma.$transaction(async (tx) => {
    const applied = await tx.softwareRelease.updateMany({
      where: { id: releaseId, organizationId, status: existing.status },
      data: { status: 'ROLLED_BACK', rolledBackAt: now },
    });
    if (applied.count !== 1) throw conflict('The release changed while it was being rolled back.');

    const updates = await tx.deviceUpdate.updateMany({
      where: {
        organizationId,
        releaseId,
        state: { in: ['OFFERED', 'DOWNLOADING', 'INSTALLING', 'INSTALLED'] },
      },
      data: { state: 'ROLLED_BACK' },
    });

    await appendAuditEvent(tx, {
      organizationId,
      actorType: 'USER',
      actorId: ctx.user.id,
      action: AuditActions.RELEASE_ROLLED_BACK,
      outcome: 'SUCCESS',
      targetType: 'software_release',
      targetId: releaseId,
      summary: `Rolled back ${existing.product} ${existing.version}`,
      metadata: {
        from: existing.status,
        reason,
        devicesRolledBack: updates.count,
      },
      ipAddress: ctx.meta.ipAddress,
      userAgent: ctx.meta.userAgent,
      requestId: ctx.meta.requestId,
    });

    const release = await tx.softwareRelease.findUniqueOrThrow({
      where: { id: releaseId },
      select: RELEASE_SELECT,
    });
    return { release, devicesRolledBack: updates.count };
  });

  return { release: toReleaseView(result.release), devicesRolledBack: result.devicesRolledBack };
}

export async function listReleases(
  organizationId: string,
  query: ReleaseListQuery,
): Promise<{ releases: ReleaseView[]; page: ReturnType<typeof paginationMeta> }> {
  const where: Prisma.SoftwareReleaseWhereInput = {
    organizationId,
    ...(query.product ? { product: query.product } : {}),
    ...(query.status ? { status: query.status } : {}),
    ...(query.q
      ? {
          OR: [
            { product: { contains: query.q, mode: 'insensitive' } },
            { version: { contains: query.q, mode: 'insensitive' } },
            { channel: { contains: query.q, mode: 'insensitive' } },
          ],
        }
      : {}),
  };

  const [total, rows] = await Promise.all([
    prisma.softwareRelease.count({ where }),
    prisma.softwareRelease.findMany({
      where,
      select: RELEASE_SELECT,
      orderBy: [{ createdAt: 'desc' }],
      skip: (query.page - 1) * query.pageSize,
      take: query.pageSize,
    }),
  ]);

  return {
    releases: rows.map(toReleaseView),
    page: paginationMeta(query.page, query.pageSize, total),
  };
}

export async function getRelease(organizationId: string, releaseId: string): Promise<ReleaseView> {
  const row = await prisma.softwareRelease.findFirst({
    where: { id: releaseId, organizationId },
    select: RELEASE_SELECT,
  });
  if (!row) throw notFound('Release not found in this organization.');
  return toReleaseView(row);
}

export interface UpdateCheckResult {
  eligible: boolean;
  release: ReleaseView | null;
  reasons: string[];
  canaryPercent: number | null;
}

/**
 * Answers "should this device take this update?" from the stored release, not
 * from what a caller says is available. A release whose signature no longer
 * verifies is not offered even if it is already staged, because the key may
 * have been withdrawn after publication.
 */
export async function checkForUpdate(
  organizationId: string,
  input: CheckUpdateInput,
): Promise<UpdateCheckResult> {
  const device = await prisma.device.findFirst({
    where: { id: input.deviceId, organizationId },
    select: { id: true, os: true, osVersion: true, status: true, managed: true },
  });
  if (!device) throw notFound('Device not found in this organization.');
  if (device.status === 'RETIRED') {
    return { eligible: false, release: null, reasons: ['device_retired'], canaryPercent: null };
  }

  const candidates = await prisma.softwareRelease.findMany({
    where: {
      organizationId,
      product: input.product,
      channel: input.channel,
      status: { in: ['CANARY', 'ROLLING', 'RELEASED'] },
    },
    select: RELEASE_SELECT,
  });

  if (candidates.length === 0) {
    return { eligible: false, release: null, reasons: ['no_release'], canaryPercent: null };
  }

  const sorted = [...candidates].sort((left, right) => {
    try {
      return compareVersions(right.version, left.version);
    } catch {
      return 0;
    }
  });
  const release = sorted[0] ?? null;
  if (release === null) {
    return { eligible: false, release: null, reasons: ['no_release'], canaryPercent: null };
  }

  const reasons: string[] = [];
  const keys = parsePublisherKeys(getPublisherKeyMaterial());
  const verification = verifyRelease({
    manifest: release.manifest,
    signatureBase64: release.manifestSignature,
    publisherKey: keys.get(release.publisherKeyId) ?? null,
    artifactSha256: release.sha256,
  });
  if (!verification.valid) {
    reasons.push(`release_${verification.reason ?? 'signature_invalid'}`);
  }

  if (release.status === 'CANARY') {
    const inCohort = assignCanary([device.id], release.canaryPercent).length === 1;
    if (!inCohort) reasons.push('outside_canary');
  }

  const compatibility = checkCompatibility(parseCompatibility(release.compatibility), {
    os: device.os,
    osVersion: device.osVersion,
  });
  reasons.push(...compatibility.reasons);

  try {
    assertAntiRollback({
      currentVersion: input.currentVersion,
      targetVersion: release.version,
      minVersion: release.minVersion,
    });
  } catch (error) {
    mapZeroTrustFailure(error);
  }

  return {
    eligible: reasons.length === 0,
    release: toReleaseView(release),
    reasons,
    canaryPercent: release.status === 'CANARY' ? release.canaryPercent : null,
  };
}

export interface OfferResult {
  offered: number;
  skipped: number;
}

/**
 * Offers a staged release to explicit devices. A device outside the canary
 * cohort is skipped rather than failing the batch, and a repeat offer is a
 * no-op because (device, release) is unique.
 */
export async function offerUpdate(
  ctx: TenantContext,
  releaseId: string,
  input: OfferUpdateInput,
): Promise<OfferResult> {
  const organizationId = ctx.organization.id;
  const release = await prisma.softwareRelease.findFirst({
    where: { id: releaseId, organizationId },
    select: RELEASE_SELECT,
  });
  if (!release) throw notFound('Release not found in this organization.');
  if (!OFFERABLE.has(release.status)) {
    throw conflict(`A release in ${release.status} cannot be offered to devices.`);
  }

  const devices = await prisma.device.findMany({
    where: { id: { in: input.deviceIds }, organizationId },
    select: { id: true },
  });
  if (devices.length !== input.deviceIds.length) {
    throw notFound('One or more devices were not found in this organization.');
  }

  const cohort =
    release.status === 'CANARY'
      ? new Set(
          assignCanary(
            devices.map((device) => device.id),
            release.canaryPercent,
          ),
        )
      : null;

  const targets = devices.filter((device) => cohort === null || cohort.has(device.id));
  const skipped = devices.length - targets.length;

  const offer = await prisma.$transaction(async (tx) => {
    const created = await tx.deviceUpdate.createMany({
      data: targets.map((device) => ({
        organizationId,
        deviceId: device.id,
        releaseId,
        state: 'OFFERED' as const,
      })),
      skipDuplicates: true,
    });

    await appendAuditEvent(tx, {
      organizationId,
      actorType: 'USER',
      actorId: ctx.user.id,
      action: AuditActions.DEVICE_UPDATE_OFFERED,
      outcome: 'SUCCESS',
      targetType: 'software_release',
      targetId: releaseId,
      summary: `Offered ${release.product} ${release.version} to ${created.count} device${created.count === 1 ? '' : 's'}`,
      metadata: {
        product: release.product,
        version: release.version,
        requested: input.deviceIds.length,
        offered: created.count,
        skipped,
        canaryPercent: release.status === 'CANARY' ? release.canaryPercent : null,
      },
      ipAddress: ctx.meta.ipAddress,
      userAgent: ctx.meta.userAgent,
      requestId: ctx.meta.requestId,
    });

    return created;
  });

  return { offered: offer.count, skipped };
}

export interface DeviceUpdateView {
  id: string;
  deviceId: string;
  releaseId: string;
  product: string;
  version: string;
  state: 'OFFERED' | 'DOWNLOADING' | 'INSTALLING' | 'INSTALLED' | 'FAILED' | 'ROLLED_BACK';
  offeredAt: string;
  installedAt: string | null;
  failedAt: string | null;
  result: Record<string, unknown>;
  terminal: boolean;
  transitions: string[];
}

const UPDATE_SELECT = {
  id: true,
  deviceId: true,
  releaseId: true,
  state: true,
  offeredAt: true,
  installedAt: true,
  failedAt: true,
  result: true,
  release: { select: { product: true, version: true } },
} satisfies Prisma.DeviceUpdateSelect;

type UpdateRow = Prisma.DeviceUpdateGetPayload<{ select: typeof UPDATE_SELECT }>;

function toUpdateView(row: UpdateRow): DeviceUpdateView {
  return {
    id: row.id,
    deviceId: row.deviceId,
    releaseId: row.releaseId,
    product: row.release.product,
    version: row.release.version,
    state: row.state,
    offeredAt: row.offeredAt.toISOString(),
    installedAt: isoOrNull(row.installedAt),
    failedAt: isoOrNull(row.failedAt),
    result: asRecord(row.result),
    terminal: (DEVICE_UPDATE_TRANSITIONS[row.state] ?? []).length === 0,
    transitions: [...(DEVICE_UPDATE_TRANSITIONS[row.state] ?? [])],
  };
}

/**
 * Records the result a device (or its connector) reports. The open update is
 * the most recent one that has not reached a terminal state; a state that is
 * not a legal successor is refused so a device cannot claim an install it never
 * performed.
 */
export async function recordUpdateResult(input: {
  organizationId: string;
  reporter: {
    type: 'USER' | 'SYSTEM';
    id: string | null;
    ipAddress?: string | null;
    userAgent?: string | null;
    requestId?: string | null;
  };
  payload: RecordUpdateResultInput;
}): Promise<DeviceUpdateView> {
  const organizationId = input.organizationId;
  const open = await prisma.deviceUpdate.findFirst({
    where: {
      organizationId,
      deviceId: input.payload.deviceId,
      state: { in: ['OFFERED', 'DOWNLOADING', 'INSTALLING'] },
    },
    orderBy: { offeredAt: 'desc' },
    select: UPDATE_SELECT,
  });
  if (!open) {
    throw notFound('No open update is pending for this device.');
  }

  const allowed = DEVICE_UPDATE_TRANSITIONS[open.state] ?? [];
  if (!allowed.includes(input.payload.state)) {
    throw conflict(`An update cannot move from ${open.state} to ${input.payload.state}.`);
  }

  const now = new Date();
  const row = await prisma.$transaction(async (tx) => {
    const applied = await tx.deviceUpdate.updateMany({
      where: { id: open.id, organizationId, state: open.state },
      data: {
        state: input.payload.state,
        ...(input.payload.state === 'INSTALLED' ? { installedAt: now } : {}),
        ...(input.payload.state === 'FAILED' ? { failedAt: now } : {}),
        ...(input.payload.result !== undefined
          ? { result: input.payload.result as Prisma.InputJsonValue }
          : {}),
      },
    });
    if (applied.count !== 1)
      throw conflict('The update changed while its result was being recorded.');

    await appendAuditEvent(tx, {
      organizationId,
      actorType: input.reporter.type,
      actorId: input.reporter.id,
      action: AuditActions.DEVICE_UPDATE_RECORDED,
      outcome: input.payload.state === 'FAILED' ? 'FAILURE' : 'SUCCESS',
      targetType: 'device_update',
      targetId: open.id,
      summary: `Update for device ${input.payload.deviceId} moved to ${input.payload.state}`,
      metadata: {
        deviceId: input.payload.deviceId,
        releaseId: open.releaseId,
        product: open.release.product,
        version: input.payload.version ?? open.release.version,
        from: open.state,
        to: input.payload.state,
        ...(input.payload.result !== undefined ? { result: input.payload.result } : {}),
      },
      ipAddress: input.reporter.ipAddress ?? null,
      userAgent: input.reporter.userAgent ?? null,
      requestId: input.reporter.requestId ?? null,
    });

    return tx.deviceUpdate.findUniqueOrThrow({ where: { id: open.id }, select: UPDATE_SELECT });
  });

  return toUpdateView(row);
}

export async function listDeviceUpdates(
  organizationId: string,
  query: UpdateListQuery,
): Promise<{ updates: DeviceUpdateView[]; page: ReturnType<typeof paginationMeta> }> {
  const where: Prisma.DeviceUpdateWhereInput = {
    organizationId,
    ...(query.deviceId ? { deviceId: query.deviceId } : {}),
    ...(query.releaseId ? { releaseId: query.releaseId } : {}),
    ...(query.state ? { state: query.state } : {}),
  };

  const [total, rows] = await Promise.all([
    prisma.deviceUpdate.count({ where }),
    prisma.deviceUpdate.findMany({
      where,
      select: UPDATE_SELECT,
      orderBy: { offeredAt: 'desc' },
      skip: (query.page - 1) * query.pageSize,
      take: query.pageSize,
    }),
  ]);

  return {
    updates: rows.map(toUpdateView),
    page: paginationMeta(query.page, query.pageSize, total),
  };
}

export interface UpdateOverview {
  releases: {
    total: number;
    draft: number;
    canary: number;
    rolling: number;
    released: number;
    rolledBack: number;
  };
  deviceUpdates: {
    offered: number;
    downloading: number;
    installing: number;
    installed: number;
    failed: number;
    rolledBack: number;
  };
  publisherKeysConfigured: number;
}

export async function getUpdateOverview(organizationId: string): Promise<UpdateOverview> {
  const [releases, updates] = await Promise.all([
    prisma.softwareRelease.groupBy({
      by: ['status'],
      where: { organizationId },
      _count: { _all: true },
    }),
    prisma.deviceUpdate.groupBy({
      by: ['state'],
      where: { organizationId },
      _count: { _all: true },
    }),
  ]);

  const releaseCounts = new Map(releases.map((entry) => [entry.status, entry._count._all]));
  const updateCounts = new Map(updates.map((entry) => [entry.state, entry._count._all]));
  const keys = parsePublisherKeys(getPublisherKeyMaterial());

  return {
    releases: {
      total: releases.reduce((sum, entry) => sum + entry._count._all, 0),
      draft: releaseCounts.get('DRAFT') ?? 0,
      canary: releaseCounts.get('CANARY') ?? 0,
      rolling: releaseCounts.get('ROLLING') ?? 0,
      released: releaseCounts.get('RELEASED') ?? 0,
      rolledBack: releaseCounts.get('ROLLED_BACK') ?? 0,
    },
    deviceUpdates: {
      offered: updateCounts.get('OFFERED') ?? 0,
      downloading: updateCounts.get('DOWNLOADING') ?? 0,
      installing: updateCounts.get('INSTALLING') ?? 0,
      installed: updateCounts.get('INSTALLED') ?? 0,
      failed: updateCounts.get('FAILED') ?? 0,
      rolledBack: updateCounts.get('ROLLED_BACK') ?? 0,
    },
    publisherKeysConfigured: keys.size,
  };
}

/** Exported for the release editor so the console shows the same rule. */
export function isValidVersion(value: string): boolean {
  return isSemver(value);
}
