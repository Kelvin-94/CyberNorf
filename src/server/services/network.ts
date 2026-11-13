import { Prisma } from '@/generated/prisma/client';
import { prisma } from '@/lib/prisma';
import { AuditActions, appendAuditEvent } from '@/server/audit/audit';
import type { TenantContext } from '@/server/authz/context';
import {
  cidrContains,
  deriveDetections,
  mapAdmission,
  type AdmissionOutcome,
  type ConnectorFailModeValue,
  type ConnectorKindValue,
  type ConnectorStatusValue,
  type DetectionCandidate,
  type NetworkFlowFact,
  type NetworkSegmentFact,
  type ZoneValue,
} from '@/server/domain/zero-trust';
import { conflict, notFound, unauthenticated } from '@/server/errors';
import type {
  AdmissionRequestInput,
  ConnectorListQuery,
  CreateConnectorInput,
  CreateSegmentInput,
  DetectionListQuery,
  FlowListQuery,
  IngestFlowsInput,
  SegmentListQuery,
  UpdateConnectorInput,
  UpdateDetectionInput,
  UpdateSegmentInput,
} from '@/server/validation/zero-trust';
import { evaluateDecision, type EvaluatedDecision } from './policy';
import { resolveNetworkFacts } from './policy-facts';
import { isUniqueConstraintError, paginationMeta } from './shared';
import { generateConnectorToken, hashToken, isoOrNull } from './zero-trust-support';

/**
 * Network access control and visibility.
 *
 * Connectors are the only components that authenticate with a token instead of
 * a user session: a RADIUS server or gateway reports what it observed and
 * accepts commands. Everything a connector reports is treated as an
 * observation, never as an assertion about a device's trust — posture reaches
 * the platform through the device's own signed report.
 *
 * Admission converts a policy verdict into a network outcome, and the connector
 * that would enforce it is an input: an unreachable connector with fail mode
 * CLOSED quarantines regardless of the verdict.
 */

const HEARTBEAT_STALE_MS = 5 * 60 * 1000;

const CONNECTOR_SELECT = {
  id: true,
  name: true,
  kind: true,
  endpointUrl: true,
  status: true,
  failMode: true,
  capabilities: true,
  lastHeartbeatAt: true,
  createdAt: true,
  updatedAt: true,
} satisfies Prisma.NetworkConnectorSelect;

type ConnectorRow = Prisma.NetworkConnectorGetPayload<{ select: typeof CONNECTOR_SELECT }>;

export interface ConnectorView {
  id: string;
  name: string;
  kind: ConnectorKindValue;
  endpointUrl: string | null;
  status: ConnectorStatusValue;
  failMode: ConnectorFailModeValue;
  capabilities: string[];
  lastHeartbeatAt: string | null;
  heartbeatStale: boolean;
  createdAt: string;
  updatedAt: string;
}

function toConnectorView(row: ConnectorRow, now: Date): ConnectorView {
  return {
    id: row.id,
    name: row.name,
    kind: row.kind,
    endpointUrl: row.endpointUrl,
    status: row.status,
    failMode: row.failMode,
    capabilities: [...row.capabilities],
    lastHeartbeatAt: isoOrNull(row.lastHeartbeatAt),
    heartbeatStale:
      row.lastHeartbeatAt === null ||
      now.getTime() - row.lastHeartbeatAt.getTime() > HEARTBEAT_STALE_MS,
    createdAt: row.createdAt.toISOString(),
    updatedAt: row.updatedAt.toISOString(),
  };
}

export async function listConnectors(
  organizationId: string,
  query: ConnectorListQuery,
): Promise<{ connectors: ConnectorView[]; page: ReturnType<typeof paginationMeta> }> {
  const where: Prisma.NetworkConnectorWhereInput = {
    organizationId,
    ...(query.kind ? { kind: query.kind } : {}),
    ...(query.status ? { status: query.status } : {}),
    ...(query.q
      ? {
          OR: [
            { name: { contains: query.q, mode: 'insensitive' } },
            { endpointUrl: { contains: query.q, mode: 'insensitive' } },
          ],
        }
      : {}),
  };

  const [total, rows] = await Promise.all([
    prisma.networkConnector.count({ where }),
    prisma.networkConnector.findMany({
      where,
      select: CONNECTOR_SELECT,
      orderBy: [{ name: 'asc' }],
      skip: (query.page - 1) * query.pageSize,
      take: query.pageSize,
    }),
  ]);

  const now = new Date();
  return {
    connectors: rows.map((row) => toConnectorView(row, now)),
    page: paginationMeta(query.page, query.pageSize, total),
  };
}

export async function getConnector(
  organizationId: string,
  connectorId: string,
): Promise<ConnectorView> {
  const row = await prisma.networkConnector.findFirst({
    where: { id: connectorId, organizationId },
    select: CONNECTOR_SELECT,
  });
  if (!row) throw notFound('Connector not found in this organization.');
  return toConnectorView(row, new Date());
}

export async function createConnector(
  ctx: TenantContext,
  input: CreateConnectorInput,
): Promise<{ connector: ConnectorView; token: string }> {
  const organizationId = ctx.organization.id;
  const credential = generateConnectorToken();

  try {
    const row = await prisma.$transaction(async (tx) => {
      const created = await tx.networkConnector.create({
        data: {
          organizationId,
          name: input.name,
          kind: input.kind,
          endpointUrl: input.endpointUrl ?? null,
          tokenHash: credential.hash,
          failMode: input.failMode,
          capabilities: input.capabilities,
          createdById: ctx.user.id,
        },
        select: CONNECTOR_SELECT,
      });

      await appendAuditEvent(tx, {
        organizationId,
        actorType: 'USER',
        actorId: ctx.user.id,
        action: AuditActions.NETWORK_CONNECTOR_CREATED,
        outcome: 'SUCCESS',
        targetType: 'network_connector',
        targetId: created.id,
        summary: `Created ${created.kind} connector "${created.name}"`,
        metadata: {
          kind: created.kind,
          failMode: created.failMode,
          capabilities: created.capabilities,
        },
        ipAddress: ctx.meta.ipAddress,
        userAgent: ctx.meta.userAgent,
        requestId: ctx.meta.requestId,
      });

      return created;
    });

    return { connector: toConnectorView(row, new Date()), token: credential.token };
  } catch (error) {
    if (isUniqueConstraintError(error)) {
      throw conflict(`A connector named "${input.name}" already exists.`);
    }
    throw error;
  }
}

export async function updateConnector(
  ctx: TenantContext,
  connectorId: string,
  input: UpdateConnectorInput,
): Promise<ConnectorView> {
  const organizationId = ctx.organization.id;
  const existing = await prisma.networkConnector.findFirst({
    where: { id: connectorId, organizationId },
    select: { id: true, name: true, failMode: true, status: true },
  });
  if (!existing) throw notFound('Connector not found in this organization.');

  try {
    const row = await prisma.$transaction(async (tx) => {
      const updated = await tx.networkConnector.update({
        where: { id: connectorId },
        data: {
          ...(input.name !== undefined ? { name: input.name } : {}),
          ...(input.endpointUrl !== undefined ? { endpointUrl: input.endpointUrl } : {}),
          ...(input.failMode !== undefined ? { failMode: input.failMode } : {}),
          ...(input.status !== undefined ? { status: input.status } : {}),
          ...(input.capabilities !== undefined ? { capabilities: input.capabilities } : {}),
        },
        select: CONNECTOR_SELECT,
      });

      await appendAuditEvent(tx, {
        organizationId,
        actorType: 'USER',
        actorId: ctx.user.id,
        action: AuditActions.NETWORK_CONNECTOR_UPDATED,
        outcome: 'SUCCESS',
        targetType: 'network_connector',
        targetId: connectorId,
        summary: `Updated connector "${updated.name}"`,
        metadata: {
          failModeChanged: input.failMode !== undefined && input.failMode !== existing.failMode,
          statusChanged: input.status !== undefined && input.status !== existing.status,
          fromFailMode: existing.failMode,
          toFailMode: updated.failMode,
        },
        ipAddress: ctx.meta.ipAddress,
        userAgent: ctx.meta.userAgent,
        requestId: ctx.meta.requestId,
      });

      return updated;
    });

    return toConnectorView(row, new Date());
  } catch (error) {
    if (isUniqueConstraintError(error)) {
      throw conflict('Another connector already uses that name.');
    }
    throw error;
  }
}

export async function rotateConnectorToken(
  ctx: TenantContext,
  connectorId: string,
): Promise<{ connector: ConnectorView; token: string }> {
  const organizationId = ctx.organization.id;
  const existing = await prisma.networkConnector.findFirst({
    where: { id: connectorId, organizationId },
    select: { id: true, name: true },
  });
  if (!existing) throw notFound('Connector not found in this organization.');

  const credential = generateConnectorToken();
  const row = await prisma.$transaction(async (tx) => {
    const updated = await tx.networkConnector.update({
      where: { id: connectorId },
      data: { tokenHash: credential.hash },
      select: CONNECTOR_SELECT,
    });

    await appendAuditEvent(tx, {
      organizationId,
      actorType: 'USER',
      actorId: ctx.user.id,
      action: AuditActions.NETWORK_CONNECTOR_TOKEN_ROTATED,
      outcome: 'SUCCESS',
      targetType: 'network_connector',
      targetId: connectorId,
      summary: `Rotated the credential for connector "${existing.name}"`,
      ipAddress: ctx.meta.ipAddress,
      userAgent: ctx.meta.userAgent,
      requestId: ctx.meta.requestId,
    });

    return updated;
  });

  return { connector: toConnectorView(row, new Date()), token: credential.token };
}

export interface ConnectorPrincipal {
  id: string;
  organizationId: string;
  name: string;
  kind: ConnectorKindValue;
  status: ConnectorStatusValue;
  failMode: ConnectorFailModeValue;
  capabilities: string[];
}

/**
 * Resolves a connector bearer token. An unknown token fails as unauthenticated
 * so the endpoint cannot be used to enumerate connectors, and a token for a
 * connector that was never enabled still resolves — connectors are created by
 * an administrator, so the token is the whole gate.
 */
export async function authenticateConnectorToken(token: string): Promise<ConnectorPrincipal> {
  if (!token.startsWith('cnf_')) throw unauthenticated();
  const connector = await prisma.networkConnector.findFirst({
    where: { tokenHash: hashToken(token) },
    select: {
      id: true,
      organizationId: true,
      name: true,
      kind: true,
      status: true,
      failMode: true,
      capabilities: true,
    },
  });
  if (!connector) throw unauthenticated();
  return { ...connector, capabilities: [...connector.capabilities] };
}

/** Records a connector heartbeat. The connector asserts its own reachability;
 * the platform records it and lets admission read the stored status. */
export async function recordConnectorHeartbeat(
  connectorId: string,
  status: ConnectorStatusValue,
): Promise<void> {
  const connector = await prisma.networkConnector.findUnique({
    where: { id: connectorId },
    select: { id: true, organizationId: true, name: true, status: true },
  });
  if (!connector) throw notFound('Connector not found.');

  const now = new Date();
  await prisma.$transaction(async (tx) => {
    await tx.networkConnector.update({
      where: { id: connectorId },
      data: { status, lastHeartbeatAt: now },
    });

    // A heartbeat only becomes an audit event when reachability changes;
    // connectors report often and the chain is not a liveness log.
    if (connector.status !== status) {
      await appendAuditEvent(tx, {
        organizationId: connector.organizationId,
        actorType: 'SYSTEM',
        // `actorId` is a foreign key to users, so a machine actor leaves it null
        // and identifies itself through the target instead.
        actorId: null,
        action: AuditActions.NETWORK_CONNECTOR_UPDATED,
        outcome: 'SUCCESS',
        targetType: 'network_connector',
        targetId: connectorId,
        summary: `Connector "${connector.name}" reported ${status}`,
        metadata: { from: connector.status, to: status },
      });
    }
  });
}

// ---------------------------------------------------------------------------
// Segments
// ---------------------------------------------------------------------------

const SEGMENT_SELECT = {
  id: true,
  name: true,
  cidr: true,
  zone: true,
  sensitivity: true,
  connectorId: true,
  createdAt: true,
  updatedAt: true,
} satisfies Prisma.NetworkSegmentSelect;

type SegmentRow = Prisma.NetworkSegmentGetPayload<{ select: typeof SEGMENT_SELECT }>;

export interface SegmentView {
  id: string;
  name: string;
  cidr: string;
  zone: ZoneValue;
  sensitivity: 'PUBLIC' | 'INTERNAL' | 'CONFIDENTIAL' | 'RESTRICTED';
  connectorId: string | null;
  createdAt: string;
  updatedAt: string;
}

function toSegmentView(row: SegmentRow): SegmentView {
  return {
    id: row.id,
    name: row.name,
    cidr: row.cidr,
    zone: row.zone,
    sensitivity: row.sensitivity,
    connectorId: row.connectorId,
    createdAt: row.createdAt.toISOString(),
    updatedAt: row.updatedAt.toISOString(),
  };
}

async function assertConnectorInOrganization(
  organizationId: string,
  connectorId: string | null | undefined,
): Promise<void> {
  if (!connectorId) return;
  const connector = await prisma.networkConnector.findFirst({
    where: { id: connectorId, organizationId },
    select: { id: true },
  });
  if (!connector) throw notFound('Connector not found in this organization.');
}

export async function listSegments(
  organizationId: string,
  query: SegmentListQuery,
): Promise<{ segments: SegmentView[]; page: ReturnType<typeof paginationMeta> }> {
  const where: Prisma.NetworkSegmentWhereInput = {
    organizationId,
    ...(query.zone ? { zone: query.zone } : {}),
    ...(query.q
      ? {
          OR: [
            { name: { contains: query.q, mode: 'insensitive' } },
            { cidr: { contains: query.q, mode: 'insensitive' } },
          ],
        }
      : {}),
  };

  const [total, rows] = await Promise.all([
    prisma.networkSegment.count({ where }),
    prisma.networkSegment.findMany({
      where,
      select: SEGMENT_SELECT,
      orderBy: [{ name: 'asc' }],
      skip: (query.page - 1) * query.pageSize,
      take: query.pageSize,
    }),
  ]);

  return {
    segments: rows.map(toSegmentView),
    page: paginationMeta(query.page, query.pageSize, total),
  };
}

export async function getSegment(organizationId: string, segmentId: string): Promise<SegmentView> {
  const row = await prisma.networkSegment.findFirst({
    where: { id: segmentId, organizationId },
    select: SEGMENT_SELECT,
  });
  if (!row) throw notFound('Segment not found in this organization.');
  return toSegmentView(row);
}

export async function createSegment(
  ctx: TenantContext,
  input: CreateSegmentInput,
): Promise<SegmentView> {
  const organizationId = ctx.organization.id;
  await assertConnectorInOrganization(organizationId, input.connectorId);

  try {
    const row = await prisma.$transaction(async (tx) => {
      const created = await tx.networkSegment.create({
        data: {
          organizationId,
          name: input.name,
          cidr: input.cidr,
          zone: input.zone,
          sensitivity: input.sensitivity,
          connectorId: input.connectorId ?? null,
        },
        select: SEGMENT_SELECT,
      });

      await appendAuditEvent(tx, {
        organizationId,
        actorType: 'USER',
        actorId: ctx.user.id,
        action: AuditActions.NETWORK_SEGMENT_CREATED,
        outcome: 'SUCCESS',
        targetType: 'network_segment',
        targetId: created.id,
        summary: `Created ${created.zone} segment "${created.name}" (${created.cidr})`,
        metadata: { cidr: created.cidr, zone: created.zone, sensitivity: created.sensitivity },
        ipAddress: ctx.meta.ipAddress,
        userAgent: ctx.meta.userAgent,
        requestId: ctx.meta.requestId,
      });

      return created;
    });
    return toSegmentView(row);
  } catch (error) {
    if (isUniqueConstraintError(error)) {
      throw conflict(`A segment named "${input.name}" already exists.`);
    }
    throw error;
  }
}

export async function updateSegment(
  ctx: TenantContext,
  segmentId: string,
  input: UpdateSegmentInput,
): Promise<SegmentView> {
  const organizationId = ctx.organization.id;
  const existing = await prisma.networkSegment.findFirst({
    where: { id: segmentId, organizationId },
    select: { id: true, name: true, zone: true, cidr: true },
  });
  if (!existing) throw notFound('Segment not found in this organization.');
  if (input.connectorId !== undefined) {
    await assertConnectorInOrganization(organizationId, input.connectorId);
  }

  try {
    const row = await prisma.$transaction(async (tx) => {
      const updated = await tx.networkSegment.update({
        where: { id: segmentId },
        data: {
          ...(input.name !== undefined ? { name: input.name } : {}),
          ...(input.cidr !== undefined ? { cidr: input.cidr } : {}),
          ...(input.zone !== undefined ? { zone: input.zone } : {}),
          ...(input.sensitivity !== undefined ? { sensitivity: input.sensitivity } : {}),
          ...(input.connectorId !== undefined ? { connectorId: input.connectorId } : {}),
        },
        select: SEGMENT_SELECT,
      });

      await appendAuditEvent(tx, {
        organizationId,
        actorType: 'USER',
        actorId: ctx.user.id,
        action: AuditActions.NETWORK_SEGMENT_UPDATED,
        outcome: 'SUCCESS',
        targetType: 'network_segment',
        targetId: segmentId,
        summary: `Updated segment "${updated.name}"`,
        metadata: {
          zoneChanged: input.zone !== undefined && input.zone !== existing.zone,
          cidrChanged: input.cidr !== undefined && input.cidr !== existing.cidr,
          fromZone: existing.zone,
          toZone: updated.zone,
        },
        ipAddress: ctx.meta.ipAddress,
        userAgent: ctx.meta.userAgent,
        requestId: ctx.meta.requestId,
      });

      return updated;
    });
    return toSegmentView(row);
  } catch (error) {
    if (isUniqueConstraintError(error)) {
      throw conflict('Another segment already uses that name.');
    }
    throw error;
  }
}

export async function deleteSegment(ctx: TenantContext, segmentId: string): Promise<void> {
  const organizationId = ctx.organization.id;
  const existing = await prisma.networkSegment.findFirst({
    where: { id: segmentId, organizationId },
    select: { id: true, name: true, cidr: true, zone: true },
  });
  if (!existing) throw notFound('Segment not found in this organization.');

  await prisma.$transaction(async (tx) => {
    await tx.networkSegment.delete({ where: { id: segmentId } });
    await appendAuditEvent(tx, {
      organizationId,
      actorType: 'USER',
      actorId: ctx.user.id,
      action: AuditActions.NETWORK_SEGMENT_UPDATED,
      outcome: 'SUCCESS',
      targetType: 'network_segment',
      targetId: segmentId,
      summary: `Deleted segment "${existing.name}" (${existing.cidr})`,
      metadata: { deleted: true, zone: existing.zone },
      ipAddress: ctx.meta.ipAddress,
      userAgent: ctx.meta.userAgent,
      requestId: ctx.meta.requestId,
    });
  });
}

// ---------------------------------------------------------------------------
// Flow ingestion and detections
// ---------------------------------------------------------------------------

function prefixLength(cidr: string): number {
  const [, prefix] = cidr.split('/');
  if (prefix === undefined) return 32;
  const parsed = Number(prefix);
  return Number.isInteger(parsed) && parsed >= 0 && parsed <= 32 ? parsed : 32;
}

function segmentFor(address: string, segments: readonly NetworkSegmentFact[]): string | null {
  let bestId: string | null = null;
  let bestPrefix = -1;
  for (const segment of segments) {
    if (!cidrContains(segment.cidr, address)) continue;
    const prefix = prefixLength(segment.cidr);
    if (prefix > bestPrefix) {
      bestPrefix = prefix;
      bestId = segment.id;
    }
  }
  return bestId;
}

export interface IngestResult {
  ingested: number;
  opened: number;
  updated: number;
  detections: DetectionCandidate[];
}

/**
 * Stores one bounded batch of observations and turns it into detections.
 *
 * Flows are inserted one at a time inside the transaction so each detection can
 * name the exact rows that triggered it; a batch is capped at 500 by the input
 * schema, which keeps that loop bounded.
 */
export async function ingestFlows(input: {
  organizationId: string;
  connectorId: string | null;
  flows: IngestFlowsInput['flows'];
  actor: {
    type: 'USER' | 'SYSTEM';
    id: string | null;
    ipAddress?: string | null;
    userAgent?: string | null;
    requestId?: string | null;
  };
}): Promise<IngestResult> {
  const organizationId = input.organizationId;
  const now = new Date();

  if (input.connectorId !== null) {
    await assertConnectorInOrganization(organizationId, input.connectorId);
  }

  const segments = await prisma.networkSegment.findMany({
    where: { organizationId },
    select: { id: true, cidr: true, zone: true, sensitivity: true },
  });
  const segmentFacts: NetworkSegmentFact[] = segments.map((segment) => ({
    id: segment.id,
    cidr: segment.cidr,
    zone: segment.zone,
    sensitivity: segment.sensitivity,
  }));

  const prepared = input.flows.map((flow) => ({
    flow,
    segmentId: segmentFor(flow.sourceAddress, segmentFacts),
  }));

  const result = await prisma.$transaction(async (tx) => {
    const facts: NetworkFlowFact[] = [];
    for (const entry of prepared) {
      const created = await tx.networkFlow.create({
        data: {
          organizationId,
          connectorId: input.connectorId,
          sourceAddress: entry.flow.sourceAddress,
          sourcePort: entry.flow.sourcePort ?? null,
          destinationAddress: entry.flow.destinationAddress,
          destinationPort: entry.flow.destinationPort ?? null,
          protocol: entry.flow.protocol,
          bytes: entry.flow.bytes,
          observedAt: entry.flow.observedAt,
          segmentId: entry.segmentId,
        },
        select: { id: true },
      });

      facts.push({
        id: created.id,
        sourceAddress: entry.flow.sourceAddress,
        sourcePort: entry.flow.sourcePort ?? null,
        destinationAddress: entry.flow.destinationAddress,
        destinationPort: entry.flow.destinationPort ?? null,
        protocol: entry.flow.protocol,
        bytes: entry.flow.bytes,
        observedAt: entry.flow.observedAt,
        segmentId: entry.segmentId,
      });
    }

    const candidates = deriveDetections({ flows: facts, segments: segmentFacts, now });
    let opened = 0;
    let updated = 0;

    for (const candidate of candidates) {
      const existing = await tx.networkDetection.findUnique({
        where: {
          organizationId_ruleKey_subjectKey: {
            organizationId,
            ruleKey: candidate.ruleKey,
            subjectKey: candidate.subjectKey,
          },
        },
        select: { id: true, status: true, firstSeenAt: true },
      });

      const observations = {
        flowIds: [...candidate.observations.flowIds],
        facts: candidate.observations.facts,
      } as Prisma.InputJsonValue;

      if (existing === null) {
        await tx.networkDetection.create({
          data: {
            organizationId,
            ruleKey: candidate.ruleKey,
            subjectKey: candidate.subjectKey,
            title: candidate.title,
            description: candidate.description,
            severity: candidate.severity,
            status: 'OPEN',
            deviceId: null,
            observations,
            freshUntil: candidate.freshUntil,
            firstSeenAt: candidate.firstSeenAt,
            lastSeenAt: candidate.lastSeenAt,
          },
        });
        opened += 1;
        continue;
      }

      await tx.networkDetection.update({
        where: { id: existing.id },
        data: {
          title: candidate.title,
          description: candidate.description,
          severity: candidate.severity,
          observations,
          freshUntil: candidate.freshUntil,
          lastSeenAt: candidate.lastSeenAt,
          // Fresh evidence reopens a closed detection; an acknowledgement stays
          // acknowledged so a responder is not asked to triage it twice.
          ...(existing.status === 'CLOSED' ? { status: 'OPEN' as const } : {}),
        },
      });
      updated += 1;
    }

    await appendAuditEvent(tx, {
      organizationId,
      actorType: input.actor.type,
      actorId: input.actor.id,
      action: AuditActions.NETWORK_FLOWS_INGESTED,
      outcome: 'SUCCESS',
      targetType: 'network_flow',
      targetId: input.connectorId,
      summary: `Ingested ${facts.length} flow${facts.length === 1 ? '' : 's'}`,
      metadata: {
        connectorId: input.connectorId,
        flows: facts.length,
        detectionsOpened: opened,
        detectionsUpdated: updated,
        ruleKeys: [...new Set(candidates.map((candidate) => candidate.ruleKey))],
      },
      ipAddress: input.actor.ipAddress ?? null,
      userAgent: input.actor.userAgent ?? null,
      requestId: input.actor.requestId ?? null,
    });

    return { ingested: facts.length, opened, updated, detections: [...candidates] };
  });

  return result;
}

export interface FlowView {
  id: string;
  connectorId: string | null;
  sourceAddress: string;
  sourcePort: number | null;
  destinationAddress: string;
  destinationPort: number | null;
  protocol: string;
  bytes: number;
  observedAt: string;
  segmentId: string | null;
}

const FLOW_SELECT = {
  id: true,
  connectorId: true,
  sourceAddress: true,
  sourcePort: true,
  destinationAddress: true,
  destinationPort: true,
  protocol: true,
  bytes: true,
  observedAt: true,
  segmentId: true,
} satisfies Prisma.NetworkFlowSelect;

export async function listFlows(
  organizationId: string,
  query: FlowListQuery,
): Promise<{ flows: FlowView[]; page: ReturnType<typeof paginationMeta> }> {
  const where: Prisma.NetworkFlowWhereInput = {
    organizationId,
    ...(query.sourceAddress ? { sourceAddress: query.sourceAddress } : {}),
    ...(query.destinationAddress ? { destinationAddress: query.destinationAddress } : {}),
    ...(query.protocol ? { protocol: query.protocol.toUpperCase() } : {}),
    ...(query.since ? { observedAt: { gte: query.since } } : {}),
  };

  const [total, rows] = await Promise.all([
    prisma.networkFlow.count({ where }),
    prisma.networkFlow.findMany({
      where,
      select: FLOW_SELECT,
      orderBy: { observedAt: 'desc' },
      skip: (query.page - 1) * query.pageSize,
      take: query.pageSize,
    }),
  ]);

  return {
    flows: rows.map((row) => ({
      ...row,
      observedAt: row.observedAt.toISOString(),
    })),
    page: paginationMeta(query.page, query.pageSize, total),
  };
}

export interface DetectionView {
  id: string;
  ruleKey: string;
  subjectKey: string;
  title: string;
  description: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  status: 'OPEN' | 'ACKNOWLEDGED' | 'CLOSED';
  observations: Record<string, unknown>;
  freshUntil: string;
  firstSeenAt: string;
  lastSeenAt: string;
  stale: boolean;
}

const DETECTION_SELECT = {
  id: true,
  ruleKey: true,
  subjectKey: true,
  title: true,
  description: true,
  severity: true,
  status: true,
  observations: true,
  freshUntil: true,
  firstSeenAt: true,
  lastSeenAt: true,
} satisfies Prisma.NetworkDetectionSelect;

type DetectionRow = Prisma.NetworkDetectionGetPayload<{ select: typeof DETECTION_SELECT }>;

function toDetectionView(row: DetectionRow, now: Date): DetectionView {
  return {
    id: row.id,
    ruleKey: row.ruleKey,
    subjectKey: row.subjectKey,
    title: row.title,
    description: row.description,
    severity: row.severity,
    status: row.status,
    observations:
      typeof row.observations === 'object' &&
      row.observations !== null &&
      !Array.isArray(row.observations)
        ? (row.observations as Record<string, unknown>)
        : {},
    freshUntil: row.freshUntil.toISOString(),
    firstSeenAt: row.firstSeenAt.toISOString(),
    lastSeenAt: row.lastSeenAt.toISOString(),
    stale: row.freshUntil.getTime() < now.getTime(),
  };
}

export async function listDetections(
  organizationId: string,
  query: DetectionListQuery,
): Promise<{ detections: DetectionView[]; page: ReturnType<typeof paginationMeta> }> {
  const where: Prisma.NetworkDetectionWhereInput = {
    organizationId,
    ...(query.status ? { status: query.status } : {}),
    ...(query.severity ? { severity: query.severity } : {}),
    ...(query.ruleKey ? { ruleKey: query.ruleKey } : {}),
    ...(query.q
      ? {
          OR: [
            { title: { contains: query.q, mode: 'insensitive' } },
            { subjectKey: { contains: query.q, mode: 'insensitive' } },
            { ruleKey: { contains: query.q, mode: 'insensitive' } },
          ],
        }
      : {}),
  };

  const [total, rows] = await Promise.all([
    prisma.networkDetection.count({ where }),
    prisma.networkDetection.findMany({
      where,
      select: DETECTION_SELECT,
      orderBy: [{ lastSeenAt: 'desc' }],
      skip: (query.page - 1) * query.pageSize,
      take: query.pageSize,
    }),
  ]);

  const now = new Date();
  return {
    detections: rows.map((row) => toDetectionView(row, now)),
    page: paginationMeta(query.page, query.pageSize, total),
  };
}

export async function getDetection(
  organizationId: string,
  detectionId: string,
): Promise<DetectionView> {
  const row = await prisma.networkDetection.findFirst({
    where: { id: detectionId, organizationId },
    select: DETECTION_SELECT,
  });
  if (!row) throw notFound('Detection not found in this organization.');
  return toDetectionView(row, new Date());
}

export async function updateDetectionStatus(
  ctx: TenantContext,
  detectionId: string,
  input: UpdateDetectionInput,
): Promise<DetectionView> {
  const organizationId = ctx.organization.id;
  const existing = await prisma.networkDetection.findFirst({
    where: { id: detectionId, organizationId },
    select: { id: true, title: true, status: true },
  });
  if (!existing) throw notFound('Detection not found in this organization.');
  if (existing.status === input.status) {
    throw conflict(`Detection is already ${input.status.toLowerCase()}.`);
  }

  const row = await prisma.$transaction(async (tx) => {
    const updated = await tx.networkDetection.update({
      where: { id: detectionId },
      data: { status: input.status },
      select: DETECTION_SELECT,
    });

    await appendAuditEvent(tx, {
      organizationId,
      actorType: 'USER',
      actorId: ctx.user.id,
      action: AuditActions.NETWORK_DETECTION_ACKNOWLEDGED,
      outcome: 'SUCCESS',
      targetType: 'network_detection',
      targetId: detectionId,
      summary: `Detection "${existing.title}" moved to ${input.status}`,
      metadata: { from: existing.status, to: input.status, note: input.note ?? null },
      ipAddress: ctx.meta.ipAddress,
      userAgent: ctx.meta.userAgent,
      requestId: ctx.meta.requestId,
    });

    return updated;
  });

  return toDetectionView(row, new Date());
}

// ---------------------------------------------------------------------------
// Admission
// ---------------------------------------------------------------------------

export interface AdmissionResult {
  decision: EvaluatedDecision;
  admission: AdmissionOutcome;
  segmentId: string | null;
}

/**
 * Posture-gated network admission.
 *
 * The verdict comes from the same decision point as any other request; this
 * function adds the network consequence. When the address falls inside a
 * segment, that segment's sensitivity is used instead of the one in the body,
 * because the caller does not get to describe where it sits.
 */
export async function admitDevice(input: {
  organizationId: string;
  request: AdmissionRequestInput;
}): Promise<AdmissionResult> {
  const sourceAddress = input.request.sourceAddress ?? null;
  const network = await resolveNetworkFacts(
    prisma,
    input.organizationId,
    sourceAddress,
    input.request.connectorId ?? null,
  );

  const evaluated = await evaluateDecision({
    organizationId: input.organizationId,
    network,
    request: {
      subject: input.request.subject,
      action: input.request.action,
      resource: {
        type: input.request.resource.type,
        id: input.request.resource.id ?? null,
        sensitivity: network.segmentSensitivity ?? input.request.resource.sensitivity,
      },
      deviceId: input.request.deviceId,
      sourceAddress,
      mfaSatisfied: input.request.mfaSatisfied,
      approvalState: 'NONE',
    },
  });

  const connector =
    network.connectorStatus === null
      ? null
      : { status: network.connectorStatus, failMode: network.connectorFailMode ?? 'CLOSED' };

  return {
    decision: evaluated,
    admission: mapAdmission({
      verdict: evaluated.outcome.verdict,
      requestedZone: input.request.requestedZone,
      connector,
    }),
    segmentId: network.segmentId,
  };
}

export interface NetworkOverview {
  connectors: { total: number; online: number; degraded: number; offline: number };
  segments: number;
  openDetections: { total: number; critical: number; high: number; medium: number; low: number };
  flows24h: number;
}

export async function getNetworkOverview(organizationId: string): Promise<NetworkOverview> {
  const since = new Date(Date.now() - 24 * 60 * 60 * 1000);
  const [connectors, segments, detections, flows24h] = await Promise.all([
    prisma.networkConnector.groupBy({
      by: ['status'],
      where: { organizationId },
      _count: { _all: true },
    }),
    prisma.networkSegment.count({ where: { organizationId } }),
    prisma.networkDetection.groupBy({
      by: ['severity'],
      where: { organizationId, status: { not: 'CLOSED' } },
      _count: { _all: true },
    }),
    prisma.networkFlow.count({ where: { organizationId, observedAt: { gte: since } } }),
  ]);

  const connectorCounts = new Map(connectors.map((entry) => [entry.status, entry._count._all]));
  const severityCounts = new Map(detections.map((entry) => [entry.severity, entry._count._all]));
  const critical = severityCounts.get('CRITICAL') ?? 0;
  const high = severityCounts.get('HIGH') ?? 0;
  const medium = severityCounts.get('MEDIUM') ?? 0;
  const low = severityCounts.get('LOW') ?? 0;

  return {
    connectors: {
      total: connectors.reduce((sum, entry) => sum + entry._count._all, 0),
      online: connectorCounts.get('ONLINE') ?? 0,
      degraded: connectorCounts.get('DEGRADED') ?? 0,
      offline: connectorCounts.get('OFFLINE') ?? 0,
    },
    segments,
    openDetections: { total: critical + high + medium + low, critical, high, medium, low },
    flows24h,
  };
}
