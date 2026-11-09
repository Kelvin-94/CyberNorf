import { createHash } from 'node:crypto';
import { Prisma, type AuditActorType, type AuditOutcome } from '@/generated/prisma/client';
import { prisma } from '@/lib/prisma';
import { canonicalize } from './canonical';

export const AuditActions = {
  ORGANIZATION_CREATED: 'organization.created',
  ORGANIZATION_UPDATED: 'organization.updated',
  MEMBER_ADDED: 'member.added',
  MEMBER_ROLE_CHANGED: 'member.role_changed',
  MEMBER_REMOVED: 'member.removed',
  ASSET_CREATED: 'asset.created',
  ASSET_UPDATED: 'asset.updated',
  ASSET_DELETED: 'asset.deleted',
  FINDING_CREATED: 'finding.created',
  FINDING_IMPORTED: 'finding.imported',
  FINDING_UPDATED: 'finding.updated',
  FINDING_STATUS_CHANGED: 'finding.status_changed',
  FINDING_DELETED: 'finding.deleted',
  INCIDENT_CREATED: 'incident.created',
  INCIDENT_UPDATED: 'incident.updated',
  INCIDENT_STATUS_CHANGED: 'incident.status_changed',
  INCIDENT_NOTE_ADDED: 'incident.note_added',
  INCIDENT_FINDING_LINKED: 'incident.finding_linked',
  INCIDENT_FINDING_UNLINKED: 'incident.finding_unlinked',
  COMPLIANCE_FRAMEWORK_ADOPTED: 'compliance.framework_adopted',
  COMPLIANCE_FRAMEWORK_WITHDRAWN: 'compliance.framework_withdrawn',
  COMPLIANCE_CONTROL_UPDATED: 'compliance.control_updated',
  COMPLIANCE_EVIDENCE_ADDED: 'compliance.evidence_added',
  COMPLIANCE_EVIDENCE_REMOVED: 'compliance.evidence_removed',
  AGENT_REGISTERED: 'agent.registered',
  AGENT_APPROVED: 'agent.approved',
  AGENT_SUSPENDED: 'agent.suspended',
  AGENT_RESUMED: 'agent.resumed',
  AGENT_REVOKED: 'agent.revoked',
  AGENT_RUN_RECORDED: 'agent.run_recorded',
  AGENT_CHECK_MAPPED: 'agent.check_mapped',
  AGENT_CHECK_UNMAPPED: 'agent.check_unmapped',
  ACCESS_DENIED: 'access.denied',
} as const;

export type AuditAction = (typeof AuditActions)[keyof typeof AuditActions];

export interface AuditEventInput {
  organizationId: string;
  actorType: AuditActorType;
  actorId?: string | null;
  action: AuditAction;
  outcome: AuditOutcome;
  targetType?: string | null;
  targetId?: string | null;
  summary?: string | null;
  metadata?: Prisma.InputJsonValue | null;
  ipAddress?: string | null;
  userAgent?: string | null;
  requestId?: string | null;
}

export interface AuditChainVerification {
  valid: boolean;
  checked: number;
  reason?: 'hash_mismatch' | 'link_mismatch' | 'sequence_gap';
  brokenAtSequence?: number;
}

type AuditTx = Prisma.TransactionClient | typeof prisma;

/** Serializes audit appends per organization so the chain stays linear. */
const AUDIT_LOCK_NAMESPACE = 0x43594e46; // "CYNF"

function hashPayload(prevHash: string | null, payload: Record<string, unknown>): string {
  return createHash('sha256')
    .update(prevHash ?? '')
    .update('\n')
    .update(canonicalize(payload))
    .digest('hex');
}

function buildPayload(event: {
  sequence: number;
  organizationId: string;
  actorType: AuditActorType;
  actorId: string | null;
  action: string;
  outcome: AuditOutcome;
  targetType: string | null;
  targetId: string | null;
  summary: string | null;
  metadata: Prisma.InputJsonValue | null;
  createdAt: Date;
}): Record<string, unknown> {
  return {
    sequence: event.sequence,
    organizationId: event.organizationId,
    actorType: event.actorType,
    actorId: event.actorId,
    action: event.action,
    outcome: event.outcome,
    targetType: event.targetType,
    targetId: event.targetId,
    summary: event.summary,
    metadata: event.metadata ?? null,
    createdAt: event.createdAt.toISOString(),
  };
}

/**
 * Appends one audit event. Pass the transaction client of the mutation being
 * audited so the change and its audit record commit atomically; if the audit
 * write fails the mutation is rolled back.
 */
export async function appendAuditEvent(tx: AuditTx, input: AuditEventInput): Promise<void> {
  // pg_advisory_xact_lock returns void, which Prisma cannot deserialize, so the
  // lock is taken in a subquery and a plain integer is selected instead.
  await tx.$queryRaw`SELECT 1::int AS locked FROM (SELECT pg_advisory_xact_lock(hashtextextended(${input.organizationId}, ${AUDIT_LOCK_NAMESPACE}))) AS audit_lock`;

  const previous = await tx.auditEvent.findFirst({
    where: { organizationId: input.organizationId },
    orderBy: { sequence: 'desc' },
    select: { sequence: true, hash: true },
  });

  const createdAt = new Date();
  const event = {
    sequence: (previous?.sequence ?? 0) + 1,
    organizationId: input.organizationId,
    actorType: input.actorType,
    actorId: input.actorId ?? null,
    action: input.action,
    outcome: input.outcome,
    targetType: input.targetType ?? null,
    targetId: input.targetId ?? null,
    summary: input.summary ?? null,
    metadata: input.metadata ?? null,
    createdAt,
  };

  const prevHash = previous?.hash ?? null;
  const payload = buildPayload(event);

  await tx.auditEvent.create({
    data: {
      ...event,
      // Nullable JSON columns need the explicit database null sentinel.
      metadata: event.metadata ?? Prisma.DbNull,
      ipAddress: input.ipAddress ?? null,
      userAgent: input.userAgent ?? null,
      requestId: input.requestId ?? null,
      prevHash,
      hash: hashPayload(prevHash, payload),
    },
  });
}

/** Appends an audit event without an enclosing transaction. */
export async function recordAuditEvent(input: AuditEventInput): Promise<void> {
  await prisma.$transaction(async (tx) => {
    await appendAuditEvent(tx, input);
  });
}

/**
 * Recomputes the hash chain for an organization. Mutating audit rows is blocked
 * by a database trigger, so a mismatch indicates out-of-band modification,
 * corrupted storage, or a defect in the append path.
 */
export async function verifyAuditChain(organizationId: string): Promise<AuditChainVerification> {
  const events = await prisma.auditEvent.findMany({
    where: { organizationId },
    orderBy: { sequence: 'asc' },
    select: {
      sequence: true,
      organizationId: true,
      actorType: true,
      actorId: true,
      action: true,
      outcome: true,
      targetType: true,
      targetId: true,
      summary: true,
      metadata: true,
      prevHash: true,
      hash: true,
      createdAt: true,
    },
  });

  let previousHash: string | null = null;
  let expectedSequence = 1;
  // Number of leading events proven intact; reported on failure so callers can
  // tell how much of the log still verifies.
  let verified = 0;

  for (const event of events) {
    if (event.sequence !== expectedSequence) {
      return {
        valid: false,
        checked: verified,
        reason: 'sequence_gap',
        brokenAtSequence: event.sequence,
      };
    }
    if (event.prevHash !== previousHash) {
      return {
        valid: false,
        checked: verified,
        reason: 'link_mismatch',
        brokenAtSequence: event.sequence,
      };
    }
    const expectedHash = hashPayload(
      previousHash,
      buildPayload({
        sequence: event.sequence,
        organizationId: event.organizationId,
        actorType: event.actorType,
        actorId: event.actorId,
        action: event.action,
        outcome: event.outcome,
        targetType: event.targetType,
        targetId: event.targetId,
        summary: event.summary,
        metadata: (event.metadata ?? null) as Prisma.InputJsonValue | null,
        createdAt: event.createdAt,
      }),
    );
    if (expectedHash !== event.hash) {
      return {
        valid: false,
        checked: verified,
        reason: 'hash_mismatch',
        brokenAtSequence: event.sequence,
      };
    }
    previousHash = event.hash;
    expectedSequence += 1;
    verified += 1;
  }

  return { valid: true, checked: verified };
}
