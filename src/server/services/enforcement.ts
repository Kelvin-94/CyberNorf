import { Prisma } from '@/generated/prisma/client';
import { prisma } from '@/lib/prisma';
import { AuditActions, appendAuditEvent } from '@/server/audit/audit';
import type { TenantContext } from '@/server/authz/context';
import {
  assertDistinctApprover,
  assertEnforcementTransition,
  enforcementTransitions,
  isTerminalEnforcementState,
  requiresSecondApprover,
  type EnforcementKindValue,
  type EnforcementStateValue,
} from '@/server/domain/zero-trust';
import { badRequest, conflict, notFound, forbidden } from '@/server/errors';
import type {
  EnforcementActionQuery,
  RequestEnforcementInput,
} from '@/server/validation/zero-trust';
import { isUniqueConstraintError, paginationMeta } from './shared';
import { asRecord, isoOrNull, mapZeroTrustFailure } from './zero-trust-support';

/**
 * Enforcement: the command channel from the platform to a connector.
 *
 * Every command is requested, approved by someone other than its requester,
 * dispatched, acknowledged by the connector, and then verified — the last two
 * as separate facts because an acknowledgement says "I received it" and a
 * verification says "I observed the effect". Idempotency is enforced by a
 * unique key per tenant so a retried request returns the original action
 * instead of issuing the command twice.
 *
 * Transitions use a compare-and-set on the current state, so two approvers
 * racing on the same request cannot both succeed.
 */

export interface EnforcementActor {
  type: 'USER' | 'SYSTEM';
  id: string | null;
  ipAddress?: string | null;
  userAgent?: string | null;
  requestId?: string | null;
}

export function actorFromContext(ctx: TenantContext): EnforcementActor {
  return {
    type: 'USER',
    id: ctx.user.id,
    ipAddress: ctx.meta.ipAddress,
    userAgent: ctx.meta.userAgent,
    requestId: ctx.meta.requestId,
  };
}

const ACTION_SELECT = {
  id: true,
  kind: true,
  targetType: true,
  targetId: true,
  targetLabel: true,
  connectorId: true,
  payload: true,
  idempotencyKey: true,
  state: true,
  reason: true,
  expiresAt: true,
  requestedById: true,
  approvedById: true,
  rejectedReason: true,
  dispatchedAt: true,
  acknowledgedAt: true,
  verifiedAt: true,
  failureReason: true,
  result: true,
  createdAt: true,
  updatedAt: true,
} satisfies Prisma.EnforcementActionSelect;

type ActionRow = Prisma.EnforcementActionGetPayload<{ select: typeof ACTION_SELECT }>;

export interface EnforcementView {
  id: string;
  kind: EnforcementKindValue;
  targetType: string;
  targetId: string;
  targetLabel: string;
  connectorId: string | null;
  payload: Record<string, unknown>;
  idempotencyKey: string;
  state: EnforcementStateValue;
  reason: string | null;
  expiresAt: string | null;
  expired: boolean;
  requestedById: string;
  approvedById: string | null;
  rejectedReason: string | null;
  dispatchedAt: string | null;
  acknowledgedAt: string | null;
  verifiedAt: string | null;
  failureReason: string | null;
  result: Record<string, unknown>;
  secondApproverRequired: boolean;
  terminal: boolean;
  transitions: EnforcementStateValue[];
  createdAt: string;
  updatedAt: string;
}

function toView(row: ActionRow, now: Date): EnforcementView {
  const expired =
    row.expiresAt !== null &&
    row.expiresAt.getTime() <= now.getTime() &&
    !isTerminalEnforcementState(row.state);
  return {
    id: row.id,
    kind: row.kind,
    targetType: row.targetType,
    targetId: row.targetId,
    targetLabel: row.targetLabel,
    connectorId: row.connectorId,
    payload: asRecord(row.payload),
    idempotencyKey: row.idempotencyKey,
    state: row.state,
    reason: row.reason,
    expiresAt: isoOrNull(row.expiresAt),
    expired,
    requestedById: row.requestedById,
    approvedById: row.approvedById,
    rejectedReason: row.rejectedReason,
    dispatchedAt: isoOrNull(row.dispatchedAt),
    acknowledgedAt: isoOrNull(row.acknowledgedAt),
    verifiedAt: isoOrNull(row.verifiedAt),
    failureReason: row.failureReason,
    result: asRecord(row.result),
    secondApproverRequired: requiresSecondApprover(row.kind),
    terminal: isTerminalEnforcementState(row.state),
    transitions: [...enforcementTransitions(row.state)],
    createdAt: row.createdAt.toISOString(),
    updatedAt: row.updatedAt.toISOString(),
  };
}

export interface RequestEnforcementResult {
  action: EnforcementView;
  /** True when the idempotency key matched an existing action. */
  replayed: boolean;
}

export async function requestEnforcement(
  ctx: TenantContext,
  input: RequestEnforcementInput,
): Promise<RequestEnforcementResult> {
  const organizationId = ctx.organization.id;

  const existing = await prisma.enforcementAction.findUnique({
    where: {
      organizationId_idempotencyKey: { organizationId, idempotencyKey: input.idempotencyKey },
    },
    select: ACTION_SELECT,
  });
  if (existing) {
    if (existing.kind !== input.kind || existing.targetId !== input.targetId) {
      throw conflict('That idempotency key was already used for a different action.');
    }
    return { action: toView(existing, new Date()), replayed: true };
  }

  if (input.connectorId) {
    const connector = await prisma.networkConnector.findFirst({
      where: { id: input.connectorId, organizationId },
      select: { id: true, name: true, capabilities: true },
    });
    if (!connector) throw notFound('Connector not found in this organization.');
    // A connector that declares capabilities only accepts those commands; an
    // empty list means the connector has not been narrowed yet.
    if (connector.capabilities.length > 0 && !connector.capabilities.includes(input.kind)) {
      throw badRequest(`Connector "${connector.name}" does not accept ${input.kind} commands.`);
    }
  }

  const expiresAt = new Date(Date.now() + input.expiresInSeconds * 1000);

  try {
    const row = await prisma.$transaction(async (tx) => {
      const created = await tx.enforcementAction.create({
        data: {
          organizationId,
          kind: input.kind,
          targetType: input.targetType,
          targetId: input.targetId,
          targetLabel: input.targetLabel,
          connectorId: input.connectorId ?? null,
          payload: input.payload as Prisma.InputJsonValue,
          idempotencyKey: input.idempotencyKey,
          state: 'REQUESTED',
          reason: input.reason ?? null,
          expiresAt,
          requestedById: ctx.user.id,
        },
        select: ACTION_SELECT,
      });

      await appendAuditEvent(tx, {
        organizationId,
        actorType: 'USER',
        actorId: ctx.user.id,
        action: AuditActions.ENFORCEMENT_REQUESTED,
        outcome: 'SUCCESS',
        targetType: created.targetType,
        targetId: created.targetId,
        summary: `Requested ${created.kind} on ${created.targetLabel}`,
        metadata: {
          actionId: created.id,
          kind: created.kind,
          connectorId: created.connectorId,
          secondApproverRequired: requiresSecondApprover(created.kind),
          expiresAt: expiresAt.toISOString(),
          reason: created.reason,
        },
        ipAddress: ctx.meta.ipAddress,
        userAgent: ctx.meta.userAgent,
        requestId: ctx.meta.requestId,
      });

      return created;
    });

    return { action: toView(row, new Date()), replayed: false };
  } catch (error) {
    if (isUniqueConstraintError(error)) {
      // A concurrent request with the same key won the race; return its row.
      const raced = await prisma.enforcementAction.findUnique({
        where: {
          organizationId_idempotencyKey: { organizationId, idempotencyKey: input.idempotencyKey },
        },
        select: ACTION_SELECT,
      });
      if (raced) return { action: toView(raced, new Date()), replayed: true };
    }
    throw error;
  }
}

async function loadAction(organizationId: string, actionId: string): Promise<ActionRow> {
  const row = await prisma.enforcementAction.findFirst({
    where: { id: actionId, organizationId },
    select: ACTION_SELECT,
  });
  if (!row) throw notFound('Enforcement action not found in this organization.');
  return row;
}

/**
 * A connector may only report on an action that was dispatched to it. Without
 * this check any connector token in the tenant could acknowledge, verify or
 * fail another gateway's command.
 */
export async function assertConnectorBound(
  organizationId: string,
  actionId: string,
  connectorId: string,
): Promise<void> {
  const action = await loadAction(organizationId, actionId);
  if (action.connectorId !== connectorId) {
    throw forbidden('This action is not bound to this connector.');
  }
}

/**
 * Compare-and-set transition. Returns false when another writer moved the row
 * first, which the callers surface as a conflict rather than retrying blindly.
 */
async function transition(
  tx: Prisma.TransactionClient,
  input: {
    id: string;
    organizationId: string;
    from: EnforcementStateValue;
    to: EnforcementStateValue;
    data?: Prisma.EnforcementActionUpdateManyMutationInput;
  },
): Promise<boolean> {
  const result = await tx.enforcementAction.updateMany({
    where: { id: input.id, organizationId: input.organizationId, state: input.from },
    data: { ...input.data, state: input.to },
  });
  return result.count === 1;
}

function assertNotExpired(row: ActionRow, now: Date): void {
  if (row.expiresAt !== null && row.expiresAt.getTime() <= now.getTime()) {
    throw conflict('This enforcement request expired before it was acted on.');
  }
}

export async function approveEnforcement(
  ctx: TenantContext,
  actionId: string,
  note?: string,
): Promise<EnforcementView> {
  const organizationId = ctx.organization.id;
  const existing = await loadAction(organizationId, actionId);
  const now = new Date();

  try {
    assertEnforcementTransition(existing.state, 'APPROVED');
    assertNotExpired(existing, now);
    assertDistinctApprover(existing.requestedById, ctx.user.id);
  } catch (error) {
    mapZeroTrustFailure(error);
  }

  const row = await prisma.$transaction(async (tx) => {
    const applied = await transition(tx, {
      id: actionId,
      organizationId,
      from: existing.state,
      to: 'APPROVED',
      data: { approvedById: ctx.user.id },
    });
    if (!applied) throw conflict('The action changed while it was being approved.');

    await appendAuditEvent(tx, {
      organizationId,
      actorType: 'USER',
      actorId: ctx.user.id,
      action: AuditActions.ENFORCEMENT_APPROVED,
      outcome: 'SUCCESS',
      targetType: existing.targetType,
      targetId: existing.targetId,
      summary: `Approved ${existing.kind} on ${existing.targetLabel}`,
      metadata: {
        actionId,
        kind: existing.kind,
        requestedById: existing.requestedById,
        secondApproverRequired: requiresSecondApprover(existing.kind),
        note: note ?? null,
      },
      ipAddress: ctx.meta.ipAddress,
      userAgent: ctx.meta.userAgent,
      requestId: ctx.meta.requestId,
    });

    return tx.enforcementAction.findUniqueOrThrow({
      where: { id: actionId },
      select: ACTION_SELECT,
    });
  });

  return toView(row, new Date());
}

export async function rejectEnforcement(
  ctx: TenantContext,
  actionId: string,
  reason: string,
): Promise<EnforcementView> {
  const organizationId = ctx.organization.id;
  const existing = await loadAction(organizationId, actionId);

  try {
    assertEnforcementTransition(existing.state, 'REJECTED');
  } catch (error) {
    mapZeroTrustFailure(error);
  }

  const row = await prisma.$transaction(async (tx) => {
    const applied = await transition(tx, {
      id: actionId,
      organizationId,
      from: existing.state,
      to: 'REJECTED',
      data: { rejectedReason: reason },
    });
    if (!applied) throw conflict('The action changed while it was being rejected.');

    await appendAuditEvent(tx, {
      organizationId,
      actorType: 'USER',
      actorId: ctx.user.id,
      action: AuditActions.ENFORCEMENT_REJECTED,
      outcome: 'SUCCESS',
      targetType: existing.targetType,
      targetId: existing.targetId,
      summary: `Rejected ${existing.kind} on ${existing.targetLabel}`,
      metadata: { actionId, kind: existing.kind, reason },
      ipAddress: ctx.meta.ipAddress,
      userAgent: ctx.meta.userAgent,
      requestId: ctx.meta.requestId,
    });

    return tx.enforcementAction.findUniqueOrThrow({
      where: { id: actionId },
      select: ACTION_SELECT,
    });
  });

  return toView(row, new Date());
}

export async function dispatchEnforcement(
  ctx: TenantContext,
  actionId: string,
): Promise<EnforcementView> {
  const organizationId = ctx.organization.id;
  const existing = await loadAction(organizationId, actionId);
  const now = new Date();

  try {
    assertEnforcementTransition(existing.state, 'DISPATCHED');
    assertNotExpired(existing, now);
  } catch (error) {
    mapZeroTrustFailure(error);
  }

  const row = await prisma.$transaction(async (tx) => {
    const applied = await transition(tx, {
      id: actionId,
      organizationId,
      from: existing.state,
      to: 'DISPATCHED',
      data: { dispatchedAt: now },
    });
    if (!applied) throw conflict('The action changed while it was being dispatched.');

    await appendAuditEvent(tx, {
      organizationId,
      actorType: 'USER',
      actorId: ctx.user.id,
      action: AuditActions.ENFORCEMENT_DISPATCHED,
      outcome: 'SUCCESS',
      targetType: existing.targetType,
      targetId: existing.targetId,
      summary: `Dispatched ${existing.kind} on ${existing.targetLabel}`,
      metadata: { actionId, kind: existing.kind, connectorId: existing.connectorId },
      ipAddress: ctx.meta.ipAddress,
      userAgent: ctx.meta.userAgent,
      requestId: ctx.meta.requestId,
    });

    return tx.enforcementAction.findUniqueOrThrow({
      where: { id: actionId },
      select: ACTION_SELECT,
    });
  });

  return toView(row, new Date());
}

/**
 * The connector reports that it received and applied the command. That is not
 * the same claim as the effect having been observed, which is what
 * `verifyEnforcement` records.
 */
export async function acknowledgeEnforcement(
  actor: EnforcementActor,
  organizationId: string,
  actionId: string,
  result: Record<string, unknown>,
): Promise<EnforcementView> {
  const existing = await loadAction(organizationId, actionId);

  try {
    assertEnforcementTransition(existing.state, 'ACKNOWLEDGED');
  } catch (error) {
    mapZeroTrustFailure(error);
  }

  const now = new Date();
  const row = await prisma.$transaction(async (tx) => {
    const applied = await transition(tx, {
      id: actionId,
      organizationId,
      from: existing.state,
      to: 'ACKNOWLEDGED',
      data: { acknowledgedAt: now, result: result as Prisma.InputJsonValue },
    });
    if (!applied) throw conflict('The action changed while it was being acknowledged.');

    await appendAuditEvent(tx, {
      organizationId,
      actorType: actor.type,
      actorId: actor.id,
      action: AuditActions.ENFORCEMENT_ACKNOWLEDGED,
      outcome: 'SUCCESS',
      targetType: existing.targetType,
      targetId: existing.targetId,
      summary: `Acknowledged ${existing.kind} on ${existing.targetLabel}`,
      metadata: {
        actionId,
        kind: existing.kind,
        connectorId: existing.connectorId,
        result: result as Prisma.InputJsonValue,
      },
      ipAddress: actor.ipAddress ?? null,
      userAgent: actor.userAgent ?? null,
      requestId: actor.requestId ?? null,
    });

    return tx.enforcementAction.findUniqueOrThrow({
      where: { id: actionId },
      select: ACTION_SELECT,
    });
  });

  return toView(row, new Date());
}

/** Records that the effect was observed, not merely that the command landed. */
export async function verifyEnforcement(
  actor: EnforcementActor,
  organizationId: string,
  actionId: string,
): Promise<EnforcementView> {
  const existing = await loadAction(organizationId, actionId);

  try {
    assertEnforcementTransition(existing.state, 'VERIFIED');
  } catch (error) {
    mapZeroTrustFailure(error);
  }

  const now = new Date();
  const row = await prisma.$transaction(async (tx) => {
    const applied = await transition(tx, {
      id: actionId,
      organizationId,
      from: existing.state,
      to: 'VERIFIED',
      data: { verifiedAt: now },
    });
    if (!applied) throw conflict('The action changed while it was being verified.');

    await appendAuditEvent(tx, {
      organizationId,
      actorType: actor.type,
      actorId: actor.id,
      action: AuditActions.ENFORCEMENT_VERIFIED,
      outcome: 'SUCCESS',
      targetType: existing.targetType,
      targetId: existing.targetId,
      summary: `Verified ${existing.kind} on ${existing.targetLabel}`,
      metadata: {
        actionId,
        kind: existing.kind,
        dispatchedAt: isoOrNull(existing.dispatchedAt),
        acknowledgedAt: isoOrNull(existing.acknowledgedAt),
      },
      ipAddress: actor.ipAddress ?? null,
      userAgent: actor.userAgent ?? null,
      requestId: actor.requestId ?? null,
    });

    return tx.enforcementAction.findUniqueOrThrow({
      where: { id: actionId },
      select: ACTION_SELECT,
    });
  });

  return toView(row, new Date());
}

export async function failEnforcement(
  actor: EnforcementActor,
  organizationId: string,
  actionId: string,
  reason: string,
): Promise<EnforcementView> {
  const existing = await loadAction(organizationId, actionId);

  try {
    assertEnforcementTransition(existing.state, 'FAILED');
  } catch (error) {
    mapZeroTrustFailure(error);
  }

  const row = await prisma.$transaction(async (tx) => {
    const applied = await transition(tx, {
      id: actionId,
      organizationId,
      from: existing.state,
      to: 'FAILED',
      data: { failureReason: reason },
    });
    if (!applied) throw conflict('The action changed while it was being failed.');

    await appendAuditEvent(tx, {
      organizationId,
      actorType: actor.type,
      actorId: actor.id,
      action: AuditActions.ENFORCEMENT_FAILED,
      outcome: 'FAILURE',
      targetType: existing.targetType,
      targetId: existing.targetId,
      summary: `Failed ${existing.kind} on ${existing.targetLabel}`,
      metadata: { actionId, kind: existing.kind, reason },
      ipAddress: actor.ipAddress ?? null,
      userAgent: actor.userAgent ?? null,
      requestId: actor.requestId ?? null,
    });

    return tx.enforcementAction.findUniqueOrThrow({
      where: { id: actionId },
      select: ACTION_SELECT,
    });
  });

  return toView(row, new Date());
}

export async function listEnforcementActions(
  organizationId: string,
  query: EnforcementActionQuery,
): Promise<{ actions: EnforcementView[]; page: ReturnType<typeof paginationMeta> }> {
  const where: Prisma.EnforcementActionWhereInput = {
    organizationId,
    ...(query.state ? { state: query.state } : {}),
    ...(query.kind ? { kind: query.kind } : {}),
    ...(query.q
      ? {
          OR: [
            { targetLabel: { contains: query.q, mode: 'insensitive' } },
            { targetId: { contains: query.q, mode: 'insensitive' } },
            { idempotencyKey: { contains: query.q, mode: 'insensitive' } },
          ],
        }
      : {}),
  };

  const [total, rows] = await Promise.all([
    prisma.enforcementAction.count({ where }),
    prisma.enforcementAction.findMany({
      where,
      select: ACTION_SELECT,
      orderBy: { createdAt: 'desc' },
      skip: (query.page - 1) * query.pageSize,
      take: query.pageSize,
    }),
  ]);

  const now = new Date();
  return {
    actions: rows.map((row) => toView(row, now)),
    page: paginationMeta(query.page, query.pageSize, total),
  };
}

export async function getEnforcementAction(
  organizationId: string,
  actionId: string,
): Promise<EnforcementView> {
  return toView(await loadAction(organizationId, actionId), new Date());
}

/**
 * The queue a connector polls: only commands dispatched to it, never another
 * gateway's actions inside the same tenant. Bounded because a connector that
 * fell behind should catch up gradually rather than receive an unbounded batch.
 */
export async function listConnectorQueue(
  organizationId: string,
  connectorId: string,
): Promise<{ actions: EnforcementView[] }> {
  const rows = await prisma.enforcementAction.findMany({
    where: { organizationId, connectorId, state: 'DISPATCHED' },
    select: ACTION_SELECT,
    orderBy: { dispatchedAt: 'asc' },
    take: 100,
  });
  const now = new Date();
  return { actions: rows.map((row) => toView(row, now)) };
}

/**
 * Expires requests nobody acted on. Dispatched commands expire too: a command
 * that never produced an acknowledgement must not remain armed indefinitely.
 * Bounded per run so a sweep cannot hold a transaction open for the whole table.
 */
export async function expireStaleEnforcementActions(options?: {
  organizationId?: string;
  limit?: number;
  now?: Date;
}): Promise<{ expired: number }> {
  const now = options?.now ?? new Date();
  const limit = Math.min(Math.max(options?.limit ?? 200, 1), 1000);

  const stale = await prisma.enforcementAction.findMany({
    where: {
      ...(options?.organizationId ? { organizationId: options.organizationId } : {}),
      state: { in: ['REQUESTED', 'APPROVED', 'DISPATCHED'] },
      expiresAt: { lt: now },
    },
    select: { id: true, organizationId: true },
    orderBy: { expiresAt: 'asc' },
    take: limit,
  });

  let expired = 0;
  for (const action of stale) {
    const didExpire = await prisma.$transaction(async (tx) => {
      const applied = await tx.enforcementAction.updateMany({
        where: {
          id: action.id,
          organizationId: action.organizationId,
          state: { in: ['REQUESTED', 'APPROVED', 'DISPATCHED'] },
        },
        data: { state: 'EXPIRED' },
      });
      if (applied.count !== 1) return false;

      await appendAuditEvent(tx, {
        organizationId: action.organizationId,
        actorType: 'SYSTEM',
        actorId: null,
        action: AuditActions.ENFORCEMENT_EXPIRED,
        outcome: 'SUCCESS',
        targetType: 'enforcement_action',
        targetId: action.id,
        summary: 'Enforcement request expired',
        metadata: { actionId: action.id },
      });
      return true;
    });
    if (didExpire) expired += 1;
  }

  return { expired };
}

export function assertConnectorActor(actor: EnforcementActor): void {
  if (actor.type !== 'SYSTEM' || actor.id === null) {
    throw forbidden('This operation requires a connector credential.');
  }
}
