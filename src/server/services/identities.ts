import { Prisma } from '@/generated/prisma/client';
import { prisma } from '@/lib/prisma';
import { AuditActions, appendAuditEvent } from '@/server/audit/audit';
import { AuthEventActions } from '@/server/auth/events';
import type { TenantContext } from '@/server/authz/context';
import { can } from '@/server/authz/roles';
import {
  canTransitionIdentity,
  evaluateIdentityRisk,
  hashIdentityCredential,
  initialIdentityStatus,
  isIdentityCredentialScope,
  isIdentityCredentialShape,
  issueIdentityCredential as mintIdentityCredential,
  normalizeIdentityIdentifier,
  type IdentityCredentialScope,
  type IdentityRisk,
} from '@/server/domain/identity';
import { badRequest, conflict, forbidden, notFound } from '@/server/errors';
import type {
  CreateIdentityInput,
  IdentityLifecycleInput,
  IdentityListQuery,
  IssueIdentityCredentialInput,
  UpdateIdentityInput,
} from '@/server/validation/identities';
import { assertQuotaAvailable } from './quotas';
import { isUniqueConstraintError, paginationMeta } from './shared';

/**
 * Identity governance service.
 *
 * The inventory is a governance record layered on top of Better Auth: it never
 * stores a console password or session, and it never widens what a membership
 * can do. Machine credentials are minted here, stored only as SHA-256 hashes and
 * verified through their own bearer endpoint. Every mutation writes both the
 * tenant audit chain and an object-level identity event so the timeline of an
 * identity can be reconstructed without reading another tenant's data.
 */

const MAX_ACTIVE_CREDENTIALS = 5;
const CREDENTIAL_WARNING_DAYS = 30;
const DORMANT_DAYS = 90;
const LAST_SEEN_WRITE_INTERVAL_MS = 60_000;

const USER_BRIEF_SELECT = {
  id: true,
  name: true,
  email: true,
} as const;

const IDENTITY_LIST_SELECT = {
  id: true,
  kind: true,
  type: true,
  displayName: true,
  identifier: true,
  department: true,
  criticality: true,
  status: true,
  source: true,
  approvedScopes: true,
  credentialTtlDays: true,
  lastSeenAt: true,
  createdAt: true,
  updatedAt: true,
  ownerUserId: true,
  linkedUserId: true,
  owner: { select: USER_BRIEF_SELECT },
  linkedUser: { select: USER_BRIEF_SELECT },
  credentials: {
    where: { revokedAt: null },
    select: { id: true, expiresAt: true },
  },
} satisfies Prisma.IdentitySelect;

const IDENTITY_DETAIL_SELECT = {
  ...IDENTITY_LIST_SELECT,
  description: true,
  approvedAt: true,
  suspendedAt: true,
  deprovisionedAt: true,
  createdBy: { select: USER_BRIEF_SELECT },
  approvedBy: { select: USER_BRIEF_SELECT },
  credentials: {
    orderBy: [{ revokedAt: 'asc' }, { createdAt: 'desc' }],
    select: {
      id: true,
      name: true,
      keyPrefix: true,
      scopes: true,
      expiresAt: true,
      lastUsedAt: true,
      revokedAt: true,
      revokedReason: true,
      createdAt: true,
      createdBy: { select: USER_BRIEF_SELECT },
    },
  },
  events: {
    orderBy: { createdAt: 'desc' },
    take: 100,
    select: {
      id: true,
      type: true,
      summary: true,
      metadata: true,
      createdAt: true,
      actor: { select: USER_BRIEF_SELECT },
    },
  },
} satisfies Prisma.IdentitySelect;

type IdentityListRow = Prisma.IdentityGetPayload<{ select: typeof IDENTITY_LIST_SELECT }>;
type IdentityDetailRow = Prisma.IdentityGetPayload<{ select: typeof IDENTITY_DETAIL_SELECT }>;
type Db = Prisma.TransactionClient | typeof prisma;

export interface IdentityUserRef {
  id: string;
  name: string;
  email: string;
}

export type CredentialStatus = 'ACTIVE' | 'EXPIRED' | 'REVOKED';

export interface IdentityCredentialView {
  id: string;
  name: string;
  prefix: string;
  scopes: string[];
  status: CredentialStatus;
  expiresAt: string;
  lastUsedAt: string | null;
  revokedAt: string | null;
  revokedReason: string | null;
  createdAt: string;
  createdBy: IdentityUserRef | null;
}

export interface IdentityEventView {
  id: string;
  type: string;
  summary: string | null;
  metadata: Prisma.JsonValue;
  createdAt: string;
  actor: IdentityUserRef | null;
}

export interface IdentitySummary {
  id: string;
  kind: 'HUMAN' | 'MACHINE';
  type: string;
  displayName: string;
  identifier: string;
  department: string | null;
  criticality: string;
  status: 'PENDING_APPROVAL' | 'ACTIVE' | 'SUSPENDED' | 'DEPROVISIONED';
  source: string;
  approvedScopes: string[];
  credentialTtlDays: number;
  owner: IdentityUserRef | null;
  linkedUser: IdentityUserRef | null;
  lastSeenAt: string | null;
  createdAt: string;
  updatedAt: string;
  risk: IdentityRisk;
}

export interface IdentityDetail extends IdentitySummary {
  description: string | null;
  approvedAt: string | null;
  suspendedAt: string | null;
  deprovisionedAt: string | null;
  createdBy: IdentityUserRef | null;
  approvedBy: IdentityUserRef | null;
  credentials: IdentityCredentialView[];
  events: IdentityEventView[];
  /** Derived counters only; raw authentication events stay outside the tenant. */
  activity: {
    lastSignInAt: string | null;
    lastSessionAt: string | null;
    failedSignInsLast24h: number;
    activeSessions: number;
  };
}

export interface IdentityOverview {
  counts: {
    total: number;
    human: number;
    machine: number;
    active: number;
    pendingApproval: number;
    suspended: number;
    deprovisioned: number;
  };
  attention: {
    pendingApprovals: number;
    unownedMachines: number;
    expiringCredentials: number;
    nonCompliantIdentities: number;
  };
}

export interface IdentityPage {
  items: IdentitySummary[];
  pagination: ReturnType<typeof paginationMeta>;
}

export interface MachineIdentityPrincipal {
  identityId: string;
  organizationId: string;
  credentialId: string;
  scopes: string[];
}

interface RiskContext {
  membershipStatus: Map<string, string>;
  failedAuth: Map<string, number>;
  activeSessions: Map<string, number>;
  lastSessionAt: Map<string, Date>;
}

function iso(value: Date | null): string | null {
  return value ? value.toISOString() : null;
}

function toUserRef(user: IdentityUserRef | null): IdentityUserRef | null {
  return user ? { id: user.id, name: user.name, email: user.email } : null;
}

function credentialStatus(
  row: { revokedAt: Date | null; expiresAt: Date },
  now: Date,
): CredentialStatus {
  if (row.revokedAt) {
    return 'REVOKED';
  }
  return row.expiresAt.getTime() <= now.getTime() ? 'EXPIRED' : 'ACTIVE';
}

function activeCredentials(row: { credentials: Array<{ expiresAt: Date }> }): Array<{
  expiresAt: Date;
}> {
  return row.credentials;
}

function toSummary(row: IdentityListRow, riskContext: RiskContext, now: Date): IdentitySummary {
  const membership = row.linkedUserId
    ? riskContext.membershipStatus.get(row.linkedUserId)
    : undefined;
  const sessions = row.linkedUserId ? riskContext.activeSessions.get(row.linkedUserId) : undefined;
  const lastSession = row.linkedUserId
    ? riskContext.lastSessionAt.get(row.linkedUserId)
    : undefined;
  const failed = row.linkedUserId ? riskContext.failedAuth.get(row.linkedUserId) : undefined;

  const lastActivityCandidates = [row.lastSeenAt, lastSession].filter(
    (value): value is Date => value instanceof Date,
  );
  const lastActivityAt =
    lastActivityCandidates.length === 0
      ? null
      : new Date(Math.max(...lastActivityCandidates.map((value) => value.getTime())));

  const risk = evaluateIdentityRisk({
    kind: row.kind,
    status: row.status,
    createdAt: row.createdAt,
    ownerUserId: row.ownerUserId,
    linkedUserId: row.linkedUserId,
    linkedMembershipStatus: membership ?? null,
    lastActivityAt,
    failedAuthLast24h: failed ?? 0,
    activeSessions: sessions ?? 0,
    credentials: activeCredentials(row),
    now,
  });

  return {
    id: row.id,
    kind: row.kind,
    type: row.type,
    displayName: row.displayName,
    identifier: row.identifier,
    department: row.department,
    criticality: row.criticality,
    status: row.status,
    source: row.source,
    approvedScopes: [...row.approvedScopes],
    credentialTtlDays: row.credentialTtlDays,
    owner: toUserRef(row.owner),
    linkedUser: toUserRef(row.linkedUser),
    lastSeenAt: iso(row.lastSeenAt),
    createdAt: row.createdAt.toISOString(),
    updatedAt: row.updatedAt.toISOString(),
    risk,
  };
}

function toDetail(
  row: IdentityDetailRow,
  riskContext: RiskContext,
  now: Date,
  activity: IdentityDetail['activity'],
): IdentityDetail {
  return {
    ...toSummary(row, riskContext, now),
    description: row.description,
    approvedAt: iso(row.approvedAt),
    suspendedAt: iso(row.suspendedAt),
    deprovisionedAt: iso(row.deprovisionedAt),
    createdBy: toUserRef(row.createdBy),
    approvedBy: toUserRef(row.approvedBy),
    credentials: row.credentials.map((credential) => ({
      id: credential.id,
      name: credential.name,
      prefix: credential.keyPrefix,
      scopes: [...credential.scopes],
      status: credentialStatus(credential, now),
      expiresAt: credential.expiresAt.toISOString(),
      lastUsedAt: iso(credential.lastUsedAt),
      revokedAt: iso(credential.revokedAt),
      revokedReason: credential.revokedReason,
      createdAt: credential.createdAt.toISOString(),
      createdBy: toUserRef(credential.createdBy),
    })),
    events: row.events.map((event) => ({
      id: event.id,
      type: event.type,
      summary: event.summary,
      metadata: event.metadata,
      createdAt: event.createdAt.toISOString(),
      actor: toUserRef(event.actor),
    })),
    activity,
  };
}

async function loadRiskContext(
  db: Db,
  organizationId: string,
  linkedUserIds: string[],
  now: Date,
): Promise<RiskContext> {
  const ids = [...new Set(linkedUserIds)];
  const membershipStatus = new Map<string, string>();
  const failedAuth = new Map<string, number>();
  const activeSessions = new Map<string, number>();
  const lastSessionAt = new Map<string, Date>();

  if (ids.length === 0) {
    return { membershipStatus, failedAuth, activeSessions, lastSessionAt };
  }

  const since = new Date(now.getTime() - 24 * 60 * 60 * 1000);

  const [memberships, failures, sessions] = await Promise.all([
    db.membership.findMany({
      where: { organizationId, userId: { in: ids } },
      select: { userId: true, status: true },
    }),
    db.authEvent.groupBy({
      by: ['userId'],
      where: {
        userId: { in: ids },
        action: AuthEventActions.SIGN_IN_FAILED,
        outcome: 'FAILURE',
        createdAt: { gte: since },
      },
      _count: { _all: true },
    }),
    db.session.groupBy({
      by: ['userId'],
      where: { userId: { in: ids }, expiresAt: { gt: now } },
      _count: { _all: true },
      _max: { createdAt: true },
    }),
  ]);

  for (const membership of memberships) {
    // A user has at most one membership per organization, so the last write is
    // also the only one.
    membershipStatus.set(membership.userId, membership.status);
  }
  for (const failure of failures) {
    if (failure.userId) {
      failedAuth.set(failure.userId, failure._count._all);
    }
  }
  for (const session of sessions) {
    activeSessions.set(session.userId, session._count._all);
    if (session._max.createdAt) {
      lastSessionAt.set(session.userId, session._max.createdAt);
    }
  }

  return { membershipStatus, failedAuth, activeSessions, lastSessionAt };
}

async function loadActivity(
  db: Db,
  userId: string | null,
  now: Date,
): Promise<IdentityDetail['activity']> {
  if (!userId) {
    return {
      lastSignInAt: null,
      lastSessionAt: null,
      failedSignInsLast24h: 0,
      activeSessions: 0,
    };
  }

  const since = new Date(now.getTime() - 24 * 60 * 60 * 1000);
  const [lastSignIn, failures, sessions, lastSession] = await Promise.all([
    db.authEvent.findFirst({
      where: { userId, action: AuthEventActions.SIGNED_IN, outcome: 'SUCCESS' },
      orderBy: { createdAt: 'desc' },
      select: { createdAt: true },
    }),
    db.authEvent.count({
      where: {
        userId,
        action: AuthEventActions.SIGN_IN_FAILED,
        outcome: 'FAILURE',
        createdAt: { gte: since },
      },
    }),
    db.session.count({ where: { userId, expiresAt: { gt: now } } }),
    db.session.findFirst({
      where: { userId },
      orderBy: { createdAt: 'desc' },
      select: { createdAt: true },
    }),
  ]);

  return {
    lastSignInAt: iso(lastSignIn?.createdAt ?? null),
    lastSessionAt: iso(lastSession?.createdAt ?? null),
    failedSignInsLast24h: failures,
    activeSessions: sessions,
  };
}

async function loadIdentityDetail(
  db: Db,
  organizationId: string,
  identityId: string,
  now: Date,
): Promise<IdentityDetail | null> {
  const row = await db.identity.findFirst({
    where: { id: identityId, organizationId },
    select: IDENTITY_DETAIL_SELECT,
  });
  if (!row) {
    return null;
  }
  const [riskContext, activity] = await Promise.all([
    loadRiskContext(db, organizationId, row.linkedUserId ? [row.linkedUserId] : [], now),
    loadActivity(db, row.linkedUserId, now),
  ]);
  return toDetail(row, riskContext, now, activity);
}

async function assertActiveMember(organizationId: string, userId: string): Promise<void> {
  const membership = await prisma.membership.findFirst({
    where: { organizationId, userId, status: 'ACTIVE' },
    select: { id: true },
  });
  if (!membership) {
    throw badRequest('The selected user must be an active member of this organization.');
  }
}

async function assertLinkableUser(
  organizationId: string,
  userId: string,
  identityId?: string,
): Promise<void> {
  await assertActiveMember(organizationId, userId);
  const existing = await prisma.identity.findFirst({
    where: {
      organizationId,
      linkedUserId: userId,
      ...(identityId ? { id: { not: identityId } } : {}),
    },
    select: { id: true, displayName: true },
  });
  if (existing) {
    throw conflict(`That account is already linked to another identity (${existing.displayName}).`);
  }
}

function normalizeScopes(scopes: readonly string[]): IdentityCredentialScope[] {
  const unique = [...new Set(scopes)];
  for (const scope of unique) {
    if (!isIdentityCredentialScope(scope)) {
      throw badRequest(`Unknown credential scope: ${scope}.`);
    }
  }
  return unique as IdentityCredentialScope[];
}

function isSubset(requested: readonly string[], approved: readonly string[]): boolean {
  return requested.every((scope) => approved.includes(scope));
}

async function writeIdentityEvent(
  tx: Prisma.TransactionClient,
  input: {
    organizationId: string;
    identityId: string;
    type: Prisma.IdentityEventCreateInput['type'];
    actorId: string;
    summary: string;
    metadata?: Prisma.InputJsonValue;
  },
): Promise<void> {
  await tx.identityEvent.create({
    data: {
      organizationId: input.organizationId,
      identityId: input.identityId,
      type: input.type,
      actorId: input.actorId,
      summary: input.summary,
      ...(input.metadata !== undefined ? { metadata: input.metadata } : {}),
    },
  });
}

// ---------------------------------------------------------------------------
// Read paths
// ---------------------------------------------------------------------------

export async function getIdentityOverview(organizationId: string): Promise<IdentityOverview> {
  const now = new Date();
  const warningCutoff = new Date(now.getTime() + CREDENTIAL_WARNING_DAYS * 24 * 60 * 60 * 1000);
  const dormantCutoff = new Date(now.getTime() - DORMANT_DAYS * 24 * 60 * 60 * 1000);

  const [grouped, pendingApprovals, unownedMachines, expiringCredentials, dormantIdentities] =
    await Promise.all([
      prisma.identity.groupBy({
        by: ['kind', 'status'],
        where: { organizationId },
        _count: { _all: true },
      }),
      prisma.identity.count({
        where: { organizationId, kind: 'MACHINE', status: 'PENDING_APPROVAL' },
      }),
      prisma.identity.count({
        where: {
          organizationId,
          kind: 'MACHINE',
          ownerUserId: null,
          status: { not: 'DEPROVISIONED' },
        },
      }),
      prisma.identityCredential.count({
        where: {
          organizationId,
          revokedAt: null,
          expiresAt: { gt: now, lte: warningCutoff },
          identity: { status: 'ACTIVE' },
        },
      }),
      prisma.identity.count({
        where: {
          organizationId,
          status: { not: 'DEPROVISIONED' },
          OR: [
            { lastSeenAt: null, createdAt: { lte: dormantCutoff } },
            { lastSeenAt: { lte: dormantCutoff } },
          ],
        },
      }),
    ]);

  const counts = {
    total: 0,
    human: 0,
    machine: 0,
    active: 0,
    pendingApproval: 0,
    suspended: 0,
    deprovisioned: 0,
  };

  for (const group of grouped) {
    const count = group._count._all;
    counts.total += count;
    if (group.kind === 'HUMAN') {
      counts.human += count;
    } else {
      counts.machine += count;
    }
    if (group.status === 'ACTIVE') counts.active += count;
    if (group.status === 'PENDING_APPROVAL') counts.pendingApproval += count;
    if (group.status === 'SUSPENDED') counts.suspended += count;
    if (group.status === 'DEPROVISIONED') counts.deprovisioned += count;
  }

  return {
    counts,
    attention: {
      pendingApprovals,
      unownedMachines,
      expiringCredentials,
      nonCompliantIdentities: dormantIdentities,
    },
  };
}

export async function listIdentities(
  organizationId: string,
  query: IdentityListQuery,
): Promise<IdentityPage> {
  const now = new Date();
  const where: Prisma.IdentityWhereInput = {
    organizationId,
    ...(query.kind ? { kind: query.kind } : {}),
    ...(query.type ? { type: query.type } : {}),
    ...(query.status ? { status: query.status } : {}),
    ...(query.search
      ? {
          OR: [
            { displayName: { contains: query.search, mode: 'insensitive' as const } },
            { identifier: { contains: query.search, mode: 'insensitive' as const } },
            { department: { contains: query.search, mode: 'insensitive' as const } },
          ],
        }
      : {}),
  };

  const orderBy: Prisma.IdentityOrderByWithRelationInput =
    query.sort === 'lastSeenAt'
      ? { lastSeenAt: { sort: query.direction, nulls: 'last' } }
      : { [query.sort]: query.direction };

  const [total, rows] = await Promise.all([
    prisma.identity.count({ where }),
    prisma.identity.findMany({
      where,
      select: IDENTITY_LIST_SELECT,
      orderBy: [orderBy, { id: 'asc' }],
      skip: (query.page - 1) * query.pageSize,
      take: query.pageSize,
    }),
  ]);

  const linkedUserIds = rows
    .map((row) => row.linkedUserId)
    .filter((value): value is string => value !== null);
  const riskContext = await loadRiskContext(prisma, organizationId, linkedUserIds, now);

  return {
    items: rows.map((row) => toSummary(row, riskContext, now)),
    pagination: paginationMeta(query.page, query.pageSize, total),
  };
}

export async function getIdentityDetail(
  organizationId: string,
  identityId: string,
): Promise<IdentityDetail> {
  const detail = await loadIdentityDetail(prisma, organizationId, identityId, new Date());
  if (!detail) {
    throw notFound('Identity not found.');
  }
  return detail;
}

export interface AssignableMember {
  userId: string;
  name: string;
  email: string;
  role: string;
}

/**
 * People who can own an identity or be linked to one. Only active memberships
 * are offered, matching the service-side validation.
 */
export async function listAssignableMembers(organizationId: string): Promise<AssignableMember[]> {
  const memberships = await prisma.membership.findMany({
    where: { organizationId, status: 'ACTIVE' },
    select: { role: true, user: { select: USER_BRIEF_SELECT } },
    orderBy: { user: { name: 'asc' } },
    take: 500,
  });
  return memberships.map((membership) => ({
    userId: membership.user.id,
    name: membership.user.name,
    email: membership.user.email,
    role: membership.role,
  }));
}

// ---------------------------------------------------------------------------
// Writes
// ---------------------------------------------------------------------------

export async function createIdentity(
  ctx: TenantContext,
  input: CreateIdentityInput,
): Promise<IdentityDetail> {
  const organizationId = ctx.organization.id;
  const identifier = normalizeIdentityIdentifier(input.identifier);

  if (input.ownerUserId) {
    await assertActiveMember(organizationId, input.ownerUserId);
  }
  if (input.linkedUserId) {
    await assertLinkableUser(organizationId, input.linkedUserId);
  }

  let linkedUserId = input.linkedUserId ?? null;
  if (input.kind === 'HUMAN' && linkedUserId === null && identifier.includes('@')) {
    const user = await prisma.user.findFirst({
      where: { email: { equals: identifier, mode: 'insensitive' } },
      select: { id: true },
    });
    if (user) {
      const membership = await prisma.membership.findFirst({
        where: { organizationId, userId: user.id, status: 'ACTIVE' },
        select: { id: true },
      });
      if (membership) {
        linkedUserId = user.id;
      }
    }
  }

  const approvedScopes =
    input.kind === 'MACHINE' ? normalizeScopes(input.approvedScopes ?? []) : [];

  const now = new Date();

  try {
    const created = await prisma.$transaction(async (tx) => {
      await assertQuotaAvailable(tx, {
        organizationId,
        tier: ctx.organization.tier,
        resource: 'identities',
      });

      const identity = await tx.identity.create({
        data: {
          organizationId,
          kind: input.kind,
          type: input.type,
          displayName: input.displayName,
          identifier,
          criticality: input.criticality,
          source: input.source,
          status: initialIdentityStatus(input.kind),
          approvedScopes,
          credentialTtlDays: input.credentialTtlDays,
          createdById: ctx.user.id,
          ...(input.description !== undefined ? { description: input.description } : {}),
          ...(input.department !== undefined ? { department: input.department } : {}),
          ...(input.ownerUserId ? { ownerUserId: input.ownerUserId } : {}),
          ...(linkedUserId ? { linkedUserId } : {}),
        },
        select: { id: true },
      });

      await writeIdentityEvent(tx, {
        organizationId,
        identityId: identity.id,
        type: 'CREATED',
        actorId: ctx.user.id,
        summary: `Recorded ${input.kind === 'HUMAN' ? 'human' : 'non-human'} identity "${input.displayName}"`,
        metadata: { identifier, type: input.type, source: input.source },
      });

      if (input.kind === 'MACHINE' && !can(ctx.membership.role, 'identity.approve')) {
        await writeIdentityEvent(tx, {
          organizationId,
          identityId: identity.id,
          type: 'SUBMITTED_FOR_APPROVAL',
          actorId: ctx.user.id,
          summary: 'Submitted for owner approval before it can authenticate',
        });
      }

      await appendAuditEvent(tx, {
        organizationId,
        actorType: 'USER',
        actorId: ctx.user.id,
        action: AuditActions.IDENTITY_CREATED,
        outcome: 'SUCCESS',
        targetType: 'identity',
        targetId: identity.id,
        summary: `Created ${input.kind.toLowerCase()} identity "${input.displayName}"`,
        metadata: {
          kind: input.kind,
          type: input.type,
          status: initialIdentityStatus(input.kind),
          source: input.source,
          hasOwner: Boolean(input.ownerUserId),
          linkedToUser: linkedUserId !== null,
          approvedScopes,
        },
        ipAddress: ctx.meta.ipAddress,
        userAgent: ctx.meta.userAgent,
        requestId: ctx.meta.requestId,
      });

      const detail = await loadIdentityDetail(tx, organizationId, identity.id, now);
      if (!detail) {
        throw new Error('Identity disappeared immediately after creation.');
      }
      return detail;
    });

    return created;
  } catch (error) {
    if (isUniqueConstraintError(error)) {
      throw conflict(
        `An identity with identifier "${identifier}" already exists in this organization.`,
      );
    }
    throw error;
  }
}

export async function updateIdentity(
  ctx: TenantContext,
  identityId: string,
  input: UpdateIdentityInput,
): Promise<IdentityDetail> {
  const organizationId = ctx.organization.id;
  const existing = await prisma.identity.findFirst({
    where: { id: identityId, organizationId },
    select: {
      id: true,
      kind: true,
      displayName: true,
      status: true,
      ownerUserId: true,
      linkedUserId: true,
      approvedScopes: true,
    },
  });
  if (!existing) {
    throw notFound('Identity not found.');
  }
  if (existing.status === 'DEPROVISIONED') {
    throw conflict('A deprovisioned identity cannot be edited.');
  }

  if (input.ownerUserId !== undefined && input.ownerUserId !== null) {
    await assertActiveMember(organizationId, input.ownerUserId);
  }
  if (existing.kind === 'MACHINE' && input.ownerUserId === null) {
    throw badRequest('A non-human identity must keep an accountable owner.');
  }
  if (input.linkedUserId !== undefined && input.linkedUserId !== null) {
    if (existing.kind === 'MACHINE') {
      throw badRequest('A non-human identity cannot be linked to a console account.');
    }
    await assertLinkableUser(organizationId, input.linkedUserId, identityId);
  }
  if (input.linkedUserId === null && existing.kind === 'HUMAN' && existing.linkedUserId !== null) {
    // Unlinking is allowed; it records that the person no longer has an account
    // and the risk heuristic will surface it.
  }
  if (input.approvedScopes !== undefined && existing.kind === 'HUMAN') {
    throw badRequest('Only non-human identities can be granted credential scopes.');
  }

  const now = new Date();
  const nextScopes =
    input.approvedScopes !== undefined ? normalizeScopes(input.approvedScopes) : undefined;
  const ownerChanged =
    input.ownerUserId !== undefined && input.ownerUserId !== existing.ownerUserId;

  const detail = await prisma.$transaction(async (tx) => {
    const updated = await tx.identity.update({
      where: { id: existing.id },
      data: {
        ...(input.displayName !== undefined ? { displayName: input.displayName } : {}),
        ...(input.description !== undefined ? { description: input.description } : {}),
        ...(input.department !== undefined ? { department: input.department } : {}),
        ...(input.criticality !== undefined ? { criticality: input.criticality } : {}),
        ...(input.ownerUserId !== undefined ? { ownerUserId: input.ownerUserId } : {}),
        ...(input.linkedUserId !== undefined ? { linkedUserId: input.linkedUserId } : {}),
        ...(input.credentialTtlDays !== undefined
          ? { credentialTtlDays: input.credentialTtlDays }
          : {}),
        ...(nextScopes !== undefined ? { approvedScopes: nextScopes } : {}),
      },
      select: { id: true, approvedScopes: true, credentialTtlDays: true },
    });

    if (ownerChanged) {
      await writeIdentityEvent(tx, {
        organizationId,
        identityId: updated.id,
        type: 'OWNER_ASSIGNED',
        actorId: ctx.user.id,
        summary: input.ownerUserId ? 'Accountable owner assigned' : 'Accountable owner removed',
        ...(input.ownerUserId ? { metadata: { ownerUserId: input.ownerUserId } } : {}),
      });
    }

    // Narrowing the approved scope set must not leave a credential holding a
    // scope the identity no longer has. Revocation is atomic with the update so
    // a concurrent request cannot keep using the old grant.
    if (nextScopes !== undefined) {
      const credentials = await tx.identityCredential.findMany({
        where: { organizationId, identityId: updated.id, revokedAt: null },
        select: { id: true, scopes: true },
      });
      const revoked: string[] = [];
      for (const credential of credentials) {
        if (!isSubset(credential.scopes, nextScopes)) {
          revoked.push(credential.id);
        }
      }
      if (revoked.length > 0) {
        await tx.identityCredential.updateMany({
          where: { id: { in: revoked } },
          data: { revokedAt: now, revokedReason: 'scope_narrowed' },
        });
        await writeIdentityEvent(tx, {
          organizationId,
          identityId: updated.id,
          type: 'CREDENTIAL_REVOKED',
          actorId: ctx.user.id,
          summary: `${revoked.length} credential(s) revoked because the approved scopes changed`,
          metadata: { reason: 'scope_narrowed', count: revoked.length },
        });
      }
    }

    await writeIdentityEvent(tx, {
      organizationId,
      identityId: updated.id,
      type: 'UPDATED',
      actorId: ctx.user.id,
      summary: 'Identity details updated',
      metadata: {
        fields: Object.keys(input).filter((key) => key !== 'approvedScopes'),
        scopesChanged: nextScopes !== undefined,
      },
    });

    await appendAuditEvent(tx, {
      organizationId,
      actorType: 'USER',
      actorId: ctx.user.id,
      action: AuditActions.IDENTITY_UPDATED,
      outcome: 'SUCCESS',
      targetType: 'identity',
      targetId: updated.id,
      summary: `Updated identity "${input.displayName ?? existing.displayName}"`,
      metadata: {
        fields: Object.keys(input),
        ownerChanged,
        credentialTtlDays: updated.credentialTtlDays,
        approvedScopes: [...updated.approvedScopes],
      },
      ipAddress: ctx.meta.ipAddress,
      userAgent: ctx.meta.userAgent,
      requestId: ctx.meta.requestId,
    });

    const result = await loadIdentityDetail(tx, organizationId, updated.id, now);
    if (!result) {
      throw new Error('Identity disappeared during update.');
    }
    return result;
  });

  return detail;
}

const LIFECYCLE: Readonly<
  Record<
    IdentityLifecycleInput['action'],
    {
      to: 'ACTIVE' | 'SUSPENDED' | 'DEPROVISIONED';
      event: 'APPROVED' | 'SUSPENDED' | 'REACTIVATED' | 'DEPROVISIONED';
      audit: (typeof AuditActions)[keyof typeof AuditActions];
      summary: string;
    }
  >
> = {
  APPROVE: {
    to: 'ACTIVE',
    event: 'APPROVED',
    audit: AuditActions.IDENTITY_APPROVED,
    summary: 'Approved for use',
  },
  SUSPEND: {
    to: 'SUSPENDED',
    event: 'SUSPENDED',
    audit: AuditActions.IDENTITY_SUSPENDED,
    summary: 'Suspended; credentials revoked',
  },
  REACTIVATE: {
    to: 'ACTIVE',
    event: 'REACTIVATED',
    audit: AuditActions.IDENTITY_REACTIVATED,
    summary: 'Reactivated',
  },
  DEPROVISION: {
    to: 'DEPROVISIONED',
    event: 'DEPROVISIONED',
    audit: AuditActions.IDENTITY_DEPROVISIONED,
    summary: 'Deprovisioned; credentials revoked',
  },
};

export async function transitionIdentity(
  ctx: TenantContext,
  identityId: string,
  input: IdentityLifecycleInput,
): Promise<IdentityDetail> {
  const organizationId = ctx.organization.id;
  const identity = await prisma.identity.findFirst({
    where: { id: identityId, organizationId },
    select: {
      id: true,
      kind: true,
      displayName: true,
      status: true,
      linkedUserId: true,
      approvedScopes: true,
    },
  });
  if (!identity) {
    throw notFound('Identity not found.');
  }

  const action = LIFECYCLE[input.action];

  if (input.action === 'APPROVE' && !can(ctx.membership.role, 'identity.approve')) {
    throw forbidden('Only an organization owner can approve a non-human identity.');
  }

  if (input.action === 'APPROVE' && identity.kind !== 'MACHINE') {
    throw badRequest('Human identities are active on creation and do not require approval.');
  }

  if (
    identity.status === 'ACTIVE' &&
    (input.action === 'SUSPEND' || input.action === 'DEPROVISION') &&
    identity.kind === 'HUMAN' &&
    identity.linkedUserId
  ) {
    const membership = await prisma.membership.findFirst({
      where: { organizationId, userId: identity.linkedUserId, status: 'ACTIVE' },
      select: { id: true },
    });
    if (membership) {
      throw conflict(
        'Remove the linked console access before suspending or deprovisioning this person.',
      );
    }
  }

  // The transition table is the single source of truth for what is legal.
  if (!canTransitionIdentity(identity.status, action.to)) {
    throw conflict(`An identity in ${identity.status} cannot be moved to ${action.to}.`);
  }

  const now = new Date();

  return prisma.$transaction(async (tx) => {
    const updated = await tx.identity.update({
      where: { id: identity.id },
      data: {
        status: action.to,
        ...(input.action === 'APPROVE'
          ? { approvedById: ctx.user.id, approvedAt: now, suspendedAt: null }
          : {}),
        ...(input.action === 'SUSPEND' ? { suspendedAt: now } : {}),
        ...(input.action === 'REACTIVATE' ? { suspendedAt: null } : {}),
        ...(input.action === 'DEPROVISION' ? { deprovisionedAt: now } : {}),
      },
      select: { id: true },
    });

    let revokedCount = 0;
    if (input.action === 'SUSPEND' || input.action === 'DEPROVISION') {
      const revoked = await tx.identityCredential.updateMany({
        where: { organizationId, identityId: identity.id, revokedAt: null },
        data: {
          revokedAt: now,
          revokedReason:
            input.action === 'SUSPEND' ? 'identity_suspended' : 'identity_deprovisioned',
        },
      });
      revokedCount = revoked.count;
      if (revokedCount > 0) {
        await writeIdentityEvent(tx, {
          organizationId,
          identityId: identity.id,
          type: 'CREDENTIAL_REVOKED',
          actorId: ctx.user.id,
          summary: `${revokedCount} credential(s) revoked automatically`,
          metadata: { reason: input.action.toLowerCase(), count: revokedCount },
        });
      }
    }

    await writeIdentityEvent(tx, {
      organizationId,
      identityId: updated.id,
      type: action.event,
      actorId: ctx.user.id,
      summary: input.note ? `${action.summary}: ${input.note}` : action.summary,
      metadata: {
        from: identity.status,
        to: action.to,
        ...(revokedCount > 0 ? { revokedCredentials: revokedCount } : {}),
      },
    });

    await appendAuditEvent(tx, {
      organizationId,
      actorType: 'USER',
      actorId: ctx.user.id,
      action: action.audit,
      outcome: 'SUCCESS',
      targetType: 'identity',
      targetId: updated.id,
      summary: `${action.summary}: ${identity.displayName}`,
      metadata: {
        kind: identity.kind,
        from: identity.status,
        to: action.to,
        revokedCredentials: revokedCount,
        note: input.note ?? null,
      },
      ipAddress: ctx.meta.ipAddress,
      userAgent: ctx.meta.userAgent,
      requestId: ctx.meta.requestId,
    });

    const result = await loadIdentityDetail(tx, organizationId, updated.id, now);
    if (!result) {
      throw new Error('Identity disappeared during lifecycle transition.');
    }
    return result;
  });
}

export interface IssuedCredential {
  /** Plaintext credential; present in this response only. */
  token: string;
  credential: IdentityCredentialView;
}

export async function issueCredential(
  ctx: TenantContext,
  identityId: string,
  input: IssueIdentityCredentialInput,
): Promise<IssuedCredential> {
  const organizationId = ctx.organization.id;
  const identity = await prisma.identity.findFirst({
    where: { id: identityId, organizationId },
    select: {
      id: true,
      kind: true,
      status: true,
      displayName: true,
      approvedScopes: true,
      credentialTtlDays: true,
    },
  });
  if (!identity) {
    throw notFound('Identity not found.');
  }
  if (identity.kind !== 'MACHINE') {
    throw badRequest('Only non-human identities can hold credentials.');
  }
  if (identity.status !== 'ACTIVE') {
    throw conflict('Approve and activate the identity before issuing a credential.');
  }

  const scopes = normalizeScopes(input.scopes);
  if (!isSubset(scopes, identity.approvedScopes)) {
    throw forbidden(
      'The requested scopes are not approved for this identity. Update its approved scopes first.',
    );
  }

  const now = new Date();
  const activeCount = await prisma.identityCredential.count({
    where: { organizationId, identityId, revokedAt: null, expiresAt: { gt: now } },
  });
  if (activeCount >= MAX_ACTIVE_CREDENTIALS) {
    throw conflict(
      `This identity already holds ${MAX_ACTIVE_CREDENTIALS} active credentials. Revoke one first.`,
    );
  }

  const ttlDays = input.ttlDays ?? identity.credentialTtlDays;
  const issued = mintIdentityCredential({ ttlDays, now });

  const created = await prisma.$transaction(async (tx) => {
    const credential = await tx.identityCredential.create({
      data: {
        organizationId,
        identityId,
        name: input.name,
        keyHash: issued.hash,
        keyPrefix: issued.prefix,
        scopes,
        expiresAt: issued.expiresAt,
        createdById: ctx.user.id,
      },
      select: {
        id: true,
        name: true,
        keyPrefix: true,
        scopes: true,
        expiresAt: true,
        lastUsedAt: true,
        revokedAt: true,
        revokedReason: true,
        createdAt: true,
      },
    });

    await writeIdentityEvent(tx, {
      organizationId,
      identityId,
      type: 'CREDENTIAL_ISSUED',
      actorId: ctx.user.id,
      summary: `Issued credential "${credential.name}" (${credential.keyPrefix}…)`,
      metadata: {
        credentialId: credential.id,
        keyPrefix: credential.keyPrefix,
        scopes,
        expiresAt: credential.expiresAt.toISOString(),
      },
    });

    await appendAuditEvent(tx, {
      organizationId,
      actorType: 'USER',
      actorId: ctx.user.id,
      action: AuditActions.IDENTITY_CREDENTIAL_ISSUED,
      outcome: 'SUCCESS',
      targetType: 'identity_credential',
      targetId: credential.id,
      summary: `Issued credential "${credential.name}" for ${identity.displayName}`,
      metadata: {
        identityId,
        keyPrefix: credential.keyPrefix,
        scopes,
        expiresAt: credential.expiresAt.toISOString(),
      },
      ipAddress: ctx.meta.ipAddress,
      userAgent: ctx.meta.userAgent,
      requestId: ctx.meta.requestId,
    });

    return credential;
  });

  return {
    token: issued.token,
    credential: {
      id: created.id,
      name: created.name,
      prefix: created.keyPrefix,
      scopes: [...created.scopes],
      status: 'ACTIVE',
      expiresAt: created.expiresAt.toISOString(),
      lastUsedAt: null,
      revokedAt: null,
      revokedReason: null,
      createdAt: created.createdAt.toISOString(),
      createdBy: { id: ctx.user.id, name: ctx.user.name, email: ctx.user.email },
    },
  };
}

export async function rotateCredential(
  ctx: TenantContext,
  identityId: string,
  credentialId: string,
): Promise<IssuedCredential> {
  const organizationId = ctx.organization.id;
  const existing = await prisma.identityCredential.findFirst({
    where: { id: credentialId, identityId, organizationId },
    select: {
      id: true,
      name: true,
      keyPrefix: true,
      scopes: true,
      expiresAt: true,
      revokedAt: true,
      identity: {
        select: {
          id: true,
          kind: true,
          status: true,
          displayName: true,
          approvedScopes: true,
          credentialTtlDays: true,
        },
      },
    },
  });
  if (!existing) {
    throw notFound('Credential not found.');
  }
  if (existing.revokedAt) {
    throw conflict('A revoked credential cannot be rotated. Issue a new one instead.');
  }
  if (existing.identity.status !== 'ACTIVE') {
    throw conflict('The identity must be active before its credential can be rotated.');
  }
  if (!isSubset(existing.scopes, existing.identity.approvedScopes)) {
    throw conflict(
      'This credential holds scopes that are no longer approved. Issue a new credential instead.',
    );
  }

  const now = new Date();
  const issued = mintIdentityCredential({
    ttlDays: existing.identity.credentialTtlDays,
    now,
  });

  const created = await prisma.$transaction(async (tx) => {
    await tx.identityCredential.update({
      where: { id: existing.id },
      data: { revokedAt: now, revokedReason: 'rotated' },
    });

    const replacement = await tx.identityCredential.create({
      data: {
        organizationId,
        identityId,
        name: existing.name,
        keyHash: issued.hash,
        keyPrefix: issued.prefix,
        scopes: existing.scopes,
        expiresAt: issued.expiresAt,
        createdById: ctx.user.id,
      },
      select: {
        id: true,
        name: true,
        keyPrefix: true,
        scopes: true,
        expiresAt: true,
        lastUsedAt: true,
        revokedAt: true,
        revokedReason: true,
        createdAt: true,
      },
    });

    await writeIdentityEvent(tx, {
      organizationId,
      identityId,
      type: 'CREDENTIAL_REVOKED',
      actorId: ctx.user.id,
      summary: `Credential "${existing.name}" (${existing.keyPrefix}…) revoked by rotation`,
      metadata: {
        credentialId: existing.id,
        keyPrefix: existing.keyPrefix,
        replacementId: replacement.id,
      },
    });

    await writeIdentityEvent(tx, {
      organizationId,
      identityId,
      type: 'CREDENTIAL_ISSUED',
      actorId: ctx.user.id,
      summary: `Rotated credential "${replacement.name}" (${replacement.keyPrefix}…)`,
      metadata: {
        credentialId: replacement.id,
        keyPrefix: replacement.keyPrefix,
        scopes: [...replacement.scopes],
        expiresAt: replacement.expiresAt.toISOString(),
        rotatedFrom: existing.keyPrefix,
      },
    });

    await appendAuditEvent(tx, {
      organizationId,
      actorType: 'USER',
      actorId: ctx.user.id,
      action: AuditActions.IDENTITY_CREDENTIAL_ROTATED,
      outcome: 'SUCCESS',
      targetType: 'identity_credential',
      targetId: replacement.id,
      summary: `Rotated credential "${replacement.name}" for ${existing.identity.displayName}`,
      metadata: {
        identityId,
        previousPrefix: existing.keyPrefix,
        newPrefix: replacement.keyPrefix,
        scopes: [...replacement.scopes],
        expiresAt: replacement.expiresAt.toISOString(),
      },
      ipAddress: ctx.meta.ipAddress,
      userAgent: ctx.meta.userAgent,
      requestId: ctx.meta.requestId,
    });

    return replacement;
  });

  return {
    token: issued.token,
    credential: {
      id: created.id,
      name: created.name,
      prefix: created.keyPrefix,
      scopes: [...created.scopes],
      status: 'ACTIVE',
      expiresAt: created.expiresAt.toISOString(),
      lastUsedAt: null,
      revokedAt: null,
      revokedReason: null,
      createdAt: created.createdAt.toISOString(),
      createdBy: { id: ctx.user.id, name: ctx.user.name, email: ctx.user.email },
    },
  };
}

export async function revokeCredential(
  ctx: TenantContext,
  identityId: string,
  credentialId: string,
): Promise<IdentityCredentialView> {
  const organizationId = ctx.organization.id;
  const existing = await prisma.identityCredential.findFirst({
    where: { id: credentialId, identityId, organizationId },
    select: {
      id: true,
      name: true,
      keyPrefix: true,
      scopes: true,
      expiresAt: true,
      lastUsedAt: true,
      revokedAt: true,
      revokedReason: true,
      createdAt: true,
      identity: { select: { displayName: true } },
      createdBy: { select: USER_BRIEF_SELECT },
    },
  });
  if (!existing) {
    throw notFound('Credential not found.');
  }
  if (existing.revokedAt) {
    throw conflict('This credential is already revoked.');
  }

  const now = new Date();
  const updated = await prisma.$transaction(async (tx) => {
    const credential = await tx.identityCredential.update({
      where: { id: existing.id },
      data: { revokedAt: now, revokedReason: 'revoked_by_operator' },
      select: {
        id: true,
        name: true,
        keyPrefix: true,
        scopes: true,
        expiresAt: true,
        lastUsedAt: true,
        revokedAt: true,
        revokedReason: true,
        createdAt: true,
      },
    });

    await writeIdentityEvent(tx, {
      organizationId,
      identityId,
      type: 'CREDENTIAL_REVOKED',
      actorId: ctx.user.id,
      summary: `Revoked credential "${credential.name}" (${credential.keyPrefix}…)`,
      metadata: { credentialId, keyPrefix: credential.keyPrefix },
    });

    await appendAuditEvent(tx, {
      organizationId,
      actorType: 'USER',
      actorId: ctx.user.id,
      action: AuditActions.IDENTITY_CREDENTIAL_REVOKED,
      outcome: 'SUCCESS',
      targetType: 'identity_credential',
      targetId: credential.id,
      summary: `Revoked credential "${credential.name}" for ${existing.identity.displayName}`,
      metadata: { identityId, keyPrefix: credential.keyPrefix },
      ipAddress: ctx.meta.ipAddress,
      userAgent: ctx.meta.userAgent,
      requestId: ctx.meta.requestId,
    });

    return credential;
  });

  return {
    id: updated.id,
    name: updated.name,
    prefix: updated.keyPrefix,
    scopes: [...updated.scopes],
    status: 'REVOKED',
    expiresAt: updated.expiresAt.toISOString(),
    lastUsedAt: iso(updated.lastUsedAt),
    revokedAt: iso(updated.revokedAt),
    revokedReason: updated.revokedReason,
    createdAt: updated.createdAt.toISOString(),
    createdBy: toUserRef(existing.createdBy),
  };
}

// ---------------------------------------------------------------------------
// Machine authentication
// ---------------------------------------------------------------------------

/**
 * Verifies a machine bearer credential. A null result means "not
 * authenticated" for every reason; the caller must not distinguish revoked,
 * expired and suspended identities in the response.
 */
export async function authenticateMachineIdentity(
  token: string,
  now: Date = new Date(),
): Promise<MachineIdentityPrincipal | null> {
  if (!isIdentityCredentialShape(token)) {
    return null;
  }

  const credential = await prisma.identityCredential.findUnique({
    where: { keyHash: hashIdentityCredential(token) },
    select: {
      id: true,
      organizationId: true,
      scopes: true,
      expiresAt: true,
      revokedAt: true,
      identityId: true,
      identity: { select: { status: true } },
    },
  });

  if (
    !credential ||
    credential.revokedAt !== null ||
    credential.expiresAt.getTime() <= now.getTime() ||
    credential.identity.status !== 'ACTIVE'
  ) {
    return null;
  }

  await prisma.$transaction([
    prisma.identityCredential.update({
      where: { id: credential.id },
      data: { lastUsedAt: now },
    }),
    prisma.identity.updateMany({
      where: {
        id: credential.identityId,
        OR: [
          { lastSeenAt: null },
          { lastSeenAt: { lt: new Date(now.getTime() - LAST_SEEN_WRITE_INTERVAL_MS) } },
        ],
      },
      data: { lastSeenAt: now },
    }),
  ]);

  return {
    identityId: credential.identityId,
    organizationId: credential.organizationId,
    credentialId: credential.id,
    scopes: [...credential.scopes],
  };
}

export function machineIdentityHasScope(
  principal: MachineIdentityPrincipal,
  scope: IdentityCredentialScope,
): boolean {
  return principal.scopes.includes(scope);
}

export interface MachineIdentitySelfView {
  identity: {
    id: string;
    organizationId: string;
    kind: string;
    type: string;
    displayName: string;
    identifier: string;
    status: string;
    criticality: string;
    lastSeenAt: string | null;
    approvedScopes: string[];
  };
  credential: {
    id: string;
    name: string;
    prefix: string;
    scopes: string[];
    expiresAt: string;
    lastUsedAt: string | null;
  };
  serverTime: string;
}

export async function describeMachineIdentity(
  principal: MachineIdentityPrincipal,
  now: Date = new Date(),
): Promise<MachineIdentitySelfView | null> {
  const [identity, credential] = await Promise.all([
    prisma.identity.findFirst({
      where: {
        id: principal.identityId,
        organizationId: principal.organizationId,
        status: 'ACTIVE',
      },
      select: {
        id: true,
        organizationId: true,
        kind: true,
        type: true,
        displayName: true,
        identifier: true,
        status: true,
        criticality: true,
        lastSeenAt: true,
        approvedScopes: true,
      },
    }),
    prisma.identityCredential.findFirst({
      where: { id: principal.credentialId, revokedAt: null, expiresAt: { gt: now } },
      select: {
        id: true,
        name: true,
        keyPrefix: true,
        scopes: true,
        expiresAt: true,
        lastUsedAt: true,
      },
    }),
  ]);

  if (!identity || !credential) {
    return null;
  }

  return {
    identity: {
      id: identity.id,
      organizationId: identity.organizationId,
      kind: identity.kind,
      type: identity.type,
      displayName: identity.displayName,
      identifier: identity.identifier,
      status: identity.status,
      criticality: identity.criticality,
      lastSeenAt: iso(identity.lastSeenAt),
      approvedScopes: [...identity.approvedScopes],
    },
    credential: {
      id: credential.id,
      name: credential.name,
      prefix: credential.keyPrefix,
      scopes: [...credential.scopes],
      expiresAt: credential.expiresAt.toISOString(),
      lastUsedAt: iso(credential.lastUsedAt),
    },
    serverTime: now.toISOString(),
  };
}
