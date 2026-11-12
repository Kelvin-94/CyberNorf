import type { MembershipStatus } from '@/generated/prisma/client';
import { prisma } from '@/lib/prisma';
import { AuditActions, appendAuditEvent } from '@/server/audit/audit';
import type { TenantContext } from '@/server/authz/context';
import { can, type OrgRole } from '@/server/authz/roles';
import { badRequest, conflict, forbidden, notFound } from '@/server/errors';

export interface MemberSummary {
  membershipId: string;
  userId: string;
  name: string;
  email: string;
  role: OrgRole;
  status: MembershipStatus;
  twoFactorEnabled: boolean;
  joinedAt: Date;
}

const MEMBER_SELECT = {
  id: true,
  role: true,
  status: true,
  createdAt: true,
  user: {
    select: { id: true, name: true, email: true, twoFactorEnabled: true },
  },
} as const;

function toSummary(membership: {
  id: string;
  role: OrgRole;
  status: MembershipStatus;
  createdAt: Date;
  user: { id: string; name: string; email: string; twoFactorEnabled: boolean | null };
}): MemberSummary {
  return {
    membershipId: membership.id,
    userId: membership.user.id,
    name: membership.user.name,
    email: membership.user.email,
    role: membership.role,
    status: membership.status,
    twoFactorEnabled: membership.user.twoFactorEnabled === true,
    joinedAt: membership.createdAt,
  };
}

/**
 * Role grants are staged so an administrator cannot escalate beyond their own
 * level: adding, removing, or re-roling an ADMIN or OWNER membership requires
 * the caller to be an OWNER.
 */
function assertCanManageRole(actorRole: OrgRole, role: OrgRole): void {
  if (can(actorRole, 'member.manage_privileged')) {
    return;
  }
  if (role === 'OWNER' || role === 'ADMIN') {
    throw forbidden('Only organization owners can grant or revoke administrator roles.');
  }
}

export async function listMembers(organizationId: string): Promise<MemberSummary[]> {
  const memberships = await prisma.membership.findMany({
    where: { organizationId },
    select: MEMBER_SELECT,
    orderBy: [{ status: 'asc' }, { role: 'asc' }, { createdAt: 'asc' }],
    take: 500,
  });
  return memberships.map(toSummary);
}

export async function addMember(
  ctx: TenantContext,
  input: { email: string; role: OrgRole },
): Promise<MemberSummary> {
  assertCanManageRole(ctx.membership.role, input.role);

  // Addresses are stored as entered at registration, so compare without case.
  const user = await prisma.user.findFirst({
    where: { email: { equals: input.email.trim(), mode: 'insensitive' } },
    select: { id: true, name: true, email: true },
  });

  if (!user) {
    // v1 has no invitation email flow: the person must register first.
    throw badRequest('No account exists for that email address. Ask them to register first.');
  }

  const existing = await prisma.membership.findUnique({
    where: { userId_organizationId: { userId: user.id, organizationId: ctx.organization.id } },
    select: { id: true, status: true },
  });

  if (existing?.status === 'ACTIVE') {
    throw conflict('That user is already a member of this organization.');
  }

  return prisma.$transaction(async (tx) => {
    const membership = existing
      ? await tx.membership.update({
          where: { id: existing.id },
          data: { role: input.role, status: 'ACTIVE' },
          select: MEMBER_SELECT,
        })
      : await tx.membership.create({
          data: {
            userId: user.id,
            organizationId: ctx.organization.id,
            role: input.role,
            status: 'ACTIVE',
          },
          select: MEMBER_SELECT,
        });

    await appendAuditEvent(tx, {
      organizationId: ctx.organization.id,
      actorType: 'USER',
      actorId: ctx.user.id,
      action: AuditActions.MEMBER_ADDED,
      outcome: 'SUCCESS',
      targetType: 'membership',
      targetId: membership.id,
      summary: `${user.email} added as ${input.role}`,
      metadata: { userId: user.id, role: input.role, reinvited: Boolean(existing) },
      ipAddress: ctx.meta.ipAddress,
      userAgent: ctx.meta.userAgent,
      requestId: ctx.meta.requestId,
    });

    return toSummary(membership);
  });
}

export async function changeMemberRole(
  ctx: TenantContext,
  membershipId: string,
  role: OrgRole,
): Promise<MemberSummary> {
  const membership = await prisma.membership.findFirst({
    where: { id: membershipId, organizationId: ctx.organization.id },
    select: MEMBER_SELECT,
  });

  if (!membership || membership.status !== 'ACTIVE') {
    throw notFound('Member not found.');
  }

  assertCanManageRole(ctx.membership.role, membership.role);
  assertCanManageRole(ctx.membership.role, role);

  if (membership.role === role) {
    return toSummary(membership);
  }

  if (membership.role === 'OWNER') {
    const remainingOwners = await prisma.membership.count({
      where: {
        organizationId: ctx.organization.id,
        role: 'OWNER',
        status: 'ACTIVE',
        id: { not: membership.id },
      },
    });
    if (remainingOwners === 0) {
      throw conflict('An organization must always keep at least one owner.');
    }
  }

  return prisma.$transaction(async (tx) => {
    const updated = await tx.membership.update({
      where: { id: membership.id },
      data: { role },
      select: MEMBER_SELECT,
    });

    await appendAuditEvent(tx, {
      organizationId: ctx.organization.id,
      actorType: 'USER',
      actorId: ctx.user.id,
      action: AuditActions.MEMBER_ROLE_CHANGED,
      outcome: 'SUCCESS',
      targetType: 'membership',
      targetId: membership.id,
      summary: `${membership.user.email} changed from ${membership.role} to ${role}`,
      metadata: { userId: membership.user.id, from: membership.role, to: role },
      ipAddress: ctx.meta.ipAddress,
      userAgent: ctx.meta.userAgent,
      requestId: ctx.meta.requestId,
    });

    return toSummary(updated);
  });
}

/**
 * Removes a member by disabling the membership. The row stays in place so the
 * audit trail keeps resolving actor identities. Authorization is evaluated per
 * request against the membership, so disabling it ends access to this tenant
 * immediately; sessions are only destroyed when the user has no remaining
 * active membership anywhere, otherwise they would be signed out of the other
 * organizations they still belong to.
 */
export async function removeMember(ctx: TenantContext, membershipId: string): Promise<void> {
  const membership = await prisma.membership.findFirst({
    where: { id: membershipId, organizationId: ctx.organization.id },
    select: MEMBER_SELECT,
  });

  if (!membership || membership.status !== 'ACTIVE') {
    throw notFound('Member not found.');
  }

  assertCanManageRole(ctx.membership.role, membership.role);

  if (membership.role === 'OWNER') {
    const remainingOwners = await prisma.membership.count({
      where: {
        organizationId: ctx.organization.id,
        role: 'OWNER',
        status: 'ACTIVE',
        id: { not: membership.id },
      },
    });
    if (remainingOwners === 0) {
      throw conflict('An organization must always keep at least one owner.');
    }
  }

  await prisma.$transaction(async (tx) => {
    await tx.membership.update({
      where: { id: membership.id },
      data: { status: 'DISABLED' },
    });

    // Two-factor enrollment stays intact: it protects the account, not the
    // tenant. Sessions are only dropped once no active membership remains.
    const remainingMemberships = await tx.membership.count({
      where: { userId: membership.user.id, status: 'ACTIVE' },
    });
    if (remainingMemberships === 0) {
      await tx.session.deleteMany({ where: { userId: membership.user.id } });
    }

    await appendAuditEvent(tx, {
      organizationId: ctx.organization.id,
      actorType: 'USER',
      actorId: ctx.user.id,
      action: AuditActions.MEMBER_REMOVED,
      outcome: 'SUCCESS',
      targetType: 'membership',
      targetId: membership.id,
      summary: `${membership.user.email} removed from the organization`,
      metadata: { userId: membership.user.id, role: membership.role },
      ipAddress: ctx.meta.ipAddress,
      userAgent: ctx.meta.userAgent,
      requestId: ctx.meta.requestId,
    });
  });
}
