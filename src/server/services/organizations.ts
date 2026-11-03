import { prisma } from '@/lib/prisma';
import { AuditActions, appendAuditEvent } from '@/server/audit/audit';
import type { TenantContext } from '@/server/authz/context';
import type { OrgRole } from '@/server/authz/roles';
import { conflict } from '@/server/errors';

export interface OrganizationSummary {
  id: string;
  name: string;
  slug: string;
  description: string | null;
  tier: string;
  role: OrgRole;
  memberCount: number;
}

function slugify(value: string): string {
  return value
    .toLowerCase()
    .normalize('NFKD')
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 40)
    .replace(/^-+|-+$/g, '');
}

async function allocateSlug(requested: string | undefined, name: string): Promise<string> {
  const base = requested ?? (slugify(name) || 'organization');
  for (let attempt = 0; attempt < 50; attempt += 1) {
    const candidate = attempt === 0 ? base : `${base}-${attempt + 1}`.slice(0, 40);
    const existing = await prisma.organization.findUnique({
      where: { slug: candidate },
      select: { id: true },
    });
    if (!existing) {
      return candidate;
    }
  }
  throw conflict('Unable to allocate a unique organization slug. Choose another name or slug.');
}

export async function listUserOrganizations(userId: string): Promise<OrganizationSummary[]> {
  const memberships = await prisma.membership.findMany({
    where: { userId, status: 'ACTIVE' },
    select: {
      role: true,
      organization: {
        select: {
          id: true,
          name: true,
          slug: true,
          description: true,
          tier: true,
          _count: { select: { memberships: true } },
        },
      },
    },
    orderBy: { organization: { name: 'asc' } },
  });

  return memberships.map((membership) => ({
    id: membership.organization.id,
    name: membership.organization.name,
    slug: membership.organization.slug,
    description: membership.organization.description,
    tier: membership.organization.tier,
    role: membership.role,
    memberCount: membership.organization._count.memberships,
  }));
}

export async function createOrganization(
  user: TenantContext['user'],
  input: { name: string; slug?: string; description?: string | null },
  meta: TenantContext['meta'],
): Promise<OrganizationSummary> {
  const slug = await allocateSlug(input.slug, input.name);

  return prisma.$transaction(async (tx) => {
    const organization = await tx.organization.create({
      data: {
        name: input.name,
        slug,
        description: input.description ?? null,
        memberships: { create: { userId: user.id, role: 'OWNER', status: 'ACTIVE' } },
      },
      select: { id: true, name: true, slug: true, description: true, tier: true },
    });

    await appendAuditEvent(tx, {
      organizationId: organization.id,
      actorType: 'USER',
      actorId: user.id,
      action: AuditActions.ORGANIZATION_CREATED,
      outcome: 'SUCCESS',
      targetType: 'organization',
      targetId: organization.id,
      summary: `Organization ${organization.name} created`,
      metadata: { slug: organization.slug },
      ipAddress: meta.ipAddress,
      userAgent: meta.userAgent,
      requestId: meta.requestId,
    });

    return { ...organization, role: 'OWNER' as const, memberCount: 1 };
  });
}

export async function updateOrganization(
  ctx: TenantContext,
  input: { name?: string; description?: string | null },
): Promise<void> {
  await prisma.$transaction(async (tx) => {
    const before = await tx.organization.findUniqueOrThrow({
      where: { id: ctx.organization.id },
      select: { name: true, description: true },
    });

    await tx.organization.update({
      where: { id: ctx.organization.id },
      data: {
        ...(input.name !== undefined ? { name: input.name } : {}),
        ...(input.description !== undefined ? { description: input.description } : {}),
      },
    });

    await appendAuditEvent(tx, {
      organizationId: ctx.organization.id,
      actorType: 'USER',
      actorId: ctx.user.id,
      action: AuditActions.ORGANIZATION_UPDATED,
      outcome: 'SUCCESS',
      targetType: 'organization',
      targetId: ctx.organization.id,
      summary: 'Organization settings updated',
      metadata: {
        before,
        after: {
          name: input.name ?? before.name,
          description: input.description === undefined ? before.description : input.description,
        },
      },
      ipAddress: ctx.meta.ipAddress,
      userAgent: ctx.meta.userAgent,
      requestId: ctx.meta.requestId,
    });
  });
}

export async function getOrganizationSettings(ctx: TenantContext) {
  const organization = await prisma.organization.findUniqueOrThrow({
    where: { id: ctx.organization.id },
    select: { id: true, name: true, slug: true, description: true, tier: true, createdAt: true },
  });
  return { ...organization, role: ctx.membership.role };
}
