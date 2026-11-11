import type { SubscriptionTier } from '@/generated/prisma/client';
import { auth } from '@/lib/auth';
import { prisma } from '@/lib/prisma';
import { AuditActions, recordAuditEvent } from '@/server/audit/audit';
import { forbidden, notFound, unauthenticated } from '@/server/errors';
import { getRequestMeta, type RequestMeta } from '@/server/http/request-meta';
import { redactError } from '@/server/security/redaction';
import { resolveApiKeyUser } from './api-key';
import { can, requiresSecondFactor, type Capability, type OrgRole } from './roles';

export interface AuthenticatedUser {
  id: string;
  name: string;
  email: string;
  twoFactorEnabled: boolean;
  /** Session id for cookie authentication; null when a personal API key was used. */
  sessionId: string | null;
  /**
   * Set when the request presented a personal API key. The key is bound to one
   * organization, and tenant resolution refuses any other organization even if
   * the owner belongs to it.
   */
  apiKey: { id: string; organizationId: string } | null;
}

export interface TenantContext {
  user: AuthenticatedUser;
  organization: {
    id: string;
    name: string;
    slug: string;
    tier: SubscriptionTier;
  };
  membership: {
    id: string;
    role: OrgRole;
  };
  meta: RequestMeta;
}

/**
 * Resolves the caller from either a personal API key (Authorization: Bearer) or
 * the Better Auth session cookie. A presented but unusable key throws instead of
 * falling back to the cookie, so credentials are never silently mixed.
 */
export async function getAuthenticatedUser(headers: Headers): Promise<AuthenticatedUser | null> {
  const apiKeyUser = await resolveApiKeyUser(headers);
  if (apiKeyUser) {
    return apiKeyUser;
  }

  const result = await auth.api.getSession({ headers });
  if (!result) {
    return null;
  }

  return {
    id: result.user.id,
    name: result.user.name,
    email: result.user.email,
    twoFactorEnabled: result.user.twoFactorEnabled === true,
    sessionId: result.session.id,
    apiKey: null,
  };
}

export async function requireAuthenticatedUser(headers: Headers): Promise<AuthenticatedUser> {
  const user = await getAuthenticatedUser(headers);
  if (!user) {
    throw unauthenticated();
  }
  return user;
}

async function auditDeniedAccess(
  ctx: Omit<TenantContext, 'meta'>,
  meta: RequestMeta,
  capability: Capability,
  reason: 'missing_capability' | 'second_factor_required',
): Promise<void> {
  try {
    await recordAuditEvent({
      organizationId: ctx.organization.id,
      actorType: 'USER',
      actorId: ctx.user.id,
      action: AuditActions.ACCESS_DENIED,
      outcome: 'DENIED',
      targetType: 'organization',
      targetId: ctx.organization.id,
      summary: `Denied ${capability} for role ${ctx.membership.role}`,
      metadata: { capability, role: ctx.membership.role, reason },
      ipAddress: meta.ipAddress,
      userAgent: meta.userAgent,
      requestId: meta.requestId,
    });
  } catch (error) {
    // A failing audit write must never turn a denial into an allow.
    console.error(`[${meta.requestId}] failed to record denied access:`, redactError(error));
  }
}

/**
 * Resolves the tenant from the authenticated session and an organization
 * identifier (id or slug). The membership row is the source of truth, so a
 * client-supplied organization identifier alone never grants access.
 *
 * Callers that are not members receive NOT_FOUND to avoid disclosing other
 * tenants. Members that lack the capability receive FORBIDDEN plus a DENIED
 * audit record.
 */
export async function requireTenantContext(
  headers: Headers,
  organizationIdentifier: string,
  capability?: Capability,
  meta: RequestMeta = getRequestMeta(new Request('http://localhost')),
  resolvedUser?: AuthenticatedUser,
): Promise<TenantContext> {
  // The API layer resolves the session once and passes it in; direct callers
  // (server components, tests) can omit it and have it looked up here.
  const user = resolvedUser ?? (await requireAuthenticatedUser(headers));

  const organization = await prisma.organization.findFirst({
    where: { OR: [{ id: organizationIdentifier }, { slug: organizationIdentifier }] },
    select: { id: true, name: true, slug: true, tier: true },
  });

  if (!organization) {
    throw notFound('Organization not found.');
  }

  // A personal API key is issued for exactly one organization. Answering 404
  // for any other tenant keeps the key from probing a second organization the
  // owner happens to be a member of.
  if (user.apiKey && user.apiKey.organizationId !== organization.id) {
    throw notFound('Organization not found.');
  }

  const membership = await prisma.membership.findUnique({
    where: { userId_organizationId: { userId: user.id, organizationId: organization.id } },
    select: { id: true, role: true, status: true },
  });

  if (!membership || membership.status !== 'ACTIVE') {
    throw notFound('Organization not found.');
  }

  const ctx: TenantContext = {
    user,
    organization,
    membership: { id: membership.id, role: membership.role },
    meta,
  };

  if (capability) {
    if (!can(membership.role, capability)) {
      await auditDeniedAccess(ctx, meta, capability, 'missing_capability');
      throw forbidden('Your role does not permit this action.');
    }

    if (requiresSecondFactor(membership.role, capability) && !user.twoFactorEnabled) {
      await auditDeniedAccess(ctx, meta, capability, 'second_factor_required');
      throw forbidden(
        'Privileged roles must enroll two-factor authentication before changing data.',
        'MFA_REQUIRED',
      );
    }
  }

  return ctx;
}
