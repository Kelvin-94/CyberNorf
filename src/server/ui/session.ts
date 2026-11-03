import { headers } from 'next/headers';
import { notFound, redirect } from 'next/navigation';
import {
  getAuthenticatedUser,
  requireTenantContext,
  type AuthenticatedUser,
  type TenantContext,
} from '@/server/authz/context';
import type { Capability } from '@/server/authz/roles';
import { AppError } from '@/server/errors';
import { getRequestMeta } from '@/server/http/request-meta';

/**
 * Server-component session helpers. Pages never read cookies directly: the
 * session is validated by Better Auth and tenant access is resolved through the
 * same membership policy used by the API.
 */

export async function getSessionUser(): Promise<AuthenticatedUser | null> {
  const requestHeaders = await headers();
  return getAuthenticatedUser(new Headers(requestHeaders));
}

export async function requireSessionUser(): Promise<AuthenticatedUser> {
  const user = await getSessionUser();
  if (!user) {
    redirect('/sign-in');
  }
  return user;
}

/**
 * Resolves the tenant context for a page. Unauthenticated visitors are sent to
 * sign-in and non-members get a 404 so the page never reveals another tenant.
 * Members that lack the capability receive `null` so the page can render an
 * explicit access-denied state instead of a blank screen.
 */
export async function loadTenantContext(
  organizationSlug: string,
  capability: Capability = 'organization.read',
): Promise<TenantContext | null> {
  const requestHeaders = new Headers(await headers());
  const user = await getAuthenticatedUser(requestHeaders);
  if (!user) {
    redirect('/sign-in');
  }

  const meta = getRequestMeta(
    new Request(`http://localhost/app/${encodeURIComponent(organizationSlug)}`, {
      headers: requestHeaders,
    }),
  );

  try {
    return await requireTenantContext(requestHeaders, organizationSlug, capability, meta, user);
  } catch (error) {
    if (error instanceof AppError && error.statusCode === 404) {
      notFound();
    }
    if (error instanceof AppError && error.statusCode === 403) {
      return null;
    }
    throw error;
  }
}
