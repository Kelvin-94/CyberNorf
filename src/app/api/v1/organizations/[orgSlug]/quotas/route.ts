import { jsonResponse, withTenantApi } from '@/server/api/handler';
import { getQuotaUsage } from '@/server/services/quotas';

export const dynamic = 'force-dynamic';

type Params = { orgSlug: string };

/**
 * Read-only view of the tenant's limits and current usage. Raising a limit is an
 * operator action, not something a tenant can do for itself, so there is no
 * write method here: overrides are applied with `npm run quota -- set`.
 */
export const GET = withTenantApi<Params>('organization.read', {}, async ({ meta, ctx }) => {
  const quotas = await getQuotaUsage(ctx.organization.id, ctx.organization.tier);
  return jsonResponse(quotas, meta);
});
