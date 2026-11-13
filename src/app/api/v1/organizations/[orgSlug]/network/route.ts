import { jsonResponse, withTenantApi } from '@/server/api/handler';
import { getNetworkOverview } from '@/server/services/network';

export const dynamic = 'force-dynamic';

type Params = { orgSlug: string };

export const GET = withTenantApi<Params>('network.read', {}, async ({ meta, ctx }) => {
  const overview = await getNetworkOverview(ctx.organization.id);
  return jsonResponse({ overview }, meta);
});
