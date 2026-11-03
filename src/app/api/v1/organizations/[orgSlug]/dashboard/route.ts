import { jsonResponse, withTenantApi } from '@/server/api/handler';
import { getDashboardSummary } from '@/server/services/dashboard';

export const dynamic = 'force-dynamic';

export const GET = withTenantApi('organization.read', {}, async ({ meta, ctx }) => {
  return jsonResponse(await getDashboardSummary(ctx), meta);
});
