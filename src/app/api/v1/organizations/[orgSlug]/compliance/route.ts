import { jsonResponse, withTenantApi } from '@/server/api/handler';
import { getComplianceOverview } from '@/server/services/compliance';

export const dynamic = 'force-dynamic';

/** Compliance posture roll-up across every framework the tenant adopted. */
export const GET = withTenantApi('compliance.read', {}, async ({ meta, ctx }) => {
  const overview = await getComplianceOverview(ctx);
  return jsonResponse(overview, meta);
});
