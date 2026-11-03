import { jsonResponse, withTenantApi } from '@/server/api/handler';
import { listFindingFormOptions } from '@/server/services/findings';

export const dynamic = 'force-dynamic';

export const GET = withTenantApi('finding.read', {}, async ({ meta, ctx }) => {
  const options = await listFindingFormOptions(ctx.organization.id);
  return jsonResponse(options, meta);
});
