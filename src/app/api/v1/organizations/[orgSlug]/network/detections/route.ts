import { jsonResponse, withTenantApi } from '@/server/api/handler';
import { listDetections } from '@/server/services/network';
import { parseQuery } from '@/server/validation/common';
import { detectionListQuerySchema } from '@/server/validation/zero-trust';

export const dynamic = 'force-dynamic';

type Params = { orgSlug: string };

export const GET = withTenantApi<Params>('network.read', {}, async ({ request, meta, ctx }) => {
  const query = parseQuery(request, detectionListQuerySchema);
  const result = await listDetections(ctx.organization.id, query);
  return jsonResponse(result, meta);
});
