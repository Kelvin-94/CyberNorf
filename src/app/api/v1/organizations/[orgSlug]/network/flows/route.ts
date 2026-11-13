import { jsonResponse, withTenantApi } from '@/server/api/handler';
import { listFlows } from '@/server/services/network';
import { parseQuery } from '@/server/validation/common';
import { flowListQuerySchema } from '@/server/validation/zero-trust';

export const dynamic = 'force-dynamic';

type Params = { orgSlug: string };

/**
 * Flows are ingested by connectors over the token-authenticated API, not by
 * operators, so this route is read-only.
 */
export const GET = withTenantApi<Params>('network.read', {}, async ({ request, meta, ctx }) => {
  const query = parseQuery(request, flowListQuerySchema);
  const result = await listFlows(ctx.organization.id, query);
  return jsonResponse(result, meta);
});
