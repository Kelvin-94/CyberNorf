import { jsonResponse, withTenantApi } from '@/server/api/handler';
import { readJsonBody } from '@/server/http/request-meta';
import { createCheckMap, listCheckMaps } from '@/server/services/check-maps';
import { parseQuery } from '@/server/validation/common';
import { checkMapQuerySchema, createCheckMapSchema } from '@/server/validation/agents';

export const dynamic = 'force-dynamic';

type Params = { orgSlug: string };

/**
 * Agent checks feed control evidence automatically once they are mapped. Reading
 * the mapping is part of reading agent posture; changing it is agent management.
 */
export const GET = withTenantApi<Params>('agent.read', {}, async ({ request, meta, ctx }) => {
  const query = parseQuery(request, checkMapQuerySchema);
  const overview = await listCheckMaps(ctx, query.agentId ?? null);
  return jsonResponse(overview, meta);
});

export const POST = withTenantApi<Params>('agent.manage', {}, async ({ request, meta, ctx }) => {
  const input = createCheckMapSchema.parse(await readJsonBody(request));
  const result = await createCheckMap(ctx, input);
  return jsonResponse(result, meta, 201);
});
