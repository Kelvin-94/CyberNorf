import { jsonResponse, withTenantApi } from '@/server/api/handler';
import { readJsonBody } from '@/server/http/request-meta';
import { createSegment, listSegments } from '@/server/services/network';
import { parseQuery } from '@/server/validation/common';
import { createSegmentSchema, segmentListQuerySchema } from '@/server/validation/zero-trust';

export const dynamic = 'force-dynamic';

type Params = { orgSlug: string };

export const GET = withTenantApi<Params>('network.read', {}, async ({ request, meta, ctx }) => {
  const query = parseQuery(request, segmentListQuerySchema);
  const result = await listSegments(ctx.organization.id, query);
  return jsonResponse(result, meta);
});

export const POST = withTenantApi<Params>('network.manage', {}, async ({ request, meta, ctx }) => {
  const input = createSegmentSchema.parse(await readJsonBody(request));
  const segment = await createSegment(ctx, input);
  return jsonResponse({ segment }, meta, 201);
});
