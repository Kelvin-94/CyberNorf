import { jsonResponse, withTenantApi } from '@/server/api/handler';
import { readJsonBody } from '@/server/http/request-meta';
import { deleteSegment, getSegment, updateSegment } from '@/server/services/network';
import { updateSegmentSchema } from '@/server/validation/zero-trust';

export const dynamic = 'force-dynamic';

type Params = { orgSlug: string; segmentId: string };

export const GET = withTenantApi<Params>('network.read', {}, async ({ meta, ctx, params }) => {
  const segment = await getSegment(ctx.organization.id, params.segmentId);
  return jsonResponse({ segment }, meta);
});

export const PATCH = withTenantApi<Params>(
  'network.manage',
  {},
  async ({ request, meta, ctx, params }) => {
    const input = updateSegmentSchema.parse(await readJsonBody(request));
    const segment = await updateSegment(ctx, params.segmentId, input);
    return jsonResponse({ segment }, meta);
  },
);

export const DELETE = withTenantApi<Params>('network.manage', {}, async ({ meta, ctx, params }) => {
  await deleteSegment(ctx, params.segmentId);
  return jsonResponse({ deleted: true }, meta);
});
