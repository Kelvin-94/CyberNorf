import { jsonResponse, withTenantApi } from '@/server/api/handler';
import { readJsonBody } from '@/server/http/request-meta';
import { getDetection, updateDetectionStatus } from '@/server/services/network';
import { updateDetectionSchema } from '@/server/validation/zero-trust';

export const dynamic = 'force-dynamic';

type Params = { orgSlug: string; detectionId: string };

export const GET = withTenantApi<Params>('network.read', {}, async ({ meta, ctx, params }) => {
  const detection = await getDetection(ctx.organization.id, params.detectionId);
  return jsonResponse({ detection }, meta);
});

export const PATCH = withTenantApi<Params>(
  'network.manage',
  {},
  async ({ request, meta, ctx, params }) => {
    const input = updateDetectionSchema.parse(await readJsonBody(request));
    const detection = await updateDetectionStatus(ctx, params.detectionId, input);
    return jsonResponse({ detection }, meta);
  },
);
