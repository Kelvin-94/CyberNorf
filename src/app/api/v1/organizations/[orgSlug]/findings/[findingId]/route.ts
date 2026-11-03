import { emptyResponse, jsonResponse, withTenantApi } from '@/server/api/handler';
import { readJsonBody } from '@/server/http/request-meta';
import { deleteFinding, getFindingDetail, updateFinding } from '@/server/services/findings';
import { withoutUndefined } from '@/server/validation/common';
import { updateFindingSchema } from '@/server/validation/findings';

export const dynamic = 'force-dynamic';

type Params = { orgSlug: string; findingId: string };

export const GET = withTenantApi<Params>('finding.read', {}, async ({ meta, ctx, params }) => {
  const finding = await getFindingDetail(ctx, params.findingId);
  return jsonResponse({ finding }, meta);
});

export const PATCH = withTenantApi<Params>(
  'finding.update',
  {},
  async ({ request, meta, ctx, params }) => {
    const input = updateFindingSchema.parse(await readJsonBody(request));
    const finding = await updateFinding(ctx, params.findingId, withoutUndefined(input));
    return jsonResponse({ finding }, meta);
  },
);

export const DELETE = withTenantApi<Params>('finding.delete', {}, async ({ meta, ctx, params }) => {
  await deleteFinding(ctx, params.findingId);
  return emptyResponse(meta);
});
