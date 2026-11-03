import { jsonResponse, withTenantApi } from '@/server/api/handler';
import { readJsonBody } from '@/server/http/request-meta';
import { createAsset, listAssets } from '@/server/services/assets';
import { parseQuery, withoutUndefined } from '@/server/validation/common';
import { assetQuerySchema, createAssetSchema } from '@/server/validation/organizations';

export const dynamic = 'force-dynamic';

export const GET = withTenantApi('asset.read', {}, async ({ request, meta, ctx }) => {
  const query = parseQuery(request, assetQuerySchema);
  const result = await listAssets(ctx.organization.id, {
    search: query.search ?? null,
    ...(query.type ? { type: query.type } : {}),
    ...(query.status ? { status: query.status } : {}),
    ...(query.criticality ? { criticality: query.criticality } : {}),
    page: query.page,
    pageSize: query.pageSize,
    sort: query.sort,
    direction: query.direction,
  });
  return jsonResponse(result, meta);
});

export const POST = withTenantApi('asset.create', {}, async ({ request, meta, ctx }) => {
  const input = createAssetSchema.parse(await readJsonBody(request));
  const asset = await createAsset(ctx, withoutUndefined(input));
  return jsonResponse({ asset }, meta, 201);
});
