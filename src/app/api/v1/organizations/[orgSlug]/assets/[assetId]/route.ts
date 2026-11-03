import { emptyResponse, jsonResponse, withTenantApi } from '@/server/api/handler';
import { readJsonBody } from '@/server/http/request-meta';
import { deleteAsset, getAssetDetail, updateAsset } from '@/server/services/assets';
import { withoutUndefined } from '@/server/validation/common';
import { updateAssetSchema } from '@/server/validation/organizations';

export const dynamic = 'force-dynamic';

type Params = { orgSlug: string; assetId: string };

export const GET = withTenantApi<Params>('asset.read', {}, async ({ meta, ctx, params }) => {
  const asset = await getAssetDetail(ctx, params.assetId);
  return jsonResponse({ asset }, meta);
});

export const PATCH = withTenantApi<Params>(
  'asset.update',
  {},
  async ({ request, meta, ctx, params }) => {
    const input = updateAssetSchema.parse(await readJsonBody(request));
    const asset = await updateAsset(ctx, params.assetId, withoutUndefined(input));
    return jsonResponse({ asset }, meta);
  },
);

export const DELETE = withTenantApi<Params>('asset.delete', {}, async ({ meta, ctx, params }) => {
  await deleteAsset(ctx, params.assetId);
  return emptyResponse(meta);
});
