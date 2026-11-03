import { jsonResponse, withTenantApi } from '@/server/api/handler';
import { listAssetOptions } from '@/server/services/assets';

export const dynamic = 'force-dynamic';

export const GET = withTenantApi('asset.read', {}, async ({ meta, ctx }) => {
  const assets = await listAssetOptions(ctx.organization.id);
  return jsonResponse({ assets }, meta);
});
