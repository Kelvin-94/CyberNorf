import { jsonResponse, withTenantApi } from '@/server/api/handler';
import { getRelease } from '@/server/services/updates';

export const dynamic = 'force-dynamic';

type Params = { orgSlug: string; releaseId: string };

export const GET = withTenantApi<Params>('update.read', {}, async ({ meta, ctx, params }) => {
  const release = await getRelease(ctx.organization.id, params.releaseId);
  return jsonResponse({ release }, meta);
});
