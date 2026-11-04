import { emptyResponse, jsonResponse, withTenantApi } from '@/server/api/handler';
import { getFrameworkDetail, withdrawFramework } from '@/server/services/compliance';

export const dynamic = 'force-dynamic';

type Params = { orgSlug: string; frameworkKey: string };

export const GET = withTenantApi<Params>('compliance.read', {}, async ({ meta, ctx, params }) => {
  const detail = await getFrameworkDetail(ctx, params.frameworkKey);
  return jsonResponse(detail, meta);
});

export const DELETE = withTenantApi<Params>(
  'compliance.manage',
  {},
  async ({ meta, ctx, params }) => {
    await withdrawFramework(ctx, params.frameworkKey);
    return emptyResponse(meta);
  },
);
