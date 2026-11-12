import { jsonResponse, withTenantApi } from '@/server/api/handler';
import { readJsonBody } from '@/server/http/request-meta';
import {
  DEFAULT_RETENTION_POLICY,
  RETENTION_POLICY_BOUNDS,
  getRetentionPolicy,
  updateRetentionPolicy,
} from '@/server/services/retention';
import { retentionPolicySchema } from '@/server/validation/retention';

export const dynamic = 'force-dynamic';

type Params = { orgSlug: string };

export const GET = withTenantApi<Params>('retention.read', {}, async ({ meta, ctx }) => {
  const retention = await getRetentionPolicy(ctx.organization.id);
  return jsonResponse(
    {
      retention,
      defaults: DEFAULT_RETENTION_POLICY,
      bounds: RETENTION_POLICY_BOUNDS,
    },
    meta,
  );
});

export const PUT = withTenantApi<Params>('retention.manage', {}, async ({ request, meta, ctx }) => {
  const input = retentionPolicySchema.parse(await readJsonBody(request));
  const retention = await updateRetentionPolicy(ctx, input);
  return jsonResponse({ retention }, meta);
});
