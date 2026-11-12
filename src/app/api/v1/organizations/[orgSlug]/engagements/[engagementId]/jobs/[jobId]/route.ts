import { jsonResponse, withTenantApi } from '@/server/api/handler';
import { getExecutionJob } from '@/server/services/execution';

export const dynamic = 'force-dynamic';

type Params = { orgSlug: string; engagementId: string; jobId: string };

export const GET = withTenantApi<Params>('execution.read', {}, async ({ meta, ctx, params }) => {
  const job = await getExecutionJob(ctx.organization.id, params.jobId);
  return jsonResponse({ job }, meta);
});
