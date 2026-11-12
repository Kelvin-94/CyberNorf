import { jsonResponse, withTenantApi } from '@/server/api/handler';
import { startExecutionJob } from '@/server/services/execution';

export const dynamic = 'force-dynamic';

type Params = { orgSlug: string; engagementId: string; jobId: string };

export const POST = withTenantApi<Params>(
  'execution.dispatch',
  { rateLimit: { limit: 30, windowSeconds: 60, scope: 'user' } },
  async ({ meta, ctx, params }) => {
    const job = await startExecutionJob(ctx, params.jobId);
    return jsonResponse({ job }, meta);
  },
);
