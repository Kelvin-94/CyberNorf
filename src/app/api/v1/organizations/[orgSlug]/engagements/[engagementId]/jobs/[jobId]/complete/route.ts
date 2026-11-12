import { jsonResponse, withTenantApi } from '@/server/api/handler';
import { readJsonBody } from '@/server/http/request-meta';
import { completeExecutionJob } from '@/server/services/execution';
import { completeExecutionJobSchema } from '@/server/validation/engagements';

export const dynamic = 'force-dynamic';

type Params = { orgSlug: string; engagementId: string; jobId: string };

export const POST = withTenantApi<Params>(
  'execution.dispatch',
  { rateLimit: { limit: 60, windowSeconds: 60, scope: 'user' } },
  async ({ request, meta, ctx, params }) => {
    const input = completeExecutionJobSchema.parse(await readJsonBody(request));
    const job = await completeExecutionJob(ctx, params.jobId, {
      outcome: input.outcome,
      ...(input.summary !== undefined ? { summary: input.summary } : {}),
    });
    return jsonResponse({ job }, meta);
  },
);
