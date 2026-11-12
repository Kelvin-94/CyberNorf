import { jsonResponse, withTenantApi } from '@/server/api/handler';
import { readJsonBody } from '@/server/http/request-meta';
import { reviewExecutionJob } from '@/server/services/execution';
import { reviewExecutionJobSchema } from '@/server/validation/engagements';

export const dynamic = 'force-dynamic';

type Params = { orgSlug: string; engagementId: string; jobId: string };

export const POST = withTenantApi<Params>(
  'execution.review',
  {},
  async ({ request, meta, ctx, params }) => {
    const input = reviewExecutionJobSchema.parse(await readJsonBody(request));
    const job = await reviewExecutionJob(ctx, params.jobId, {
      decision: input.decision,
      ...(input.note !== undefined ? { note: input.note } : {}),
    });
    return jsonResponse({ job }, meta);
  },
);
