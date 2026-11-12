import { jsonResponse, withTenantApi } from '@/server/api/handler';
import { readJsonBody } from '@/server/http/request-meta';
import { cancelExecutionJob } from '@/server/services/execution';
import { cancelExecutionJobSchema } from '@/server/validation/engagements';

export const dynamic = 'force-dynamic';

type Params = { orgSlug: string; engagementId: string; jobId: string };

export const POST = withTenantApi<Params>(
  'execution.cancel',
  {},
  async ({ request, meta, ctx, params }) => {
    const input = cancelExecutionJobSchema.parse(await readJsonBody(request));
    const job = await cancelExecutionJob(ctx, params.jobId, { reason: input.reason });
    return jsonResponse({ job }, meta);
  },
);
