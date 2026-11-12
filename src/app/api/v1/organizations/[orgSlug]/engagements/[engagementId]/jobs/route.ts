import { jsonResponse, withTenantApi } from '@/server/api/handler';
import { readJsonBody } from '@/server/http/request-meta';
import { listExecutionJobs, requestExecutionJob } from '@/server/services/execution';
import { parseQuery } from '@/server/validation/common';
import { createExecutionJobSchema, jobListQuerySchema } from '@/server/validation/engagements';

export const dynamic = 'force-dynamic';

type Params = { orgSlug: string; engagementId: string };

export const GET = withTenantApi<Params>(
  'execution.read',
  {},
  async ({ request, meta, ctx, params }) => {
    const query = parseQuery(request, jobListQuerySchema);
    const page = await listExecutionJobs(ctx.organization.id, {
      engagementId: params.engagementId,
      ...(query.status ? { status: query.status } : {}),
      page: query.page,
      pageSize: query.pageSize,
    });
    return jsonResponse(page, meta);
  },
);

export const POST = withTenantApi<Params>(
  'execution.dispatch',
  { rateLimit: { limit: 20, windowSeconds: 60, scope: 'user' } },
  async ({ request, meta, ctx, params }) => {
    const input = createExecutionJobSchema.parse(await readJsonBody(request));
    const job = await requestExecutionJob(ctx, params.engagementId, {
      capability: input.capability,
      targetType: input.targetType,
      targetValue: input.targetValue,
      ...(input.workerId !== undefined ? { workerId: input.workerId } : {}),
      ...(input.limits !== undefined ? { limits: input.limits } : {}),
    });
    return jsonResponse({ job }, meta, 201);
  },
);
