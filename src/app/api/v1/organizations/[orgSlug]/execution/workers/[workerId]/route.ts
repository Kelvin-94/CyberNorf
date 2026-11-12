import { jsonResponse, withTenantApi } from '@/server/api/handler';
import { readJsonBody } from '@/server/http/request-meta';
import { updateExecutionWorker } from '@/server/services/execution';
import { withoutUndefined } from '@/server/validation/common';
import { updateWorkerSchema } from '@/server/validation/engagements';

export const dynamic = 'force-dynamic';

type Params = { orgSlug: string; workerId: string };

export const PATCH = withTenantApi<Params>(
  'execution.worker_manage',
  {},
  async ({ request, meta, ctx, params }) => {
    const input = updateWorkerSchema.parse(await readJsonBody(request));
    const worker = await updateExecutionWorker(ctx, params.workerId, withoutUndefined(input));
    return jsonResponse({ worker }, meta);
  },
);
