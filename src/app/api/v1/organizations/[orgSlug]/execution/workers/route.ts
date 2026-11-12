import { jsonResponse, withTenantApi } from '@/server/api/handler';
import { readJsonBody } from '@/server/http/request-meta';
import { listExecutionWorkers, registerExecutionWorker } from '@/server/services/execution';
import { parseQuery } from '@/server/validation/common';
import { registerWorkerSchema, workerListQuerySchema } from '@/server/validation/engagements';

export const dynamic = 'force-dynamic';

type Params = { orgSlug: string };

export const GET = withTenantApi<Params>('execution.read', {}, async ({ request, meta, ctx }) => {
  const query = parseQuery(request, workerListQuerySchema);
  const page = await listExecutionWorkers(ctx.organization.id, {
    page: query.page,
    pageSize: query.pageSize,
    ...(query.status ? { status: query.status } : {}),
  });
  return jsonResponse(page, meta);
});

export const POST = withTenantApi<Params>(
  'execution.worker_manage',
  {},
  async ({ request, meta, ctx }) => {
    const input = registerWorkerSchema.parse(await readJsonBody(request));
    const worker = await registerExecutionWorker(ctx, {
      name: input.name,
      isolated: input.isolated,
      egressAllowlist: input.egressAllowlist,
      ...(input.attestationRef !== undefined ? { attestationRef: input.attestationRef } : {}),
    });
    return jsonResponse({ worker }, meta, 201);
  },
);
