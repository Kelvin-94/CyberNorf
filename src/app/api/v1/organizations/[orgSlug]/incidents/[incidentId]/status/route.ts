import { jsonResponse, withTenantApi } from '@/server/api/handler';
import { readJsonBody } from '@/server/http/request-meta';
import { changeIncidentStatus } from '@/server/services/incidents';
import { changeIncidentStatusSchema } from '@/server/validation/findings';

export const dynamic = 'force-dynamic';

type Params = { orgSlug: string; incidentId: string };

export const POST = withTenantApi<Params>(
  'incident.update',
  {},
  async ({ request, meta, ctx, params }) => {
    const input = changeIncidentStatusSchema.parse(await readJsonBody(request));
    const result = await changeIncidentStatus(
      ctx,
      params.incidentId,
      input.status,
      input.note ?? null,
    );
    return jsonResponse(result, meta);
  },
);
