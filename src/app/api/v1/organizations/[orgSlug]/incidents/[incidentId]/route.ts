import { jsonResponse, withTenantApi } from '@/server/api/handler';
import { readJsonBody } from '@/server/http/request-meta';
import { getIncidentDetail, updateIncident } from '@/server/services/incidents';
import { withoutUndefined } from '@/server/validation/common';
import { updateIncidentSchema } from '@/server/validation/findings';

export const dynamic = 'force-dynamic';

type Params = { orgSlug: string; incidentId: string };

export const GET = withTenantApi<Params>('incident.read', {}, async ({ meta, ctx, params }) => {
  const incident = await getIncidentDetail(ctx, params.incidentId);
  return jsonResponse({ incident }, meta);
});

export const PATCH = withTenantApi<Params>(
  'incident.update',
  {},
  async ({ request, meta, ctx, params }) => {
    const input = updateIncidentSchema.parse(await readJsonBody(request));
    const incident = await updateIncident(ctx, params.incidentId, withoutUndefined(input));
    return jsonResponse({ incident }, meta);
  },
);
