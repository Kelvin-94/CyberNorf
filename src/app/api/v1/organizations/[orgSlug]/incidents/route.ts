import { jsonResponse, withTenantApi } from '@/server/api/handler';
import { readJsonBody } from '@/server/http/request-meta';
import { createIncident, listIncidents } from '@/server/services/incidents';
import { parseQuery, withoutUndefined } from '@/server/validation/common';
import { createIncidentSchema, incidentQuerySchema } from '@/server/validation/findings';

export const dynamic = 'force-dynamic';

export const GET = withTenantApi('incident.read', {}, async ({ request, meta, ctx }) => {
  const query = parseQuery(request, incidentQuerySchema);
  const result = await listIncidents(ctx.organization.id, {
    search: query.search ?? null,
    ...(query.status ? { status: query.status } : {}),
    ...(query.severity ? { severity: query.severity } : {}),
    ...(query.assignedToId ? { assignedToId: query.assignedToId } : {}),
    page: query.page,
    pageSize: query.pageSize,
    sort: query.sort,
    direction: query.direction,
  });
  return jsonResponse(result, meta);
});

export const POST = withTenantApi('incident.create', {}, async ({ request, meta, ctx }) => {
  const input = createIncidentSchema.parse(await readJsonBody(request));
  const incident = await createIncident(ctx, withoutUndefined(input));
  return jsonResponse({ incident }, meta, 201);
});
