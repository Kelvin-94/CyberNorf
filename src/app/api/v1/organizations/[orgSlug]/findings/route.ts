import { jsonResponse, withTenantApi } from '@/server/api/handler';
import { readJsonBody } from '@/server/http/request-meta';
import { createFinding, listFindings } from '@/server/services/findings';
import { parseQuery, withoutUndefined } from '@/server/validation/common';
import { createFindingSchema, findingQuerySchema } from '@/server/validation/findings';

export const dynamic = 'force-dynamic';

export const GET = withTenantApi('finding.read', {}, async ({ request, meta, ctx }) => {
  const query = parseQuery(request, findingQuerySchema);
  const result = await listFindings(ctx.organization.id, {
    search: query.search ?? null,
    ...(query.status ? { status: query.status } : {}),
    ...(query.severity ? { severity: query.severity } : {}),
    ...(query.assetId ? { assetId: query.assetId } : {}),
    ...(query.incidentId ? { incidentId: query.incidentId } : {}),
    ...(query.assignedToId ? { assignedToId: query.assignedToId } : {}),
    page: query.page,
    pageSize: query.pageSize,
    sort: query.sort,
    direction: query.direction,
  });
  return jsonResponse(result, meta);
});

export const POST = withTenantApi('finding.create', {}, async ({ request, meta, ctx }) => {
  const input = createFindingSchema.parse(await readJsonBody(request));
  const finding = await createFinding(ctx, withoutUndefined(input));
  return jsonResponse({ finding }, meta, 201);
});
