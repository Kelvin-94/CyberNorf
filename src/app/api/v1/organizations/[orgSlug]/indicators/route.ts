import { jsonResponse, withTenantApi } from '@/server/api/handler';
import { readJsonBody } from '@/server/http/request-meta';
import { createIndicator, listIndicators } from '@/server/services/indicators';
import { parseQuery, withoutUndefined } from '@/server/validation/common';
import { createIndicatorSchema, indicatorQuerySchema } from '@/server/validation/indicators';

export const dynamic = 'force-dynamic';

export const GET = withTenantApi('indicator.read', {}, async ({ request, meta, ctx }) => {
  const query = parseQuery(request, indicatorQuerySchema);
  const result = await listIndicators(ctx.organization.id, {
    search: query.search ?? null,
    ...(query.type ? { type: query.type } : {}),
    ...(query.status ? { status: query.status } : {}),
    ...(query.expired === 'true' ? { expiredOnly: true } : {}),
    page: query.page,
    pageSize: query.pageSize,
    sort: query.sort,
    direction: query.direction,
  });
  return jsonResponse(result, meta);
});

export const POST = withTenantApi('indicator.manage', {}, async ({ request, meta, ctx }) => {
  const input = createIndicatorSchema.parse(await readJsonBody(request));
  const indicator = await createIndicator(ctx, withoutUndefined(input));
  return jsonResponse({ indicator }, meta, 201);
});
