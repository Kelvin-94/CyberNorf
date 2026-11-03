import { jsonResponse, withTenantApi } from '@/server/api/handler';
import { listAuditEvents } from '@/server/services/audit';
import { auditQuerySchema } from '@/server/validation/audit';
import { parseQuery } from '@/server/validation/common';

export const dynamic = 'force-dynamic';

export const GET = withTenantApi('audit.read', {}, async ({ request, meta, ctx }) => {
  const query = parseQuery(request, auditQuerySchema);
  const result = await listAuditEvents(ctx.organization.id, {
    search: query.search ?? null,
    ...(query.action ? { action: query.action } : {}),
    ...(query.outcome ? { outcome: query.outcome } : {}),
    ...(query.targetType ? { targetType: query.targetType } : {}),
    ...(query.actorId ? { actorId: query.actorId } : {}),
    ...(query.from ? { from: query.from } : {}),
    ...(query.to ? { to: query.to } : {}),
    page: query.page,
    pageSize: query.pageSize,
    direction: query.direction,
  });
  return jsonResponse(result, meta);
});
