import { jsonResponse, withTenantApi } from '@/server/api/handler';
import { listIncidentAssignees } from '@/server/services/incidents';

export const dynamic = 'force-dynamic';

export const GET = withTenantApi('incident.read', {}, async ({ meta, ctx }) => {
  const members = await listIncidentAssignees(ctx.organization.id);
  return jsonResponse({ members }, meta);
});
