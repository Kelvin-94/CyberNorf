import { jsonResponse, withTenantApi } from '@/server/api/handler';
import { readJsonBody } from '@/server/http/request-meta';
import { linkFindingsToIncident } from '@/server/services/incidents';
import { linkFindingsSchema } from '@/server/validation/findings';

export const dynamic = 'force-dynamic';

type Params = { orgSlug: string; incidentId: string };

export const POST = withTenantApi<Params>(
  'incident.update',
  {},
  async ({ request, meta, ctx, params }) => {
    const input = linkFindingsSchema.parse(await readJsonBody(request));
    const result = await linkFindingsToIncident(ctx, params.incidentId, input.findingIds);
    return jsonResponse(result, meta);
  },
);
