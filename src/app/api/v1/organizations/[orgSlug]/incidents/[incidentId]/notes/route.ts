import { jsonResponse, withTenantApi } from '@/server/api/handler';
import { readJsonBody } from '@/server/http/request-meta';
import { addIncidentNote } from '@/server/services/incidents';
import { incidentNoteSchema } from '@/server/validation/findings';

export const dynamic = 'force-dynamic';

type Params = { orgSlug: string; incidentId: string };

export const POST = withTenantApi<Params>(
  'incident.note',
  {},
  async ({ request, meta, ctx, params }) => {
    const input = incidentNoteSchema.parse(await readJsonBody(request));
    const note = await addIncidentNote(ctx, params.incidentId, input.body);
    return jsonResponse({ note }, meta, 201);
  },
);
