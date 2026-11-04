import { jsonResponse, withTenantApi } from '@/server/api/handler';
import { readJsonBody } from '@/server/http/request-meta';
import { addEvidence } from '@/server/services/compliance';
import { createEvidenceSchema } from '@/server/validation/compliance';

export const dynamic = 'force-dynamic';

type Params = { orgSlug: string; controlId: string };

export const POST = withTenantApi<Params>(
  'compliance.evidence',
  { rateLimit: { limit: 120, windowSeconds: 60, scope: 'user' } },
  async ({ request, meta, ctx, params }) => {
    const input = createEvidenceSchema.parse(await readJsonBody(request));
    const evidence = await addEvidence(ctx, params.controlId, {
      kind: input.kind,
      findingId: input.findingId,
      incidentId: input.incidentId,
      assetId: input.assetId,
      reference: input.reference,
      note: input.note ?? null,
    });
    return jsonResponse({ evidence }, meta, 201);
  },
);
