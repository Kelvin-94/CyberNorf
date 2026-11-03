import { jsonResponse, withTenantApi } from '@/server/api/handler';
import { readJsonBody } from '@/server/http/request-meta';
import { changeFindingStatus, getFindingDetail } from '@/server/services/findings';
import { changeFindingStatusSchema } from '@/server/validation/findings';

export const dynamic = 'force-dynamic';

type Params = { orgSlug: string; findingId: string };

/**
 * Status changes are modelled as a transition on the finding rather than a
 * field patch, so illegal moves are rejected with 409 and the change reason is
 * recorded alongside the audit event.
 */
export const POST = withTenantApi<Params>(
  'finding.update',
  {},
  async ({ request, meta, ctx, params }) => {
    const input = changeFindingStatusSchema.parse(await readJsonBody(request));
    const result = await changeFindingStatus(
      ctx,
      params.findingId,
      input.status,
      input.note ?? null,
    );
    const finding = await getFindingDetail(ctx, params.findingId);
    return jsonResponse({ result, finding }, meta);
  },
);
