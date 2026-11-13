import { jsonResponse, withTenantApi } from '@/server/api/handler';
import { readJsonBody } from '@/server/http/request-meta';
import { offerUpdate } from '@/server/services/updates';
import { offerUpdateSchema } from '@/server/validation/zero-trust';

export const dynamic = 'force-dynamic';

type Params = { orgSlug: string; releaseId: string };

/**
 * Offering records the intent to update a device; it never installs anything.
 * Devices outside the release's current cohort are skipped and counted.
 */
export const POST = withTenantApi<Params>(
  'update.manage',
  {},
  async ({ request, meta, ctx, params }) => {
    const input = offerUpdateSchema.parse(await readJsonBody(request));
    const result = await offerUpdate(ctx, params.releaseId, input);
    return jsonResponse(result, meta, 201);
  },
);
