import { jsonResponse, withTenantApi } from '@/server/api/handler';
import { readJsonBody } from '@/server/http/request-meta';
import { rollbackRelease } from '@/server/services/updates';
import { rollbackReleaseSchema } from '@/server/validation/zero-trust';

export const dynamic = 'force-dynamic';

type Params = { orgSlug: string; releaseId: string };

/**
 * Rolling a release back marks it ROLLED_BACK and cascades every device update
 * tied to it, so no device is left believing it is on a withdrawn build.
 */
export const POST = withTenantApi<Params>(
  'update.manage',
  {},
  async ({ request, meta, ctx, params }) => {
    const input = rollbackReleaseSchema.parse(await readJsonBody(request));
    const result = await rollbackRelease(ctx, params.releaseId, input.reason);
    return jsonResponse(result, meta);
  },
);
