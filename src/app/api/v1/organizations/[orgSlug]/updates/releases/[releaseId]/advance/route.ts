import { jsonResponse, withTenantApi } from '@/server/api/handler';
import { readJsonBody } from '@/server/http/request-meta';
import { advanceRelease } from '@/server/services/updates';
import { advanceReleaseSchema } from '@/server/validation/zero-trust';

export const dynamic = 'force-dynamic';

type Params = { orgSlug: string; releaseId: string };

/**
 * Staging moves one step at a time (DRAFT to CANARY to ROLLING to RELEASED);
 * skipping a stage is refused so a wider cohort always follows a narrower one.
 */
export const POST = withTenantApi<Params>(
  'update.manage',
  {},
  async ({ request, meta, ctx, params }) => {
    const input = advanceReleaseSchema.parse(await readJsonBody(request));
    const release = await advanceRelease(ctx, params.releaseId, input);
    return jsonResponse({ release }, meta);
  },
);
