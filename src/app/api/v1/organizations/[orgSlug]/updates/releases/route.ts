import { jsonResponse, withTenantApi } from '@/server/api/handler';
import { readJsonBody } from '@/server/http/request-meta';
import { getUpdateOverview, listReleases, publishRelease } from '@/server/services/updates';
import { parseQuery } from '@/server/validation/common';
import { publishReleaseSchema, releaseListQuerySchema } from '@/server/validation/zero-trust';

export const dynamic = 'force-dynamic';

type Params = { orgSlug: string };

export const GET = withTenantApi<Params>('update.read', {}, async ({ request, meta, ctx }) => {
  const query = parseQuery(request, releaseListQuerySchema);
  const [page, overview] = await Promise.all([
    listReleases(ctx.organization.id, query),
    getUpdateOverview(ctx.organization.id),
  ]);
  return jsonResponse({ ...page, overview }, meta);
});

/**
 * Publishing verifies the publisher signature over the manifest and the
 * manifest digest before anything is stored, so an unverifiable release never
 * reaches the staging states that devices trust.
 */
export const POST = withTenantApi<Params>('update.manage', {}, async ({ request, meta, ctx }) => {
  const input = publishReleaseSchema.parse(await readJsonBody(request));
  const release = await publishRelease(ctx, input);
  return jsonResponse({ release }, meta, 201);
});
