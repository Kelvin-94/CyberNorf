import { jsonResponse, withTenantApi } from '@/server/api/handler';
import { readJsonBody } from '@/server/http/request-meta';
import { createIdentity, getIdentityOverview, listIdentities } from '@/server/services/identities';
import { parseQuery } from '@/server/validation/common';
import { createIdentitySchema, identityListQuerySchema } from '@/server/validation/identities';

export const dynamic = 'force-dynamic';

type Params = { orgSlug: string };

export const GET = withTenantApi<Params>('identity.read', {}, async ({ request, meta, ctx }) => {
  const query = parseQuery(request, identityListQuerySchema);
  const [page, overview] = await Promise.all([
    listIdentities(ctx.organization.id, query),
    getIdentityOverview(ctx.organization.id),
  ]);
  return jsonResponse({ ...page, overview }, meta);
});

export const POST = withTenantApi<Params>('identity.manage', {}, async ({ request, meta, ctx }) => {
  const input = createIdentitySchema.parse(await readJsonBody(request));
  const identity = await createIdentity(ctx, input);
  return jsonResponse(
    { identity },
    meta,
    201,
    identity.status === 'PENDING_APPROVAL' ? { 'X-Identity-Pending-Approval': 'true' } : {},
  );
});
