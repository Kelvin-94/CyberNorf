import { jsonResponse, withTenantApi } from '@/server/api/handler';
import { readJsonBody } from '@/server/http/request-meta';
import { getIdentityDetail, updateIdentity } from '@/server/services/identities';
import { updateIdentitySchema } from '@/server/validation/identities';

export const dynamic = 'force-dynamic';

type Params = { orgSlug: string; identityId: string };

export const GET = withTenantApi<Params>('identity.read', {}, async ({ meta, ctx, params }) => {
  const identity = await getIdentityDetail(ctx.organization.id, params.identityId);
  return jsonResponse({ identity }, meta);
});

export const PATCH = withTenantApi<Params>(
  'identity.manage',
  {},
  async ({ request, meta, ctx, params }) => {
    const input = updateIdentitySchema.parse(await readJsonBody(request));
    const identity = await updateIdentity(ctx, params.identityId, input);
    return jsonResponse({ identity }, meta);
  },
);
