import { jsonResponse, withTenantApi } from '@/server/api/handler';
import { revokeCredential } from '@/server/services/identities';

export const dynamic = 'force-dynamic';

type Params = { orgSlug: string; identityId: string; credentialId: string };

export const DELETE = withTenantApi<Params>(
  'identity.manage',
  {},
  async ({ meta, ctx, params }) => {
    const credential = await revokeCredential(ctx, params.identityId, params.credentialId);
    return jsonResponse({ credential }, meta);
  },
);
