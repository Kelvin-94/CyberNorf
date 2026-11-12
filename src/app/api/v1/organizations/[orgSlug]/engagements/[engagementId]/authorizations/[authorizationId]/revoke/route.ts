import { jsonResponse, withTenantApi } from '@/server/api/handler';
import { readJsonBody } from '@/server/http/request-meta';
import { revokeAuthorization } from '@/server/services/engagements';
import { revokeAuthorizationSchema } from '@/server/validation/engagements';

export const dynamic = 'force-dynamic';

type Params = { orgSlug: string; engagementId: string; authorizationId: string };

export const POST = withTenantApi<Params>(
  'engagement.authorize',
  {},
  async ({ request, meta, ctx, params }) => {
    const input = revokeAuthorizationSchema.parse(await readJsonBody(request));
    const authorization = await revokeAuthorization(
      ctx,
      params.engagementId,
      params.authorizationId,
      { reason: input.reason },
    );
    return jsonResponse({ authorization }, meta);
  },
);
