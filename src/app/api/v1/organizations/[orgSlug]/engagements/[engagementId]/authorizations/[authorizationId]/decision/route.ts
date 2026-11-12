import { jsonResponse, withTenantApi } from '@/server/api/handler';
import { readJsonBody } from '@/server/http/request-meta';
import { decideAuthorization } from '@/server/services/engagements';
import { decideAuthorizationSchema } from '@/server/validation/engagements';

export const dynamic = 'force-dynamic';

type Params = { orgSlug: string; engagementId: string; authorizationId: string };

export const POST = withTenantApi<Params>(
  'engagement.authorize',
  {},
  async ({ request, meta, ctx, params }) => {
    const input = decideAuthorizationSchema.parse(await readJsonBody(request));
    const authorization = await decideAuthorization(
      ctx,
      params.engagementId,
      params.authorizationId,
      {
        decision: input.decision,
        ...(input.note !== undefined ? { note: input.note } : {}),
      },
    );
    return jsonResponse({ authorization }, meta);
  },
);
