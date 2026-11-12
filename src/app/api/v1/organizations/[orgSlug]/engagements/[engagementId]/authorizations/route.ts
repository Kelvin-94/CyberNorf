import { jsonResponse, withTenantApi } from '@/server/api/handler';
import { readJsonBody } from '@/server/http/request-meta';
import { getEngagement, requestAuthorization } from '@/server/services/engagements';
import { requestAuthorizationSchema } from '@/server/validation/engagements';

export const dynamic = 'force-dynamic';

type Params = { orgSlug: string; engagementId: string };

export const GET = withTenantApi<Params>('engagement.read', {}, async ({ meta, ctx, params }) => {
  const engagement = await getEngagement(ctx.organization.id, params.engagementId);
  return jsonResponse({ authorizations: engagement.authorizations }, meta);
});

export const POST = withTenantApi<Params>(
  'engagement.manage',
  {},
  async ({ request, meta, ctx, params }) => {
    const input = requestAuthorizationSchema.parse(await readJsonBody(request));
    const authorization = await requestAuthorization(ctx, params.engagementId, {
      expiresAt: input.expiresAt,
      reference: input.reference,
      ...(input.conditions !== undefined ? { conditions: input.conditions } : {}),
    });
    return jsonResponse({ authorization }, meta, 201);
  },
);
