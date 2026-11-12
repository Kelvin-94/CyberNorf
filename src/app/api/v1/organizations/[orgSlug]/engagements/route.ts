import { jsonResponse, withTenantApi } from '@/server/api/handler';
import { readJsonBody } from '@/server/http/request-meta';
import { createEngagement, listEngagements } from '@/server/services/engagements';
import { parseQuery } from '@/server/validation/common';
import { createEngagementSchema, engagementListQuerySchema } from '@/server/validation/engagements';

export const dynamic = 'force-dynamic';

type Params = { orgSlug: string };

export const GET = withTenantApi<Params>('engagement.read', {}, async ({ request, meta, ctx }) => {
  const query = parseQuery(request, engagementListQuerySchema);
  const page = await listEngagements(ctx.organization.id, query);
  return jsonResponse(page, meta);
});

export const POST = withTenantApi<Params>(
  'engagement.manage',
  {},
  async ({ request, meta, ctx }) => {
    const input = createEngagementSchema.parse(await readJsonBody(request));
    const engagement = await createEngagement(ctx, {
      name: input.name,
      startsAt: input.startsAt,
      endsAt: input.endsAt,
      ...(input.description !== undefined ? { description: input.description } : {}),
    });
    return jsonResponse({ engagement }, meta, 201);
  },
);
