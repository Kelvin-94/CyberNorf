import { jsonResponse, withTenantApi } from '@/server/api/handler';
import { readJsonBody } from '@/server/http/request-meta';
import { addScopeEntry, getEngagement } from '@/server/services/engagements';
import { createScopeEntrySchema } from '@/server/validation/engagements';

export const dynamic = 'force-dynamic';

type Params = { orgSlug: string; engagementId: string };

export const GET = withTenantApi<Params>('engagement.read', {}, async ({ meta, ctx, params }) => {
  const engagement = await getEngagement(ctx.organization.id, params.engagementId);
  return jsonResponse({ scopeEntries: engagement.scopeEntries }, meta);
});

export const POST = withTenantApi<Params>(
  'engagement.manage',
  {},
  async ({ request, meta, ctx, params }) => {
    const input = createScopeEntrySchema.parse(await readJsonBody(request));
    const entry = await addScopeEntry(ctx, params.engagementId, {
      kind: input.kind,
      targetType: input.targetType,
      value: input.value,
      ...(input.note !== undefined ? { note: input.note } : {}),
    });
    return jsonResponse({ scopeEntry: entry }, meta, 201);
  },
);
