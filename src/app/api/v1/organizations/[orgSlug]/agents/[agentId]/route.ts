import { jsonResponse, withTenantApi } from '@/server/api/handler';
import { readOptionalJsonBody } from '@/server/http/request-meta';
import { getAgentDetail, revokeAgent } from '@/server/services/agents';
import { agentLifecycleSchema } from '@/server/validation/agents';

export const dynamic = 'force-dynamic';

type Params = { orgSlug: string; agentId: string };

export const GET = withTenantApi<Params>('agent.read', {}, async ({ meta, ctx, params }) => {
  const detail = await getAgentDetail(ctx, params.agentId);
  return jsonResponse(detail, meta);
});

/** Revocation is the only way to remove access; the record itself is kept. */
export const DELETE = withTenantApi<Params>(
  'agent.manage',
  {},
  async ({ request, meta, ctx, params }) => {
    const input = agentLifecycleSchema.parse(await readOptionalJsonBody(request));
    const agent = await revokeAgent(ctx, params.agentId, input.note ?? null);
    return jsonResponse({ agent }, meta);
  },
);
