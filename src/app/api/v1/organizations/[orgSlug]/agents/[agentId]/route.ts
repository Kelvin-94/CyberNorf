import { jsonResponse, withTenantApi } from '@/server/api/handler';
import { readJsonBody, readOptionalJsonBody } from '@/server/http/request-meta';
import { getAgentDetail, revokeAgent, updateAgentHeartbeat } from '@/server/services/agents';
import { agentHeartbeatSchema, agentLifecycleSchema } from '@/server/validation/agents';

export const dynamic = 'force-dynamic';

type Params = { orgSlug: string; agentId: string };

export const GET = withTenantApi<Params>('agent.read', {}, async ({ meta, ctx, params }) => {
  const detail = await getAgentDetail(ctx, params.agentId);
  return jsonResponse(detail, meta);
});

/**
 * Sets the expected reporting cadence. It is an alerting preference rather than
 * an access change, so management rights on the agent are enough; approval and
 * revocation already govern what the agent may do.
 */
export const PATCH = withTenantApi<Params>(
  'agent.manage',
  {},
  async ({ request, meta, ctx, params }) => {
    const input = agentHeartbeatSchema.parse(await readJsonBody(request));
    const agent = await updateAgentHeartbeat(ctx, params.agentId, input);
    return jsonResponse({ agent }, meta);
  },
);

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
