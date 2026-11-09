import { jsonResponse, withTenantApi } from '@/server/api/handler';
import { readOptionalJsonBody } from '@/server/http/request-meta';
import { rotateAgentToken } from '@/server/services/agents';
import { agentLifecycleSchema } from '@/server/validation/agents';

export const dynamic = 'force-dynamic';

type Params = { orgSlug: string; agentId: string };

/**
 * Replaces an active agent's credential. The capability gate admits OWNER and
 * ADMIN, and the service rejects every role except OWNER, because the response
 * carries the new plaintext token exactly once.
 */
export const POST = withTenantApi<Params>(
  'agent.manage',
  {},
  async ({ request, meta, ctx, params }) => {
    const input = agentLifecycleSchema.parse(await readOptionalJsonBody(request));
    const result = await rotateAgentToken(ctx, params.agentId, input.note ?? null);
    return jsonResponse(result, meta, 200, { 'X-Agent-Token-Issued': 'once' });
  },
);
