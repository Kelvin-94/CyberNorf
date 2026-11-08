import { jsonResponse, withTenantApi } from '@/server/api/handler';
import { readOptionalJsonBody } from '@/server/http/request-meta';
import { approveAgent } from '@/server/services/agents';
import { approveAgentSchema } from '@/server/validation/agents';
import { withoutUndefined } from '@/server/validation/common';

export const dynamic = 'force-dynamic';

type Params = { orgSlug: string; agentId: string };

/**
 * Owner-only approval. The capability gate admits OWNER and ADMIN, and the
 * service rejects every role except OWNER, so approval cannot be delegated.
 */
export const POST = withTenantApi<Params>(
  'agent.manage',
  {},
  async ({ request, meta, ctx, params }) => {
    const input = approveAgentSchema.parse(await readOptionalJsonBody(request));
    const result = await approveAgent(ctx, params.agentId, withoutUndefined(input));
    return jsonResponse(result, meta, 200, { 'X-Agent-Token-Issued': 'once' });
  },
);
