import { jsonResponse, withTenantApi } from '@/server/api/handler';
import { readOptionalJsonBody } from '@/server/http/request-meta';
import { resumeAgent } from '@/server/services/agents';
import { agentLifecycleSchema } from '@/server/validation/agents';

export const dynamic = 'force-dynamic';

type Params = { orgSlug: string; agentId: string };

export const POST = withTenantApi<Params>(
  'agent.manage',
  {},
  async ({ request, meta, ctx, params }) => {
    const input = agentLifecycleSchema.parse(await readOptionalJsonBody(request));
    const agent = await resumeAgent(ctx, params.agentId, input.note ?? null);
    return jsonResponse({ agent }, meta);
  },
);
