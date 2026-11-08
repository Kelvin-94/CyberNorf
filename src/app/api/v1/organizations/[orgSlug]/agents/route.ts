import { jsonResponse, withTenantApi } from '@/server/api/handler';
import { readJsonBody } from '@/server/http/request-meta';
import { listAgents, registerAgent } from '@/server/services/agents';
import { registerAgentSchema } from '@/server/validation/agents';
import { withoutUndefined } from '@/server/validation/common';

export const dynamic = 'force-dynamic';

type Params = { orgSlug: string };

/** Every role that can read the console may see which agents are connected. */
export const GET = withTenantApi<Params>('agent.read', {}, async ({ meta, ctx }) => {
  const overview = await listAgents(ctx);
  return jsonResponse(overview, meta);
});

export const POST = withTenantApi<Params>('agent.manage', {}, async ({ request, meta, ctx }) => {
  const input = registerAgentSchema.parse(await readJsonBody(request));
  const result = await registerAgent(ctx, withoutUndefined(input));
  // The plaintext token is in the body exactly once; the header only marks that
  // this response carried a credential so clients never cache or log it.
  return jsonResponse(result, meta, 201, result.token ? { 'X-Agent-Token-Issued': 'once' } : {});
});
