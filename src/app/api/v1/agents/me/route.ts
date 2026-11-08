import { withAgentApi } from '@/server/api/agent';
import { jsonResponse } from '@/server/api/handler';
import { describeAgent } from '@/server/services/agents';

export const dynamic = 'force-dynamic';

/**
 * Credential self-check. The bundled monitor calls this first so a mistyped or
 * revoked token fails loudly before any checks run.
 */
export const GET = withAgentApi('monitor.read', async ({ meta, agent }) => {
  const profile = await describeAgent(agent);
  return jsonResponse({ agent: profile }, meta);
});
