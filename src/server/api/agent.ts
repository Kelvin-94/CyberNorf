import type { NextRequest } from 'next/server';
import { agentHasScope, type AgentScope } from '@/server/domain/agents';
import { forbidden, toErrorResponse, unauthenticated } from '@/server/errors';
import { getRequestMeta, type RequestMeta } from '@/server/http/request-meta';
import { enforceRateLimit } from '@/server/security/rate-limit';
import { authenticateAgentToken, type AgentPrincipal } from '@/server/services/agents';
import type { NextRouteContext, RouteParams } from './handler';

export interface AgentHandlerInput<P extends RouteParams> {
  request: NextRequest;
  meta: RequestMeta;
  params: P;
  agent: AgentPrincipal;
}

/** Pre-authentication floor per client address, per method. */
const ADDRESS_LIMIT = 60;
/** Per-agent ceiling once the token is resolved. */
const AGENT_LIMIT = 120;

function bearerToken(request: NextRequest): string | null {
  const header = request.headers.get('authorization');
  if (!header) {
    return null;
  }
  const [scheme, value] = header.split(' ');
  if (!value || scheme?.toLowerCase() !== 'bearer') {
    return null;
  }
  return value.trim();
}

/**
 * Wraps an agent-facing route.
 *
 * Agent credentials travel in the Authorization header and never in cookies, so
 * these routes deliberately skip the same-origin CSRF check that protects the
 * browser session API: a browser cannot be tricked into attaching a bearer
 * token it does not hold, and the token is scoped to monitoring only.
 *
 * Authentication resolves to an ACTIVE, unexpired agent, and the requested
 * scope must be granted on that agent before the handler runs. Unknown tokens,
 * suspended agents and expired tokens all fail as unauthenticated so the
 * endpoint cannot be used to enumerate agents.
 */
export function withAgentApi<P extends RouteParams = RouteParams>(
  scope: AgentScope,
  handler: (input: AgentHandlerInput<P>) => Promise<Response>,
): (request: NextRequest, context: NextRouteContext<P>) => Promise<Response> {
  return async (request, context) => {
    const meta = getRequestMeta(request);

    try {
      await enforceRateLimit(
        `agent-api:ip:${meta.ipAddress ?? 'unknown'}:${request.method}`,
        ADDRESS_LIMIT,
        60,
      );

      const token = bearerToken(request);
      if (!token) {
        throw unauthenticated();
      }

      const agent = await authenticateAgentToken(token);

      if (!agentHasScope(agent.scopes, scope)) {
        throw forbidden(`This agent credential does not grant the ${scope} scope.`);
      }

      await enforceRateLimit(`agent-api:agent:${agent.id}:${request.method}`, AGENT_LIMIT, 60);

      const params = ((await context?.params) ?? {}) as P;

      return await handler({ request, meta, params, agent });
    } catch (error) {
      return toErrorResponse(error, meta.requestId);
    }
  };
}
