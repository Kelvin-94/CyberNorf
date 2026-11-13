import type { NextRequest } from 'next/server';
import { toErrorResponse, unauthenticated } from '@/server/errors';
import { getRequestMeta, type RequestMeta } from '@/server/http/request-meta';
import { enforceRateLimit } from '@/server/security/rate-limit';
import { authenticateConnectorToken, type ConnectorPrincipal } from '@/server/services/network';
import type { NextRouteContext, RouteParams } from './handler';

export interface ConnectorHandlerInput<P extends RouteParams> {
  request: NextRequest;
  meta: RequestMeta;
  params: P;
  connector: ConnectorPrincipal;
}

/** Pre-authentication floor per client address, per method. */
const ADDRESS_LIMIT = 60;
/** Per-connector ceiling once the token is resolved. Flows arrive in batches. */
const CONNECTOR_LIMIT = 240;

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
 * Wraps a connector-facing route.
 *
 * Connectors authenticate with a bearer token created by an administrator and
 * never with a browser session, so these routes skip the same-origin CSRF check
 * that guards the session API: a browser cannot be made to attach a token it
 * does not hold. Unknown and revoked tokens both fail as unauthenticated so the
 * endpoint cannot be used to enumerate connectors.
 *
 * A resolved connector is not by itself permission to act on any object: the
 * handlers additionally check that the action they are reporting on is bound to
 * this connector.
 */
export function withConnectorApi<P extends RouteParams = RouteParams>(
  handler: (input: ConnectorHandlerInput<P>) => Promise<Response>,
): (request: NextRequest, context: NextRouteContext<P>) => Promise<Response> {
  return async (request, context) => {
    const meta = getRequestMeta(request);

    try {
      await enforceRateLimit(
        `connector-api:ip:${meta.ipAddress ?? 'unknown'}:${request.method}`,
        ADDRESS_LIMIT,
        60,
      );

      const token = bearerToken(request);
      if (!token) {
        throw unauthenticated();
      }

      const connector = await authenticateConnectorToken(token);
      await enforceRateLimit(
        `connector-api:connector:${connector.id}:${request.method}`,
        CONNECTOR_LIMIT,
        60,
      );

      const params = ((await context?.params) ?? {}) as P;

      return await handler({ request, meta, params, connector });
    } catch (error) {
      return toErrorResponse(error, meta.requestId);
    }
  };
}
