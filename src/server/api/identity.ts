import type { NextRequest } from 'next/server';
import type { IdentityCredentialScope } from '@/server/domain/identity';
import { forbidden, toErrorResponse, unauthenticated } from '@/server/errors';
import { getRequestMeta, type RequestMeta } from '@/server/http/request-meta';
import { enforceRateLimit } from '@/server/security/rate-limit';
import {
  authenticateMachineIdentity,
  machineIdentityHasScope,
  type MachineIdentityPrincipal,
} from '@/server/services/identities';
import type { NextRouteContext, RouteParams } from './handler';

export interface MachineIdentityHandlerInput<P extends RouteParams> {
  request: NextRequest;
  meta: RequestMeta;
  params: P;
  identity: MachineIdentityPrincipal;
}

/** Pre-authentication floor per client address, per method. */
const ADDRESS_LIMIT = 60;
/** Per-credential ceiling once the token is resolved. */
const CREDENTIAL_LIMIT = 120;

function bearerToken(request: NextRequest): string | null {
  const header = request.headers.get('authorization');
  if (!header) {
    return null;
  }
  const [scheme, value] = header.split(' ');
  if (!value || scheme?.toLowerCase() !== 'bearer') {
    return null;
  }
  const token = value.trim();
  return token.length > 0 ? token : null;
}

/**
 * Wraps a machine-identity-facing route.
 *
 * Credentials travel in the Authorization header and never in cookies, so the
 * browser CSRF check does not apply: a browser cannot be tricked into attaching
 * a bearer token it does not hold. Unknown, revoked, expired and suspended
 * credentials all resolve to the same 401, and the requested scope must be on
 * the credential before the handler runs.
 */
export function withMachineIdentityApi<P extends RouteParams = RouteParams>(
  scope: IdentityCredentialScope,
  handler: (input: MachineIdentityHandlerInput<P>) => Promise<Response>,
): (request: NextRequest, context: NextRouteContext<P>) => Promise<Response> {
  return async (request, context) => {
    const meta = getRequestMeta(request);

    try {
      await enforceRateLimit(
        `identity-api:ip:${meta.ipAddress ?? 'unknown'}:${request.method}`,
        ADDRESS_LIMIT,
        60,
      );

      const token = bearerToken(request);
      if (!token) {
        throw unauthenticated();
      }

      const principal = await authenticateMachineIdentity(token);
      if (!principal) {
        throw unauthenticated();
      }

      if (!machineIdentityHasScope(principal, scope)) {
        throw forbidden(`This identity credential does not grant the ${scope} scope.`);
      }

      await enforceRateLimit(
        `identity-api:credential:${principal.credentialId}:${request.method}`,
        CREDENTIAL_LIMIT,
        60,
      );

      const params = ((await context?.params) ?? {}) as P;

      return await handler({ request, meta, params, identity: principal });
    } catch (error) {
      return toErrorResponse(error, meta.requestId);
    }
  };
}
