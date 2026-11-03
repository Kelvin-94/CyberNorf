import type { NextRequest } from 'next/server';
import {
  requireAuthenticatedUser,
  requireTenantContext,
  type AuthenticatedUser,
  type TenantContext,
} from '@/server/authz/context';
import type { Capability } from '@/server/authz/roles';
import { badRequest, toErrorResponse } from '@/server/errors';
import { assertSameOrigin, getRequestMeta, type RequestMeta } from '@/server/http/request-meta';
import { enforceRateLimit } from '@/server/security/rate-limit';

export interface RouteParams {
  [key: string]: string | string[] | undefined;
}

export interface NextRouteContext<P extends RouteParams> {
  params: Promise<P>;
}

export interface HandlerInput<P extends RouteParams> {
  request: NextRequest;
  meta: RequestMeta;
  params: P;
  user: AuthenticatedUser;
}

export interface TenantHandlerInput<P extends RouteParams> extends HandlerInput<P> {
  ctx: TenantContext;
}

export interface RateLimitOption {
  limit: number;
  windowSeconds: number;
  /** Bucket identity. User-scoped buckets fall back to the client address. */
  scope?: 'user' | 'ip';
}

export interface RouteOptions {
  /** Defaults to true. Public routes must opt out explicitly. */
  requiresAuth?: boolean;
  rateLimit?: RateLimitOption;
  /** Safe HTTP methods skip the same-origin check. */
  safeMethodsOnly?: boolean;
}

const DEFAULT_READ_LIMIT: RateLimitOption = { limit: 240, windowSeconds: 60, scope: 'ip' };
const DEFAULT_WRITE_LIMIT: RateLimitOption = { limit: 60, windowSeconds: 60, scope: 'ip' };

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

export function jsonResponse(
  body: unknown,
  meta: RequestMeta,
  status = 200,
  extraHeaders: Record<string, string> = {},
): Response {
  return Response.json(body, { status, headers: securityHeaders(meta, extraHeaders) });
}

export function emptyResponse(
  meta: RequestMeta,
  status = 204,
  extraHeaders: Record<string, string> = {},
): Response {
  return new Response(null, { status, headers: securityHeaders(meta, extraHeaders) });
}

export function securityHeaders(
  meta: RequestMeta,
  extraHeaders: Record<string, string> = {},
): Record<string, string> {
  return {
    'Cache-Control': 'no-store, max-age=0',
    'X-Request-Id': meta.requestId,
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer',
    ...extraHeaders,
  };
}

async function applyRateLimit(
  request: NextRequest,
  meta: RequestMeta,
  user: AuthenticatedUser | null,
  option: RateLimitOption,
  bucket: string,
): Promise<void> {
  const scope = option.scope ?? 'ip';
  const identity =
    scope === 'user' && user ? `user:${user.id}` : `ip:${meta.ipAddress ?? 'unknown'}`;
  await enforceRateLimit(
    `${bucket}:${identity}:${request.method}`,
    option.limit,
    option.windowSeconds,
  );
}

/**
 * Wraps an authenticated API route: request metadata, CSRF origin check for
 * state changes, rate limiting, and uniform error mapping. Handlers throw
 * AppError (or any error) and never build error responses themselves.
 */
export function withApi<P extends RouteParams = RouteParams>(
  options: RouteOptions,
  handler: (input: HandlerInput<P>) => Promise<Response>,
): (request: NextRequest, context: NextRouteContext<P>) => Promise<Response> {
  return async (request, context) => {
    const meta = getRequestMeta(request);

    try {
      if (!SAFE_METHODS.has(request.method)) {
        assertSameOrigin(request);
      }

      const requiresAuth = options.requiresAuth ?? true;
      const user = requiresAuth ? await requireAuthenticatedUser(request.headers) : null;

      const rateLimit =
        options.rateLimit ??
        (SAFE_METHODS.has(request.method) ? DEFAULT_READ_LIMIT : DEFAULT_WRITE_LIMIT);
      await applyRateLimit(
        request,
        meta,
        user,
        rateLimit,
        options.rateLimit?.scope === 'user' ? 'api-user' : 'api-ip',
      );

      const params = ((await context?.params) ?? {}) as P;

      return await handler({ request, meta, params, user: user as AuthenticatedUser });
    } catch (error) {
      return toErrorResponse(error, meta.requestId);
    }
  };
}

/**
 * Tenant-scoped route wrapper. The organization is resolved from the path
 * parameter (?orgSlug?) and must correspond to an active membership; the
 * capability check runs before the handler, so authorization never depends on
 * handler-side logic.
 */
export function withTenantApi<P extends RouteParams = RouteParams>(
  capability: Capability,
  options: RouteOptions,
  handler: (input: TenantHandlerInput<P>) => Promise<Response>,
  orgParam = 'orgSlug',
): (
  request: NextRequest,
  context: NextRouteContext<P & Record<string, string>>,
) => Promise<Response> {
  return async (request, context) => {
    const meta = getRequestMeta(request);

    try {
      if (!SAFE_METHODS.has(request.method)) {
        assertSameOrigin(request);
      }

      const params = ((await context?.params) ?? {}) as P & Record<string, string>;
      const organizationIdentifier = params[orgParam];
      if (typeof organizationIdentifier !== 'string' || organizationIdentifier.length === 0) {
        throw badRequest('An organization identifier is required in the request path.');
      }

      const user = await requireAuthenticatedUser(request.headers);
      const rateLimit =
        options.rateLimit ??
        (SAFE_METHODS.has(request.method) ? DEFAULT_READ_LIMIT : DEFAULT_WRITE_LIMIT);
      await applyRateLimit(request, meta, user, rateLimit, 'api-tenant');

      const ctx = await requireTenantContext(
        request.headers,
        organizationIdentifier,
        capability,
        meta,
        user,
      );

      return await handler({ request, meta, params, user, ctx });
    } catch (error) {
      return toErrorResponse(error, meta.requestId);
    }
  };
}
