import type { NextRequest } from 'next/server';
import {
  requireAuthenticatedUser,
  requireTenantContext,
  type AuthenticatedUser,
  type TenantContext,
} from '@/server/authz/context';
import type { Capability } from '@/server/authz/roles';
import { badRequest, toErrorResponse } from '@/server/errors';
import { hasAuthorizationHeader } from '@/server/authz/api-key';
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
  /** Bucket identity. User-scoped buckets also get the address floor below. */
  scope?: 'user' | 'ip';
}

export interface RouteOptions {
  rateLimit?: RateLimitOption;
}

const DEFAULT_READ_LIMIT: RateLimitOption = { limit: 240, windowSeconds: 60, scope: 'ip' };
const DEFAULT_WRITE_LIMIT: RateLimitOption = { limit: 60, windowSeconds: 60, scope: 'ip' };

/**
 * Address floor applied to user-scoped limits before authentication runs. Each
 * authenticated user keeps their own bucket, but the address still cannot drive
 * unlimited session lookups by rotating accounts.
 */
const ADDRESS_FLOOR_LIMIT: RateLimitOption = { limit: 600, windowSeconds: 60, scope: 'ip' };

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

function isUserScoped(option: RateLimitOption): boolean {
  return option.scope === 'user';
}

/**
 * Address-scoped limiting runs before authentication, so an unauthenticated
 * flood is rejected before the session lookup reaches the database.
 */
async function enforceAddressLimit(
  request: NextRequest,
  meta: RequestMeta,
  option: RateLimitOption,
  bucket: string,
): Promise<void> {
  await enforceRateLimit(
    `${bucket}:ip:${meta.ipAddress ?? 'unknown'}:${request.method}`,
    option.limit,
    option.windowSeconds,
  );
}

async function enforceUserLimit(
  request: NextRequest,
  user: AuthenticatedUser,
  option: RateLimitOption,
  bucket: string,
): Promise<void> {
  // A personal API key gets its own bucket instead of sharing the owner's, so a
  // noisy script cannot exhaust the budget of the same person signed in to the
  // console. Key limits are always enforced: keys travel across addresses, so
  // the address floor alone would not bound them.
  const identity = user.apiKey ? `api-key:${user.apiKey.id}` : `user:${user.id}`;
  await enforceRateLimit(
    `${bucket}:${identity}:${request.method}`,
    option.limit,
    option.windowSeconds,
  );
}

/**
 * The origin check defends cookie-authenticated state changes against CSRF.
 * A bearer credential is not attached automatically by browsers, and the value
 * cannot be set cross-site without a CORS preflight, so those requests are not
 * subject to it.
 */
function requiresOriginCheck(request: NextRequest): boolean {
  return !SAFE_METHODS.has(request.method) && !hasAuthorizationHeader(request.headers);
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
      if (requiresOriginCheck(request)) {
        assertSameOrigin(request);
      }

      const rateLimit =
        options.rateLimit ??
        (SAFE_METHODS.has(request.method) ? DEFAULT_READ_LIMIT : DEFAULT_WRITE_LIMIT);

      await enforceAddressLimit(
        request,
        meta,
        isUserScoped(rateLimit) ? ADDRESS_FLOOR_LIMIT : rateLimit,
        'api',
      );

      const user = await requireAuthenticatedUser(request.headers);
      if (isUserScoped(rateLimit) || user.apiKey) {
        await enforceUserLimit(request, user, rateLimit, 'api');
      }

      const params = ((await context?.params) ?? {}) as P;

      return await handler({ request, meta, params, user });
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
      if (requiresOriginCheck(request)) {
        assertSameOrigin(request);
      }

      const params = ((await context?.params) ?? {}) as P & Record<string, string>;
      const organizationIdentifier = params[orgParam];
      if (typeof organizationIdentifier !== 'string' || organizationIdentifier.length === 0) {
        throw badRequest('An organization identifier is required in the request path.');
      }

      const rateLimit =
        options.rateLimit ??
        (SAFE_METHODS.has(request.method) ? DEFAULT_READ_LIMIT : DEFAULT_WRITE_LIMIT);

      await enforceAddressLimit(
        request,
        meta,
        isUserScoped(rateLimit) ? ADDRESS_FLOOR_LIMIT : rateLimit,
        'api-tenant',
      );

      const user = await requireAuthenticatedUser(request.headers);
      if (isUserScoped(rateLimit) || user.apiKey) {
        await enforceUserLimit(request, user, rateLimit, 'api-tenant');
      }

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
