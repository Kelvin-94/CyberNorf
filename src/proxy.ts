import { NextResponse, type NextRequest } from 'next/server';
import { isLoopbackHost } from '@/server/config';
import { buildCsp, generateNonce } from '@/server/security/csp';

/** Strips the port from a `Host`/`x-forwarded-host` value, keeping IPv6 brackets. */
function hostnameOf(value: string): string {
  const host = value.trim().toLowerCase();
  if (host.startsWith('[')) {
    const end = host.indexOf(']');
    return end === -1 ? host : host.slice(0, end + 1);
  }
  return host.split(':')[0] ?? host;
}

/**
 * Passes the request through with the policy attached to both sides. Next.js
 * only applies the nonce to the scripts it renders when the policy is visible
 * on the request, and the response header is what the browser enforces; a
 * mismatch between the two would block every inline bootstrap script.
 */
function withPolicy(requestHeaders: Headers, csp: string): NextResponse {
  const response = NextResponse.next({ request: { headers: requestHeaders } });
  response.headers.set('Content-Security-Policy', csp);
  return response;
}

/**
 * Per-request security headers, plus the production guard against cleartext
 * requests reaching the app: a proxy that terminates TLS must forward
 * `x-forwarded-proto`, and anything arriving as http is redirected before a
 * session cookie can be read or written.
 *
 * Loopback hosts are exempt so `npm run build && npm run start` and CI smoke
 * runs keep working over http, where traffic never leaves the machine.
 * Development is untouched for the same reason.
 */
export default function proxy(request: NextRequest): NextResponse {
  const nonce = generateNonce();
  const csp = buildCsp({ nonce, production: process.env.NODE_ENV === 'production' });
  const requestHeaders = new Headers(request.headers);
  requestHeaders.set('x-nonce', nonce);
  requestHeaders.set('content-security-policy', csp);

  if (process.env.NODE_ENV !== 'production') {
    return withPolicy(requestHeaders, csp);
  }

  const forwardedHost = request.headers.get('x-forwarded-host')?.split(',')[0]?.trim();
  const requestHost = forwardedHost ?? request.headers.get('host') ?? request.nextUrl.host;

  if (isLoopbackHost(hostnameOf(requestHost))) {
    return withPolicy(requestHeaders, csp);
  }

  // A TLS-terminating proxy must forward `x-forwarded-proto`; when it is
  // missing nothing proves the hop was encrypted, so treat it as cleartext.
  const forwardedProto = request.headers
    .get('x-forwarded-proto')
    ?.split(',')[0]
    ?.trim()
    .toLowerCase();

  if (forwardedProto !== 'https') {
    // Built from scratch so no port leaks in from the internal listener address.
    const target = new URL(
      `${request.nextUrl.pathname}${request.nextUrl.search}`,
      `https://${requestHost}`,
    );
    const redirect = NextResponse.redirect(target, 308);
    redirect.headers.set('Content-Security-Policy', csp);
    return redirect;
  }

  return withPolicy(requestHeaders, csp);
}

export const config = {
  // Static assets never carry credentials and are served by the CDN in front
  // of a deployment, so they are excluded from the redirect hop.
  matcher: ['/((?!_next/static|_next/image|favicon.ico).*)'],
};
