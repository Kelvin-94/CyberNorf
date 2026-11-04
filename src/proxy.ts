import { NextResponse, type NextRequest } from 'next/server';
import { isLoopbackHost } from '@/server/config';

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
 * Production guard against cleartext requests reaching the app: a proxy that
 * terminates TLS must forward `x-forwarded-proto`, and anything arriving as
 * http is redirected before a session cookie can be read or written.
 *
 * Loopback hosts are exempt so `npm run build && npm run start` and CI smoke
 * runs keep working over http, where traffic never leaves the machine.
 * Development is untouched for the same reason.
 */
export default function proxy(request: NextRequest): NextResponse {
  if (process.env.NODE_ENV !== 'production') {
    return NextResponse.next();
  }

  const forwardedHost = request.headers.get('x-forwarded-host')?.split(',')[0]?.trim();
  const requestHost = forwardedHost ?? request.headers.get('host') ?? request.nextUrl.host;

  if (isLoopbackHost(hostnameOf(requestHost))) {
    return NextResponse.next();
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
    return NextResponse.redirect(target, 308);
  }

  return NextResponse.next();
}

export const config = {
  // Static assets never carry credentials and are served by the CDN in front
  // of a deployment, so they are excluded from the redirect hop.
  matcher: ['/((?!_next/static|_next/image|favicon.ico).*)'],
};
