import type { NextConfig } from 'next';

const isProduction = process.env.NODE_ENV === 'production';

/**
 * Static security headers.
 *
 * The Content-Security-Policy is deliberately absent: it carries a per-request
 * script nonce, so `src/proxy.ts` builds it from `src/server/security/csp.ts`
 * and sets it on both the request and the response. Emitting a second, static
 * policy here would be intersected with the real one and would reintroduce the
 * `'unsafe-inline'` allowance the nonce removes.
 */
const securityHeaders = [
  { key: 'X-Content-Type-Options', value: 'nosniff' },
  { key: 'X-Frame-Options', value: 'DENY' },
  { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
  { key: 'Cross-Origin-Opener-Policy', value: 'same-origin' },
  // Responses are for this origin only, and Flash/PDF cross-domain policy files
  // must not be served: neither is used by the console, so both are denied.
  { key: 'Cross-Origin-Resource-Policy', value: 'same-origin' },
  { key: 'X-Permitted-Cross-Domain-Policies', value: 'none' },
  // Opts into an origin-keyed agent cluster, so same-site documents from other
  // origins cannot share this one's cluster (a Spectre-style side-channel guard).
  { key: 'Origin-Agent-Cluster', value: '?1' },
  { key: 'X-DNS-Prefetch-Control', value: 'off' },
  {
    key: 'Permissions-Policy',
    value: 'camera=(), microphone=(), geolocation=(), payment=(), usb=()',
  },
  // HSTS is only meaningful over TLS: in development it would pin localhost to
  // https and break every other local project.
  ...(isProduction
    ? [{ key: 'Strict-Transport-Security', value: 'max-age=31536000; includeSubDomains' }]
    : []),
];

const nextConfig: NextConfig = {
  poweredByHeader: false,
  images: {
    // The optimizer rejects SVG by default, and an attacker-supplied SVG is a
    // script container once a browser renders it in place. Stated explicitly so
    // the protection cannot be lost to a copied config snippet.
    dangerouslyAllowSVG: false,
  },
  async headers() {
    return [{ source: '/:path*', headers: securityHeaders }];
  },
};

export default nextConfig;
