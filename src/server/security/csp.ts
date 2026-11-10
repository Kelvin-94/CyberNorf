/**
 * Content Security Policy construction.
 *
 * The policy is built per response because `script-src` carries a fresh nonce.
 * Next.js reads the policy from the request headers and stamps that nonce onto
 * the scripts it renders, so the policy must be identical on the request and on
 * the response that leaves the server.
 *
 * `style-src` still allows inline styles: React and Next write style attributes
 * that a nonce cannot cover, and inline styles cannot execute script. Scripts
 * get no such allowance — inline script is only accepted with the nonce.
 */

export interface CspOptions {
  /** Base64 nonce generated for this response. */
  nonce: string;
  /** Production adds `upgrade-insecure-requests` and drops development-only relaxations. */
  production: boolean;
}

export function buildCsp({ nonce, production }: CspOptions): string {
  return [
    "default-src 'self'",
    `script-src 'self' 'nonce-${nonce}'${production ? '' : " 'unsafe-eval'"}`,
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: blob:",
    "font-src 'self' data:",
    // The development server serves hot reload over a websocket.
    `connect-src 'self'${production ? '' : ' ws: wss:'}`,
    "object-src 'none'",
    "base-uri 'none'",
    "form-action 'self'",
    "frame-ancestors 'none'",
    ...(production ? ['upgrade-insecure-requests'] : []),
  ].join('; ');
}

/**
 * 128 bits from the platform CSPRNG, base64 encoded. Base64 is safe inside the
 * quoted nonce source expression and matches what Next.js accepts.
 */
export function generateNonce(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  let binary = '';
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary);
}
