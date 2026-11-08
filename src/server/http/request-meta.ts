import { randomUUID } from 'node:crypto';
import { getAppOrigin, isProduction } from '@/server/config';
import { AppError, forbidden } from '@/server/errors';

export interface RequestMeta {
  requestId: string;
  ipAddress: string | null;
  userAgent: string | null;
}

const REQUEST_ID_PATTERN = /^[A-Za-z0-9._-]{8,64}$/;

/**
 * Extracts correlation and client context for logs and audit records. Client
 * address headers are advisory: only trust them when a proxy you control
 * overwrites them (see docs/DEVELOPMENT.md).
 */
export function getRequestMeta(request: Request): RequestMeta {
  const forwarded = request.headers.get('x-forwarded-for');
  const forwardedFor = forwarded?.split(',')[0]?.trim();
  const realIp = request.headers.get('x-real-ip')?.trim();
  const suppliedRequestId = request.headers.get('x-request-id')?.trim();

  return {
    requestId:
      suppliedRequestId && REQUEST_ID_PATTERN.test(suppliedRequestId)
        ? suppliedRequestId
        : randomUUID(),
    ipAddress: forwardedFor || realIp || null,
    userAgent: request.headers.get('user-agent')?.slice(0, 512) ?? null,
  };
}

/**
 * CSRF defense for cookie-authenticated state changes. Browsers attach Origin
 * (and Sec-Fetch-Site) to cross-origin requests, so a mismatched or cross-site
 * value is rejected. Requests with neither header come from non-browser clients
 * and cannot be forged by a third-party site.
 */
export function assertSameOrigin(request: Request): void {
  const origin = request.headers.get('origin');
  const fetchSite = request.headers.get('sec-fetch-site');

  if (fetchSite === 'cross-site') {
    throw forbidden('Cross-site requests are not allowed for this endpoint.');
  }

  if (origin) {
    const allowed = new Set([getAppOrigin()]);
    if (isProduction()) {
      allowed.add(getAppOrigin().replace('http://', 'https://'));
    }
    if (!allowed.has(origin.replace(/\/+$/, ''))) {
      throw forbidden('Cross-site requests are not allowed for this endpoint.');
    }
  }
}

/**
 * Reads a JSON body that may be absent. Lifecycle endpoints accept an empty
 * body because the action is carried by the URL, and an optional note is the
 * only payload a caller can send.
 */
export async function readOptionalJsonBody(
  request: Request,
  maxBytes = 16 * 1024,
): Promise<unknown> {
  const contentType = request.headers.get('content-type') ?? '';
  const text = await request.text();
  if (text.trim().length === 0) {
    return {};
  }
  if (!contentType.toLowerCase().startsWith('application/json')) {
    throw new AppError(415, 'UNSUPPORTED_MEDIA_TYPE', 'Requests must use application/json.');
  }
  if (Buffer.byteLength(text, 'utf8') > maxBytes) {
    throw new AppError(413, 'PAYLOAD_TOO_LARGE', 'The request body is too large.');
  }
  try {
    return JSON.parse(text);
  } catch {
    throw new AppError(400, 'BAD_REQUEST', 'The request body must be valid JSON.');
  }
}

export async function readJsonBody(request: Request, maxBytes = 256 * 1024): Promise<unknown> {
  const contentType = request.headers.get('content-type') ?? '';
  if (!contentType.toLowerCase().startsWith('application/json')) {
    throw new AppError(415, 'UNSUPPORTED_MEDIA_TYPE', 'Requests must use application/json.');
  }

  const declaredLength = Number(request.headers.get('content-length') ?? '0');
  if (Number.isFinite(declaredLength) && declaredLength > maxBytes) {
    throw new AppError(413, 'PAYLOAD_TOO_LARGE', 'The request body is too large.');
  }

  const text = await request.text();
  if (Buffer.byteLength(text, 'utf8') > maxBytes) {
    throw new AppError(413, 'PAYLOAD_TOO_LARGE', 'The request body is too large.');
  }

  try {
    return JSON.parse(text);
  } catch {
    throw new AppError(400, 'BAD_REQUEST', 'The request body must be valid JSON.');
  }
}
