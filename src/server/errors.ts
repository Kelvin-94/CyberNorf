import { ZodError } from 'zod';
import { ZeroTrustError } from '@/server/domain/zero-trust';
import { logger } from '@/server/logging/logger';

export type ErrorCode =
  | 'BAD_REQUEST'
  | 'VALIDATION_FAILED'
  | 'UNAUTHENTICATED'
  | 'FORBIDDEN'
  | 'NOT_FOUND'
  | 'CONFLICT'
  | 'RATE_LIMITED'
  | 'UNSUPPORTED_MEDIA_TYPE'
  | 'PAYLOAD_TOO_LARGE'
  | 'MFA_REQUIRED'
  | 'INTERNAL_ERROR';

export interface ErrorDetail {
  path: string;
  message: string;
}

export class AppError extends Error {
  readonly statusCode: number;
  readonly code: ErrorCode;
  readonly details: ErrorDetail[];
  readonly headers: Record<string, string>;

  constructor(
    statusCode: number,
    code: ErrorCode,
    message: string,
    options: { details?: ErrorDetail[]; headers?: Record<string, string> } = {},
  ) {
    super(message);
    this.name = 'AppError';
    this.statusCode = statusCode;
    this.code = code;
    this.details = options.details ?? [];
    this.headers = options.headers ?? {};
  }
}

export const badRequest = (message: string) => new AppError(400, 'BAD_REQUEST', message);

export const unauthenticated = () =>
  new AppError(401, 'UNAUTHENTICATED', 'Authentication is required.');

/**
 * Used when the caller is not permitted to act on the requested organization or
 * resource. Callers that are not members receive NOT_FOUND instead, so the API
 * does not disclose the existence of other tenants' records.
 */
export const forbidden = (
  message = 'You do not have permission to perform this action.',
  code: ErrorCode = 'FORBIDDEN',
) => new AppError(403, code, message);

export const notFound = (message = 'The requested resource was not found.') =>
  new AppError(404, 'NOT_FOUND', message);

export const conflict = (message: string) => new AppError(409, 'CONFLICT', message);

export const tooManyRequests = (retryAfterSeconds: number) =>
  new AppError(429, 'RATE_LIMITED', 'Too many requests. Please try again later.', {
    headers: { 'Retry-After': String(Math.max(1, retryAfterSeconds)) },
  });

export const validationFailed = (error: ZodError) =>
  new AppError(422, 'VALIDATION_FAILED', 'The submitted data is invalid.', {
    details: error.issues.slice(0, 20).map((issue) => ({
      path: issue.path.join('.') || '(root)',
      message: issue.message,
    })),
  });

export const internalError = () =>
  new AppError(500, 'INTERNAL_ERROR', 'An unexpected error occurred.');

export function toErrorResponse(error: unknown, requestId: string): Response {
  if (error instanceof AppError) {
    return Response.json(
      {
        error: {
          code: error.code,
          message: error.message,
          requestId,
          ...(error.details.length > 0 ? { details: error.details } : {}),
        },
      },
      {
        status: error.statusCode,
        headers: {
          'Cache-Control': 'no-store, max-age=0',
          'X-Request-Id': requestId,
          'X-Content-Type-Options': 'nosniff',
          ...error.headers,
        },
      },
    );
  }

  if (error instanceof ZodError) {
    return toErrorResponse(validationFailed(error), requestId);
  }

  // Domain rules throw their own error type. Services map the cases they can
  // explain, but a missed mapping must not surface as a 500: the code is
  // returned as a detail so the caller can tell which rule refused.
  if (error instanceof ZeroTrustError) {
    const isConflict = error.code === 'invalid_transition' || error.code === 'self_approval';
    return toErrorResponse(
      new AppError(
        isConflict ? 409 : 422,
        isConflict ? 'CONFLICT' : 'VALIDATION_FAILED',
        error.message,
        {
          details: [{ path: '(root)', message: error.code }],
        },
      ),
      requestId,
    );
  }

  // Unexpected failures are logged server-side without request payloads. The
  // logger redacts the message and stack again, so a provider error that echoes
  // a credential cannot reach the log even if it reached this catch.
  logger.error('request.unhandled_error', { requestId, error });

  return toErrorResponse(internalError(), requestId);
}
