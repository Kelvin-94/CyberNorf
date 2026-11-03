import { randomUUID } from 'node:crypto';
import { prisma } from '@/lib/prisma';
import { tooManyRequests } from '@/server/errors';

export interface RateLimitResult {
  allowed: boolean;
  remaining: number;
  retryAfterSeconds: number;
}

/**
 * Fixed-window rate limiting shared through PostgreSQL so limits hold across
 * application instances. The increment and reset happen in one statement, so
 * concurrent requests cannot both observe a stale counter.
 */
export async function consumeRateLimit(
  key: string,
  limit: number,
  windowSeconds: number,
): Promise<RateLimitResult> {
  const now = new Date();
  const windowStartThreshold = new Date(now.getTime() - windowSeconds * 1000);

  const rows = await prisma.$queryRaw<Array<{ count: number; windowStart: Date }>>`
    INSERT INTO "api_rate_limits" ("id", "key", "count", "windowStart", "updatedAt")
    VALUES (${randomUUID()}, ${key}, 1, ${now}, ${now})
    ON CONFLICT ("key") DO UPDATE SET
      "count" = CASE WHEN "api_rate_limits"."windowStart" <= ${windowStartThreshold} THEN 1 ELSE "api_rate_limits"."count" + 1 END,
      "windowStart" = CASE WHEN "api_rate_limits"."windowStart" <= ${windowStartThreshold} THEN ${now} ELSE "api_rate_limits"."windowStart" END,
      "updatedAt" = ${now}
    RETURNING "count", "windowStart"
  `;

  const row = rows[0];
  if (!row) {
    // The statement always returns a row; treat an unexpected empty result as
    // an unavailable limiter and refuse the request rather than fail open.
    throw tooManyRequests(windowSeconds);
  }

  const remaining = Math.max(0, limit - row.count);
  const resetAt = new Date(row.windowStart).getTime() + windowSeconds * 1000;
  const retryAfterSeconds = Math.max(1, Math.ceil((resetAt - now.getTime()) / 1000));

  return { allowed: row.count <= limit, remaining, retryAfterSeconds };
}

export async function enforceRateLimit(
  key: string,
  limit: number,
  windowSeconds: number,
): Promise<void> {
  const result = await consumeRateLimit(key, limit, windowSeconds);
  if (!result.allowed) {
    throw tooManyRequests(result.retryAfterSeconds);
  }
}
