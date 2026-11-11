import { jsonResponse, withTenantApi } from '@/server/api/handler';
import { readJsonBody } from '@/server/http/request-meta';
import { importIndicators } from '@/server/services/indicators';
import { withoutUndefined } from '@/server/validation/common';
import { importIndicatorsSchema } from '@/server/validation/indicators';

export const dynamic = 'force-dynamic';

/**
 * A feed import is a heavier request than a single create, so it gets its own
 * rate limit rather than sharing the default write budget: an operator importing
 * ten feeds in a row should not be throttled as if they were spamming the API.
 */
export const POST = withTenantApi(
  'indicator.manage',
  { rateLimit: { limit: 10, windowSeconds: 60 } },
  async ({ request, meta, ctx }) => {
    const input = importIndicatorsSchema.parse(await readJsonBody(request));
    const result = await importIndicators(ctx, withoutUndefined(input));
    // 200 rather than 201: the response describes a mixed outcome (some created,
    // some refreshed, some rejected), not one resource that came into existence.
    return jsonResponse(result, meta);
  },
);
