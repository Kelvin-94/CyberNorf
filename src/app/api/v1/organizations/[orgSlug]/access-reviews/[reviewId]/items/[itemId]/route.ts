import { jsonResponse, withTenantApi } from '@/server/api/handler';
import { readJsonBody } from '@/server/http/request-meta';
import { decideAccessReviewItem } from '@/server/services/access-reviews';
import { decideAccessReviewItemSchema } from '@/server/validation/identities';

export const dynamic = 'force-dynamic';

type Params = { orgSlug: string; reviewId: string; itemId: string };

/**
 * A reviewer cannot decide their own membership; the service rejects it before
 * the conditional update so the attempt leaves no decision behind.
 */
export const POST = withTenantApi<Params>(
  'access_review.manage',
  {},
  async ({ request, meta, ctx, params }) => {
    const input = decideAccessReviewItemSchema.parse(await readJsonBody(request));
    const review = await decideAccessReviewItem(ctx, params.reviewId, params.itemId, input);
    return jsonResponse({ review }, meta);
  },
);
