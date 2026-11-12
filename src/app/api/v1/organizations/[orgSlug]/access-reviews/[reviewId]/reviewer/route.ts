import { jsonResponse, withTenantApi } from '@/server/api/handler';
import { readJsonBody } from '@/server/http/request-meta';
import { assignAccessReviewReviewer } from '@/server/services/access-reviews';
import { assignAccessReviewReviewerSchema } from '@/server/validation/identities';

export const dynamic = 'force-dynamic';

type Params = { orgSlug: string; reviewId: string };

/**
 * Assigns or clears the reviewer for an open campaign. Once a reviewer is set
 * they are the only account that can record decisions, which is what makes the
 * assignment a separation-of-duties control rather than a label.
 */
export const POST = withTenantApi<Params>(
  'access_review.manage',
  {},
  async ({ request, meta, ctx, params }) => {
    const input = assignAccessReviewReviewerSchema.parse(await readJsonBody(request));
    const review = await assignAccessReviewReviewer(ctx, params.reviewId, input.reviewerId);
    return jsonResponse({ review }, meta);
  },
);
