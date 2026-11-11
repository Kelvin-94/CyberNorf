import { jsonResponse, withTenantApi } from '@/server/api/handler';
import { finalizeAccessReview } from '@/server/services/access-reviews';

export const dynamic = 'force-dynamic';

type Params = { orgSlug: string; reviewId: string };

/**
 * Finalization refuses to run while any item is undecided and refuses to remove
 * the last active owner. Revocations are applied in the same transaction as the
 * completion record, so a partially-applied campaign cannot be reported.
 */
export const POST = withTenantApi<Params>(
  'access_review.manage',
  {},
  async ({ meta, ctx, params }) => {
    const review = await finalizeAccessReview(ctx, params.reviewId);
    return jsonResponse({ review }, meta);
  },
);
