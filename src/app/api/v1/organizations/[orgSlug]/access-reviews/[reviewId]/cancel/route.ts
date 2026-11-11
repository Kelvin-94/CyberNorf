import { jsonResponse, withTenantApi } from '@/server/api/handler';
import { cancelAccessReview } from '@/server/services/access-reviews';

export const dynamic = 'force-dynamic';

type Params = { orgSlug: string; reviewId: string };

export const POST = withTenantApi<Params>(
  'access_review.manage',
  {},
  async ({ meta, ctx, params }) => {
    const review = await cancelAccessReview(ctx, params.reviewId);
    return jsonResponse({ review }, meta);
  },
);
