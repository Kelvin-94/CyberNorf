import { jsonResponse, withTenantApi } from '@/server/api/handler';
import { getAccessReviewDetail } from '@/server/services/access-reviews';

export const dynamic = 'force-dynamic';

type Params = { orgSlug: string; reviewId: string };

export const GET = withTenantApi<Params>(
  'access_review.read',
  {},
  async ({ meta, ctx, params }) => {
    const review = await getAccessReviewDetail(ctx.organization.id, params.reviewId);
    return jsonResponse({ review }, meta);
  },
);
