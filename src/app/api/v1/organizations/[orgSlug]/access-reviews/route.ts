import { jsonResponse, withTenantApi } from '@/server/api/handler';
import { readJsonBody } from '@/server/http/request-meta';
import { createAccessReview, listAccessReviews } from '@/server/services/access-reviews';
import { parseQuery } from '@/server/validation/common';
import {
  accessReviewListQuerySchema,
  createAccessReviewSchema,
} from '@/server/validation/identities';

export const dynamic = 'force-dynamic';

type Params = { orgSlug: string };

export const GET = withTenantApi<Params>(
  'access_review.read',
  {},
  async ({ request, meta, ctx }) => {
    const query = parseQuery(request, accessReviewListQuerySchema);
    const page = await listAccessReviews(ctx.organization.id, query);
    return jsonResponse(page, meta);
  },
);

export const POST = withTenantApi<Params>(
  'access_review.manage',
  {},
  async ({ request, meta, ctx }) => {
    const input = createAccessReviewSchema.parse(await readJsonBody(request));
    const review = await createAccessReview(ctx, {
      title: input.title,
      dueAt: input.dueAt,
      ...(input.description !== undefined ? { description: input.description } : {}),
      ...(input.reviewerId !== undefined ? { reviewerId: input.reviewerId } : {}),
    });
    return jsonResponse({ review }, meta, 201);
  },
);
