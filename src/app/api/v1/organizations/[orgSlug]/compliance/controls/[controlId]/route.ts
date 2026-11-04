import { jsonResponse, withTenantApi } from '@/server/api/handler';
import { readJsonBody } from '@/server/http/request-meta';
import { updateControl } from '@/server/services/compliance';
import { updateControlSchema } from '@/server/validation/compliance';
import { withoutUndefined } from '@/server/validation/common';

export const dynamic = 'force-dynamic';

type Params = { orgSlug: string; controlId: string };

export const PATCH = withTenantApi<Params>(
  'compliance.manage',
  {},
  async ({ request, meta, ctx, params }) => {
    const input = updateControlSchema.parse(await readJsonBody(request));
    const control = await updateControl(ctx, params.controlId, withoutUndefined(input));
    return jsonResponse({ control }, meta);
  },
);
