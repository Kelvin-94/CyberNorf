import { jsonResponse, withTenantApi } from '@/server/api/handler';
import { readJsonBody } from '@/server/http/request-meta';
import { listEnforcementActions, requestEnforcement } from '@/server/services/enforcement';
import { parseQuery } from '@/server/validation/common';
import {
  enforcementActionQuerySchema,
  requestEnforcementSchema,
} from '@/server/validation/zero-trust';

export const dynamic = 'force-dynamic';

type Params = { orgSlug: string };

export const GET = withTenantApi<Params>('enforcement.read', {}, async ({ request, meta, ctx }) => {
  const query = parseQuery(request, enforcementActionQuerySchema);
  const result = await listEnforcementActions(ctx.organization.id, query);
  return jsonResponse(result, meta);
});

/**
 * Requesting an action never executes it. A second, distinct operator has to
 * approve it before a connector can be told to act.
 */
export const POST = withTenantApi<Params>(
  'enforcement.manage',
  {},
  async ({ request, meta, ctx }) => {
    const input = requestEnforcementSchema.parse(await readJsonBody(request));
    const result = await requestEnforcement(ctx, input);
    return jsonResponse(result, meta, 201);
  },
);
