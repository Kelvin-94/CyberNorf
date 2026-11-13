import { jsonResponse, withTenantApi } from '@/server/api/handler';
import { readJsonBody } from '@/server/http/request-meta';
import { admitDevice } from '@/server/services/network';
import { admissionRequestSchema } from '@/server/validation/zero-trust';

export const dynamic = 'force-dynamic';

type Params = { orgSlug: string };

/**
 * Posture-gated admission. The caller states where it wants to be and what it
 * observed; the verdict, the segment and the resulting network outcome are all
 * resolved server-side.
 */
export const POST = withTenantApi<Params>('network.manage', {}, async ({ request, meta, ctx }) => {
  const input = admissionRequestSchema.parse(await readJsonBody(request));
  const result = await admitDevice({ organizationId: ctx.organization.id, request: input });
  return jsonResponse(result, meta, 201);
});
