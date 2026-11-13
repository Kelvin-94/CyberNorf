import { jsonResponse, withTenantApi } from '@/server/api/handler';
import { readJsonBody } from '@/server/http/request-meta';
import { recordUpdateResult } from '@/server/services/updates';
import { recordUpdateResultSchema } from '@/server/validation/zero-trust';

export const dynamic = 'force-dynamic';

type Params = { orgSlug: string };

/**
 * Install results are reported by the managed agent after it has applied an
 * offer. The service only accepts states a device update can actually be in,
 * and a FAILED or ROLLED_BACK report is kept rather than overwritten.
 */
export const POST = withTenantApi<Params>('update.manage', {}, async ({ request, meta, ctx }) => {
  const input = recordUpdateResultSchema.parse(await readJsonBody(request));
  const update = await recordUpdateResult({
    organizationId: ctx.organization.id,
    reporter: {
      type: 'USER',
      id: ctx.user.id,
      ipAddress: ctx.meta.ipAddress,
      userAgent: ctx.meta.userAgent,
      requestId: ctx.meta.requestId,
    },
    payload: input,
  });
  return jsonResponse({ update }, meta, 201);
});
