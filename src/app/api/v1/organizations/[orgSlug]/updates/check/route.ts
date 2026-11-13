import { jsonResponse, withTenantApi } from '@/server/api/handler';
import { readJsonBody } from '@/server/http/request-meta';
import { checkForUpdate } from '@/server/services/updates';
import { checkUpdateSchema } from '@/server/validation/zero-trust';

export const dynamic = 'force-dynamic';

type Params = { orgSlug: string };

/**
 * The device-facing eligibility check. Answering it never changes state; the
 * reasons array says why a device was held back (cohort, compatibility, digest,
 * anti-rollback) rather than silently returning nothing.
 */
export const POST = withTenantApi<Params>('update.read', {}, async ({ request, meta, ctx }) => {
  const input = checkUpdateSchema.parse(await readJsonBody(request));
  const result = await checkForUpdate(ctx.organization.id, input);
  return jsonResponse(result, meta);
});
