import { jsonResponse, withTenantApi } from '@/server/api/handler';
import { readJsonBody } from '@/server/http/request-meta';
import { getOrganizationSettings, updateOrganization } from '@/server/services/organizations';
import { withoutUndefined } from '@/server/validation/common';
import { updateOrganizationSchema } from '@/server/validation/organizations';

export const dynamic = 'force-dynamic';

export const GET = withTenantApi('organization.read', {}, async ({ meta, ctx }) => {
  const organization = await getOrganizationSettings(ctx);
  return jsonResponse({ organization }, meta);
});

export const PATCH = withTenantApi('organization.update', {}, async ({ request, meta, ctx }) => {
  const input = updateOrganizationSchema.parse(await readJsonBody(request));
  await updateOrganization(ctx, withoutUndefined(input));
  const organization = await getOrganizationSettings(ctx);
  return jsonResponse({ organization }, meta);
});
