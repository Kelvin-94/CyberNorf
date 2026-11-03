import { jsonResponse, withApi } from '@/server/api/handler';
import { readJsonBody } from '@/server/http/request-meta';
import { createOrganization, listUserOrganizations } from '@/server/services/organizations';
import { withoutUndefined } from '@/server/validation/common';
import { createOrganizationSchema } from '@/server/validation/organizations';

export const dynamic = 'force-dynamic';

export const GET = withApi({}, async ({ meta, user }) => {
  const organizations = await listUserOrganizations(user.id);
  return jsonResponse({ organizations }, meta);
});

export const POST = withApi(
  { rateLimit: { limit: 10, windowSeconds: 60, scope: 'user' } },
  async ({ request, meta, user }) => {
    const input = createOrganizationSchema.parse(await readJsonBody(request));
    const organization = await createOrganization(user, withoutUndefined(input), meta);
    return jsonResponse({ organization }, meta, 201);
  },
);
