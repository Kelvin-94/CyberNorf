import { jsonResponse, withTenantApi } from '@/server/api/handler';
import { readJsonBody } from '@/server/http/request-meta';
import { addMember, listMembers } from '@/server/services/members';
import { addMemberSchema } from '@/server/validation/organizations';

export const dynamic = 'force-dynamic';

export const GET = withTenantApi('organization.read', {}, async ({ meta, ctx }) => {
  const members = await listMembers(ctx.organization.id);
  return jsonResponse({ members }, meta);
});

export const POST = withTenantApi(
  'organization.manage_members',
  { rateLimit: { limit: 20, windowSeconds: 60, scope: 'user' } },
  async ({ request, meta, ctx }) => {
    const input = addMemberSchema.parse(await readJsonBody(request));
    const member = await addMember(ctx, input);
    return jsonResponse({ member }, meta, 201);
  },
);
