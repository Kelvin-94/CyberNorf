import { emptyResponse, jsonResponse, withTenantApi } from '@/server/api/handler';
import { readJsonBody } from '@/server/http/request-meta';
import { changeMemberRole, removeMember } from '@/server/services/members';
import { changeMemberRoleSchema } from '@/server/validation/organizations';

export const dynamic = 'force-dynamic';

type Params = { orgSlug: string; membershipId: string };

export const PATCH = withTenantApi<Params>(
  'organization.manage_members',
  {},
  async ({ request, meta, ctx, params }) => {
    const input = changeMemberRoleSchema.parse(await readJsonBody(request));
    const member = await changeMemberRole(ctx, params.membershipId, input.role);
    return jsonResponse({ member }, meta);
  },
);

export const DELETE = withTenantApi<Params>(
  'organization.manage_members',
  {},
  async ({ meta, ctx, params }) => {
    await removeMember(ctx, params.membershipId);
    return emptyResponse(meta);
  },
);
