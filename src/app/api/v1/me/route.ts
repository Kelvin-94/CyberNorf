import { jsonResponse, withApi } from '@/server/api/handler';
import { ROLE_CAPABILITIES } from '@/server/authz/roles';
import { listUserOrganizations } from '@/server/services/organizations';

export const dynamic = 'force-dynamic';

export const GET = withApi({}, async ({ meta, user }) => {
  const organizations = await listUserOrganizations(user.id);

  return jsonResponse(
    {
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        twoFactorEnabled: user.twoFactorEnabled,
      },
      organizations: organizations.map((organization) => ({
        id: organization.id,
        name: organization.name,
        slug: organization.slug,
        tier: organization.tier,
        role: organization.role,
        memberCount: organization.memberCount,
        capabilities: [...ROLE_CAPABILITIES[organization.role]],
      })),
    },
    meta,
  );
});
