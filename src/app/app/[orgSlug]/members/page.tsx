import type { Metadata } from 'next';
import { notFound } from 'next/navigation';
import { ActionForm } from '@/components/action-form';
import { MemberControls } from '@/components/members/member-controls';
import { can } from '@/server/authz/roles';
import { listMembers } from '@/server/services/members';
import { loadTenantContext } from '@/server/ui/session';

export const metadata: Metadata = { title: 'Members · CyberNorf' };
export const dynamic = 'force-dynamic';

const ROLE_DESCRIPTIONS: Record<string, string> = {
  OWNER:
    'Superuser: everything an administrator can do, plus privileged role grants, owner approvals and retention purges.',
  ADMIN: 'Manages assets, findings, incidents, agents, and analysts.',
  ANALYST: 'Records and investigates findings and incidents.',
  VIEWER: 'Read-only access, including the audit trail.',
};

export default async function MembersPage({ params }: { params: Promise<{ orgSlug: string }> }) {
  const { orgSlug } = await params;
  const ctx = await loadTenantContext(orgSlug, 'organization.read');
  if (!ctx) {
    notFound();
  }

  const members = await listMembers(ctx.organization.id);
  const manage = can(ctx.membership.role, 'organization.manage_members');
  // Granting an ADMIN or OWNER membership is the owner-only
  // member.manage_privileged capability. An administrator can still add and
  // re-role analysts and viewers, just not create a peer or a superior.
  const assignableRoles = can(ctx.membership.role, 'member.manage_privileged')
    ? ['OWNER', 'ADMIN', 'ANALYST', 'VIEWER']
    : ['ANALYST', 'VIEWER'];

  return (
    <>
      <div className="page-header">
        <div>
          <p className="eyebrow">Governance</p>
          <h1>Members</h1>
          <p className="small muted" style={{ marginTop: '0.35rem' }}>
            {members.length} membership{members.length === 1 ? '' : 's'} · you are{' '}
            {ctx.membership.role}
          </p>
        </div>
      </div>

      <section className="card">
        <table className="data-table">
          <thead>
            <tr>
              <th>Member</th>
              <th>Role</th>
              <th>Status</th>
              <th>2FA</th>
              <th>Joined</th>
            </tr>
          </thead>
          <tbody>
            {members.map((member) => {
              const isSelf = member.userId === ctx.user.id;
              return (
                <tr key={member.membershipId}>
                  <td>
                    {member.name}
                    {isSelf ? <span className="badge">you</span> : null}
                    <div className="small muted">{member.email}</div>
                  </td>
                  <td>
                    {manage && !isSelf && member.status === 'ACTIVE' ? (
                      <MemberControls
                        action={`/api/v1/organizations/${ctx.organization.slug}/members/${member.membershipId}`}
                        role={member.role}
                        assignableRoles={assignableRoles}
                      />
                    ) : (
                      <>
                        <span className="badge">{member.role}</span>
                        <div className="small muted">{ROLE_DESCRIPTIONS[member.role]}</div>
                      </>
                    )}
                  </td>
                  <td className="small">{member.status}</td>
                  <td className="small">
                    {member.twoFactorEnabled ? (
                      <span className="badge success">enabled</span>
                    ) : (
                      <span className="badge medium">not enrolled</span>
                    )}
                  </td>
                  <td className="mono small">{member.joinedAt.toISOString().slice(0, 10)}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </section>

      {manage ? (
        <section className="card stack" style={{ marginTop: '1.5rem', maxWidth: '44rem' }}>
          <h2>Add a member</h2>
          <p className="small muted">
            The person must already have a CyberNorf account. Administrators may add analysts and
            viewers; only owners may grant administrator or owner roles.
          </p>
          <ActionForm
            action={`/api/v1/organizations/${ctx.organization.slug}/members`}
            fields={[
              { name: 'email', label: 'Email', type: 'email', required: true },
              {
                name: 'role',
                label: 'Role',
                type: 'select',
                defaultValue: 'ANALYST',
                options: assignableRoles
                  .filter((role) => role !== 'OWNER')
                  .map((role) => ({ value: role, label: role })),
              },
            ]}
            submitLabel="Add member"
            successMessage="Member added."
            resetOnSuccess
          />
        </section>
      ) : null}
    </>
  );
}
