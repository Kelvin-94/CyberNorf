import type { Metadata } from 'next';
import { notFound } from 'next/navigation';
import { ActionForm } from '@/components/action-form';
import { can } from '@/server/authz/roles';
import { getOrganizationSettings } from '@/server/services/organizations';
import { loadTenantContext } from '@/server/ui/session';

export const metadata: Metadata = { title: 'Settings · CyberNorf' };
export const dynamic = 'force-dynamic';

export default async function SettingsPage({ params }: { params: Promise<{ orgSlug: string }> }) {
  const { orgSlug } = await params;
  const ctx = await loadTenantContext(orgSlug, 'organization.read');
  if (!ctx) {
    notFound();
  }

  const organization = await getOrganizationSettings(ctx);
  const canUpdate = can(ctx.membership.role, 'organization.update');

  return (
    <>
      <div className="page-header">
        <div>
          <p className="eyebrow">Governance</p>
          <h1>Settings</h1>
        </div>
      </div>

      <section className="card">
        <dl className="detail-grid">
          <div>
            <dt>Organization</dt>
            <dd>{organization.name}</dd>
          </div>
          <div>
            <dt>Slug</dt>
            <dd className="mono">{organization.slug}</dd>
          </div>
          <div>
            <dt>Tier</dt>
            <dd>{organization.tier.toLowerCase()}</dd>
          </div>
          <div>
            <dt>Your role</dt>
            <dd>{organization.role}</dd>
          </div>
          <div>
            <dt>Created</dt>
            <dd className="mono">{organization.createdAt.toISOString().slice(0, 10)}</dd>
          </div>
        </dl>
        <p className="small muted" style={{ marginTop: '1rem' }}>
          The slug is part of every URL and API path in this workspace and is not editable through
          the interface. Subscription tier does not gate any capability in this release.
        </p>
      </section>

      {canUpdate ? (
        <section className="card stack" style={{ marginTop: '1.5rem', maxWidth: '44rem' }}>
          <h2>Profile</h2>
          <ActionForm
            action={`/api/v1/organizations/${ctx.organization.slug}/settings`}
            method="PATCH"
            fields={[
              {
                name: 'name',
                label: 'Name',
                defaultValue: organization.name,
                required: true,
                maxLength: 80,
                full: true,
              },
              {
                name: 'description',
                label: 'Description',
                type: 'textarea',
                defaultValue: organization.description ?? '',
                maxLength: 500,
                full: true,
              },
            ]}
            submitLabel="Save settings"
            successMessage="Settings updated."
          />
        </section>
      ) : (
        <p className="banner" style={{ marginTop: '1.5rem' }}>
          Your role is read-only for organization settings.
        </p>
      )}
    </>
  );
}
