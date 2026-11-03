import type { Metadata } from 'next';
import Link from 'next/link';
import { CreateOrganizationForm } from '@/components/app/create-organization-form';
import { SignOutButton } from '@/components/app/sign-out-button';
import { requireSessionUser } from '@/server/ui/session';
import { listUserOrganizations } from '@/server/services/organizations';

export const metadata: Metadata = { title: 'Organizations · CyberNorf' };
export const dynamic = 'force-dynamic';

export default async function OrganizationsPage() {
  const user = await requireSessionUser();
  const organizations = await listUserOrganizations(user.id);

  return (
    <main className="app-main" style={{ maxWidth: '60rem', margin: '0 auto' }}>
      <div className="page-header">
        <div>
          <p className="eyebrow">CyberNorf</p>
          <h1>Your organizations</h1>
          <p className="muted small" style={{ marginTop: '0.4rem' }}>
            Signed in as {user.email}
          </p>
        </div>
        <div className="row">
          <Link href="/account/security">
            <button type="button" className="secondary">
              Account security
            </button>
          </Link>
          <SignOutButton />
        </div>
      </div>

      {organizations.length === 0 ? (
        <p className="banner">
          You are not a member of any organization yet. Create one below, or ask an owner to add
          your email address to theirs.
        </p>
      ) : (
        <div className="grid">
          {organizations.map((organization) => (
            <Link
              key={organization.id}
              href={`/app/${organization.slug}`}
              className="card stack"
              style={{ textDecoration: 'none' }}
            >
              <div className="row" style={{ justifyContent: 'space-between' }}>
                <strong>{organization.name}</strong>
                <span className="badge">{organization.role}</span>
              </div>
              <span className="small muted">
                {organization.memberCount} member{organization.memberCount === 1 ? '' : 's'} ·{' '}
                {organization.tier.toLowerCase()}
              </span>
            </Link>
          ))}
        </div>
      )}

      <section className="card stack" style={{ marginTop: '2rem', maxWidth: '36rem' }}>
        <h2>Create an organization</h2>
        <p className="small muted">You become its first owner.</p>
        <CreateOrganizationForm />
      </section>
    </main>
  );
}
