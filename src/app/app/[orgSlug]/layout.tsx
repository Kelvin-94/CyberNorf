import type { ReactNode } from 'react';
import Link from 'next/link';
import { MfaRequiredBanner } from '@/components/access-denied';
import { SignOutButton } from '@/components/app/sign-out-button';
import { NavLinks, type NavItem } from '@/components/nav-links';
import { can, type Capability } from '@/server/authz/roles';
import { loadTenantContext } from '@/server/ui/session';

export const dynamic = 'force-dynamic';

// Each entry mirrors the capability required by the destination page so the
// sidebar never advertises a section the current role cannot open.
const NAV_ITEMS: Array<{
  href: string;
  label: string;
  group: NavItem['group'];
  capability: Capability;
}> = [
  { href: '', label: 'Dashboard', group: 'Investigate', capability: 'organization.read' },
  { href: '/assets', label: 'Assets', group: 'Investigate', capability: 'asset.read' },
  { href: '/findings', label: 'Findings', group: 'Investigate', capability: 'finding.read' },
  { href: '/incidents', label: 'Incidents', group: 'Investigate', capability: 'incident.read' },
  { href: '/compliance', label: 'Compliance', group: 'Govern', capability: 'compliance.read' },
  { href: '/audit', label: 'Audit trail', group: 'Govern', capability: 'audit.read' },
  { href: '/members', label: 'Members', group: 'Govern', capability: 'organization.read' },
  { href: '/settings', label: 'Settings', group: 'Govern', capability: 'organization.read' },
];

export default async function OrganizationLayout({
  children,
  params,
}: {
  children: ReactNode;
  params: Promise<{ orgSlug: string }>;
}) {
  const { orgSlug } = await params;
  const ctx = await loadTenantContext(orgSlug, 'organization.read');

  if (!ctx) {
    return (
      <main className="app-main">
        <p className="banner error">You do not have access to this organization.</p>
        <Link href="/app">Return to your organizations</Link>
      </main>
    );
  }

  const base = `/app/${ctx.organization.slug}`;
  const items: NavItem[] = NAV_ITEMS.filter((item) =>
    can(ctx.membership.role, item.capability),
  ).map((item) => ({
    href: `${base}${item.href}`,
    label: item.label,
    group: item.group,
  }));
  const mfaWarning =
    (ctx.membership.role === 'OWNER' || ctx.membership.role === 'ADMIN') &&
    !ctx.user.twoFactorEnabled;

  return (
    <div className="app-shell">
      <aside className="app-sidebar">
        <div>
          <Link href="/app" className="brand">
            CyberNorf
            <small>{ctx.organization.name}</small>
          </Link>
        </div>

        <div className="row" style={{ gap: '0.4rem' }}>
          <span className="badge">{ctx.membership.role}</span>
          {can(ctx.membership.role, 'finding.create') ? null : (
            <span className="badge">Read only</span>
          )}
        </div>

        <NavLinks items={items} />

        <div className="stack" style={{ marginTop: 'auto', gap: '0.5rem' }}>
          <Link href="/app" className="nav-link">
            Switch organization
          </Link>
          <Link href="/account/security" className="nav-link">
            Account security
          </Link>
          <SignOutButton />
        </div>
      </aside>

      <main className="app-main">
        {mfaWarning ? <MfaRequiredBanner /> : null}
        {children}
      </main>
    </div>
  );
}
