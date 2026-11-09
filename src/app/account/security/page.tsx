import type { Metadata } from 'next';
import Link from 'next/link';
import { ApiKeysPanel } from '@/components/account/api-keys-panel';
import { TwoFactorPanel } from '@/components/account/two-factor-panel';
import { listUserApiKeys } from '@/server/services/api-keys';
import { listUserOrganizations } from '@/server/services/organizations';
import { requireSessionUser } from '@/server/ui/session';

export const metadata: Metadata = { title: 'Account security · CyberNorf' };
export const dynamic = 'force-dynamic';

export default async function AccountSecurityPage() {
  const user = await requireSessionUser();
  const [apiKeys, organizations] = await Promise.all([
    listUserApiKeys(user.id),
    listUserOrganizations(user.id),
  ]);

  return (
    <main className="app-main" style={{ maxWidth: '46rem', margin: '0 auto' }}>
      <p className="eyebrow">Account</p>
      <h1>Security settings</h1>
      <p className="muted" style={{ marginTop: '0.5rem' }}>
        Signed in as {user.email}.
      </p>

      <section className="card stack" style={{ marginTop: '1.5rem' }}>
        <h2>Two-factor authentication</h2>
        <TwoFactorPanel enabled={user.twoFactorEnabled} />
      </section>

      <section className="card stack" style={{ marginTop: '1.5rem' }}>
        <h2>Personal API keys</h2>
        <ApiKeysPanel
          organizations={organizations.map((organization) => ({
            id: organization.id,
            name: organization.name,
            role: organization.role,
          }))}
          initialKeys={apiKeys}
          twoFactorEnabled={user.twoFactorEnabled}
        />
      </section>

      <p className="small muted" style={{ marginTop: '1.5rem' }}>
        <Link href="/app">Back to the console</Link>
      </p>
    </main>
  );
}
