import Link from 'next/link';
import { getSessionUser } from '@/server/ui/session';

export const dynamic = 'force-dynamic';

export default async function Home() {
  const user = await getSessionUser();

  return (
    <main className="page-shell">
      <section className="status-card" aria-labelledby="page-title">
        <p className="eyebrow">CyberNorf · Security operations</p>
        <h1 id="page-title">Track assets, findings, and incidents in one place</h1>
        <p className="description">
          CyberNorf is a multi-tenant security operations console. Assets, findings, and
          investigations are scoped to your organization, every change is authorized on the server,
          and each action is written to a tamper-evident audit trail.
        </p>
        <div className="row" style={{ marginTop: '1.75rem' }}>
          {user ? (
            <Link href="/app">
              <button type="button">Open the console</button>
            </Link>
          ) : (
            <>
              <Link href="/sign-in">
                <button type="button">Sign in</button>
              </Link>
              <Link href="/sign-up">
                <button type="button" className="secondary">
                  Create an account
                </button>
              </Link>
            </>
          )}
        </div>
        <p className="footnote">
          {user ? `Signed in as ${user.email}.` : 'Accounts require a 12-character password.'} See
          the repository documentation for the current scope of this phase.
        </p>
      </section>
    </main>
  );
}
