import type { Metadata } from 'next';
import Link from 'next/link';
import { notFound } from 'next/navigation';
import { getDashboardSummary } from '@/server/services/dashboard';
import { loadTenantContext } from '@/server/ui/session';

export const metadata: Metadata = { title: 'Dashboard · CyberNorf' };
export const dynamic = 'force-dynamic';

export default async function DashboardPage({ params }: { params: Promise<{ orgSlug: string }> }) {
  const { orgSlug } = await params;
  const ctx = await loadTenantContext(orgSlug, 'organization.read');
  if (!ctx) {
    notFound();
  }

  const summary = await getDashboardSummary(ctx);
  const base = `/app/${ctx.organization.slug}`;

  return (
    <>
      <div className="page-header">
        <div>
          <p className="eyebrow">Security operations</p>
          <h1>{ctx.organization.name}</h1>
          <p className="small muted" style={{ marginTop: '0.35rem' }}>
            {summary.assets.total} assets · {summary.members} active members · tier{' '}
            {ctx.organization.tier.toLowerCase()}
          </p>
        </div>
        <div className="row">
          <Link href={`${base}/findings`}>
            <button type="button" className="secondary">
              Findings
            </button>
          </Link>
          <Link href={`${base}/incidents`}>
            <button type="button" className="secondary">
              Incidents
            </button>
          </Link>
        </div>
      </div>

      <div className="grid">
        <div className="stat">
          <p className="stat-label">Open findings</p>
          <p className="stat-value">{summary.findings.openTotal}</p>
          <p className="small muted">
            {summary.findings.bySeverity.CRITICAL} critical · {summary.findings.bySeverity.HIGH}{' '}
            high
          </p>
        </div>
        <div className="stat">
          <p className="stat-label">Active assets</p>
          <p className="stat-value">{summary.assets.active}</p>
          <p className="small muted">
            {summary.assets.inactive} inactive · {summary.assets.retired} retired
          </p>
        </div>
        <div className="stat">
          <p className="stat-label">Open incidents</p>
          <p className="stat-value">{summary.incidents.open}</p>
          <p className="small muted">
            {summary.incidents.byStatus.CLOSED ?? 0} closed historically
          </p>
        </div>
        <div className="stat">
          <p className="stat-label">Audit events</p>
          <p className="stat-value">{summary.recentEvents.length}</p>
          <p className="small muted">Recent activity shown below</p>
        </div>
      </div>

      <div
        className="grid"
        style={{ marginTop: '1.5rem', gridTemplateColumns: 'repeat(auto-fit, minmax(22rem, 1fr))' }}
      >
        <section className="card">
          <h2>Priority findings</h2>
          {summary.latestFindings.length === 0 ? (
            <p className="small muted">
              No open findings. Register an asset, then record or import findings.
            </p>
          ) : (
            <table className="data-table">
              <thead>
                <tr>
                  <th>Finding</th>
                  <th>Severity</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {summary.latestFindings.map((finding) => (
                  <tr key={finding.id}>
                    <td>
                      <Link href={`${base}/findings/${finding.id}`}>{finding.title}</Link>
                      <div className="small muted">{finding.asset?.name ?? 'No asset'}</div>
                    </td>
                    <td>
                      <span className={`badge ${finding.severity.toLowerCase()}`}>
                        {finding.severity}
                      </span>
                    </td>
                    <td className="small">{finding.status.replace('_', ' ')}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </section>

        <section className="card">
          <h2>Recent audit activity</h2>
          {summary.recentEvents.length === 0 ? (
            <p className="small muted">No recorded activity yet.</p>
          ) : (
            <table className="data-table">
              <thead>
                <tr>
                  <th>Action</th>
                  <th>Actor</th>
                  <th>When</th>
                </tr>
              </thead>
              <tbody>
                {summary.recentEvents.map((event) => (
                  <tr key={event.id}>
                    <td className="small">
                      {event.summary ?? event.action}
                      <div className="mono muted">{event.action}</div>
                    </td>
                    <td className="small">{event.actor?.name ?? 'system'}</td>
                    <td className="small muted">
                      {event.createdAt.toISOString().slice(0, 16).replace('T', ' ')}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          <p className="small" style={{ marginTop: '0.75rem' }}>
            <Link href={`${base}/audit`}>Open the full audit trail</Link>
          </p>
        </section>
      </div>
    </>
  );
}
