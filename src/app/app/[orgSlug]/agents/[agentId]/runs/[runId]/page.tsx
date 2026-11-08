import type { Metadata } from 'next';
import Link from 'next/link';
import { notFound } from 'next/navigation';
import { getAgentRun } from '@/server/services/agents';
import { loadTenantContext } from '@/server/ui/session';

export const metadata: Metadata = { title: 'Agent run · CyberNorf' };
export const dynamic = 'force-dynamic';

function formatTimestamp(value: string | null): string {
  return value ? new Date(value).toLocaleString() : '—';
}

function checkBadgeClass(status: string): string {
  if (status === 'PASS') {
    return 'success';
  }
  return status === 'FAIL' ? 'denied' : 'info';
}

export default async function AgentRunPage({
  params,
}: {
  params: Promise<{ orgSlug: string; agentId: string; runId: string }>;
}) {
  const { orgSlug, agentId, runId } = await params;
  const ctx = await loadTenantContext(orgSlug, 'agent.read');
  if (!ctx) {
    notFound();
  }

  let detail: Awaited<ReturnType<typeof getAgentRun>>;
  try {
    detail = await getAgentRun(ctx, agentId, runId);
  } catch {
    // Runs from another tenant are indistinguishable from missing ones.
    notFound();
  }

  const base = `/app/${ctx.organization.slug}`;
  const run = detail.run;

  return (
    <>
      <div className="page-header">
        <div>
          <p className="eyebrow">
            <Link href={`${base}/agents`}>Agents</Link> /{' '}
            <Link href={`${base}/agents/${agentId}`}>record</Link> / run
          </p>
          <h1>Monitoring run</h1>
          <p className="small muted" style={{ marginTop: '0.35rem' }}>
            {run.hostname ?? 'unknown host'}
            {run.platform ? ` · ${run.platform}` : ''} · started {formatTimestamp(run.startedAt)}
          </p>
        </div>
      </div>

      <div className="grid">
        <div className="stat">
          <p className="stat-label">Outcome</p>
          <p className="stat-value small">{run.status.toLowerCase()}</p>
          <p className="small muted">{run.checkCount} checks evaluated</p>
        </div>
        <div className="stat">
          <p className="stat-label">Passed</p>
          <p className="stat-value">{run.passCount}</p>
          <p className="small muted">Host hardening checks met</p>
        </div>
        <div className="stat">
          <p className="stat-label">Failed</p>
          <p className="stat-value">{run.failCount}</p>
          <p className="small muted">Each failure raises or refreshes a finding</p>
        </div>
        <div className="stat">
          <p className="stat-label">Skipped</p>
          <p className="stat-value">{run.skipCount}</p>
          <p className="small muted">Evidence unreadable with the agent's privileges</p>
        </div>
      </div>

      <p className="small muted">
        Findings created {run.findingsCreated} · refreshed {run.findingsRefreshed} ·{' '}
        {detail.findings.length} linked finding{detail.findings.length === 1 ? '' : 's'}
      </p>

      <section className="card" style={{ marginTop: '1.5rem' }}>
        <h2>Checks</h2>
        {detail.checks.length === 0 ? (
          <p className="small muted">This run reported no checks, so the host is unmonitored.</p>
        ) : (
          <table className="data-table">
            <thead>
              <tr>
                <th>Check</th>
                <th>Status</th>
                <th>Severity</th>
                <th>Evidence</th>
              </tr>
            </thead>
            <tbody>
              {detail.checks.map((check) => (
                <tr key={`${check.id}-${check.target ?? ''}`}>
                  <td>
                    {check.title}
                    <div className="mono muted">{check.id}</div>
                    {check.target ? <div className="small muted">Target {check.target}</div> : null}
                  </td>
                  <td>
                    <span className={`badge ${checkBadgeClass(check.status)}`}>
                      {check.status.toLowerCase()}
                    </span>
                  </td>
                  <td>
                    <span className={`badge ${check.severity.toLowerCase()}`}>
                      {check.severity}
                    </span>
                  </td>
                  <td className="small">
                    {check.detail ?? '—'}
                    {check.remediation ? (
                      <div className="muted">Fix: {check.remediation}</div>
                    ) : null}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>

      <section className="card" style={{ marginTop: '1.5rem' }}>
        <h2>Linked findings</h2>
        {detail.findings.length === 0 ? (
          <p className="small muted">
            No open findings match the failed checks in this run. A resolved finding stays resolved
            until a later run fails the same check again.
          </p>
        ) : (
          <ul className="stack" style={{ gap: '0.4rem' }}>
            {detail.findings.map((finding) => (
              <li key={finding.id} className="row" style={{ gap: '0.6rem' }}>
                <span className={`badge ${finding.severity.toLowerCase()}`}>
                  {finding.severity}
                </span>
                <Link href={`${base}/findings/${finding.id}`}>{finding.title}</Link>
                <span className="small muted">{finding.status.replaceAll('_', ' ')}</span>
              </li>
            ))}
          </ul>
        )}
      </section>
    </>
  );
}
