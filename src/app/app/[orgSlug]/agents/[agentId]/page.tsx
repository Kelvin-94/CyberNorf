import type { Metadata } from 'next';
import Link from 'next/link';
import { notFound } from 'next/navigation';
import { ActionButton } from '@/components/action-button';
import { ApproveAgentForm } from '@/components/agents/approve-agent-form';
import { AgentStatusBadge } from '@/components/agents/agent-status-badge';
import { canTransitionAgent, AGENT_SCOPE_DETAILS, AGENT_SCOPES } from '@/server/domain/agents';
import { getAgentDetail } from '@/server/services/agents';
import { loadTenantContext } from '@/server/ui/session';

export const metadata: Metadata = { title: 'Agent · CyberNorf' };
export const dynamic = 'force-dynamic';

function formatTimestamp(value: string | null): string {
  return value ? new Date(value).toLocaleString() : '—';
}

function formatDuration(value: number | null): string {
  if (value === null) {
    return '—';
  }
  return value >= 1000 ? `${(value / 1000).toFixed(1)}s` : `${value}ms`;
}

export default async function AgentDetailPage({
  params,
}: {
  params: Promise<{ orgSlug: string; agentId: string }>;
}) {
  const { orgSlug, agentId } = await params;
  const ctx = await loadTenantContext(orgSlug, 'agent.read');
  if (!ctx) {
    notFound();
  }

  const detail = await getAgentDetail(ctx, agentId);
  const base = `/app/${ctx.organization.slug}`;
  const agent = detail.agent;
  // The routes admit OWNER and ADMIN, but approval, suspension and revocation
  // are owner-only in the service, so the UI never offers an action that will
  // be rejected.
  const isOwner = ctx.membership.role === 'OWNER';
  const canSuspend = canTransitionAgent(agent.status, 'SUSPENDED');
  const canResume = canTransitionAgent(agent.status, 'ACTIVE') && agent.status === 'SUSPENDED';
  const canRevoke = canTransitionAgent(agent.status, 'REVOKED');

  return (
    <>
      <div className="page-header">
        <div>
          <p className="eyebrow">
            <Link href={`${base}/agents`}>Agents</Link> / {agent.source}
          </p>
          <h1>{agent.name}</h1>
          <p className="small muted" style={{ marginTop: '0.35rem' }}>
            <AgentStatusBadge status={agent.status} /> {agent.description ?? 'No description'}
          </p>
        </div>
      </div>

      <div className="grid">
        <div className="stat">
          <p className="stat-label">Runs reported</p>
          <p className="stat-value">{agent.runCount}</p>
          <p className="small muted">Last run {formatTimestamp(agent.lastRunAt)}</p>
        </div>
        <div className="stat">
          <p className="stat-label">Last seen</p>
          <p className="stat-value small">{formatTimestamp(agent.lastSeenAt)}</p>
          <p className="small muted">Updated on every authenticated request</p>
        </div>
        <div className="stat">
          <p className="stat-label">Credential</p>
          <p className="stat-value small mono">{agent.tokenPrefix ?? 'not issued'}</p>
          <p className="small muted">Expires {formatTimestamp(agent.tokenExpiresAt)}</p>
        </div>
        <div className="stat">
          <p className="stat-label">Open findings</p>
          <p className="stat-value">
            {detail.findings.filter((finding) => finding.status !== 'RESOLVED').length}
          </p>
          <p className="small muted">{detail.findings.length} raised by this agent</p>
        </div>
      </div>

      <section className="card stack">
        <h2>Access</h2>
        <p className="small">
          Scopes: <span className="mono">{agent.scopes.join(', ')}</span>
        </p>
        <p className="small muted">
          The credential is stored only as a SHA-256 hash. It is issued once, on registration for
          builtin agents and on owner approval for external sources.
        </p>
        <p className="small muted">
          Registered {formatTimestamp(agent.createdAt)}
          {agent.approvedAt ? ` · approved ${formatTimestamp(agent.approvedAt)}` : ''}
          {agent.revokedAt ? ` · revoked ${formatTimestamp(agent.revokedAt)}` : ''}
        </p>
      </section>

      <section className="card stack" style={{ marginTop: '1.5rem', maxWidth: '46rem' }}>
        <h2>Lifecycle</h2>

        {agent.status === 'PENDING_APPROVAL' ? (
          isOwner ? (
            <>
              <p className="small muted">
                Approving this agent issues its first credential. It stays inert until then.
              </p>
              <ApproveAgentForm
                orgSlug={ctx.organization.slug}
                agentId={agent.id}
                agentName={agent.name}
                scopeOptions={AGENT_SCOPES.filter((scope) => agent.scopes.includes(scope)).map(
                  (scope) => ({
                    value: scope,
                    label: scope,
                    detail: AGENT_SCOPE_DETAILS[scope],
                  }),
                )}
              />
            </>
          ) : (
            <p className="banner warning">
              Only an organization owner can approve this agent. No credential exists yet.
            </p>
          )
        ) : null}

        {agent.status === 'REVOKED' ? (
          <p className="small muted">
            This agent was revoked. Its credential no longer authenticates and the record is kept
            for the audit trail.
          </p>
        ) : null}

        {isOwner && agent.status !== 'PENDING_APPROVAL' && agent.status !== 'REVOKED' ? (
          <div className="row" style={{ flexWrap: 'wrap', gap: '0.75rem' }}>
            {canSuspend ? (
              <ActionButton
                action={`/api/v1/organizations/${ctx.organization.slug}/agents/${agent.id}/suspend`}
                label="Suspend agent"
                successMessage="Agent suspended. The credential no longer authenticates."
              />
            ) : null}
            {canResume ? (
              <ActionButton
                action={`/api/v1/organizations/${ctx.organization.slug}/agents/${agent.id}/resume`}
                label="Resume agent"
                variant="secondary"
                successMessage="Agent resumed."
              />
            ) : null}
            {canRevoke ? (
              <ActionButton
                action={`/api/v1/organizations/${ctx.organization.slug}/agents/${agent.id}`}
                method="DELETE"
                label="Revoke agent"
                variant="danger"
                confirmText={`Revoke ${agent.name}? This permanently disables its credential and cannot be undone.`}
                successMessage="Agent revoked."
              />
            ) : null}
          </div>
        ) : null}

        {!isOwner && agent.status !== 'REVOKED' && agent.status !== 'PENDING_APPROVAL' ? (
          <p className="small muted">Only an organization owner can change this agent's state.</p>
        ) : null}
      </section>

      <section className="card" style={{ marginTop: '1.5rem' }}>
        <h2>Recent runs</h2>
        {detail.runs.length === 0 ? (
          <p className="small muted">
            No runs yet. Start the builtin monitor with a token for this agent, or submit a report
            to <span className="mono">POST /api/v1/agents/me/runs</span>.
          </p>
        ) : (
          <table className="data-table">
            <thead>
              <tr>
                <th>Started</th>
                <th>Host</th>
                <th>Status</th>
                <th>Checks</th>
                <th>Findings</th>
                <th>Duration</th>
              </tr>
            </thead>
            <tbody>
              {detail.runs.map((run) => (
                <tr key={run.id}>
                  <td className="small">
                    <Link href={`${base}/agents/${agent.id}/runs/${run.id}`}>
                      {formatTimestamp(run.startedAt)}
                    </Link>
                  </td>
                  <td className="small">
                    {run.hostname ?? '—'}
                    <div className="mono muted">{run.platform ?? ''}</div>
                  </td>
                  <td>
                    <span
                      className={`badge ${
                        run.status === 'COMPLETED'
                          ? 'success'
                          : run.status === 'PARTIAL'
                            ? 'medium'
                            : 'denied'
                      }`}
                    >
                      {run.status.toLowerCase()}
                    </span>
                  </td>
                  <td className="small">
                    {run.passCount} pass / {run.failCount} fail / {run.skipCount} skip
                  </td>
                  <td className="small">
                    {run.findingsCreated} new · {run.findingsRefreshed} refreshed
                  </td>
                  <td className="small">{formatDuration(run.durationMs)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>

      <section className="card" style={{ marginTop: '1.5rem' }}>
        <h2>Findings raised by this agent</h2>
        {detail.findings.length === 0 ? (
          <p className="small muted">
            No findings. Failed checks create a finding and are refreshed on later runs instead of
            duplicating.
          </p>
        ) : (
          <table className="data-table">
            <thead>
              <tr>
                <th>Finding</th>
                <th>Severity</th>
                <th>Status</th>
                <th>Last seen</th>
              </tr>
            </thead>
            <tbody>
              {detail.findings.map((finding) => (
                <tr key={finding.id}>
                  <td>
                    <Link href={`${base}/findings/${finding.id}`}>{finding.title}</Link>
                  </td>
                  <td>
                    <span className={`badge ${finding.severity.toLowerCase()}`}>
                      {finding.severity}
                    </span>
                  </td>
                  <td className="small">{finding.status.replaceAll('_', ' ')}</td>
                  <td className="small">{formatTimestamp(finding.lastSeenAt)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>
    </>
  );
}
