import type { Metadata } from 'next';
import Link from 'next/link';
import { notFound } from 'next/navigation';
import { AgentStatusBadge } from '@/components/agents/agent-status-badge';
import { RegisterAgentForm } from '@/components/agents/register-agent-form';
import { can } from '@/server/authz/roles';
import { listAgents } from '@/server/services/agents';
import { loadTenantContext } from '@/server/ui/session';

export const metadata: Metadata = { title: 'Agents · CyberNorf' };
export const dynamic = 'force-dynamic';

function formatTimestamp(value: string | null): string {
  return value ? new Date(value).toLocaleString() : '—';
}

export default async function AgentsPage({ params }: { params: Promise<{ orgSlug: string }> }) {
  const { orgSlug } = await params;
  const ctx = await loadTenantContext(orgSlug, 'agent.read');
  if (!ctx) {
    notFound();
  }

  const overview = await listAgents(ctx);
  const base = `/app/${ctx.organization.slug}`;
  const canManage = can(ctx.membership.role, 'agent.manage');
  const activeAgents = overview.agents.filter((agent) => agent.status === 'ACTIVE');

  return (
    <>
      <div className="page-header">
        <div>
          <p className="eyebrow">Automation</p>
          <h1>Monitoring agents</h1>
          <p className="small muted" style={{ marginTop: '0.35rem' }}>
            Scoped agents that report authentication, access and vulnerability evidence from your
            hosts. Agents connect inward, so monitoring works on networks with no outbound Internet
            access.
          </p>
        </div>
      </div>

      <div className="grid">
        <div className="stat">
          <p className="stat-label">Active agents</p>
          <p className="stat-value">{overview.counts.ACTIVE}</p>
          <p className="small muted">{overview.agents.length} registered in this organization</p>
        </div>
        <div className="stat">
          <p className="stat-label">Awaiting approval</p>
          <p className="stat-value">{overview.counts.PENDING_APPROVAL}</p>
          <p className="small muted">External agents without a credential</p>
        </div>
        <div className="stat">
          <p className="stat-label">Runs reported</p>
          <p className="stat-value">
            {overview.agents.reduce((total, agent) => total + agent.runCount, 0)}
          </p>
          <p className="small muted">Monitoring runs across all agents</p>
        </div>
        <div className="stat">
          <p className="stat-label">Credential lifetime</p>
          <p className="stat-value small">
            {overview.tokenPolicy.builtinDays}d / {overview.tokenPolicy.externalDays}d
          </p>
          <p className="small muted">Builtin / third-party agent tokens</p>
        </div>
      </div>

      <section className="card">
        <h2>Registered agents</h2>
        {overview.agents.length === 0 ? (
          <p className="small muted">
            No agents yet. Register the builtin monitor on a host you control, or connect an
            external agent and have the organization owner approve it.
          </p>
        ) : (
          <table className="data-table">
            <thead>
              <tr>
                <th>Agent</th>
                <th>Source</th>
                <th>Status</th>
                <th>Health</th>
                <th>Scopes</th>
                <th>Last run</th>
                <th>Runs</th>
              </tr>
            </thead>
            <tbody>
              {overview.agents.map((agent) => (
                <tr key={agent.id}>
                  <td>
                    <Link href={`${base}/agents/${agent.id}`}>{agent.name}</Link>
                    <div className="small muted">{agent.description ?? 'No description'}</div>
                  </td>
                  <td className="small">{agent.source}</td>
                  <td>
                    <AgentStatusBadge status={agent.status} />
                  </td>
                  <td>
                    <span
                      className={`badge ${
                        agent.health === 'ONLINE'
                          ? 'success'
                          : agent.health === 'OFFLINE'
                            ? 'denied'
                            : 'medium'
                      }`}
                    >
                      {agent.health.toLowerCase()}
                    </span>
                    <div className="small muted">
                      {agent.expectedIntervalMinutes
                        ? `every ${agent.expectedIntervalMinutes} min`
                        : 'no interval'}
                    </div>
                  </td>
                  <td className="mono small">{agent.scopes.join(', ')}</td>
                  <td className="small">{formatTimestamp(agent.lastRunAt)}</td>
                  <td className="small">{agent.runCount}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>

      <section className="card stack" style={{ marginTop: '1.5rem', maxWidth: '44rem' }}>
        <h2>Offline operation</h2>
        <p className="small muted">
          The builtin monitor reads local evidence only: no cloud API is contacted. On an air-gapped
          host, run it with <span className="mono">--dry-run</span> and write the report to a file
          with <span className="mono">--out</span>; submit it later from a connected host with{' '}
          <span className="mono">--in</span>. External agents such as ChatGPT or Claude use the same
          report endpoint and are never called by this platform.
        </p>
        <p className="small muted">
          {activeAgents.length} of {overview.agents.length} agents currently hold a live credential.
        </p>
      </section>

      {canManage ? (
        <section className="card stack" style={{ marginTop: '1.5rem', maxWidth: '44rem' }}>
          <h2>Connect an agent</h2>
          <p className="small muted">
            A builtin agent is activated immediately and its token is shown once. Every external
            source stays inert until an organization owner approves that specific agent.
          </p>
          <RegisterAgentForm orgSlug={ctx.organization.slug} />
        </section>
      ) : (
        <p className="small muted" style={{ marginTop: '1.5rem' }}>
          Registering or approving agents requires an administrator or owner.
        </p>
      )}
    </>
  );
}
