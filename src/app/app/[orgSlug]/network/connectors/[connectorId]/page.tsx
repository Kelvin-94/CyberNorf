import type { Metadata } from 'next';
import Link from 'next/link';
import { notFound } from 'next/navigation';
import { ActionForm } from '@/components/action-form';
import { can } from '@/server/authz/roles';
import { CONNECTOR_FAIL_MODES } from '@/server/domain/zero-trust';
import { AppError } from '@/server/errors';
import { getConnector } from '@/server/services/network';
import { listEnforcementActions } from '@/server/services/enforcement';
import { loadTenantContext } from '@/server/ui/session';
import { enforcementActionQuerySchema } from '@/server/validation/zero-trust';

export const metadata: Metadata = { title: 'Connector · CyberNorf' };
export const dynamic = 'force-dynamic';

const STATUS_BADGES: Record<string, string> = {
  ONLINE: 'success',
  DEGRADED: 'medium',
  OFFLINE: 'critical',
};

export default async function ConnectorPage({
  params,
}: {
  params: Promise<{ orgSlug: string; connectorId: string }>;
}) {
  const { orgSlug, connectorId } = await params;
  const ctx = await loadTenantContext(orgSlug, 'network.read');
  if (!ctx) {
    notFound();
  }

  let connector;
  try {
    connector = await getConnector(ctx.organization.id, connectorId);
  } catch (error) {
    if (error instanceof AppError && error.statusCode === 404) {
      notFound();
    }
    throw error;
  }
  const canManage = can(ctx.membership.role, 'network.manage');
  const actions = await listEnforcementActions(
    ctx.organization.id,
    enforcementActionQuerySchema.parse({ pageSize: 10 }),
  );
  const connectorActions = actions.actions.filter((action) => action.connectorId === connector.id);
  const base = `/app/${ctx.organization.slug}`;
  const connectorPath = `/api/v1/organizations/${ctx.organization.slug}/network/connectors/${connector.id}`;

  return (
    <>
      <div className="page-header">
        <div>
          <p className="eyebrow">
            <Link href={`${base}/network`}>Network</Link>
          </p>
          <h1>{connector.name}</h1>
          <p className="small muted" style={{ marginTop: '0.35rem' }}>
            {connector.kind.toLowerCase()} · registered{' '}
            {new Date(connector.createdAt).toLocaleString()}
          </p>
        </div>
        <span className={`badge ${STATUS_BADGES[connector.status] ?? ''}`}>
          {connector.status.toLowerCase()}
        </span>
      </div>

      <section className="card">
        <dl className="detail-grid">
          <div>
            <dt>Endpoint</dt>
            <dd className="mono small">{connector.endpointUrl ?? '—'}</dd>
          </div>
          <div>
            <dt>Fail mode</dt>
            <dd>
              {connector.failMode === 'CLOSED'
                ? 'Fail closed — deny admission when unreachable'
                : 'Fail open — allow admission when unreachable'}
            </dd>
          </div>
          <div>
            <dt>Last heartbeat</dt>
            <dd>
              {connector.lastHeartbeatAt
                ? new Date(connector.lastHeartbeatAt).toLocaleString()
                : 'never'}
              {connector.heartbeatStale ? ' (stale)' : ''}
            </dd>
          </div>
          <div>
            <dt>Allowed commands</dt>
            <dd className="small">
              {connector.capabilities.length > 0
                ? connector.capabilities.join(', ')
                : 'all commands'}
            </dd>
          </div>
        </dl>
      </section>

      {connectorActions.length > 0 ? (
        <section className="card" style={{ marginTop: '1.5rem' }}>
          <h2>Recent commands</h2>
          <table className="data-table">
            <thead>
              <tr>
                <th>Target</th>
                <th>Kind</th>
                <th>State</th>
                <th>Requested</th>
              </tr>
            </thead>
            <tbody>
              {connectorActions.map((action) => (
                <tr key={action.id}>
                  <td>
                    <Link href={`${base}/enforcement/${action.id}`}>{action.targetLabel}</Link>
                  </td>
                  <td className="small">{action.kind.replaceAll('_', ' ').toLowerCase()}</td>
                  <td>
                    <span className="badge">{action.state.toLowerCase()}</span>
                  </td>
                  <td className="small">{new Date(action.createdAt).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      ) : null}

      {canManage ? (
        <>
          <section className="card" style={{ marginTop: '1.5rem' }}>
            <h2>Update connector</h2>
            <p className="small muted">
              Changing the fail mode takes effect on the next admission. Setting the status to
              offline has the same effect as a lost heartbeat without waiting for the stale window.
            </p>
            <ActionForm
              action={connectorPath}
              method="PATCH"
              submitLabel="Save connector"
              successMessage="Connector updated."
              fields={[
                { name: 'name', label: 'Name', defaultValue: connector.name },
                {
                  name: 'endpointUrl',
                  label: 'Endpoint URL',
                  defaultValue: connector.endpointUrl ?? '',
                },
                {
                  name: 'failMode',
                  label: 'Fail mode',
                  type: 'select',
                  defaultValue: connector.failMode,
                  options: CONNECTOR_FAIL_MODES.map((mode) => ({
                    value: mode,
                    label: `fail ${mode.toLowerCase()}`,
                  })),
                },
                {
                  name: 'status',
                  label: 'Reported status',
                  type: 'select',
                  defaultValue: connector.status,
                  help: 'Operators can force a connector offline; the connector heartbeat can restore it.',
                  options: [
                    { value: 'ONLINE', label: 'online' },
                    { value: 'DEGRADED', label: 'degraded' },
                    { value: 'OFFLINE', label: 'offline' },
                  ],
                },
              ]}
            />
          </section>

          <section className="card" style={{ marginTop: '1.5rem' }}>
            <h2>Registration token</h2>
            <p className="small muted">
              Rotating the token invalidates the current one immediately. If the connector is
              running it will fail its next call until it is given the new token.
            </p>
            <ActionForm
              action={`${connectorPath}/rotate`}
              fields={[]}
              compact
              submitLabel="Rotate token"
              confirmText="Rotate this connector's token? The current token stops working immediately."
              successMessage="Token rotated. Copy the new value now."
              reveal={[{ label: 'Connector token', key: 'token' }]}
            />
          </section>
        </>
      ) : null}
    </>
  );
}
