import type { Metadata } from 'next';
import Link from 'next/link';
import { notFound } from 'next/navigation';
import { ActionForm } from '@/components/action-form';
import { can } from '@/server/authz/roles';
import {
  CONNECTOR_KINDS,
  ENFORCEMENT_KINDS,
  SENSITIVITIES,
  ZONES,
} from '@/server/domain/zero-trust';
import { getNetworkOverview, listConnectors, listSegments } from '@/server/services/network';
import { loadTenantContext } from '@/server/ui/session';
import { connectorListQuerySchema, segmentListQuerySchema } from '@/server/validation/zero-trust';

export const metadata: Metadata = { title: 'Network · CyberNorf' };
export const dynamic = 'force-dynamic';

const STATUS_BADGES: Record<string, string> = {
  ONLINE: 'success',
  DEGRADED: 'medium',
  OFFLINE: 'critical',
};

export default async function NetworkPage({
  params,
  searchParams,
}: {
  params: Promise<{ orgSlug: string }>;
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const { orgSlug } = await params;
  const ctx = await loadTenantContext(orgSlug, 'network.read');
  if (!ctx) {
    notFound();
  }

  const raw = await searchParams;
  const connectorQuery = connectorListQuerySchema.safeParse({
    page: raw.page,
    pageSize: raw.pageSize,
    kind: raw.kind,
    status: raw.status,
    q: raw.q,
  });
  const query = connectorQuery.success ? connectorQuery.data : connectorListQuerySchema.parse({});

  const canManage = can(ctx.membership.role, 'network.manage');
  const [overview, connectors, segments] = await Promise.all([
    getNetworkOverview(ctx.organization.id),
    listConnectors(ctx.organization.id, query),
    listSegments(ctx.organization.id, segmentListQuerySchema.parse({ pageSize: 50 })),
  ]);

  const base = `/app/${ctx.organization.slug}`;
  const connectorOptions = connectors.connectors.map((connector) => ({
    value: connector.id,
    label: connector.name,
  }));

  return (
    <>
      <div className="page-header">
        <div>
          <p className="eyebrow">Zero trust</p>
          <h1>Network</h1>
          <p className="small muted" style={{ marginTop: '0.35rem' }}>
            Connectors report what they observe and accept commands; segments describe which
            addresses belong to which zone. Flows are matched to segments server-side, so the zone a
            caller sits in is never taken from the request.
          </p>
        </div>
      </div>

      <div className="grid">
        <div className="stat">
          <p className="stat-label">Connectors</p>
          <p className="stat-value">{overview.connectors.total}</p>
          <p className="small muted">
            {overview.connectors.online} online · {overview.connectors.degraded} degraded ·{' '}
            {overview.connectors.offline} offline
          </p>
        </div>
        <div className="stat">
          <p className="stat-label">Segments</p>
          <p className="stat-value">{overview.segments}</p>
          <p className="small muted">CIDR ranges mapped to a zone</p>
        </div>
        <div className="stat">
          <p className="stat-label">Open detections</p>
          <p className="stat-value">{overview.openDetections.total}</p>
          <p className="small muted">
            {overview.openDetections.critical} critical · {overview.openDetections.high} high
          </p>
        </div>
        <div className="stat">
          <p className="stat-label">Flows (24h)</p>
          <p className="stat-value">{overview.flows24h}</p>
          <p className="small muted">Observed by connectors</p>
        </div>
      </div>

      <section className="card">
        <div className="row" style={{ justifyContent: 'space-between' }}>
          <h2>Connectors</h2>
          <div className="row" style={{ gap: '0.6rem' }}>
            <Link href={`${base}/network/detections`} className="nav-link">
              Detections
            </Link>
            <Link href={`${base}/network/flows`} className="nav-link">
              Flows
            </Link>
            <Link href={`${base}/network/admission`} className="nav-link">
              Test admission
            </Link>
          </div>
        </div>
        {connectors.connectors.length === 0 ? (
          <p className="small muted">
            No connector yet. A connector is the enforcement point: a RADIUS server, gateway,
            firewall or EDR that reports telemetry and applies commands.
          </p>
        ) : (
          <table className="data-table">
            <thead>
              <tr>
                <th>Connector</th>
                <th>Kind</th>
                <th>Status</th>
                <th>Fail mode</th>
                <th>Capabilities</th>
                <th>Last heartbeat</th>
              </tr>
            </thead>
            <tbody>
              {connectors.connectors.map((connector) => (
                <tr key={connector.id}>
                  <td>
                    <Link href={`${base}/network/connectors/${connector.id}`}>
                      {connector.name}
                    </Link>
                    {connector.endpointUrl ? (
                      <div className="small muted mono">{connector.endpointUrl}</div>
                    ) : null}
                  </td>
                  <td className="small">{connector.kind.toLowerCase()}</td>
                  <td>
                    <span className={`badge ${STATUS_BADGES[connector.status] ?? ''}`}>
                      {connector.status.toLowerCase()}
                    </span>
                    {connector.heartbeatStale ? (
                      <div className="small muted">heartbeat stale</div>
                    ) : null}
                  </td>
                  <td>
                    <span
                      className={`badge ${connector.failMode === 'CLOSED' ? 'info' : 'medium'}`}
                    >
                      fail {connector.failMode.toLowerCase()}
                    </span>
                  </td>
                  <td className="small muted">
                    {connector.capabilities.length > 0
                      ? connector.capabilities.join(', ')
                      : 'all commands'}
                  </td>
                  <td className="small">
                    {connector.lastHeartbeatAt
                      ? new Date(connector.lastHeartbeatAt).toLocaleString()
                      : 'never'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>

      <section className="card" style={{ marginTop: '1.5rem' }}>
        <h2>Segments</h2>
        {segments.segments.length === 0 ? (
          <p className="small muted">
            No segment is defined, so every source address resolves to the external zone and policy
            that requires an internal zone will deny.
          </p>
        ) : (
          <table className="data-table">
            <thead>
              <tr>
                <th>Segment</th>
                <th>CIDR</th>
                <th>Zone</th>
                <th>Sensitivity</th>
                <th>Connector</th>
              </tr>
            </thead>
            <tbody>
              {segments.segments.map((segment) => (
                <tr key={segment.id}>
                  <td>{segment.name}</td>
                  <td className="mono small">{segment.cidr}</td>
                  <td>
                    <span className="badge info">{segment.zone.toLowerCase()}</span>
                  </td>
                  <td className="small">{segment.sensitivity.toLowerCase()}</td>
                  <td className="small muted">
                    {segment.connectorId
                      ? (connectorOptions.find((option) => option.value === segment.connectorId)
                          ?.label ?? segment.connectorId)
                      : '—'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>

      {canManage ? (
        <div className="grid" style={{ marginTop: '1.5rem', alignItems: 'start' }}>
          <details className="card">
            <summary>
              <strong>Register a connector</strong>
            </summary>
            <p className="small muted">
              The registration token is shown once. A connector that has been given capabilities
              only receives those commands; leaving the list empty allows every command.
            </p>
            <ActionForm
              action={`/api/v1/organizations/${ctx.organization.slug}/network/connectors`}
              submitLabel="Create connector"
              successMessage="Connector created."
              resetOnSuccess
              reveal={[{ label: 'Registration token', key: 'token' }]}
              fields={[
                { name: 'name', label: 'Name', required: true, placeholder: 'HQ RADIUS' },
                {
                  name: 'kind',
                  label: 'Kind',
                  type: 'select',
                  required: true,
                  defaultValue: 'RADIUS',
                  options: CONNECTOR_KINDS.map((kind) => ({
                    value: kind,
                    label: kind.toLowerCase(),
                  })),
                },
                {
                  name: 'endpointUrl',
                  label: 'Endpoint URL',
                  placeholder: 'https://radius.internal.example',
                },
                {
                  name: 'failMode',
                  label: 'Fail mode',
                  type: 'select',
                  defaultValue: 'CLOSED',
                  help: 'Closed denies admission when the connector is unreachable.',
                  options: [
                    { value: 'CLOSED', label: 'Closed (deny)' },
                    { value: 'OPEN', label: 'Open (allow)' },
                  ],
                },
                {
                  name: 'capabilities',
                  label: 'Allowed commands',
                  type: 'json',
                  full: true,
                  placeholder: '["SESSION_REVOKE","NETWORK_QUARANTINE"]',
                  help: `Subset of ${ENFORCEMENT_KINDS.join(', ')}. Leave blank for all.`,
                },
              ]}
            />
          </details>

          <details className="card">
            <summary>
              <strong>Add a segment</strong>
            </summary>
            <p className="small muted">
              The most specific segment covering an address wins, so a /32 host entry overrides the
              /16 it sits in.
            </p>
            <ActionForm
              action={`/api/v1/organizations/${ctx.organization.slug}/network/segments`}
              submitLabel="Create segment"
              successMessage="Segment created."
              resetOnSuccess
              fields={[
                { name: 'name', label: 'Name', required: true, placeholder: 'Corporate LAN' },
                { name: 'cidr', label: 'CIDR', required: true, placeholder: '10.20.0.0/16' },
                {
                  name: 'zone',
                  label: 'Zone',
                  type: 'select',
                  required: true,
                  defaultValue: 'CORPORATE',
                  options: ZONES.map((zone) => ({ value: zone, label: zone.toLowerCase() })),
                },
                {
                  name: 'sensitivity',
                  label: 'Sensitivity',
                  type: 'select',
                  defaultValue: 'INTERNAL',
                  options: SENSITIVITIES.map((value) => ({
                    value,
                    label: value.toLowerCase(),
                  })),
                },
                {
                  name: 'connectorId',
                  label: 'Enforced by',
                  type: 'select',
                  allowEmpty: true,
                  options: connectorOptions,
                },
              ]}
            />
          </details>
        </div>
      ) : null}
    </>
  );
}
