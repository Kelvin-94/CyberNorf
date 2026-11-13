import type { Metadata } from 'next';
import Link from 'next/link';
import { notFound } from 'next/navigation';
import { ActionForm } from '@/components/action-form';
import { can } from '@/server/authz/roles';
import { DEVICE_STATUSES, TRUST_STATES } from '@/server/domain/zero-trust';
import { getDeviceOverview, listDevices } from '@/server/services/devices';
import { loadTenantContext } from '@/server/ui/session';
import { deviceListQuerySchema } from '@/server/validation/zero-trust';

export const metadata: Metadata = { title: 'Devices · CyberNorf' };
export const dynamic = 'force-dynamic';

const STATUS_BADGES: Record<string, string> = {
  ACTIVE: 'success',
  PENDING: 'medium',
  SUSPENDED: 'denied',
  RETIRED: 'low',
};

const TRUST_BADGES: Record<string, string> = {
  TRUSTED: 'success',
  PARTIAL: 'medium',
  UNKNOWN: 'low',
  UNTRUSTED: 'critical',
};

function formatTimestamp(value: string | null): string {
  return value ? new Date(value).toLocaleString() : '—';
}

export default async function DevicesPage({
  params,
  searchParams,
}: {
  params: Promise<{ orgSlug: string }>;
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const { orgSlug } = await params;
  const ctx = await loadTenantContext(orgSlug, 'device.read');
  if (!ctx) {
    notFound();
  }

  const raw = await searchParams;
  const parsed = deviceListQuerySchema.safeParse({
    page: raw.page,
    pageSize: raw.pageSize,
    status: raw.status,
    trustState: raw.trustState,
    managed: raw.managed,
    q: raw.q,
  });
  const query = parsed.success ? parsed.data : deviceListQuerySchema.parse({});

  const canManage = can(ctx.membership.role, 'device.manage');
  const [page, overview] = await Promise.all([
    listDevices(ctx.organization.id, query),
    getDeviceOverview(ctx.organization.id),
  ]);

  const base = `/app/${ctx.organization.slug}`;
  const filterParams = new URLSearchParams();
  for (const [key, value] of Object.entries({
    status: query.status,
    trustState: query.trustState,
    managed: query.managed === undefined ? undefined : String(query.managed),
    q: query.q,
    pageSize: String(query.pageSize),
  })) {
    if (value) {
      filterParams.set(key, value);
    }
  }
  const pageHref = (target: number) => {
    const next = new URLSearchParams(filterParams);
    next.set('page', String(target));
    return `${base}/devices?${next.toString()}`;
  };

  return (
    <>
      <div className="page-header">
        <div>
          <p className="eyebrow">Zero trust</p>
          <h1>Devices</h1>
          <p className="small muted" style={{ marginTop: '0.35rem' }}>
            Every endpoint that can reach a protected resource, with the trust state derived from
            its signed posture report. Trust is recomputed at decision time, so a report that
            expires lowers a device&apos;s standing without anyone writing to it.
          </p>
        </div>
      </div>

      <div className="grid">
        <div className="stat">
          <p className="stat-label">Registered</p>
          <p className="stat-value">{overview.counts.total}</p>
          <p className="small muted">
            {overview.counts.active} active · {overview.counts.pending} pending
          </p>
        </div>
        <div className="stat">
          <p className="stat-label">Trusted</p>
          <p className="stat-value">{overview.counts.trusted}</p>
          <p className="small muted">
            {overview.counts.partial} partial · {overview.counts.untrusted} untrusted
          </p>
        </div>
        <div className="stat">
          <p className="stat-label">Unmanaged</p>
          <p className="stat-value">{overview.counts.unmanaged}</p>
          <p className="small muted">Active devices with no management agent</p>
        </div>
        <div className="stat">
          <p className="stat-label">Suspended</p>
          <p className="stat-value">{overview.counts.suspended}</p>
          <p className="small muted">{overview.counts.retired} retired</p>
        </div>
      </div>

      <section className="card">
        <div className="row" style={{ justifyContent: 'space-between', flexWrap: 'wrap' }}>
          <h2>Inventory</h2>
          <form method="get" className="row" style={{ gap: '0.4rem', flexWrap: 'wrap' }}>
            <input
              name="q"
              defaultValue={query.q ?? ''}
              placeholder="Search name, hardware id, OS"
              aria-label="Search devices"
              style={{ width: '16rem' }}
            />
            <select name="status" defaultValue={query.status ?? ''} aria-label="Status">
              <option value="">All statuses</option>
              {DEVICE_STATUSES.map((status) => (
                <option key={status} value={status}>
                  {status.toLowerCase()}
                </option>
              ))}
            </select>
            <select name="trustState" defaultValue={query.trustState ?? ''} aria-label="Trust">
              <option value="">All trust states</option>
              {TRUST_STATES.map((state) => (
                <option key={state} value={state}>
                  {state.toLowerCase()}
                </option>
              ))}
            </select>
            <select
              name="managed"
              defaultValue={query.managed === undefined ? '' : String(query.managed)}
              aria-label="Managed"
            >
              <option value="">Managed and unmanaged</option>
              <option value="true">Managed</option>
              <option value="false">Unmanaged</option>
            </select>
            <button type="submit" className="secondary">
              Filter
            </button>
            <Link href={`${base}/devices`} className="nav-link">
              Reset
            </Link>
          </form>
        </div>

        {page.devices.length === 0 ? (
          <p className="small muted">
            No devices match this filter. {canManage ? 'Register one below.' : ''}
          </p>
        ) : (
          <table className="data-table">
            <thead>
              <tr>
                <th>Device</th>
                <th>Status</th>
                <th>Trust</th>
                <th>Posture</th>
                <th>Management</th>
                <th>Last seen</th>
              </tr>
            </thead>
            <tbody>
              {page.devices.map((device) => (
                <tr key={device.id}>
                  <td>
                    <Link href={`${base}/devices/${device.id}`}>{device.name}</Link>
                    <div className="mono small muted">{device.hardwareId}</div>
                  </td>
                  <td>
                    <span className={`badge ${STATUS_BADGES[device.status] ?? ''}`}>
                      {device.status.toLowerCase()}
                    </span>
                  </td>
                  <td>
                    <span className={`badge ${TRUST_BADGES[device.trustState] ?? ''}`}>
                      {device.trustState.toLowerCase()} · {device.trustScore}
                    </span>
                    {device.trust.reasons.length > 0 ? (
                      <div className="small muted">{device.trust.reasons[0]}</div>
                    ) : null}
                  </td>
                  <td className="small">
                    {device.trust.postureFresh ? (
                      <>fresh until {formatTimestamp(device.trust.expiresAt)}</>
                    ) : (
                      <span className="badge medium">stale</span>
                    )}
                    {device.trust.failingChecks.length > 0 ? (
                      <div className="muted">
                        failing: {device.trust.failingChecks.slice(0, 3).join(', ')}
                      </div>
                    ) : null}
                  </td>
                  <td className="small">
                    {device.managed ? 'Managed' : 'Unmanaged'}
                    <div className="muted">
                      {device.attestationVerified
                        ? `${device.attestationKind.toLowerCase()} attested`
                        : 'no attestation'}
                    </div>
                  </td>
                  <td className="small">{formatTimestamp(device.lastSeenAt)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}

        <div className="row" style={{ justifyContent: 'space-between', marginTop: '0.75rem' }}>
          <span className="small muted">
            Page {page.page.page} of {page.page.pageCount} · {page.page.total} devices
          </span>
          <div className="row" style={{ gap: '0.4rem' }}>
            {page.page.page > 1 ? (
              <Link className="nav-link" href={pageHref(page.page.page - 1)}>
                Previous
              </Link>
            ) : null}
            {page.page.page < page.page.pageCount ? (
              <Link className="nav-link" href={pageHref(page.page.page + 1)}>
                Next
              </Link>
            ) : null}
          </div>
        </div>
      </section>

      <section className="card" style={{ marginTop: '1.5rem' }}>
        <h2>How trust is decided</h2>
        <p className="small muted">
          A device starts at unknown. Trust moves up to partial when it has a fresh signed posture
          report with no failing checks, and to trusted when that report also passes every check
          policy names, when the device is managed and when its attestation verified. A single
          failing check is enough to drop a device below partial: a machine that reports a disabled
          disk encryption check is not equivalent to one that simply has not reported yet.
        </p>
        <p className="small muted">
          Posture is only accepted when the report verifies against the key registered for the
          device. Reports are re-evaluated against the clock on every read, so a report that was
          fresh at collection time becomes stale on its own.
        </p>
      </section>

      {canManage ? (
        <details className="card" style={{ marginTop: '1.5rem' }}>
          <summary>
            <strong>Register a device</strong>
          </summary>
          <p className="small muted">
            Registration records the public key the device will sign posture reports with. The
            hardware identifier is the device&apos;s stable identity; renaming a device does not
            change it.
          </p>
          <ActionForm
            action={`/api/v1/organizations/${ctx.organization.slug}/devices`}
            submitLabel="Register device"
            successMessage="Device registered."
            resetOnSuccess
            fields={[
              { name: 'name', label: 'Name', required: true, placeholder: 'Kelvin’s MacBook' },
              {
                name: 'hardwareId',
                label: 'Hardware identifier',
                required: true,
                placeholder: 'HW-9F2A-77C1',
                help: 'Letters, digits, colon, underscore and hyphen only.',
              },
              {
                name: 'publicKey',
                label: 'Public key',
                type: 'textarea',
                required: true,
                full: true,
                help: 'Base64 or PEM Ed25519 public key.',
              },
              {
                name: 'attestationKind',
                label: 'Attestation',
                type: 'select',
                defaultValue: 'NONE',
                options: [
                  { value: 'NONE', label: 'None' },
                  { value: 'TPM', label: 'TPM' },
                  { value: 'SECURE_ENCLAVE', label: 'Secure enclave' },
                  { value: 'VTPM', label: 'Virtual TPM' },
                ],
              },
              {
                name: 'attestationVerified',
                label: 'Attestation already verified',
                type: 'checkbox',
              },
              { name: 'managed', label: 'Managed by an agent', type: 'checkbox' },
              { name: 'os', label: 'Operating system', placeholder: 'macOS' },
              { name: 'osVersion', label: 'OS version', placeholder: '15.1' },
            ]}
          />
        </details>
      ) : null}
    </>
  );
}
