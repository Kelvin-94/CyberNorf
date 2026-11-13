import type { Metadata } from 'next';
import Link from 'next/link';
import { notFound } from 'next/navigation';
import { ActionButton } from '@/components/action-button';
import { ActionForm } from '@/components/action-form';
import { can } from '@/server/authz/roles';
import { AppError } from '@/server/errors';
import { getDeviceDetail } from '@/server/services/devices';
import { loadTenantContext } from '@/server/ui/session';

export const metadata: Metadata = { title: 'Device · CyberNorf' };
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

const CHECK_BADGES: Record<string, string> = {
  PASS: 'success',
  FAIL: 'critical',
  UNKNOWN: 'low',
};

function formatTimestamp(value: string | null): string {
  return value ? new Date(value).toLocaleString() : '—';
}

export default async function DeviceDetailPage({
  params,
}: {
  params: Promise<{ orgSlug: string; deviceId: string }>;
}) {
  const { orgSlug, deviceId } = await params;
  const ctx = await loadTenantContext(orgSlug, 'device.read');
  if (!ctx) {
    notFound();
  }

  let detail;
  try {
    detail = await getDeviceDetail(ctx.organization.id, deviceId);
  } catch (error) {
    if (error instanceof AppError && error.statusCode === 404) {
      notFound();
    }
    throw error;
  }
  const device = detail.device;
  const canManage = can(ctx.membership.role, 'device.manage');
  const base = `/app/${ctx.organization.slug}`;
  const lifecyclePath = `/api/v1/organizations/${ctx.organization.slug}/devices/${device.id}/lifecycle`;

  return (
    <>
      <div className="page-header">
        <div>
          <p className="eyebrow">
            <Link href={`${base}/devices`}>Devices</Link>
          </p>
          <h1>{device.name}</h1>
          <p className="small muted" style={{ marginTop: '0.35rem' }}>
            <span className="mono">{device.hardwareId}</span> · {device.keyAlgorithm} · registered{' '}
            {formatTimestamp(device.createdAt)}
          </p>
        </div>
        <div className="row" style={{ gap: '0.4rem' }}>
          <span className={`badge ${STATUS_BADGES[device.status] ?? ''}`}>
            {device.status.toLowerCase()}
          </span>
          <span className={`badge ${TRUST_BADGES[device.trustState] ?? ''}`}>
            {device.trustState.toLowerCase()} · {device.trustScore}
          </span>
        </div>
      </div>

      {device.trust.reasons.length > 0 ? (
        <div className="note" style={{ marginBottom: '1.25rem' }}>
          <p className="small" style={{ margin: 0 }}>
            <strong>Why this score:</strong> {device.trust.reasons.join(' · ')}
          </p>
        </div>
      ) : null}

      <section className="card">
        <h2>Identity and posture</h2>
        <dl className="detail-grid">
          <div>
            <dt>Management</dt>
            <dd>{device.managed ? 'Managed' : 'Unmanaged'}</dd>
          </div>
          <div>
            <dt>Attestation</dt>
            <dd>
              {device.attestationKind.toLowerCase()}
              {device.attestationVerified ? ' · verified' : ' · unverified'}
            </dd>
          </div>
          <div>
            <dt>Operating system</dt>
            <dd>
              {device.os ?? '—'}
              {device.osVersion ? ` ${device.osVersion}` : ''}
            </dd>
          </div>
          <div>
            <dt>Posture fresh until</dt>
            <dd>{device.trust.postureFresh ? formatTimestamp(device.trust.expiresAt) : 'stale'}</dd>
          </div>
          <div>
            <dt>Passing checks</dt>
            <dd>{device.trust.passedChecks.length}</dd>
          </div>
          <div>
            <dt>Failing checks</dt>
            <dd>
              {device.trust.failingChecks.length > 0
                ? device.trust.failingChecks.join(', ')
                : 'none'}
            </dd>
          </div>
          <div>
            <dt>Unknown checks</dt>
            <dd>
              {device.trust.unknownChecks.length > 0
                ? device.trust.unknownChecks.join(', ')
                : 'none'}
            </dd>
          </div>
          <div>
            <dt>Last seen</dt>
            <dd>{formatTimestamp(device.lastSeenAt)}</dd>
          </div>
        </dl>
      </section>

      <section className="card" style={{ marginTop: '1.5rem' }}>
        <h2>Posture reports</h2>
        {detail.postureReports.length === 0 ? (
          <p className="small muted">
            No posture report has been submitted. A device without a report stays unknown and policy
            that requires a fresh report will deny it.
          </p>
        ) : (
          <div className="stack">
            {detail.postureReports.map((report) => (
              <div key={report.id} className="note">
                <div className="row" style={{ justifyContent: 'space-between' }}>
                  <span className="small">
                    Collected {formatTimestamp(report.collectedAt)} · expires{' '}
                    {formatTimestamp(report.expiresAt)}
                  </span>
                  <span className="row" style={{ gap: '0.35rem' }}>
                    <span className="badge info">{report.source.toLowerCase()}</span>
                    <span className={`badge ${report.signatureVerified ? 'success' : 'medium'}`}>
                      {report.signatureVerified ? 'signature verified' : 'unsigned'}
                    </span>
                  </span>
                </div>
                <table className="data-table" style={{ marginTop: '0.5rem' }}>
                  <thead>
                    <tr>
                      <th>Check</th>
                      <th>Result</th>
                      <th>Detail</th>
                    </tr>
                  </thead>
                  <tbody>
                    {report.checks.map((check) => (
                      <tr key={check.id}>
                        <td className="mono small">{check.id}</td>
                        <td>
                          <span className={`badge ${CHECK_BADGES[check.status] ?? ''}`}>
                            {check.status.toLowerCase()}
                          </span>
                        </td>
                        <td className="small muted">{check.detail ?? '—'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ))}
          </div>
        )}
      </section>

      {detail.enforcementActions.length > 0 ? (
        <section className="card" style={{ marginTop: '1.5rem' }}>
          <h2>Enforcement history</h2>
          <table className="data-table">
            <thead>
              <tr>
                <th>Action</th>
                <th>Kind</th>
                <th>State</th>
                <th>Requested</th>
              </tr>
            </thead>
            <tbody>
              {detail.enforcementActions.map((action) => (
                <tr key={action.id}>
                  <td>
                    <Link href={`${base}/enforcement/${action.id}`}>{action.targetLabel}</Link>
                  </td>
                  <td className="small">{action.kind.replaceAll('_', ' ').toLowerCase()}</td>
                  <td>
                    <span className="badge">{action.state.toLowerCase()}</span>
                  </td>
                  <td className="small">{formatTimestamp(action.createdAt)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      ) : null}

      {canManage ? (
        <>
          <section className="card" style={{ marginTop: '1.5rem' }}>
            <h2>Lifecycle</h2>
            <p className="small muted">
              Suspending a device blocks new admissions without deleting its history. Retirement is
              terminal and requires a reason; both are recorded in the audit trail with the operator
              who made the change.
            </p>
            <div className="row" style={{ gap: '0.75rem', flexWrap: 'wrap' }}>
              {device.status !== 'ACTIVE' && device.status !== 'RETIRED' ? (
                <ActionButton
                  action={lifecyclePath}
                  body={{ action: 'activate' }}
                  label="Activate"
                  variant="primary"
                />
              ) : null}
              {device.status === 'ACTIVE' ? (
                <ActionButton
                  action={lifecyclePath}
                  body={{ action: 'suspend', reason: 'Suspended from the device console.' }}
                  label="Suspend"
                  confirmText="Suspend this device? New admissions will be denied."
                  variant="secondary"
                />
              ) : null}
              {device.status !== 'RETIRED' ? (
                <ActionButton
                  action={lifecyclePath}
                  body={{ action: 'retire', reason: 'Retired from the device console.' }}
                  label="Retire"
                  confirmText="Retire this device? This is terminal and its records become read-only."
                  variant="danger"
                />
              ) : null}
            </div>
          </section>

          <section className="card" style={{ marginTop: '1.5rem' }}>
            <h2>Edit device</h2>
            <ActionForm
              action={`/api/v1/organizations/${ctx.organization.slug}/devices/${device.id}`}
              method="PATCH"
              submitLabel="Save changes"
              successMessage="Device updated."
              fields={[
                { name: 'name', label: 'Name', defaultValue: device.name },
                { name: 'os', label: 'Operating system', defaultValue: device.os ?? '' },
                { name: 'osVersion', label: 'OS version', defaultValue: device.osVersion ?? '' },
                {
                  name: 'managed',
                  label: 'Managed by an agent',
                  type: 'checkbox',
                  defaultValue: device.managed ? 'true' : 'false',
                },
                {
                  name: 'publicKey',
                  label: 'Replace public key',
                  type: 'textarea',
                  full: true,
                  help: 'Leave blank to keep the current key. Replacing it invalidates reports signed with the old key.',
                },
              ]}
            />
          </section>

          <details className="card" style={{ marginTop: '1.5rem' }}>
            <summary>
              <strong>Submit a posture report</strong>
            </summary>
            <p className="small muted">
              Operators normally never submit posture by hand; the managed agent does, signed with
              the device key. This form exists for lab devices whose agent is not yet installed, and
              records the report as manual so it is distinguishable in the audit trail.
            </p>
            <p className="small muted">
              <strong>A report only raises trust when it is signed.</strong> Without a signature the
              report is stored and audited, but the device stays unknown, because an unauthenticated
              claim of compliance is worth nothing to policy. Sign the canonical payload —{' '}
              <span className="mono">{`{ deviceId, collectedAt, checks: [{ id, status, detail? }] }`}</span>{' '}
              with <span className="mono">collectedAt</span> as an ISO timestamp — using the device
              private key and paste the base64 signature below.
            </p>
            <ActionForm
              action={`/api/v1/organizations/${ctx.organization.slug}/devices/${device.id}/posture`}
              submitLabel="Record report"
              successMessage="Posture recorded and trust recomputed."
              resetOnSuccess
              fields={[
                {
                  name: 'collectedAt',
                  label: 'Collected at',
                  type: 'datetime-local',
                  required: true,
                },
                {
                  name: 'ttlSeconds',
                  label: 'Validity (seconds)',
                  type: 'number',
                  placeholder: '86400',
                  help: 'Between 300 and 604800. Defaults to 24 hours.',
                },
                {
                  name: 'checks',
                  label: 'Checks',
                  type: 'json',
                  required: true,
                  full: true,
                  placeholder: '[{"id":"disk_encryption","status":"PASS"}]',
                  help: 'JSON array of { id, status, detail? } with status PASS, FAIL or UNKNOWN.',
                },
                {
                  name: 'signature',
                  label: 'Signature (base64)',
                  type: 'textarea',
                  rows: 3,
                  full: true,
                  maxLength: 4000,
                  help: 'Optional. Required for the report to affect trust; must verify against the key registered for this device.',
                },
              ]}
            />
          </details>
        </>
      ) : null}
    </>
  );
}
