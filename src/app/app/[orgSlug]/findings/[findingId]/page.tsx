import type { Metadata } from 'next';
import Link from 'next/link';
import { notFound } from 'next/navigation';
import { ActionButton } from '@/components/action-button';
import { ActionForm } from '@/components/action-form';
import { StatusControl } from '@/components/status-control';
import { can } from '@/server/authz/roles';
import { allowedFindingTransitions } from '@/server/domain/transitions';
import { AppError } from '@/server/errors';
import { getFindingDetail, listFindingFormOptions } from '@/server/services/findings';
import { loadTenantContext } from '@/server/ui/session';

export const metadata: Metadata = { title: 'Finding · CyberNorf' };
export const dynamic = 'force-dynamic';

const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];

export default async function FindingDetailPage({
  params,
}: {
  params: Promise<{ orgSlug: string; findingId: string }>;
}) {
  const { orgSlug, findingId } = await params;
  const ctx = await loadTenantContext(orgSlug, 'finding.read');
  if (!ctx) {
    notFound();
  }

  let finding;
  try {
    finding = await getFindingDetail(ctx, findingId);
  } catch (error) {
    if (error instanceof AppError && error.statusCode === 404) {
      notFound();
    }
    throw error;
  }

  const options = can(ctx.membership.role, 'finding.update')
    ? await listFindingFormOptions(ctx.organization.id)
    : null;

  const base = `/app/${ctx.organization.slug}`;
  const endpoint = `/api/v1/organizations/${ctx.organization.slug}/findings/${finding.id}`;
  const transitions = allowedFindingTransitions(finding.status);

  return (
    <>
      <p className="small muted">
        <Link href={`${base}/findings`}>← Findings</Link>
      </p>

      <div className="page-header">
        <div>
          <p className="eyebrow">
            {finding.agent
              ? `${finding.source} · raised by ${finding.agent.name}`
              : `${finding.source} · ${finding.cveId ?? 'No CVE'}`}
          </p>
          <h1>{finding.title}</h1>
        </div>
        <div className="row">
          <span className={`badge ${finding.severity.toLowerCase()}`}>{finding.severity}</span>
          <span className="badge">{finding.status.replaceAll('_', ' ')}</span>
        </div>
      </div>

      <section className="card">
        <dl className="detail-grid">
          <div>
            <dt>Asset</dt>
            <dd>
              {finding.asset ? (
                <Link href={`${base}/assets/${finding.asset.id}`}>
                  {finding.asset.name}{' '}
                  <span className="mono muted">({finding.asset.identifier})</span>
                </Link>
              ) : (
                '—'
              )}
            </dd>
          </div>
          <div>
            <dt>Owner</dt>
            <dd>{finding.assignedTo?.name ?? 'Unassigned'}</dd>
          </div>
          <div>
            <dt>CVSS</dt>
            <dd>{finding.cvssScore === null ? '—' : finding.cvssScore.toFixed(1)}</dd>
          </div>
          <div>
            <dt>Incident</dt>
            <dd>
              {finding.incident ? (
                <Link href={`${base}/incidents/${finding.incident.id}`}>
                  {finding.incident.title}
                </Link>
              ) : (
                '—'
              )}
            </dd>
          </div>
          <div>
            <dt>First seen</dt>
            <dd>{finding.firstSeenAt.toISOString().slice(0, 16).replace('T', ' ')}</dd>
          </div>
          <div>
            <dt>Last seen</dt>
            <dd>{finding.lastSeenAt.toISOString().slice(0, 16).replace('T', ' ')}</dd>
          </div>
          <div>
            <dt>Reported by</dt>
            <dd>
              {finding.agent ? (
                <>
                  <Link href={`${base}/agents/${finding.agent.id}`}>{finding.agent.name}</Link>{' '}
                  <span className="muted small">
                    (agent, registered by {finding.createdBy.name})
                  </span>
                </>
              ) : (
                finding.createdBy.name
              )}
            </dd>
          </div>
          <div>
            <dt>Resolved</dt>
            <dd>
              {finding.resolvedAt
                ? finding.resolvedAt.toISOString().slice(0, 16).replace('T', ' ')
                : '—'}
            </dd>
          </div>
        </dl>
      </section>

      <section className="card" style={{ marginTop: '1.5rem' }}>
        <h2>Description</h2>
        <p style={{ whiteSpace: 'pre-wrap' }}>
          {finding.description ?? 'No description recorded.'}
        </p>
        <h2 style={{ marginTop: '1.25rem' }}>Remediation</h2>
        <p style={{ whiteSpace: 'pre-wrap' }}>
          {finding.remediation ?? 'No remediation guidance recorded.'}
        </p>
      </section>

      {can(ctx.membership.role, 'finding.update') ? (
        <section className="card stack" style={{ marginTop: '1.5rem', maxWidth: '44rem' }}>
          <h2>Update status</h2>
          <StatusControl
            action={`${endpoint}/status`}
            current={finding.status}
            transitions={[...transitions]}
            withNote
          />
        </section>
      ) : null}

      {options ? (
        <section className="card stack" style={{ marginTop: '1.5rem', maxWidth: '44rem' }}>
          <h2>Edit finding</h2>
          <ActionForm
            action={endpoint}
            method="PATCH"
            fields={[
              {
                name: 'title',
                label: 'Title',
                defaultValue: finding.title,
                required: true,
                maxLength: 200,
                full: true,
              },
              {
                name: 'severity',
                label: 'Severity',
                type: 'select',
                defaultValue: finding.severity,
                options: SEVERITIES.map((severity) => ({ value: severity, label: severity })),
              },
              {
                name: 'assetId',
                label: 'Asset',
                type: 'select',
                defaultValue: finding.asset?.id ?? '',
                options: [
                  { value: '', label: 'No asset' },
                  ...options.assets.map((asset) => ({
                    value: asset.id,
                    label: `${asset.name} (${asset.identifier})`,
                  })),
                ],
              },
              {
                name: 'assignedToId',
                label: 'Owner',
                type: 'select',
                defaultValue: finding.assignedTo?.id ?? '',
                options: [
                  { value: '', label: 'Unassigned' },
                  ...options.members.map((member) => ({
                    value: member.id,
                    label: `${member.name} <${member.email}>`,
                  })),
                ],
              },
              {
                name: 'incidentId',
                label: 'Incident',
                type: 'select',
                defaultValue: finding.incident?.id ?? '',
                options: [
                  { value: '', label: 'Not linked' },
                  ...options.incidents.map((incident) => ({
                    value: incident.id,
                    label: incident.title,
                  })),
                ],
              },
              {
                name: 'cveId',
                label: 'CVE',
                defaultValue: finding.cveId ?? '',
                placeholder: 'CVE-2026-12345',
              },
              {
                name: 'cvssScore',
                label: 'CVSS score',
                type: 'number',
                min: 0,
                max: 10,
                step: 0.1,
                defaultValue: finding.cvssScore === null ? '' : String(finding.cvssScore),
              },
              {
                name: 'description',
                label: 'Description',
                type: 'textarea',
                defaultValue: finding.description ?? '',
                maxLength: 5000,
                full: true,
              },
              {
                name: 'remediation',
                label: 'Remediation',
                type: 'textarea',
                defaultValue: finding.remediation ?? '',
                maxLength: 5000,
                full: true,
              },
            ]}
            submitLabel="Save changes"
            successMessage="Finding updated."
          />
        </section>
      ) : null}

      <section className="card" style={{ marginTop: '1.5rem' }}>
        <h2>History</h2>
        <p className="small muted">
          Derived from the append-only audit trail for this finding. Entries cannot be edited or
          removed.
        </p>
        {finding.history.length === 0 ? (
          <p className="small muted">No audit entries recorded yet.</p>
        ) : (
          <table className="data-table">
            <thead>
              <tr>
                <th>When</th>
                <th>Action</th>
                <th>Outcome</th>
                <th>Actor</th>
                <th>Summary</th>
              </tr>
            </thead>
            <tbody>
              {finding.history.map((event) => (
                <tr key={event.id}>
                  <td className="mono small">
                    {event.createdAt.toISOString().slice(0, 16).replace('T', ' ')}
                  </td>
                  <td className="mono small">{event.action}</td>
                  <td className="small">{event.outcome}</td>
                  <td className="small">{event.actor?.name ?? event.actorType}</td>
                  <td className="small">{event.summary}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>

      {can(ctx.membership.role, 'finding.delete') ? (
        <section className="card stack" style={{ marginTop: '1.5rem', maxWidth: '44rem' }}>
          <h2>Delete finding</h2>
          <ActionButton
            action={endpoint}
            method="DELETE"
            label="Delete finding"
            variant="danger"
            confirmText="Delete this finding permanently?"
            redirectTo={`${base}/findings`}
          />
        </section>
      ) : null}
    </>
  );
}
