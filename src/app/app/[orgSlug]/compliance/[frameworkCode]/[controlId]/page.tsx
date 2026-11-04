import type { Metadata } from 'next';
import Link from 'next/link';
import { notFound } from 'next/navigation';
import { ActionButton } from '@/components/action-button';
import { ActionForm } from '@/components/action-form';
import { EvidenceForm } from '@/components/compliance/evidence-form';
import { can } from '@/server/authz/roles';
import { CONTROL_STATUSES } from '@/server/domain/compliance';
import { getFrameworkDetail, listComplianceFormOptions } from '@/server/services/compliance';
import { loadTenantContext } from '@/server/ui/session';

export const dynamic = 'force-dynamic';

const STATUS_TONE: Record<string, string> = {
  IMPLEMENTED: 'success',
  PARTIAL: 'medium',
  IN_PROGRESS: 'info',
  NOT_STARTED: 'low',
  NOT_APPLICABLE: '',
};

function formatDate(value: Date | null): string {
  return value ? value.toISOString().slice(0, 10) : '—';
}

export async function generateMetadata({
  params,
}: {
  params: Promise<{ frameworkCode: string }>;
}): Promise<Metadata> {
  const { frameworkCode } = await params;
  return { title: `Control · ${frameworkCode.toUpperCase()} · CyberNorf` };
}

export default async function ControlDetailPage({
  params,
}: {
  params: Promise<{ orgSlug: string; frameworkCode: string; controlId: string }>;
}) {
  const { orgSlug, frameworkCode, controlId } = await params;
  const ctx = await loadTenantContext(orgSlug, 'compliance.read');
  if (!ctx) {
    notFound();
  }

  const detail = await getFrameworkDetail(ctx, frameworkCode);
  const control = detail.controls.find((entry) => entry.organizationControlId === controlId);
  if (!control || !control.organizationControlId) {
    notFound();
  }

  const options = await listComplianceFormOptions(ctx.organization.id);
  const base = `/app/${ctx.organization.slug}`;
  const endpoint = `/api/v1/organizations/${ctx.organization.slug}/compliance`;
  const frameworkHref = `${base}/compliance/${detail.framework.code}`;

  const canManage = can(ctx.membership.role, 'compliance.manage');
  const canAttachEvidence = can(ctx.membership.role, 'compliance.evidence');
  const status = control.status ?? 'NOT_STARTED';

  return (
    <>
      <p className="small muted">
        <Link href={`${base}/compliance`}>Compliance</Link> /{' '}
        <Link href={frameworkHref}>{detail.framework.code}</Link> / {control.code}
      </p>

      <div className="page-header">
        <div>
          <p className="eyebrow">{detail.framework.name}</p>
          <h1>
            <span className="mono">{control.code}</span> · {control.title}
          </h1>
          <p className="small muted" style={{ marginTop: '0.35rem' }}>
            {control.category ?? 'Uncategorised'} · weight {control.weight}
          </p>
        </div>
        <span className={`badge ${STATUS_TONE[status] ?? 'low'}`}>
          {status.replaceAll('_', ' ')}
        </span>
      </div>

      {control.description ? (
        <p className="small" style={{ maxWidth: '52rem' }}>
          {control.description}
        </p>
      ) : null}

      {control.evidenceGap ? (
        <p className="banner warning">
          This control is {status.replaceAll('_', ' ').toLowerCase()} with no evidence attached. Add
          evidence below or step the status back.
        </p>
      ) : null}

      <div
        className="grid"
        style={{
          marginTop: '1.25rem',
          gridTemplateColumns: 'repeat(auto-fit, minmax(16rem, 1fr))',
        }}
      >
        <section className="card">
          <h2>Attestation</h2>
          <dl className="detail-grid">
            <dt>Owner</dt>
            <dd>{control.owner?.name ?? 'Unassigned'}</dd>
            <dt>Last reviewed</dt>
            <dd>{formatDate(control.lastReviewedAt)}</dd>
            <dt>Next review</dt>
            <dd>{formatDate(control.nextReviewAt)}</dd>
            <dt>Evidence</dt>
            <dd>{control.evidenceCount}</dd>
          </dl>
        </section>

        <section className="card" style={{ gridColumn: 'span 2' }}>
          <h2>Notes</h2>
          <p className="small" style={{ whiteSpace: 'pre-wrap' }}>
            {control.notes ?? 'No notes recorded.'}
          </p>
        </section>
      </div>

      <section className="card stack" style={{ marginTop: '1.5rem' }}>
        <h2>Evidence</h2>
        <p className="small muted">
          Evidence must point at a record inside this organization. Marking the control implemented
          requires at least one entry.
        </p>
        {control.evidence.length === 0 ? (
          <p className="small muted">Nothing attached yet.</p>
        ) : (
          <table className="data-table">
            <thead>
              <tr>
                <th>Type</th>
                <th>Target</th>
                <th>Note</th>
                <th>Added</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {control.evidence.map((evidence) => (
                <tr key={evidence.id}>
                  <td className="small">{evidence.kind}</td>
                  <td className="small">
                    {evidence.finding ? (
                      <Link href={`${base}/findings/${evidence.finding.id}`} className="small">
                        {evidence.finding.title}
                      </Link>
                    ) : evidence.incident ? (
                      <Link href={`${base}/incidents/${evidence.incident.id}`}>
                        {evidence.incident.title}
                      </Link>
                    ) : evidence.asset ? (
                      `${evidence.asset.name} (${evidence.asset.identifier})`
                    ) : (
                      <span className="mono">{evidence.reference}</span>
                    )}
                  </td>
                  <td className="small">{evidence.note ?? '—'}</td>
                  <td className="small">
                    {formatDate(evidence.createdAt)}
                    <div className="small muted">{evidence.createdBy?.name ?? 'system'}</div>
                  </td>
                  <td>
                    {canAttachEvidence ? (
                      <ActionButton
                        action={`${endpoint}/evidence/${evidence.id}`}
                        method="DELETE"
                        label="Remove"
                        variant="secondary"
                        confirmText="Remove this evidence from the control?"
                        successMessage="Evidence removed."
                      />
                    ) : null}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}

        {canAttachEvidence ? (
          <EvidenceForm
            action={`${endpoint}/controls/${control.organizationControlId}/evidence`}
            options={options}
          />
        ) : (
          <p className="small muted">Your role can read compliance data but not attach evidence.</p>
        )}
      </section>

      {canManage ? (
        <section className="card stack" style={{ marginTop: '1.5rem', maxWidth: '44rem' }}>
          <h2>Update attestation</h2>
          <ActionForm
            action={`${endpoint}/controls/${control.organizationControlId}`}
            method="PATCH"
            fields={[
              {
                name: 'status',
                label: 'Status',
                type: 'select',
                defaultValue: status,
                options: CONTROL_STATUSES.map((entry) => ({
                  value: entry,
                  label: entry.replaceAll('_', ' '),
                })),
              },
              {
                name: 'ownerId',
                label: 'Owner',
                type: 'select',
                defaultValue: control.owner?.id ?? '',
                options: [
                  { value: '', label: 'Unassigned' },
                  ...options.members.map((member) => ({ value: member.id, label: member.name })),
                ],
              },
              {
                name: 'nextReviewAt',
                label: 'Next review',
                type: 'datetime-local',
                defaultValue: control.nextReviewAt
                  ? control.nextReviewAt.toISOString().slice(0, 16)
                  : '',
              },
              {
                name: 'notes',
                label: 'Notes',
                type: 'textarea',
                maxLength: 2000,
                defaultValue: control.notes ?? '',
                full: true,
                help: 'Clearing the field removes the notes for this control.',
              },
            ]}
            submitLabel="Save attestation"
            successMessage="Control updated."
          />
        </section>
      ) : null}
    </>
  );
}
