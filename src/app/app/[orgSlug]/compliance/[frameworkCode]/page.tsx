import type { Metadata } from 'next';
import Link from 'next/link';
import { notFound } from 'next/navigation';
import { ActionButton } from '@/components/action-button';
import { ActionForm } from '@/components/action-form';
import { can } from '@/server/authz/roles';
import { getFrameworkDetail } from '@/server/services/compliance';
import { loadTenantContext } from '@/server/ui/session';

export const dynamic = 'force-dynamic';

const BAND_TONE: Record<string, string> = {
  READY: 'success',
  PROGRESSING: 'info',
  AT_RISK: 'high',
  NOT_ASSESSED: 'low',
};

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
  return { title: `${frameworkCode.toUpperCase()} compliance · CyberNorf` };
}

export default async function FrameworkDetailPage({
  params,
}: {
  params: Promise<{ orgSlug: string; frameworkCode: string }>;
}) {
  const { orgSlug, frameworkCode } = await params;
  const ctx = await loadTenantContext(orgSlug, 'compliance.read');
  if (!ctx) {
    notFound();
  }

  const detail = await getFrameworkDetail(ctx, frameworkCode);
  const base = `/app/${ctx.organization.slug}`;
  const endpoint = `/api/v1/organizations/${ctx.organization.slug}/compliance`;
  const canManage = can(ctx.membership.role, 'compliance.manage');
  const posture = detail.posture;
  const applicableCount = posture ? posture.total - posture.counts.NOT_APPLICABLE : 0;

  return (
    <>
      <p className="small muted">
        <Link href={`${base}/compliance`}>Compliance</Link> / {detail.framework.code}
      </p>

      <div className="page-header">
        <div>
          <p className="eyebrow">Framework</p>
          <h1>{detail.framework.name}</h1>
          <p className="small muted" style={{ marginTop: '0.35rem' }}>
            {detail.framework.code} · {detail.framework.version} · {detail.framework.controlCount}{' '}
            controls · total weight {detail.framework.totalWeight}
          </p>
        </div>
        {detail.adoption ? (
          <div className="row">
            <span className={`badge ${posture ? (BAND_TONE[posture.band] ?? 'low') : 'low'}`}>
              {posture ? `${posture.score}%` : 'Not scored'}
            </span>
            {canManage ? (
              <ActionButton
                action={`${endpoint}/frameworks/${detail.framework.code}`}
                method="DELETE"
                label="Withdraw framework"
                variant="danger"
                confirmText="Withdrawing removes every control attestation for this framework. Continue?"
                successMessage="Framework withdrawn."
                redirectTo={`${base}/compliance`}
              />
            ) : null}
          </div>
        ) : null}
      </div>

      {detail.framework.description ? (
        <p className="small muted" style={{ maxWidth: '52rem' }}>
          {detail.framework.description}
        </p>
      ) : null}

      {detail.adoption ? (
        <>
          <div className="grid" style={{ marginTop: '1.25rem' }}>
            <div className="stat">
              <p className="stat-label">Weighted posture</p>
              <p className="stat-value">{posture ? `${posture.score}%` : '—'}</p>
              <p className="small muted">
                {posture ? posture.band.replaceAll('_', ' ').toLowerCase() : 'not scored'}
              </p>
            </div>
            <div className="stat">
              <p className="stat-label">Implemented</p>
              <p className="stat-value">{posture?.counts.IMPLEMENTED ?? 0}</p>
              <p className="small muted">of {applicableCount} applicable controls</p>
            </div>
            <div className="stat">
              <p className="stat-label">Partial / in progress</p>
              <p className="stat-value">
                {posture?.counts.PARTIAL ?? 0} / {posture?.counts.IN_PROGRESS ?? 0}
              </p>
              <p className="small muted">
                {posture?.counts.NOT_STARTED ?? 0} not started ·{' '}
                {posture?.counts.NOT_APPLICABLE ?? 0} not applicable
              </p>
            </div>
            <div className="stat">
              <p className="stat-label">Adopted</p>
              <p className="stat-value small">{formatDate(detail.adoption.adoptedAt)}</p>
              <p className="small muted">
                Target {formatDate(detail.adoption.targetDate)}
                {detail.adoption.adoptedBy ? ` · by ${detail.adoption.adoptedBy.name}` : ''}
              </p>
            </div>
          </div>

          {detail.integrityWarnings.length > 0 ? (
            <p className="banner warning" style={{ marginTop: '1rem' }}>
              {detail.integrityWarnings.length} attested control(s) have no evidence on record:{' '}
              {detail.integrityWarnings.map((warning) => warning.controlCode).join(', ')}.
            </p>
          ) : null}

          <section className="card stack" style={{ marginTop: '1.5rem' }}>
            <h2>Controls</h2>
            <table className="data-table">
              <thead>
                <tr>
                  <th>Control</th>
                  <th>Category</th>
                  <th>Weight</th>
                  <th>Status</th>
                  <th>Owner</th>
                  <th>Evidence</th>
                  <th>Reviewed</th>
                </tr>
              </thead>
              <tbody>
                {detail.controls.map((control) => {
                  const href = control.organizationControlId
                    ? `${base}/compliance/${detail.framework.code}/${control.organizationControlId}`
                    : null;
                  return (
                    <tr key={control.id}>
                      <td>
                        {href ? (
                          <Link href={href}>{control.code}</Link>
                        ) : (
                          <span className="mono">{control.code}</span>
                        )}
                        <div className="small muted">{control.title}</div>
                      </td>
                      <td className="small">{control.category ?? '—'}</td>
                      <td className="small">{control.weight}</td>
                      <td>
                        <span
                          className={`badge ${STATUS_TONE[control.status ?? 'NOT_STARTED'] ?? 'low'}`}
                        >
                          {(control.status ?? 'NOT_STARTED').replaceAll('_', ' ')}
                        </span>
                        {control.evidenceGap ? (
                          <div className="small muted">No evidence</div>
                        ) : null}
                      </td>
                      <td className="small">{control.owner?.name ?? 'Unassigned'}</td>
                      <td className="small">{control.evidenceCount}</td>
                      <td className="small">{formatDate(control.lastReviewedAt)}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
            <p className="small muted">{detail.catalogNotice}</p>
          </section>

          <section className="card stack" style={{ marginTop: '1.5rem' }}>
            <h2>Framework activity</h2>
            {detail.history.length === 0 ? (
              <p className="small muted">No compliance activity recorded yet.</p>
            ) : (
              <table className="data-table">
                <thead>
                  <tr>
                    <th>When</th>
                    <th>Action</th>
                    <th>Summary</th>
                    <th>Actor</th>
                  </tr>
                </thead>
                <tbody>
                  {detail.history.map((event) => (
                    <tr key={event.id}>
                      <td className="small mono">{event.createdAt.toISOString().slice(0, 19)}</td>
                      <td className="small mono">{event.action}</td>
                      <td className="small">{event.summary ?? '—'}</td>
                      <td className="small">{event.actor?.name ?? 'system'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </section>
        </>
      ) : (
        <section className="card stack" style={{ marginTop: '1.5rem', maxWidth: '40rem' }}>
          <h2>Adopt this framework</h2>
          <p className="small muted">
            The organization has not adopted {detail.framework.name} yet. There are{' '}
            {detail.framework.controlCount} controls in the catalog for it; adoption creates one
            attestation per control at NOT_STARTED.
          </p>
          {canManage ? (
            <ActionForm
              action={`${endpoint}/frameworks`}
              fields={[
                { name: 'frameworkId', type: 'hidden', defaultValue: detail.framework.id },
                {
                  name: 'targetDate',
                  label: 'Target audit date',
                  type: 'date',
                  help: 'Optional deadline for the readiness review.',
                },
              ]}
              submitLabel="Adopt framework"
              successMessage="Framework adopted."
              redirectTo={`${base}/compliance/${detail.framework.code}`}
            />
          ) : (
            <p className="banner warning">
              Your role can read compliance data but not adopt frameworks. Ask an owner or admin.
            </p>
          )}
        </section>
      )}
    </>
  );
}
