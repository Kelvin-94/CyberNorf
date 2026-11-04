import type { Metadata } from 'next';
import Link from 'next/link';
import { notFound } from 'next/navigation';
import { ActionForm } from '@/components/action-form';
import { can } from '@/server/authz/roles';
import { getComplianceOverview } from '@/server/services/compliance';
import { loadTenantContext } from '@/server/ui/session';

export const metadata: Metadata = { title: 'Compliance · CyberNorf' };
export const dynamic = 'force-dynamic';

const BAND_TONE: Record<string, string> = {
  READY: 'success',
  PROGRESSING: 'info',
  AT_RISK: 'high',
  NOT_ASSESSED: 'low',
};

function formatDate(value: Date | null): string {
  return value ? value.toISOString().slice(0, 10) : '—';
}

export default async function CompliancePage({ params }: { params: Promise<{ orgSlug: string }> }) {
  const { orgSlug } = await params;
  const ctx = await loadTenantContext(orgSlug, 'compliance.read');
  if (!ctx) {
    notFound();
  }

  const overview = await getComplianceOverview(ctx);
  const base = `/app/${ctx.organization.slug}`;
  const endpoint = `/api/v1/organizations/${ctx.organization.slug}/compliance`;
  const canManage = can(ctx.membership.role, 'compliance.manage');
  const available = overview.frameworks.filter((framework) => !framework.adopted);
  const posture = overview.posture;

  return (
    <>
      <div className="page-header">
        <div>
          <p className="eyebrow">Governance</p>
          <h1>Compliance</h1>
          <p className="small muted" style={{ marginTop: '0.35rem' }}>
            {overview.adopted} of {overview.frameworks.length} frameworks adopted ·{' '}
            {posture ? `${posture.score}% weighted posture` : 'no framework adopted yet'}
          </p>
        </div>
      </div>

      <div className="grid">
        <div className="stat">
          <p className="stat-label">Weighted posture</p>
          <p className="stat-value">{posture ? `${posture.score}%` : '—'}</p>
          <p className="small muted">
            {posture
              ? `${posture.band.replaceAll('_', ' ')} · ${posture.counts.IMPLEMENTED}/${posture.total} implemented`
              : 'Adopt a framework to start scoring'}
          </p>
        </div>
        <div className="stat">
          <p className="stat-label">Open critical / high findings</p>
          <p className="stat-value">
            {overview.riskSignals.openCriticalFindings} / {overview.riskSignals.openHighFindings}
          </p>
          <p className="small muted">Evidence candidates for control coverage</p>
        </div>
        <div className="stat">
          <p className="stat-label">Controls due for review</p>
          <p className="stat-value">{overview.riskSignals.controlsDueForReview}</p>
          <p className="small muted">Past their scheduled review date</p>
        </div>
        <div className="stat">
          <p className="stat-label">Evidence gaps</p>
          <p className="stat-value">{overview.integrityWarnings.length}</p>
          <p className="small muted">Attested controls without evidence</p>
        </div>
      </div>

      {overview.integrityWarnings.length > 0 ? (
        <section className="card stack" style={{ marginTop: '1.5rem' }}>
          <h2>Attestations without evidence</h2>
          <p className="small muted">
            These controls are marked implemented or partial while nothing backs them up. Add
            evidence or step the status back.
          </p>
          <ul className="small">
            {overview.integrityWarnings.map((warning) => (
              <li key={warning.organizationControlId}>
                <Link
                  href={`${base}/compliance/${warning.frameworkCode}/${warning.organizationControlId}`}
                >
                  {warning.frameworkCode} · {warning.controlCode}
                </Link>{' '}
                — {warning.message}
              </li>
            ))}
          </ul>
        </section>
      ) : null}

      <section className="card stack" style={{ marginTop: '1.5rem' }}>
        <h2>Frameworks</h2>
        <table className="data-table">
          <thead>
            <tr>
              <th>Framework</th>
              <th>Controls</th>
              <th>Posture</th>
              <th>Adopted</th>
              <th>Target date</th>
            </tr>
          </thead>
          <tbody>
            {overview.frameworks.map((framework) => (
              <tr key={framework.id}>
                <td>
                  <Link href={`${base}/compliance/${framework.code}`}>{framework.name}</Link>
                  <div className="small muted mono">
                    {framework.code} · {framework.version}
                  </div>
                </td>
                <td className="small">
                  {framework.controlCount} controls · weight {framework.totalWeight}
                </td>
                <td className="small">
                  {framework.posture ? (
                    <>
                      <span className={`badge ${BAND_TONE[framework.posture.band] ?? 'low'}`}>
                        {framework.posture.score}%
                      </span>{' '}
                      <span className="muted">
                        {framework.posture.band.replaceAll('_', ' ').toLowerCase()}
                      </span>
                    </>
                  ) : (
                    <span className="badge low">Not adopted</span>
                  )}
                </td>
                <td className="small">{formatDate(framework.adoptedAt)}</td>
                <td className="small">{formatDate(framework.targetDate)}</td>
              </tr>
            ))}
          </tbody>
        </table>
        <p className="small muted">{overview.catalogNotice}</p>
      </section>

      {canManage && available.length > 0 ? (
        <section className="card stack" style={{ marginTop: '1.5rem', maxWidth: '40rem' }}>
          <h2>Adopt a framework</h2>
          <p className="small muted">
            Adoption creates one attestation row per control at <code>NOT_STARTED</code> and can be
            withdrawn later while no evidence is attached.
          </p>
          <ActionForm
            action={`${endpoint}/frameworks`}
            fields={[
              {
                name: 'frameworkId',
                label: 'Framework',
                type: 'select',
                options: available.map((framework) => ({
                  value: framework.id,
                  label: `${framework.name} (${framework.code})`,
                })),
              },
              {
                name: 'targetDate',
                label: 'Target audit date',
                type: 'date',
                help: 'Optional deadline for the readiness review.',
              },
            ]}
            submitLabel="Adopt framework"
            successMessage="Framework adopted."
          />
        </section>
      ) : null}
    </>
  );
}
