import type { Metadata } from 'next';
import Link from 'next/link';
import { notFound } from 'next/navigation';
import { ActionForm } from '@/components/action-form';
import { can } from '@/server/authz/roles';
import { DETECTION_STATUSES } from '@/server/domain/zero-trust';
import { AppError } from '@/server/errors';
import { getDetection } from '@/server/services/network';
import { loadTenantContext } from '@/server/ui/session';

export const metadata: Metadata = { title: 'Detection · CyberNorf' };
export const dynamic = 'force-dynamic';

const SEVERITY_BADGES: Record<string, string> = {
  LOW: 'low',
  MEDIUM: 'medium',
  HIGH: 'high',
  CRITICAL: 'critical',
};

export default async function DetectionPage({
  params,
}: {
  params: Promise<{ orgSlug: string; detectionId: string }>;
}) {
  const { orgSlug, detectionId } = await params;
  const ctx = await loadTenantContext(orgSlug, 'network.read');
  if (!ctx) {
    notFound();
  }

  let detection;
  try {
    detection = await getDetection(ctx.organization.id, detectionId);
  } catch (error) {
    if (error instanceof AppError && error.statusCode === 404) {
      notFound();
    }
    throw error;
  }
  const canManage = can(ctx.membership.role, 'network.manage');
  const base = `/app/${ctx.organization.slug}`;
  const observations = Object.entries(detection.observations);

  return (
    <>
      <div className="page-header">
        <div>
          <p className="eyebrow">
            <Link href={`${base}/network/detections`}>Detections</Link>
          </p>
          <h1>{detection.title}</h1>
          <p className="small muted" style={{ marginTop: '0.35rem' }}>
            {detection.ruleKey} · subject <span className="mono">{detection.subjectKey}</span>
          </p>
        </div>
        <div className="row" style={{ gap: '0.4rem' }}>
          <span className={`badge ${SEVERITY_BADGES[detection.severity] ?? ''}`}>
            {detection.severity.toLowerCase()}
          </span>
          <span className="badge">{detection.status.toLowerCase()}</span>
        </div>
      </div>

      <section className="card">
        <h2>Finding</h2>
        <p>{detection.description}</p>
        <dl className="detail-grid">
          <div>
            <dt>First seen</dt>
            <dd>{new Date(detection.firstSeenAt).toLocaleString()}</dd>
          </div>
          <div>
            <dt>Last seen</dt>
            <dd>
              {new Date(detection.lastSeenAt).toLocaleString()}
              {detection.stale ? ' (stale)' : ''}
            </dd>
          </div>
          <div>
            <dt>Evidence fresh until</dt>
            <dd>{new Date(detection.freshUntil).toLocaleString()}</dd>
          </div>
        </dl>
      </section>

      <section className="card" style={{ marginTop: '1.5rem' }}>
        <h2>Observations</h2>
        {observations.length === 0 ? (
          <p className="small muted">This detection carries no structured evidence.</p>
        ) : (
          <dl className="detail-grid">
            {observations.map(([key, value]) => (
              <div key={key}>
                <dt className="mono">{key}</dt>
                <dd className="small">
                  {typeof value === 'object' && value !== null
                    ? JSON.stringify(value)
                    : String(value)}
                </dd>
              </div>
            ))}
          </dl>
        )}
      </section>

      <section className="card" style={{ marginTop: '1.5rem' }}>
        <h2>Triage</h2>
        {canManage ? (
          <>
            <p className="small muted">
              Status changes are audited with your note. Acknowledging means someone has taken
              ownership; closing means the finding is resolved or accepted.
            </p>
            <ActionForm
              action={`/api/v1/organizations/${ctx.organization.slug}/network/detections/${detection.id}`}
              method="PATCH"
              submitLabel="Save triage"
              successMessage="Detection updated."
              fields={[
                {
                  name: 'status',
                  label: 'Status',
                  type: 'select',
                  defaultValue: detection.status,
                  options: DETECTION_STATUSES.filter((status) => status !== detection.status).map(
                    (status) => ({ value: status, label: status.toLowerCase() }),
                  ),
                },
                {
                  name: 'note',
                  label: 'Note',
                  type: 'textarea',
                  rows: 3,
                  maxLength: 500,
                  full: true,
                  help: 'Optional. Stored on the audit event, not on the detection.',
                },
              ]}
            />
          </>
        ) : (
          <p className="small muted">
            Your role can read detections but not change their status. Triage requires the network
            manage capability.
          </p>
        )}
      </section>
    </>
  );
}
