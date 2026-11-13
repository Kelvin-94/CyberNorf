import type { Metadata } from 'next';
import Link from 'next/link';
import { notFound } from 'next/navigation';
import { ActionForm } from '@/components/action-form';
import { can } from '@/server/authz/roles';
import { AppError } from '@/server/errors';
import { getEnforcementAction } from '@/server/services/enforcement';
import { loadTenantContext } from '@/server/ui/session';

export const metadata: Metadata = { title: 'Enforcement action · CyberNorf' };
export const dynamic = 'force-dynamic';

const STATE_BADGES: Record<string, string> = {
  REQUESTED: 'medium',
  APPROVED: 'info',
  REJECTED: 'low',
  DISPATCHED: 'low',
  ACKNOWLEDGED: 'info',
  VERIFIED: 'success',
  FAILED: 'critical',
  EXPIRED: 'high',
};

function renderJson(value: Record<string, unknown>): string {
  return Object.keys(value).length === 0 ? '—' : JSON.stringify(value, null, 2);
}

export default async function EnforcementActionPage({
  params,
}: {
  params: Promise<{ orgSlug: string; actionId: string }>;
}) {
  const { orgSlug, actionId } = await params;
  const ctx = await loadTenantContext(orgSlug, 'enforcement.read');
  if (!ctx) {
    notFound();
  }

  let action;
  try {
    action = await getEnforcementAction(ctx.organization.id, actionId);
  } catch (error) {
    if (error instanceof AppError && error.statusCode === 404) {
      notFound();
    }
    throw error;
  }
  const canManage = can(ctx.membership.role, 'enforcement.manage');
  const base = `/app/${ctx.organization.slug}`;
  const actionPath = `/api/v1/organizations/${ctx.organization.slug}/enforcement/${action.id}`;

  const timeline: Array<[string, string | null]> = [
    ['Requested', action.createdAt],
    ['Dispatched', action.dispatchedAt],
    ['Acknowledged', action.acknowledgedAt],
    ['Verified', action.verifiedAt],
  ];

  return (
    <>
      <div className="page-header">
        <div>
          <p className="eyebrow">
            <Link href={`${base}/enforcement`}>Enforcement</Link>
          </p>
          <h1>{action.targetLabel}</h1>
          <p className="small muted" style={{ marginTop: '0.35rem' }}>
            {action.kind.replaceAll('_', ' ').toLowerCase()} · {action.targetType}{' '}
            <span className="mono">{action.targetId}</span>
          </p>
        </div>
        <div className="row" style={{ gap: '0.4rem' }}>
          <span className={`badge ${STATE_BADGES[action.state] ?? ''}`}>
            {action.state.toLowerCase()}
          </span>
          {action.secondApproverRequired ? (
            <span className="badge high">needs approver</span>
          ) : null}
          {action.expired ? <span className="badge critical">expired</span> : null}
        </div>
      </div>

      <section className="card">
        <dl className="detail-grid">
          <div>
            <dt>Reason</dt>
            <dd>{action.reason ?? '—'}</dd>
          </div>
          <div>
            <dt>Connector</dt>
            <dd className="mono small">{action.connectorId ?? '—'}</dd>
          </div>
          <div>
            <dt>Approver</dt>
            <dd className="mono small">{action.approvedById ?? 'not approved'}</dd>
          </div>
          <div>
            <dt>Expires</dt>
            <dd>{action.expiresAt ? new Date(action.expiresAt).toLocaleString() : '—'}</dd>
          </div>
          <div>
            <dt>Idempotency key</dt>
            <dd className="mono small">{action.idempotencyKey}</dd>
          </div>
          <div>
            <dt>Rejection reason</dt>
            <dd>{action.rejectedReason ?? '—'}</dd>
          </div>
          <div>
            <dt>Failure reason</dt>
            <dd>{action.failureReason ?? '—'}</dd>
          </div>
        </dl>
      </section>

      <section className="card" style={{ marginTop: '1.5rem' }}>
        <h2>Payload and result</h2>
        <div
          className="grid"
          style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(18rem, 1fr))' }}
        >
          <div>
            <p className="small muted" style={{ marginTop: 0 }}>
              Command payload
            </p>
            <pre className="note mono small" style={{ margin: 0, overflowX: 'auto' }}>
              {renderJson(action.payload)}
            </pre>
          </div>
          <div>
            <p className="small muted" style={{ marginTop: 0 }}>
              Connector result
            </p>
            <pre className="note mono small" style={{ margin: 0, overflowX: 'auto' }}>
              {renderJson(action.result)}
            </pre>
          </div>
        </div>
      </section>

      <section className="card" style={{ marginTop: '1.5rem' }}>
        <h2>Timeline</h2>
        <dl className="detail-grid">
          {timeline.map(([label, value]) => (
            <div key={label}>
              <dt>{label}</dt>
              <dd>{value ? new Date(value).toLocaleString() : '—'}</dd>
            </div>
          ))}
        </dl>
      </section>

      {canManage && !action.terminal ? (
        <section className="card" style={{ marginTop: '1.5rem' }}>
          <h2>Operator actions</h2>
          {action.state === 'REQUESTED' ? (
            <>
              <p className="small muted">
                Approval and rejection are both refused for the operator who raised the request.
                Approval does not execute anything by itself; dispatch is a separate step.
              </p>
              <div
                className="grid"
                style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(20rem, 1fr))' }}
              >
                <ActionForm
                  action={`${actionPath}/approve`}
                  submitLabel="Approve"
                  successMessage="Approved. Dispatch it when the connector is ready."
                  confirmText={`Approve ${action.kind} on ${action.targetLabel}?`}
                  fields={[
                    {
                      name: 'note',
                      label: 'Approval note',
                      maxLength: 500,
                      full: true,
                    },
                  ]}
                />
                <ActionForm
                  action={`${actionPath}/reject`}
                  submitLabel="Reject"
                  successMessage="Rejected."
                  confirmText={`Reject ${action.kind} on ${action.targetLabel}?`}
                  fields={[
                    {
                      name: 'reason',
                      label: 'Rejection reason',
                      type: 'textarea',
                      rows: 3,
                      required: true,
                      maxLength: 500,
                      full: true,
                    },
                  ]}
                />
              </div>
            </>
          ) : null}

          {action.state === 'APPROVED' ? (
            <>
              <p className="small muted">
                Dispatch hands the command to the connector. Acknowledgement and verification come
                back over the connector&apos;s own authenticated channel, so this page will show
                those states only after the connector reports them.
              </p>
              <ActionForm
                action={`${actionPath}/dispatch`}
                fields={[]}
                compact
                submitLabel="Dispatch"
                successMessage="Dispatched to the connector."
                confirmText={`Dispatch ${action.kind} on ${action.targetLabel} now?`}
              />
            </>
          ) : null}

          {action.state !== 'REQUESTED' && action.state !== 'APPROVED' ? (
            <p className="small muted">
              This action is waiting on the connector. Nothing further is required from an operator.
            </p>
          ) : null}
        </section>
      ) : null}
    </>
  );
}
