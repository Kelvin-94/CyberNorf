import type { Metadata } from 'next';
import Link from 'next/link';
import { notFound } from 'next/navigation';
import { ActionButton } from '@/components/action-button';
import { ReviewDecisionControl } from '@/components/access-reviews/review-decision';
import { can } from '@/server/authz/roles';
import { getAccessReviewDetail } from '@/server/services/access-reviews';
import { loadTenantContext } from '@/server/ui/session';

export const metadata: Metadata = { title: 'Access review · CyberNorf' };
export const dynamic = 'force-dynamic';

const STATUS_BADGES: Record<string, string> = {
  ACTIVE: 'medium',
  COMPLETED: 'success',
  CANCELLED: 'low',
};

const DECISION_BADGES: Record<string, string> = {
  PENDING: 'medium',
  RETAIN: 'success',
  REVOKE: 'denied',
};

function formatDate(value: string | null): string {
  return value ? new Date(value).toLocaleString() : '—';
}

export default async function AccessReviewDetailPage({
  params,
}: {
  params: Promise<{ orgSlug: string; reviewId: string }>;
}) {
  const { orgSlug, reviewId } = await params;
  const ctx = await loadTenantContext(orgSlug, 'access_review.read');
  if (!ctx) {
    notFound();
  }

  const review = await getAccessReviewDetail(ctx.organization.id, reviewId);
  const base = `/app/${ctx.organization.slug}`;
  const apiBase = `/api/v1/organizations/${ctx.organization.slug}/access-reviews/${review.id}`;
  const canManage = can(ctx.membership.role, 'access_review.manage');
  const isActive = review.status === 'ACTIVE';

  return (
    <>
      <div className="page-header">
        <div>
          <p className="eyebrow">
            <Link href={`${base}/access-reviews`}>Access reviews</Link> /{' '}
            {review.status.toLowerCase()}
          </p>
          <h1>{review.title}</h1>
          <p className="small muted" style={{ marginTop: '0.35rem' }}>
            <span className={`badge ${STATUS_BADGES[review.status] ?? ''}`}>
              {review.status.toLowerCase()}
            </span>{' '}
            Due {formatDate(review.dueAt)} · opened by {review.createdBy.name}
            {review.overdue ? ' · past due' : ''}
          </p>
        </div>
      </div>

      {review.description ? <p className="small">{review.description}</p> : null}

      <div className="grid">
        <div className="stat">
          <p className="stat-label">Decided</p>
          <p className="stat-value">
            {review.progress.decided} / {review.progress.total}
          </p>
          <p className="small muted">{review.progress.pending} still pending</p>
        </div>
        <div className="stat">
          <p className="stat-label">Retain</p>
          <p className="stat-value">{review.progress.retain}</p>
          <p className="small muted">Access confirmed</p>
        </div>
        <div className="stat">
          <p className="stat-label">Revoke</p>
          <p className="stat-value">{review.progress.revoke}</p>
          <p className="small muted">Removed on completion</p>
        </div>
        <div className="stat">
          <p className="stat-label">Opened</p>
          <p className="stat-value small">{formatDate(review.createdAt)}</p>
          <p className="small muted">
            {review.completedAt
              ? `Completed ${formatDate(review.completedAt)}`
              : review.cancelledAt
                ? `Cancelled ${formatDate(review.cancelledAt)}`
                : 'In progress'}
          </p>
        </div>
      </div>

      {canManage && isActive ? (
        <section className="card" style={{ marginTop: '1.5rem' }}>
          <h2>Close the review</h2>
          {review.progress.pending > 0 ? (
            <p className="banner warning">
              {review.progress.pending} member(s) still need a decision. The review cannot be
              completed until every item is decided.
            </p>
          ) : (
            <p className="small muted">
              Completing the review disables the memberships marked for revocation, drops their
              sessions when no other active membership remains, and suspends linked human
              identities. The last active owner cannot be removed.
            </p>
          )}
          <div className="row" style={{ gap: '0.5rem', flexWrap: 'wrap' }}>
            {review.progress.pending === 0 ? (
              <ActionButton
                action={`${apiBase}/finalize`}
                label="Complete review"
                confirmText={`Complete "${review.title}" and apply ${review.progress.revoke} revocation(s)? This cannot be undone.`}
                successMessage="Access review completed."
              />
            ) : null}
            <ActionButton
              action={`${apiBase}/cancel`}
              label="Cancel review"
              variant="secondary"
              confirmText="Cancel this review without applying any decisions?"
              successMessage="Access review cancelled."
            />
          </div>
        </section>
      ) : null}

      <section className="card" style={{ marginTop: '1.5rem' }}>
        <h2>Decisions</h2>
        <p className="small muted">
          Reviewers cannot decide their own access. A decision is final once recorded; only an
          administrator can open a new review to revisit it.
        </p>
        <table className="data-table">
          <thead>
            <tr>
              <th>Member</th>
              <th>Role at snapshot</th>
              <th>Current membership</th>
              <th>Decision</th>
              <th>Recorded</th>
              {canManage && isActive ? <th>Action</th> : null}
            </tr>
          </thead>
          <tbody>
            {review.items.map((item) => {
              const isSelf = item.userId === ctx.user.id;
              return (
                <tr key={item.id}>
                  <td>
                    {item.userName}
                    <div className="small muted">{item.userEmail}</div>
                  </td>
                  <td className="small">{item.roleAtReview}</td>
                  <td className="small">
                    <span
                      className={`badge ${item.membershipStatus === 'ACTIVE' ? 'success' : 'low'}`}
                    >
                      {item.membershipStatus.toLowerCase()}
                    </span>
                    {item.currentRole !== item.roleAtReview ? (
                      <div className="muted">now {item.currentRole}</div>
                    ) : null}
                  </td>
                  <td className="small">
                    <span className={`badge ${DECISION_BADGES[item.decision] ?? ''}`}>
                      {item.decision.toLowerCase()}
                    </span>
                  </td>
                  <td className="small">
                    {item.decidedAt
                      ? `${formatDate(item.decidedAt)}${item.decidedBy ? ` · ${item.decidedBy.name}` : ''}`
                      : '—'}
                    {item.note ? <div className="muted">{item.note}</div> : null}
                  </td>
                  {canManage && isActive ? (
                    <td>
                      {item.decision === 'PENDING' ? (
                        isSelf ? (
                          <span className="small muted">
                            Own access — another reviewer must decide.
                          </span>
                        ) : (
                          <ReviewDecisionControl
                            action={`${apiBase}/items/${item.id}`}
                            memberName={item.userEmail}
                          />
                        )
                      ) : (
                        <span className="small muted">Recorded</span>
                      )}
                    </td>
                  ) : null}
                </tr>
              );
            })}
          </tbody>
        </table>
      </section>
    </>
  );
}
