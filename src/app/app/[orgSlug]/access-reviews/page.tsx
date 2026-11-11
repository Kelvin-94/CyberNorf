import type { Metadata } from 'next';
import Link from 'next/link';
import { notFound } from 'next/navigation';
import { ActionForm } from '@/components/action-form';
import { can } from '@/server/authz/roles';
import { getAccessReviewOverview, listAccessReviews } from '@/server/services/access-reviews';
import { loadTenantContext } from '@/server/ui/session';
import { accessReviewListQuerySchema } from '@/server/validation/identities';

export const metadata: Metadata = { title: 'Access reviews · CyberNorf' };
export const dynamic = 'force-dynamic';

const STATUS_BADGES: Record<string, string> = {
  ACTIVE: 'medium',
  COMPLETED: 'success',
  CANCELLED: 'low',
};

function formatDate(value: string | null): string {
  return value ? new Date(value).toLocaleString() : '—';
}

export default async function AccessReviewsPage({
  params,
  searchParams,
}: {
  params: Promise<{ orgSlug: string }>;
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const { orgSlug } = await params;
  const ctx = await loadTenantContext(orgSlug, 'access_review.read');
  if (!ctx) {
    notFound();
  }

  const raw = await searchParams;
  const parsed = accessReviewListQuerySchema.safeParse({
    page: raw.page,
    pageSize: raw.pageSize,
    status: raw.status,
    search: raw.search,
  });
  const query = parsed.success ? parsed.data : accessReviewListQuerySchema.parse({});

  const [page, overview] = await Promise.all([
    listAccessReviews(ctx.organization.id, query),
    getAccessReviewOverview(ctx.organization.id),
  ]);
  const canManage = can(ctx.membership.role, 'access_review.manage');
  const base = `/app/${ctx.organization.slug}`;

  const pageHref = (target: number) => {
    const params = new URLSearchParams();
    if (query.status) params.set('status', query.status);
    if (query.search) params.set('search', query.search);
    params.set('page', String(target));
    return `${base}/access-reviews?${params.toString()}`;
  };

  return (
    <>
      <div className="page-header">
        <div>
          <p className="eyebrow">Identity governance</p>
          <h1>Access reviews</h1>
          <p className="small muted" style={{ marginTop: '0.35rem' }}>
            Periodic recertification of console access. A review snapshots every active membership
            when it opens; completing it removes the members marked for revocation and suspends
            their linked human identities.
          </p>
        </div>
      </div>

      <div className="grid">
        <div className="stat">
          <p className="stat-label">Open reviews</p>
          <p className="stat-value">{overview.active}</p>
          <p className="small muted">{overview.overdue} past due</p>
        </div>
        <div className="stat">
          <p className="stat-label">Completed</p>
          <p className="stat-value">{overview.completed}</p>
          <p className="small muted">Decisions applied to memberships</p>
        </div>
        <div className="stat">
          <p className="stat-label">Cancelled</p>
          <p className="stat-value">{overview.cancelled}</p>
          <p className="small muted">Closed without applying decisions</p>
        </div>
      </div>

      <section className="card">
        <div className="row" style={{ justifyContent: 'space-between', flexWrap: 'wrap' }}>
          <h2>Campaigns</h2>
          <form method="get" className="row" style={{ gap: '0.4rem' }}>
            <input
              name="search"
              defaultValue={query.search ?? ''}
              placeholder="Search title"
              aria-label="Search reviews"
            />
            <select name="status" defaultValue={query.status ?? ''} aria-label="Status">
              <option value="">All statuses</option>
              <option value="ACTIVE">Active</option>
              <option value="COMPLETED">Completed</option>
              <option value="CANCELLED">Cancelled</option>
            </select>
            <button type="submit" className="secondary">
              Filter
            </button>
          </form>
        </div>

        {page.items.length === 0 ? (
          <p className="small muted">No access reviews match this filter.</p>
        ) : (
          <table className="data-table">
            <thead>
              <tr>
                <th>Review</th>
                <th>Status</th>
                <th>Progress</th>
                <th>Due</th>
                <th>Created by</th>
              </tr>
            </thead>
            <tbody>
              {page.items.map((review) => (
                <tr key={review.id}>
                  <td>
                    <Link href={`${base}/access-reviews/${review.id}`}>{review.title}</Link>
                    {review.description ? (
                      <div className="small muted">{review.description}</div>
                    ) : null}
                  </td>
                  <td>
                    <span className={`badge ${STATUS_BADGES[review.status] ?? ''}`}>
                      {review.status.toLowerCase()}
                    </span>
                    {review.overdue ? (
                      <div className="small" style={{ color: '#ffc2c8' }}>
                        past due
                      </div>
                    ) : null}
                  </td>
                  <td className="small">
                    {review.progress.decided} / {review.progress.total} decided
                    <div className="muted">
                      {review.progress.retain} retain · {review.progress.revoke} revoke
                    </div>
                  </td>
                  <td className="small">{formatDate(review.dueAt)}</td>
                  <td className="small">{review.createdBy.name}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}

        <div className="row" style={{ justifyContent: 'space-between', marginTop: '0.75rem' }}>
          <span className="small muted">
            Page {page.pagination.page} of {page.pagination.pageCount}
          </span>
          <div className="row" style={{ gap: '0.4rem' }}>
            {page.pagination.page > 1 ? (
              <Link className="nav-link" href={pageHref(page.pagination.page - 1)}>
                Previous
              </Link>
            ) : null}
            {page.pagination.page < page.pagination.pageCount ? (
              <Link className="nav-link" href={pageHref(page.pagination.page + 1)}>
                Next
              </Link>
            ) : null}
          </div>
        </div>
      </section>

      {canManage ? (
        <section className="card" style={{ marginTop: '1.5rem', maxWidth: '46rem' }}>
          <h2>Open a review</h2>
          <p className="small muted">
            The snapshot is taken now and cannot be expanded later. Every active membership gets one
            item, and an undecided item keeps the review open.
          </p>
          <ActionForm
            action={`/api/v1/organizations/${ctx.organization.slug}/access-reviews`}
            fields={[
              { name: 'title', label: 'Title', required: true, maxLength: 120 },
              {
                name: 'dueAt',
                label: 'Due by',
                type: 'datetime-local',
                required: true,
              },
              {
                name: 'description',
                label: 'Scope and instructions',
                type: 'textarea',
                full: true,
              },
            ]}
            submitLabel="Open review"
            successMessage="Access review opened."
          />
        </section>
      ) : null}
    </>
  );
}
