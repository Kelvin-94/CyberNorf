import type { Metadata } from 'next';
import Link from 'next/link';
import { notFound } from 'next/navigation';
import { DETECTION_SEVERITIES, DETECTION_STATUSES } from '@/server/domain/zero-trust';
import { getNetworkOverview, listDetections } from '@/server/services/network';
import { loadTenantContext } from '@/server/ui/session';
import { detectionListQuerySchema } from '@/server/validation/zero-trust';

export const metadata: Metadata = { title: 'Detections · CyberNorf' };
export const dynamic = 'force-dynamic';

const SEVERITY_BADGES: Record<string, string> = {
  LOW: 'low',
  MEDIUM: 'medium',
  HIGH: 'high',
  CRITICAL: 'critical',
};

export default async function DetectionsPage({
  params,
  searchParams,
}: {
  params: Promise<{ orgSlug: string }>;
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const { orgSlug } = await params;
  const ctx = await loadTenantContext(orgSlug, 'network.read');
  if (!ctx) {
    notFound();
  }

  const raw = await searchParams;
  const parsed = detectionListQuerySchema.safeParse({
    page: raw.page,
    pageSize: raw.pageSize,
    status: raw.status,
    severity: raw.severity,
    ruleKey: raw.ruleKey,
    q: raw.q,
  });
  const query = parsed.success ? parsed.data : detectionListQuerySchema.parse({});

  const [{ detections, page }, overview] = await Promise.all([
    listDetections(ctx.organization.id, query),
    getNetworkOverview(ctx.organization.id),
  ]);
  const base = `/app/${ctx.organization.slug}`;

  const filterParams = new URLSearchParams();
  for (const [key, value] of Object.entries({
    status: query.status,
    severity: query.severity,
    ruleKey: query.ruleKey,
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
    return `${base}/network/detections?${next.toString()}`;
  };

  return (
    <>
      <div className="page-header">
        <div>
          <p className="eyebrow">
            <Link href={`${base}/network`}>Network</Link>
          </p>
          <h1>Detections</h1>
          <p className="small muted" style={{ marginTop: '0.35rem' }}>
            Findings raised from the posture and flow signals that are already in the warehouse.
            Detections are grouped by rule and subject so refresh noise collapses into one row that
            stays open until it is triaged.
          </p>
        </div>
      </div>

      <div className="grid">
        <div className="stat">
          <p className="stat-label">Open</p>
          <p className="stat-value">{overview.openDetections.total}</p>
          <p className="small muted">Across all severities</p>
        </div>
        <div className="stat">
          <p className="stat-label">Critical</p>
          <p className="stat-value">{overview.openDetections.critical}</p>
          <p className="small muted">{overview.openDetections.high} high</p>
        </div>
        <div className="stat">
          <p className="stat-label">Medium / low</p>
          <p className="stat-value">
            {overview.openDetections.medium + overview.openDetections.low}
          </p>
          <p className="small muted">
            {overview.openDetections.medium} medium · {overview.openDetections.low} low
          </p>
        </div>
        <div className="stat">
          <p className="stat-label">Flows (24h)</p>
          <p className="stat-value">{overview.flows24h}</p>
          <p className="small muted">Reported by connectors</p>
        </div>
      </div>

      <section className="card">
        <div className="row" style={{ justifyContent: 'space-between', flexWrap: 'wrap' }}>
          <h2>Detection queue</h2>
          <form method="get" className="row" style={{ gap: '0.4rem', flexWrap: 'wrap' }}>
            <input
              name="q"
              defaultValue={query.q ?? ''}
              placeholder="Search title or subject"
              aria-label="Search detections"
              style={{ width: '15rem' }}
            />
            <select name="status" defaultValue={query.status ?? ''} aria-label="Status">
              <option value="">All statuses</option>
              {DETECTION_STATUSES.map((status) => (
                <option key={status} value={status}>
                  {status.toLowerCase()}
                </option>
              ))}
            </select>
            <select name="severity" defaultValue={query.severity ?? ''} aria-label="Severity">
              <option value="">All severities</option>
              {DETECTION_SEVERITIES.map((severity) => (
                <option key={severity} value={severity}>
                  {severity.toLowerCase()}
                </option>
              ))}
            </select>
            <button type="submit" className="secondary">
              Filter
            </button>
          </form>
        </div>

        {detections.length === 0 ? (
          <p className="small muted" style={{ marginTop: '1rem' }}>
            Nothing matches this filter. Detections are produced by the evaluation and connector
            ingestion paths; an empty queue means no rule fired for the current window.
          </p>
        ) : (
          <table className="data-table" style={{ marginTop: '1rem' }}>
            <thead>
              <tr>
                <th>Detection</th>
                <th>Rule</th>
                <th>Severity</th>
                <th>Status</th>
                <th>Last seen</th>
              </tr>
            </thead>
            <tbody>
              {detections.map((detection) => (
                <tr key={detection.id}>
                  <td>
                    <Link href={`${base}/network/detections/${detection.id}`}>
                      {detection.title}
                    </Link>
                    <p className="small muted mono" style={{ margin: '0.15rem 0 0' }}>
                      {detection.subjectKey}
                    </p>
                  </td>
                  <td className="small mono">{detection.ruleKey}</td>
                  <td>
                    <span className={`badge ${SEVERITY_BADGES[detection.severity] ?? ''}`}>
                      {detection.severity.toLowerCase()}
                    </span>
                  </td>
                  <td>
                    <span className="badge">{detection.status.toLowerCase()}</span>
                    {detection.stale ? ' (stale)' : ''}
                  </td>
                  <td className="small">{new Date(detection.lastSeenAt).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}

        <div className="row" style={{ justifyContent: 'space-between', marginTop: '1rem' }}>
          <p className="small muted" style={{ margin: 0 }}>
            {page.total} detection{page.total === 1 ? '' : 's'} · page {page.page} of{' '}
            {page.pageCount}
          </p>
          <div className="row" style={{ gap: '0.4rem' }}>
            {page.page > 1 ? (
              <Link className="nav-link" href={pageHref(page.page - 1)}>
                Previous
              </Link>
            ) : null}
            {page.page < page.pageCount ? (
              <Link className="nav-link" href={pageHref(page.page + 1)}>
                Next
              </Link>
            ) : null}
          </div>
        </div>
      </section>
    </>
  );
}
