import type { Metadata } from 'next';
import Link from 'next/link';
import { notFound } from 'next/navigation';
import { VerifyAuditButton } from '@/components/audit/verify-audit-button';
import { listAuditEvents } from '@/server/services/audit';
import { loadTenantContext } from '@/server/ui/session';
import { auditQuerySchema } from '@/server/validation/audit';

export const metadata: Metadata = { title: 'Audit trail · CyberNorf' };
export const dynamic = 'force-dynamic';

function asString(value: string | string[] | undefined): string | undefined {
  return typeof value === 'string' && value.length > 0 ? value : undefined;
}

export default async function AuditPage({
  params,
  searchParams,
}: {
  params: Promise<{ orgSlug: string }>;
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const { orgSlug } = await params;
  const ctx = await loadTenantContext(orgSlug, 'audit.read');
  if (!ctx) {
    notFound();
  }

  const rawParams = await searchParams;
  const parsed = auditQuerySchema.safeParse({
    search: asString(rawParams.search),
    action: asString(rawParams.action),
    outcome: asString(rawParams.outcome),
    targetType: asString(rawParams.targetType),
    page: asString(rawParams.page),
  });
  const query = parsed.success ? parsed.data : auditQuerySchema.parse({});

  const result = await listAuditEvents(ctx.organization.id, {
    search: query.search ?? null,
    ...(query.action ? { action: query.action } : {}),
    ...(query.outcome ? { outcome: query.outcome } : {}),
    ...(query.targetType ? { targetType: query.targetType } : {}),
    page: query.page,
    pageSize: query.pageSize,
    direction: query.direction,
  });

  const pages = Math.max(1, Math.ceil(result.total / result.pageSize));

  return (
    <>
      <div className="page-header">
        <div>
          <p className="eyebrow">Governance</p>
          <h1>Audit trail</h1>
          <p className="small muted" style={{ marginTop: '0.35rem' }}>
            {result.total} event{result.total === 1 ? '' : 's'} · append-only and hash-chained per
            organization
          </p>
        </div>
      </div>

      <section className="card stack" style={{ marginBottom: '1.25rem' }}>
        <h2>Integrity</h2>
        <p className="small muted">
          Each event stores the hash of the previous event, so any silent edit or deletion breaks
          verification. Database triggers additionally reject updates and deletes on the audit
          table.
        </p>
        <VerifyAuditButton action={`/api/v1/organizations/${ctx.organization.slug}/audit/verify`} />
      </section>

      {parsed.success ? null : (
        <p className="banner warning">
          Some filters were ignored because they were not valid. Showing the default view.
        </p>
      )}

      <form method="get" className="row" style={{ marginBottom: '1.25rem' }}>
        <label className="field" htmlFor="search" style={{ flex: '1 1 12rem' }}>
          Search
          <input
            id="search"
            name="search"
            defaultValue={query.search ?? ''}
            placeholder="Action, summary, target id"
          />
        </label>
        <label className="field" htmlFor="action">
          Action
          <input
            id="action"
            name="action"
            defaultValue={query.action ?? ''}
            placeholder="finding.updated"
          />
        </label>
        <label className="field" htmlFor="targetType">
          Target type
          <input
            id="targetType"
            name="targetType"
            defaultValue={query.targetType ?? ''}
            placeholder="finding"
          />
        </label>
        <label className="field" htmlFor="outcome">
          Outcome
          <select id="outcome" name="outcome" defaultValue={query.outcome ?? ''}>
            <option value="">Any</option>
            <option value="SUCCESS">SUCCESS</option>
            <option value="DENIED">DENIED</option>
            <option value="FAILURE">FAILURE</option>
          </select>
        </label>
        <button type="submit" className="secondary">
          Filter
        </button>
      </form>

      <section className="card">
        {result.items.length === 0 ? (
          <p className="small muted">No audit events match the current filter.</p>
        ) : (
          <table className="data-table">
            <thead>
              <tr>
                <th>Seq</th>
                <th>When</th>
                <th>Action</th>
                <th>Outcome</th>
                <th>Actor</th>
                <th>Target</th>
                <th>Summary</th>
                <th>Hash</th>
              </tr>
            </thead>
            <tbody>
              {result.items.map((event) => (
                <tr key={event.id}>
                  <td className="mono small">{event.sequence.toString()}</td>
                  <td className="mono small">
                    {event.createdAt.toISOString().slice(0, 19).replace('T', ' ')}
                  </td>
                  <td className="mono small">{event.action}</td>
                  <td className="small">
                    <span
                      className={`badge ${
                        event.outcome === 'SUCCESS'
                          ? 'success'
                          : event.outcome === 'DENIED'
                            ? 'denied'
                            : 'high'
                      }`}
                    >
                      {event.outcome}
                    </span>
                  </td>
                  <td className="small">{event.actor?.name ?? event.actorType}</td>
                  <td className="small">
                    {event.targetType ? (
                      <>
                        {event.targetType}
                        {event.targetId ? (
                          <span className="mono muted"> {event.targetId.slice(0, 8)}</span>
                        ) : null}
                      </>
                    ) : (
                      '—'
                    )}
                  </td>
                  <td className="small">{event.summary}</td>
                  <td className="mono small muted" title={event.hash}>
                    {event.hash.slice(0, 10)}…
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>

      {pages > 1 ? (
        <nav className="row" style={{ marginTop: '1rem' }} aria-label="Pagination">
          {query.page > 1 ? <Link href={`?page=${query.page - 1}`}>← Newer</Link> : null}
          <span className="small muted">
            Page {query.page} of {pages}
          </span>
          {query.page < pages ? <Link href={`?page=${query.page + 1}`}>Older →</Link> : null}
        </nav>
      ) : null}
    </>
  );
}
