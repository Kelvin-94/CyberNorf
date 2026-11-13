import type { Metadata } from 'next';
import Link from 'next/link';
import { notFound } from 'next/navigation';
import { POLICY_EFFECTS, SUBJECT_KINDS } from '@/server/domain/zero-trust';
import { listPolicyDecisions } from '@/server/services/policy';
import { loadTenantContext } from '@/server/ui/session';
import { policyDecisionListQuerySchema } from '@/server/validation/zero-trust';

export const metadata: Metadata = { title: 'Policy decisions · CyberNorf' };
export const dynamic = 'force-dynamic';

const EFFECT_BADGES: Record<string, string> = {
  ALLOW: 'success',
  DENY: 'critical',
  STEP_UP: 'medium',
  QUARANTINE: 'high',
};

export default async function PolicyDecisionsPage({
  params,
  searchParams,
}: {
  params: Promise<{ orgSlug: string }>;
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const { orgSlug } = await params;
  const ctx = await loadTenantContext(orgSlug, 'policy.read');
  if (!ctx) {
    notFound();
  }

  const raw = await searchParams;
  const parsed = policyDecisionListQuerySchema.safeParse({
    page: raw.page,
    pageSize: raw.pageSize,
    verdict: raw.verdict,
    subjectKind: raw.subjectKind,
    q: raw.q,
  });
  const query = parsed.success ? parsed.data : policyDecisionListQuerySchema.parse({});
  const decisions = await listPolicyDecisions(ctx.organization.id, query);

  const base = `/app/${ctx.organization.slug}`;
  const filterParams = new URLSearchParams();
  for (const [key, value] of Object.entries({
    verdict: query.verdict,
    subjectKind: query.subjectKind,
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
    return `${base}/policies/decisions?${next.toString()}`;
  };

  return (
    <>
      <div className="page-header">
        <div>
          <p className="eyebrow">
            <Link href={`${base}/policies`}>Policies</Link>
          </p>
          <h1>Decision log</h1>
          <p className="small muted" style={{ marginTop: '0.35rem' }}>
            One record per evaluated request, stored with the facts it was decided from. This is the
            record that lets you explain months later why a device was admitted or refused.
          </p>
        </div>
      </div>

      <section className="card">
        <div className="row" style={{ justifyContent: 'space-between', flexWrap: 'wrap' }}>
          <h2>Decisions</h2>
          <form method="get" className="row" style={{ gap: '0.4rem', flexWrap: 'wrap' }}>
            <input
              name="q"
              defaultValue={query.q ?? ''}
              placeholder="Search subject, action, correlation id"
              aria-label="Search decisions"
              style={{ width: '18rem' }}
            />
            <select name="verdict" defaultValue={query.verdict ?? ''} aria-label="Verdict">
              <option value="">All verdicts</option>
              {POLICY_EFFECTS.map((verdict) => (
                <option key={verdict} value={verdict}>
                  {verdict.replaceAll('_', ' ').toLowerCase()}
                </option>
              ))}
            </select>
            <select name="subjectKind" defaultValue={query.subjectKind ?? ''} aria-label="Subject">
              <option value="">All subjects</option>
              {SUBJECT_KINDS.map((kind) => (
                <option key={kind} value={kind}>
                  {kind.toLowerCase()}
                </option>
              ))}
            </select>
            <button type="submit" className="secondary">
              Filter
            </button>
            <Link href={`${base}/policies/decisions`} className="nav-link">
              Reset
            </Link>
          </form>
        </div>

        {decisions.decisions.length === 0 ? (
          <p className="small muted">No decision matches this filter.</p>
        ) : (
          <table className="data-table">
            <thead>
              <tr>
                <th>When</th>
                <th>Subject</th>
                <th>Action</th>
                <th>Resource</th>
                <th>Verdict</th>
                <th>Risk</th>
                <th>Correlation</th>
              </tr>
            </thead>
            <tbody>
              {decisions.decisions.map((decision) => (
                <tr key={decision.id}>
                  <td className="small">{new Date(decision.createdAt).toLocaleString()}</td>
                  <td className="small">
                    <Link href={`${base}/policies/decisions/${decision.id}`}>
                      {decision.subjectLabel}
                    </Link>
                    <div className="muted">{decision.subjectKind.toLowerCase()}</div>
                  </td>
                  <td className="small mono">{decision.action}</td>
                  <td className="small">
                    {decision.resourceType}
                    <div className="muted">{decision.resourceSensitivity.toLowerCase()}</div>
                  </td>
                  <td>
                    <span className={`badge ${EFFECT_BADGES[decision.verdict] ?? ''}`}>
                      {decision.verdict.replaceAll('_', ' ').toLowerCase()}
                    </span>
                  </td>
                  <td className="mono small">{decision.riskScore}</td>
                  <td className="mono small muted">{decision.correlationId.slice(0, 12)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}

        <div className="row" style={{ justifyContent: 'space-between', marginTop: '0.75rem' }}>
          <span className="small muted">
            Page {decisions.page.page} of {decisions.page.pageCount} · {decisions.page.total}{' '}
            decisions
          </span>
          <div className="row" style={{ gap: '0.4rem' }}>
            {decisions.page.page > 1 ? (
              <Link className="nav-link" href={pageHref(decisions.page.page - 1)}>
                Previous
              </Link>
            ) : null}
            {decisions.page.page < decisions.page.pageCount ? (
              <Link className="nav-link" href={pageHref(decisions.page.page + 1)}>
                Next
              </Link>
            ) : null}
          </div>
        </div>
      </section>
    </>
  );
}
