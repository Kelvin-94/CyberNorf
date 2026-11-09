import type { Metadata } from 'next';
import Link from 'next/link';
import { notFound } from 'next/navigation';
import { AdvisoryDeleteButton } from '@/components/advisories/advisory-delete-button';
import { AdvisoryImportForm } from '@/components/advisories/advisory-import-form';
import { PACKAGE_ECOSYSTEMS, packageEcosystemLabel } from '@/server/domain/software';
import { can } from '@/server/authz/roles';
import { listAdvisories } from '@/server/services/software';
import { loadTenantContext } from '@/server/ui/session';
import { enumSearchParam, searchParam } from '@/server/validation/common';
import { advisoryQuerySchema, packageEcosystemSchema } from '@/server/validation/software';

export const metadata: Metadata = { title: 'Advisories · CyberNorf' };
export const dynamic = 'force-dynamic';

export default async function AdvisoriesPage({
  params,
  searchParams,
}: {
  params: Promise<{ orgSlug: string }>;
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const { orgSlug } = await params;
  const ctx = await loadTenantContext(orgSlug, 'advisory.read');
  if (!ctx) {
    notFound();
  }

  const rawParams = await searchParams;
  const query = advisoryQuerySchema.parse({
    search: searchParam(rawParams, 'search'),
    ecosystem: enumSearchParam(rawParams, 'ecosystem', packageEcosystemSchema),
  });
  const result = await listAdvisories(ctx, query);
  const canManage = can(ctx.membership.role, 'advisory.manage');

  const filterQuery = (page: number) => {
    const search = new URLSearchParams();
    if (query.search) {
      search.set('search', query.search);
    }
    if (query.ecosystem) {
      search.set('ecosystem', query.ecosystem);
    }
    if (page > 1) {
      search.set('page', String(page));
    }
    const suffix = search.toString();
    return suffix ? `?${suffix}` : '';
  };

  return (
    <>
      <div className="page-header">
        <div>
          <p className="eyebrow">Exposure</p>
          <h1>Advisory feed</h1>
          <p className="small muted" style={{ marginTop: '0.35rem' }}>
            {result.total} advisor{result.total === 1 ? 'y' : 'ies'} imported for{' '}
            {ctx.organization.name}. Agent inventories are matched against this feed on every run,
            without any outbound request.
          </p>
        </div>
      </div>

      {canManage ? (
        <section className="card" style={{ marginBottom: '1.25rem' }}>
          <h2>Import advisories</h2>
          <p className="small muted">
            Paste an export from your vulnerability source (NVD, GHSA, vendor bulletin). Imports are
            idempotent: the same identifier and package updates the existing row.
          </p>
          <AdvisoryImportForm orgSlug={ctx.organization.slug} />
        </section>
      ) : (
        <p className="banner small" style={{ marginBottom: '1.25rem' }}>
          Only administrators can import or remove advisories. Ask an administrator to refresh the
          feed.
        </p>
      )}

      <form method="get" className="row" style={{ marginBottom: '1.25rem' }}>
        <label className="field" htmlFor="search" style={{ flex: '1 1 14rem' }}>
          Search
          <input
            id="search"
            name="search"
            defaultValue={query.search ?? ''}
            placeholder="Identifier, package or summary"
          />
        </label>
        <label className="field" htmlFor="ecosystem">
          Ecosystem
          <select id="ecosystem" name="ecosystem" defaultValue={query.ecosystem ?? ''}>
            <option value="">Any</option>
            {PACKAGE_ECOSYSTEMS.map((ecosystem) => (
              <option key={ecosystem} value={ecosystem}>
                {packageEcosystemLabel(ecosystem)}
              </option>
            ))}
          </select>
        </label>
        <button type="submit" className="secondary">
          Filter
        </button>
      </form>

      <section className="card">
        {result.items.length === 0 ? (
          <p className="small muted">
            No advisories match. Import a feed, then run an agent that reports software inventory to
            turn matches into findings.
          </p>
        ) : (
          <table className="data-table">
            <thead>
              <tr>
                <th>Advisory</th>
                <th>Package</th>
                <th>Severity</th>
                <th>Affected</th>
                <th>Fixed in</th>
                {canManage ? <th /> : null}
              </tr>
            </thead>
            <tbody>
              {result.items.map((advisory) => (
                <tr key={advisory.id}>
                  <td>
                    <div className="mono">{advisory.identifier}</div>
                    <div className="small muted">{advisory.summary}</div>
                    {advisory.referenceUrl ? (
                      <a
                        className="small"
                        href={advisory.referenceUrl}
                        rel="noreferrer noopener"
                        target="_blank"
                      >
                        Reference
                      </a>
                    ) : null}
                  </td>
                  <td>
                    <div className="mono">{advisory.packageName}</div>
                    <div className="small muted">{packageEcosystemLabel(advisory.ecosystem)}</div>
                  </td>
                  <td>
                    <span className={`badge ${advisory.severity.toLowerCase()}`}>
                      {advisory.severity}
                    </span>
                    {advisory.cvssScore !== null ? (
                      <div className="small muted">CVSS {advisory.cvssScore.toFixed(1)}</div>
                    ) : null}
                  </td>
                  <td className="mono small">{advisory.affectedRange}</td>
                  <td className="mono small">{advisory.fixedVersion ?? '—'}</td>
                  {canManage ? (
                    <td>
                      <AdvisoryDeleteButton
                        orgSlug={ctx.organization.slug}
                        advisoryId={advisory.id}
                        label={`${advisory.identifier} for ${advisory.packageName}`}
                      />
                    </td>
                  ) : null}
                </tr>
              ))}
            </tbody>
          </table>
        )}

        {result.pageCount > 1 ? (
          <div className="row" style={{ marginTop: '1rem' }}>
            {result.page > 1 ? (
              <Link
                className="button secondary"
                href={`/app/${ctx.organization.slug}/advisories${filterQuery(result.page - 1)}`}
              >
                Previous
              </Link>
            ) : null}
            <span className="small muted">
              Page {result.page} of {result.pageCount}
            </span>
            {result.page < result.pageCount ? (
              <Link
                className="button secondary"
                href={`/app/${ctx.organization.slug}/advisories${filterQuery(result.page + 1)}`}
              >
                Next
              </Link>
            ) : null}
          </div>
        ) : null}
      </section>
    </>
  );
}
