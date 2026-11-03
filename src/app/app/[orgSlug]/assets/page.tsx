import type { Metadata } from 'next';
import Link from 'next/link';
import { notFound } from 'next/navigation';
import { ActionForm } from '@/components/action-form';
import { can } from '@/server/authz/roles';
import { listAssets } from '@/server/services/assets';
import { loadTenantContext } from '@/server/ui/session';
import { enumSearchParam, searchParam } from '@/server/validation/common';
import {
  assetQuerySchema,
  assetStatusSchema,
  assetTypeSchema,
} from '@/server/validation/organizations';

export const metadata: Metadata = { title: 'Assets · CyberNorf' };
export const dynamic = 'force-dynamic';

export default async function AssetsPage({
  params,
  searchParams,
}: {
  params: Promise<{ orgSlug: string }>;
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const { orgSlug } = await params;
  const ctx = await loadTenantContext(orgSlug, 'asset.read');
  if (!ctx) {
    notFound();
  }

  const rawParams = await searchParams;
  // Unknown filter values fall back to "any" so a hand-edited URL cannot break
  // the page; the API keeps rejecting them with a 422.
  const query = assetQuerySchema.parse({
    search: searchParam(rawParams, 'search'),
    type: enumSearchParam(rawParams, 'type', assetTypeSchema),
    status: enumSearchParam(rawParams, 'status', assetStatusSchema),
  });

  const result = await listAssets(ctx.organization.id, {
    search: query.search ?? null,
    ...(query.type ? { type: query.type } : {}),
    ...(query.status ? { status: query.status } : {}),
    page: query.page,
    pageSize: query.pageSize,
    sort: query.sort,
    direction: query.direction,
  });

  const base = `/app/${ctx.organization.slug}`;
  const canCreate = can(ctx.membership.role, 'asset.create');

  return (
    <>
      <div className="page-header">
        <div>
          <p className="eyebrow">Inventory</p>
          <h1>Authorized assets</h1>
          <p className="small muted" style={{ marginTop: '0.35rem' }}>
            {result.total} asset{result.total === 1 ? '' : 's'} recorded for {ctx.organization.name}
          </p>
        </div>
      </div>

      <form method="get" className="row" style={{ marginBottom: '1.25rem' }}>
        <label className="field" htmlFor="search" style={{ flex: '1 1 14rem' }}>
          Search
          <input
            id="search"
            name="search"
            defaultValue={query.search ?? ''}
            placeholder="Name or identifier"
          />
        </label>
        <label className="field" htmlFor="status">
          Status
          <select id="status" name="status" defaultValue={query.status ?? ''}>
            <option value="">Any</option>
            <option value="ACTIVE">Active</option>
            <option value="INACTIVE">Inactive</option>
            <option value="RETIRED">Retired</option>
          </select>
        </label>
        <button type="submit" className="secondary">
          Filter
        </button>
      </form>

      <section className="card">
        {result.items.length === 0 ? (
          <p className="small muted">
            No assets yet. Register the systems you are authorized to test.
          </p>
        ) : (
          <table className="data-table">
            <thead>
              <tr>
                <th>Asset</th>
                <th>Type</th>
                <th>Criticality</th>
                <th>Status</th>
                <th>Findings</th>
              </tr>
            </thead>
            <tbody>
              {result.items.map((asset) => (
                <tr key={asset.id}>
                  <td>
                    <Link href={`${base}/assets/${asset.id}`}>{asset.name}</Link>
                    <div className="mono muted">{asset.identifier}</div>
                  </td>
                  <td className="small">{asset.type.replaceAll('_', ' ')}</td>
                  <td>
                    <span className={`badge ${asset.criticality.toLowerCase()}`}>
                      {asset.criticality}
                    </span>
                  </td>
                  <td className="small">{asset.status}</td>
                  <td className="small">{asset.openFindings}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>

      {canCreate ? (
        <section className="card stack" style={{ marginTop: '1.5rem', maxWidth: '44rem' }}>
          <h2>Register an asset</h2>
          <p className="small muted">
            Only register systems inside your engagement scope. Identifiers are unique per
            organization.
          </p>
          <ActionForm
            action={`/api/v1/organizations/${ctx.organization.slug}/assets`}
            fields={[
              { name: 'name', label: 'Name', required: true, maxLength: 120 },
              {
                name: 'type',
                label: 'Type',
                type: 'select',
                defaultValue: 'DOMAIN',
                options: [
                  { value: 'DOMAIN', label: 'Domain' },
                  { value: 'IP_ADDRESS', label: 'IP address' },
                  { value: 'CIDR', label: 'CIDR range' },
                  { value: 'HOSTNAME', label: 'Hostname' },
                  { value: 'WEB_APPLICATION', label: 'Web application' },
                  { value: 'CLOUD_ACCOUNT', label: 'Cloud account' },
                  { value: 'OTHER', label: 'Other' },
                ],
              },
              {
                name: 'identifier',
                label: 'Identifier',
                required: true,
                placeholder: 'app.example.com',
              },
              {
                name: 'criticality',
                label: 'Criticality',
                type: 'select',
                defaultValue: 'MEDIUM',
                options: [
                  { value: 'LOW', label: 'Low' },
                  { value: 'MEDIUM', label: 'Medium' },
                  { value: 'HIGH', label: 'High' },
                  { value: 'CRITICAL', label: 'Critical' },
                ],
              },
              {
                name: 'description',
                label: 'Description',
                type: 'textarea',
                maxLength: 2000,
                full: true,
              },
            ]}
            submitLabel="Register asset"
            successMessage="Asset registered."
            resetOnSuccess
          />
        </section>
      ) : null}
    </>
  );
}
