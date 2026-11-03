import type { Metadata } from 'next';
import Link from 'next/link';
import { notFound } from 'next/navigation';
import { ActionButton } from '@/components/action-button';
import { ActionForm } from '@/components/action-form';
import { can } from '@/server/authz/roles';
import { getAssetDetail } from '@/server/services/assets';
import { AppError } from '@/server/errors';
import { loadTenantContext } from '@/server/ui/session';

export const metadata: Metadata = { title: 'Asset · CyberNorf' };
export const dynamic = 'force-dynamic';

export default async function AssetDetailPage({
  params,
}: {
  params: Promise<{ orgSlug: string; assetId: string }>;
}) {
  const { orgSlug, assetId } = await params;
  const ctx = await loadTenantContext(orgSlug, 'asset.read');
  if (!ctx) {
    notFound();
  }

  let asset;
  try {
    asset = await getAssetDetail(ctx, assetId);
  } catch (error) {
    if (error instanceof AppError && error.statusCode === 404) {
      notFound();
    }
    throw error;
  }

  const base = `/app/${ctx.organization.slug}`;
  const endpoint = `/api/v1/organizations/${ctx.organization.slug}/assets/${asset.id}`;

  return (
    <>
      <p className="small muted">
        <Link href={`${base}/assets`}>← Assets</Link>
      </p>

      <div className="page-header">
        <div>
          <p className="eyebrow">{asset.type.replaceAll('_', ' ')}</p>
          <h1>{asset.name}</h1>
          <p className="mono muted" style={{ marginTop: '0.4rem' }}>
            {asset.identifier}
          </p>
        </div>
        <div className="row">
          <span className={`badge ${asset.criticality.toLowerCase()}`}>{asset.criticality}</span>
          <span className="badge">{asset.status}</span>
          <span className="badge">{asset.verificationStatus}</span>
        </div>
      </div>

      {asset.description ? <p className="muted">{asset.description}</p> : null}

      <section className="card" style={{ marginTop: '1.25rem' }}>
        <h2>Findings on this asset</h2>
        {asset.findings.length === 0 ? (
          <p className="small muted">No findings recorded against this asset.</p>
        ) : (
          <table className="data-table">
            <thead>
              <tr>
                <th>Finding</th>
                <th>Severity</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {asset.findings.map((finding) => (
                <tr key={finding.id}>
                  <td>
                    <Link href={`${base}/findings/${finding.id}`}>{finding.title}</Link>
                  </td>
                  <td>
                    <span className={`badge ${finding.severity.toLowerCase()}`}>
                      {finding.severity}
                    </span>
                  </td>
                  <td className="small">{finding.status.replaceAll('_', ' ')}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>

      {can(ctx.membership.role, 'asset.update') ? (
        <section className="card stack" style={{ marginTop: '1.5rem', maxWidth: '44rem' }}>
          <h2>Edit asset</h2>
          <ActionForm
            action={endpoint}
            method="PATCH"
            fields={[
              { name: 'name', label: 'Name', defaultValue: asset.name, maxLength: 120 },
              {
                name: 'criticality',
                label: 'Criticality',
                type: 'select',
                defaultValue: asset.criticality,
                options: [
                  { value: 'LOW', label: 'Low' },
                  { value: 'MEDIUM', label: 'Medium' },
                  { value: 'HIGH', label: 'High' },
                  { value: 'CRITICAL', label: 'Critical' },
                ],
              },
              {
                name: 'status',
                label: 'Status',
                type: 'select',
                defaultValue: asset.status,
                options: [
                  { value: 'ACTIVE', label: 'Active' },
                  { value: 'INACTIVE', label: 'Inactive' },
                  { value: 'RETIRED', label: 'Retired' },
                ],
              },
              {
                name: 'description',
                label: 'Description',
                type: 'textarea',
                defaultValue: asset.description ?? '',
                maxLength: 2000,
                full: true,
              },
            ]}
            submitLabel="Save changes"
            successMessage="Asset updated."
          />
        </section>
      ) : null}

      {can(ctx.membership.role, 'asset.delete') ? (
        <section className="card stack" style={{ marginTop: '1.5rem', maxWidth: '44rem' }}>
          <h2>Delete asset</h2>
          <p className="small muted">
            Deleting an asset detaches its findings instead of deleting them. The action is recorded
            in the audit trail.
          </p>
          <ActionButton
            action={endpoint}
            method="DELETE"
            label="Delete asset"
            variant="danger"
            confirmText="Delete this asset? Findings are kept but unlinked."
            redirectTo={`${base}/assets`}
          />
        </section>
      ) : null}
    </>
  );
}
