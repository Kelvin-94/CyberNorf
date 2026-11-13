import type { Metadata } from 'next';
import Link from 'next/link';
import { notFound } from 'next/navigation';
import { ActionForm } from '@/components/action-form';
import { can } from '@/server/authz/roles';
import { RELEASE_STATUSES } from '@/server/domain/zero-trust';
import { getUpdateOverview, listDeviceUpdates, listReleases } from '@/server/services/updates';
import { loadTenantContext } from '@/server/ui/session';
import { releaseListQuerySchema, updateListQuerySchema } from '@/server/validation/zero-trust';

export const metadata: Metadata = { title: 'Updates · CyberNorf' };
export const dynamic = 'force-dynamic';

const RELEASE_BADGES: Record<string, string> = {
  DRAFT: 'low',
  CANARY: 'medium',
  ROLLING: 'info',
  RELEASED: 'success',
  ROLLED_BACK: 'critical',
};

const UPDATE_BADGES: Record<string, string> = {
  OFFERED: 'low',
  DOWNLOADING: 'info',
  INSTALLING: 'info',
  INSTALLED: 'success',
  FAILED: 'critical',
  ROLLED_BACK: 'high',
};

export default async function UpdatesPage({
  params,
  searchParams,
}: {
  params: Promise<{ orgSlug: string }>;
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const { orgSlug } = await params;
  const ctx = await loadTenantContext(orgSlug, 'update.read');
  if (!ctx) {
    notFound();
  }

  const raw = await searchParams;
  const parsed = releaseListQuerySchema.safeParse({
    page: raw.page,
    pageSize: raw.pageSize,
    product: raw.product,
    status: raw.status,
    q: raw.q,
  });
  const query = parsed.success ? parsed.data : releaseListQuerySchema.parse({});

  const canManage = can(ctx.membership.role, 'update.manage');
  const [releases, overview, updates] = await Promise.all([
    listReleases(ctx.organization.id, query),
    getUpdateOverview(ctx.organization.id),
    listDeviceUpdates(ctx.organization.id, updateListQuerySchema.parse({ pageSize: 15 })),
  ]);

  const base = `/app/${ctx.organization.slug}`;
  const page = releases.page;

  const filterParams = new URLSearchParams();
  for (const [key, value] of Object.entries({
    product: query.product,
    status: query.status,
    q: query.q,
  })) {
    if (value) {
      filterParams.set(key, value);
    }
  }
  const pageHref = (target: number) => {
    const next = new URLSearchParams(filterParams);
    next.set('page', String(target));
    return `${base}/updates?${next.toString()}`;
  };

  return (
    <>
      <div className="page-header">
        <div>
          <p className="eyebrow">Zero trust</p>
          <h1>Updates</h1>
          <p className="small muted" style={{ marginTop: '0.35rem' }}>
            Signed release manifests and the update state of each device. A release is published as
            a draft, ramped through canary and rolling stages, then marked released. Devices are
            only offered a build whose signature verifies against a configured publisher key and
            whose compatibility and minimum-version constraints they meet.
          </p>
        </div>
      </div>

      <div className="grid">
        <div className="stat">
          <p className="stat-label">Releases</p>
          <p className="stat-value">{overview.releases.total}</p>
          <p className="small muted">
            {overview.releases.draft} draft · {overview.releases.canary} canary
          </p>
        </div>
        <div className="stat">
          <p className="stat-label">In rollout</p>
          <p className="stat-value">{overview.releases.rolling}</p>
          <p className="small muted">{overview.releases.released} released</p>
        </div>
        <div className="stat">
          <p className="stat-label">Installs</p>
          <p className="stat-value">{overview.deviceUpdates.installed}</p>
          <p className="small muted">
            {overview.deviceUpdates.failed} failed · {overview.deviceUpdates.offered} offered
          </p>
        </div>
        <div className="stat">
          <p className="stat-label">Publisher keys</p>
          <p className="stat-value">{overview.publisherKeysConfigured}</p>
          <p className="small muted">
            {overview.publisherKeysConfigured === 0
              ? 'Configure ZERO_TRUST_PUBLISHER_KEYS to publish'
              : 'Configured in the environment'}
          </p>
        </div>
      </div>

      <section className="card">
        <div className="row" style={{ justifyContent: 'space-between', flexWrap: 'wrap' }}>
          <h2>Releases</h2>
          <form method="get" className="row" style={{ gap: '0.4rem', flexWrap: 'wrap' }}>
            <input
              name="q"
              defaultValue={query.q ?? ''}
              placeholder="Search product or version"
              aria-label="Search releases"
              style={{ width: '14rem' }}
            />
            <select name="status" defaultValue={query.status ?? ''} aria-label="Status">
              <option value="">All statuses</option>
              {RELEASE_STATUSES.map((status) => (
                <option key={status} value={status}>
                  {status.replaceAll('_', ' ').toLowerCase()}
                </option>
              ))}
            </select>
            <button type="submit" className="secondary">
              Filter
            </button>
          </form>
        </div>

        {releases.releases.length === 0 ? (
          <p className="small muted" style={{ marginTop: '1rem' }}>
            No releases yet. Publishing requires a signed manifest: the digest and signature are
            verified before any device is offered the build.
          </p>
        ) : (
          <table className="data-table" style={{ marginTop: '1rem' }}>
            <thead>
              <tr>
                <th>Product</th>
                <th>Version</th>
                <th>Channel</th>
                <th>Status</th>
                <th>Canary</th>
                <th>Published</th>
              </tr>
            </thead>
            <tbody>
              {releases.releases.map((release) => (
                <tr key={release.id}>
                  <td>
                    <Link href={`${base}/updates/releases/${release.id}`}>{release.product}</Link>
                  </td>
                  <td className="mono small">{release.version}</td>
                  <td className="small">{release.channel}</td>
                  <td>
                    <span className={`badge ${RELEASE_BADGES[release.status] ?? ''}`}>
                      {release.status.replaceAll('_', ' ').toLowerCase()}
                    </span>
                  </td>
                  <td className="small">{release.canaryPercent}%</td>
                  <td className="small">
                    {release.releasedAt ? new Date(release.releasedAt).toLocaleString() : '—'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}

        <div className="row" style={{ justifyContent: 'space-between', marginTop: '1rem' }}>
          <p className="small muted" style={{ margin: 0 }}>
            {page.total} release{page.total === 1 ? '' : 's'} · page {page.page} of {page.pageCount}
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

      <section className="card" style={{ marginTop: '1.5rem' }}>
        <h2>Recent device updates</h2>
        {updates.updates.length === 0 ? (
          <p className="small muted">
            No updates have been offered yet. Offering a release records an intent per device and
            the device reports its own progress back.
          </p>
        ) : (
          <table className="data-table">
            <thead>
              <tr>
                <th>Product</th>
                <th>Version</th>
                <th>Device</th>
                <th>State</th>
                <th>Offered</th>
              </tr>
            </thead>
            <tbody>
              {updates.updates.map((update) => (
                <tr key={update.id}>
                  <td>{update.product}</td>
                  <td className="mono small">{update.version}</td>
                  <td className="small">
                    <Link href={`${base}/devices/${update.deviceId}`}>{update.deviceId}</Link>
                  </td>
                  <td>
                    <span className={`badge ${UPDATE_BADGES[update.state] ?? ''}`}>
                      {update.state.toLowerCase()}
                    </span>
                  </td>
                  <td className="small">{new Date(update.offeredAt).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>

      {canManage ? (
        <section className="card" style={{ marginTop: '1.5rem' }}>
          <h2>Publish a release</h2>
          <p className="small muted">
            Sign the canonical manifest with the publisher key that matches{' '}
            <span className="mono">publisherKeyId</span>. The digest is checked against the artifact
            and the signature against the configured key material before the release becomes
            offerable.
          </p>
          <ActionForm
            action={`/api/v1/organizations/${ctx.organization.slug}/updates/releases`}
            submitLabel="Publish draft"
            successMessage="Release stored as a draft. Advance it when you are ready to roll out."
            fields={[
              { name: 'product', label: 'Product', required: true, placeholder: 'agent' },
              { name: 'version', label: 'Version', required: true, placeholder: '2.4.1' },
              { name: 'channel', label: 'Channel', defaultValue: 'stable', required: true },
              {
                name: 'artifactUrl',
                label: 'Artifact URL',
                required: true,
                full: true,
                placeholder: 'https://downloads.example.com/agent-2.4.1.pkg',
              },
              {
                name: 'sha256',
                label: 'SHA-256',
                required: true,
                full: true,
                maxLength: 64,
                placeholder: '64 hexadecimal characters',
                help: 'Digest of the artifact the manifest describes.',
              },
              {
                name: 'publisherKeyId',
                label: 'Publisher key id',
                required: true,
                help: 'Must match a key in ZERO_TRUST_PUBLISHER_KEYS.',
              },
              {
                name: 'minVersion',
                label: 'Minimum version',
                placeholder: '2.0.0',
                help: 'Optional. Devices below this version are not offered the update.',
              },
              {
                name: 'manifestSignature',
                label: 'Manifest signature',
                type: 'textarea',
                rows: 4,
                required: true,
                full: true,
                maxLength: 4000,
                help: 'Base64 signature over the canonical manifest.',
              },
              {
                name: 'compatibility',
                label: 'Compatibility (JSON)',
                type: 'json',
                full: true,
                placeholder: '{ "os": ["macos", "windows"], "minOsVersion": "13.0.0" }',
              },
              {
                name: 'canaryPercent',
                label: 'Canary percentage',
                type: 'number',
                min: 1,
                max: 100,
                defaultValue: '10',
              },
            ]}
          />
        </section>
      ) : null}
    </>
  );
}
