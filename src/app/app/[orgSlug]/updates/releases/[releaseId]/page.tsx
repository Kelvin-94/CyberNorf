import type { Metadata } from 'next';
import Link from 'next/link';
import { notFound } from 'next/navigation';
import { ActionForm } from '@/components/action-form';
import { can } from '@/server/authz/roles';
import { AppError } from '@/server/errors';
import { getRelease, listDeviceUpdates } from '@/server/services/updates';
import { loadTenantContext } from '@/server/ui/session';
import { updateListQuerySchema } from '@/server/validation/zero-trust';

export const metadata: Metadata = { title: 'Release · CyberNorf' };
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

export default async function ReleasePage({
  params,
}: {
  params: Promise<{ orgSlug: string; releaseId: string }>;
}) {
  const { orgSlug, releaseId } = await params;
  const ctx = await loadTenantContext(orgSlug, 'update.read');
  if (!ctx) {
    notFound();
  }

  let release;
  try {
    release = await getRelease(ctx.organization.id, releaseId);
  } catch (error) {
    if (error instanceof AppError && error.statusCode === 404) {
      notFound();
    }
    throw error;
  }
  const canManage = can(ctx.membership.role, 'update.manage');
  const updates = await listDeviceUpdates(
    ctx.organization.id,
    updateListQuerySchema.parse({ releaseId: release.id, pageSize: 50 }),
  );
  const base = `/app/${ctx.organization.slug}`;
  const releasePath = `/api/v1/organizations/${ctx.organization.slug}/updates/releases/${release.id}`;
  const compatibility = release.compatibility;
  const supportedOs = compatibility.os ?? [];

  return (
    <>
      <div className="page-header">
        <div>
          <p className="eyebrow">
            <Link href={`${base}/updates`}>Updates</Link>
          </p>
          <h1>
            {release.product} <span className="mono">{release.version}</span>
          </h1>
          <p className="small muted" style={{ marginTop: '0.35rem' }}>
            {release.channel} channel · created {new Date(release.createdAt).toLocaleString()}
          </p>
        </div>
        <span className={`badge ${RELEASE_BADGES[release.status] ?? ''}`}>
          {release.status.replaceAll('_', ' ').toLowerCase()}
        </span>
      </div>

      <section className="card">
        <dl className="detail-grid">
          <div>
            <dt>Artifact</dt>
            <dd className="mono small" style={{ wordBreak: 'break-all' }}>
              {release.artifactUrl}
            </dd>
          </div>
          <div>
            <dt>SHA-256</dt>
            <dd className="mono small" style={{ wordBreak: 'break-all' }}>
              {release.sha256}
            </dd>
          </div>
          <div>
            <dt>Publisher key</dt>
            <dd className="mono small">{release.publisherKeyId}</dd>
          </div>
          <div>
            <dt>Minimum version</dt>
            <dd className="mono small">{release.minVersion ?? 'none'}</dd>
          </div>
          <div>
            <dt>Canary</dt>
            <dd>{release.canaryPercent}%</dd>
          </div>
          <div>
            <dt>Compatibility</dt>
            <dd className="small">
              {supportedOs.length > 0 ? supportedOs.join(', ') : 'any OS'}
              {compatibility.minOsVersion ? ` · from ${compatibility.minOsVersion}` : ''}
              {compatibility.maxOsVersion ? ` · up to ${compatibility.maxOsVersion}` : ''}
            </dd>
          </div>
          <div>
            <dt>Released</dt>
            <dd>{release.releasedAt ? new Date(release.releasedAt).toLocaleString() : '—'}</dd>
          </div>
          <div>
            <dt>Rolled back</dt>
            <dd>{release.rolledBackAt ? new Date(release.rolledBackAt).toLocaleString() : '—'}</dd>
          </div>
        </dl>
      </section>

      <section className="card" style={{ marginTop: '1.5rem' }}>
        <h2>Offers</h2>
        {updates.updates.length === 0 ? (
          <p className="small muted">
            This release has not been offered to any device yet.{' '}
            {release.offerable
              ? 'Use the offer form below to target specific devices.'
              : 'It must be in canary, rolling or released state before devices can be offered it.'}
          </p>
        ) : (
          <table className="data-table">
            <thead>
              <tr>
                <th>Device</th>
                <th>State</th>
                <th>Offered</th>
                <th>Installed</th>
                <th>Result</th>
              </tr>
            </thead>
            <tbody>
              {updates.updates.map((update) => (
                <tr key={update.id}>
                  <td className="small">
                    <Link href={`${base}/devices/${update.deviceId}`}>{update.deviceId}</Link>
                  </td>
                  <td>
                    <span className={`badge ${UPDATE_BADGES[update.state] ?? ''}`}>
                      {update.state.toLowerCase()}
                    </span>
                  </td>
                  <td className="small">{new Date(update.offeredAt).toLocaleString()}</td>
                  <td className="small">
                    {update.installedAt ? new Date(update.installedAt).toLocaleString() : '—'}
                  </td>
                  <td className="small mono">
                    {Object.keys(update.result).length === 0 ? '—' : JSON.stringify(update.result)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>

      {canManage ? (
        <section className="card" style={{ marginTop: '1.5rem' }}>
          <h2>Rollout</h2>
          {release.transitions.length > 0 ? (
            <>
              <p className="small muted">
                Advancing is one-way: a release moves forward through canary and rolling stages
                before it is marked released. Rollback is available for any state that is not
                already rolled back.
              </p>
              <ActionForm
                action={`${releasePath}/advance`}
                submitLabel="Advance release"
                successMessage="Release advanced."
                confirmText={`Advance ${release.product} ${release.version} to the next stage?`}
                fields={[
                  {
                    name: 'to',
                    label: 'Next stage',
                    type: 'select',
                    required: true,
                    defaultValue: String(release.transitions[0]),
                    options: release.transitions.map((status) => ({
                      value: status,
                      label: status.toLowerCase(),
                    })),
                  },
                  {
                    name: 'canaryPercent',
                    label: 'Canary percentage',
                    type: 'number',
                    min: 1,
                    max: 100,
                    defaultValue: String(release.canaryPercent),
                    help: 'Applies when moving to canary.',
                  },
                ]}
              />
            </>
          ) : (
            <p className="small muted">This release has reached a terminal state.</p>
          )}
        </section>
      ) : null}

      {canManage && release.status !== 'ROLLED_BACK' ? (
        <section className="card" style={{ marginTop: '1.5rem' }}>
          <h2>Rollback</h2>
          <p className="small muted">
            Rolling back stops new offers and records why. Devices that already installed the build
            are not reverted automatically; use an enforcement action if a device must be moved off
            it.
          </p>
          <ActionForm
            action={`${releasePath}/rollback`}
            submitLabel="Roll back release"
            confirmText={`Roll back ${release.product} ${release.version}? Devices stop being offered it.`}
            successMessage="Release rolled back."
            fields={[
              {
                name: 'reason',
                label: 'Reason',
                type: 'textarea',
                rows: 3,
                required: true,
                maxLength: 500,
                full: true,
              },
            ]}
          />
        </section>
      ) : null}

      {canManage && release.offerable ? (
        <section className="card" style={{ marginTop: '1.5rem' }}>
          <h2>Offer to devices</h2>
          <p className="small muted">
            Offering records one pending update per device. A device that is already on this
            version, or that fails the compatibility or minimum-version gate, is skipped by the
            offer path.
          </p>
          <ActionForm
            action={`${releasePath}/offer`}
            submitLabel="Offer update"
            successMessage="Update offered."
            confirmText={`Offer ${release.product} ${release.version} to the listed devices?`}
            fields={[
              {
                name: 'deviceIds',
                label: 'Device ids (JSON array)',
                type: 'json',
                required: true,
                full: true,
                placeholder: '["cuid1", "cuid2"]',
                help: 'Ids of the devices to target, as shown on each device page.',
              },
            ]}
          />
        </section>
      ) : null}
    </>
  );
}
