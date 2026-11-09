import type { Metadata } from 'next';
import { notFound } from 'next/navigation';
import { ActionForm } from '@/components/action-form';
import { NotificationChannelActions } from '@/components/settings/notification-channel-actions';
import { can } from '@/server/authz/roles';
import { getNotificationSettings } from '@/server/services/notifications';
import { getOrganizationSettings } from '@/server/services/organizations';
import { loadTenantContext } from '@/server/ui/session';

function formatTimestamp(value: string | null): string {
  return value ? new Date(value).toLocaleString() : '—';
}

export const metadata: Metadata = { title: 'Settings · CyberNorf' };
export const dynamic = 'force-dynamic';

export default async function SettingsPage({ params }: { params: Promise<{ orgSlug: string }> }) {
  const { orgSlug } = await params;
  const ctx = await loadTenantContext(orgSlug, 'organization.read');
  if (!ctx) {
    notFound();
  }

  const [organization, alerts] = await Promise.all([
    getOrganizationSettings(ctx),
    getNotificationSettings(ctx),
  ]);
  const canUpdate = can(ctx.membership.role, 'organization.update');
  const canManageAlerts = can(ctx.membership.role, 'notification.manage');

  return (
    <>
      <div className="page-header">
        <div>
          <p className="eyebrow">Governance</p>
          <h1>Settings</h1>
        </div>
      </div>

      <section className="card">
        <dl className="detail-grid">
          <div>
            <dt>Organization</dt>
            <dd>{organization.name}</dd>
          </div>
          <div>
            <dt>Slug</dt>
            <dd className="mono">{organization.slug}</dd>
          </div>
          <div>
            <dt>Tier</dt>
            <dd>{organization.tier.toLowerCase()}</dd>
          </div>
          <div>
            <dt>Your role</dt>
            <dd>{organization.role}</dd>
          </div>
          <div>
            <dt>Created</dt>
            <dd className="mono">{organization.createdAt.toISOString().slice(0, 10)}</dd>
          </div>
        </dl>
        <p className="small muted" style={{ marginTop: '1rem' }}>
          The slug is part of every URL and API path in this workspace and is not editable through
          the interface. Subscription tier does not gate any capability in this release.
        </p>
      </section>

      {canUpdate ? (
        <section className="card stack" style={{ marginTop: '1.5rem', maxWidth: '44rem' }}>
          <h2>Profile</h2>
          <ActionForm
            action={`/api/v1/organizations/${ctx.organization.slug}/settings`}
            method="PATCH"
            fields={[
              {
                name: 'name',
                label: 'Name',
                defaultValue: organization.name,
                required: true,
                maxLength: 80,
                full: true,
              },
              {
                name: 'description',
                label: 'Description',
                type: 'textarea',
                defaultValue: organization.description ?? '',
                maxLength: 500,
                full: true,
              },
            ]}
            submitLabel="Save settings"
            successMessage="Settings updated."
          />
        </section>
      ) : (
        <p className="banner" style={{ marginTop: '1.5rem' }}>
          Your role is read-only for organization settings.
        </p>
      )}

      <section className="card stack" style={{ marginTop: '1.5rem' }}>
        <h2>Alert destinations</h2>
        <p className="small muted">
          The scheduled sweep marks an agent OFFLINE when it misses twice its configured reporting
          interval, and queues a recovery alert when it reports again. Each delivery is signed with
          HMAC-SHA256 over <span className="mono">&lt;timestamp&gt;.&lt;body&gt;</span> in the{' '}
          <span className="mono">x-cybernorf-signature</span> header, so the receiver can prove the
          alert came from this platform.
        </p>

        {alerts.scheduling.enabled ? null : (
          <p className="banner warning">
            Scheduled delivery is not configured, so nothing is queued or retried. Set{' '}
            <span className="mono">CRON_SECRET</span> and call{' '}
            <span className="mono">GET /api/cron/notifications</span> with{' '}
            <span className="mono">Authorization: Bearer &lt;CRON_SECRET&gt;</span> once a minute
            from cron or a systemd timer.
          </p>
        )}

        {alerts.channels.length === 0 ? (
          <p className="small muted">
            No destination yet. Add one below and send a test to confirm the endpoint verifies the
            signature.
          </p>
        ) : (
          <table className="data-table">
            <thead>
              <tr>
                <th>Name</th>
                <th>Endpoint</th>
                <th>Last delivery</th>
                <th>{canManageAlerts ? 'Actions' : 'State'}</th>
              </tr>
            </thead>
            <tbody>
              {alerts.channels.map((channel) => (
                <tr key={channel.id}>
                  <td className="small">
                    {channel.name}
                    <div className="muted">
                      {channel.createdBy
                        ? `Added by ${channel.createdBy}`
                        : 'Added by a removed member'}
                    </div>
                  </td>
                  <td className="small mono">{channel.url}</td>
                  <td className="small">
                    {formatTimestamp(channel.lastDeliveredAt)}
                    {channel.lastError ? (
                      <div className="small" style={{ color: '#ffc2c8' }}>
                        {channel.lastError}
                      </div>
                    ) : null}
                  </td>
                  <td>
                    {canManageAlerts ? (
                      <NotificationChannelActions
                        orgSlug={ctx.organization.slug}
                        channelId={channel.id}
                        name={channel.name}
                      />
                    ) : (
                      <span className="small muted">
                        {channel.lastError
                          ? 'Failing'
                          : channel.lastDeliveredAt
                            ? 'Delivering'
                            : 'Idle'}
                      </span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}

        {canManageAlerts ? (
          <div style={{ maxWidth: '44rem' }}>
            <h3>Add a destination</h3>
            <p className="small muted">
              The URL must be HTTPS and resolve to a public address. The signing secret is stored
              sealed, never returned, and only the host appears in the audit trail.
            </p>
            <ActionForm
              action={`/api/v1/organizations/${ctx.organization.slug}/notification-channels`}
              fields={[
                { name: 'name', label: 'Name', required: true, maxLength: 60, full: true },
                {
                  name: 'url',
                  label: 'Endpoint URL',
                  type: 'text',
                  required: true,
                  placeholder: 'https://alerts.example.com/hooks/cybernorf',
                  maxLength: 500,
                  full: true,
                },
                {
                  name: 'secret',
                  label: 'Signing secret',
                  type: 'password',
                  required: true,
                  maxLength: 200,
                  full: true,
                  help: 'At least 32 characters. The receiver uses the same value to verify each delivery.',
                },
              ]}
              submitLabel="Add destination"
              successMessage="Destination added. Send a test to confirm it accepts deliveries."
              resetOnSuccess
            />
          </div>
        ) : (
          <p className="small muted">Only an administrator can add or remove a destination.</p>
        )}

        <h3>Recent deliveries</h3>
        {alerts.deliveries.length === 0 ? (
          <p className="small muted">
            No delivery yet. Test deliveries and agent alerts appear here with their retry state.
          </p>
        ) : (
          <table className="data-table">
            <thead>
              <tr>
                <th>Queued</th>
                <th>Event</th>
                <th>Destination</th>
                <th>Status</th>
                <th>Attempts</th>
                <th>Detail</th>
              </tr>
            </thead>
            <tbody>
              {alerts.deliveries.map((delivery) => (
                <tr key={delivery.id}>
                  <td className="small">{formatTimestamp(delivery.createdAt)}</td>
                  <td className="small mono">{delivery.type.toLowerCase()}</td>
                  <td className="small">{delivery.channel.name}</td>
                  <td>
                    <span
                      className={`badge ${
                        delivery.status === 'SENT'
                          ? 'success'
                          : delivery.status === 'FAILED'
                            ? 'denied'
                            : 'medium'
                      }`}
                    >
                      {delivery.status.toLowerCase()}
                    </span>
                  </td>
                  <td className="small">{delivery.attempts}</td>
                  <td className="small">
                    {delivery.deliveredAt
                      ? `Delivered ${formatTimestamp(delivery.deliveredAt)}`
                      : (delivery.lastError ??
                        `Next attempt ${formatTimestamp(delivery.nextAttemptAt)}`)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>
    </>
  );
}
