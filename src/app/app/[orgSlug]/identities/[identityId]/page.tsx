import type { Metadata } from 'next';
import Link from 'next/link';
import { notFound } from 'next/navigation';
import { ActionButton } from '@/components/action-button';
import { ActionForm } from '@/components/action-form';
import { CredentialIssuer } from '@/components/identities/credential-issuer';
import { CredentialRotate } from '@/components/identities/credential-rotate';
import { ScopeEditor } from '@/components/identities/scope-editor';
import { can } from '@/server/authz/roles';
import {
  CREDENTIAL_TTL_MAX_DAYS,
  IDENTITY_CREDENTIAL_SCOPE_DETAILS,
  IDENTITY_CREDENTIAL_SCOPES,
  canTransitionIdentity,
} from '@/server/domain/identity';
import { getIdentityDetail, listAssignableMembers } from '@/server/services/identities';
import { loadTenantContext } from '@/server/ui/session';

export const metadata: Metadata = { title: 'Identity · CyberNorf' };
export const dynamic = 'force-dynamic';

const STATUS_BADGES: Record<string, string> = {
  ACTIVE: 'success',
  PENDING_APPROVAL: 'medium',
  SUSPENDED: 'denied',
  DEPROVISIONED: 'low',
};

const RISK_BADGES: Record<string, string> = {
  LOW: 'low',
  MEDIUM: 'medium',
  HIGH: 'high',
  CRITICAL: 'critical',
};

function formatDate(value: string | null): string {
  return value ? new Date(value).toLocaleString() : '—';
}

export default async function IdentityDetailPage({
  params,
}: {
  params: Promise<{ orgSlug: string; identityId: string }>;
}) {
  const { orgSlug, identityId } = await params;
  const ctx = await loadTenantContext(orgSlug, 'identity.read');
  if (!ctx) {
    notFound();
  }

  const identity = await getIdentityDetail(ctx.organization.id, identityId);
  const base = `/app/${ctx.organization.slug}`;
  const apiBase = `/api/v1/organizations/${ctx.organization.slug}/identities/${identity.id}`;
  const canManage = can(ctx.membership.role, 'identity.manage');
  const isOwner = ctx.membership.role === 'OWNER';
  const isMachine = identity.kind === 'MACHINE';
  const members = canManage ? await listAssignableMembers(ctx.organization.id) : [];

  const canApprove =
    isMachine &&
    isOwner &&
    canTransitionIdentity(identity.status, 'ACTIVE') &&
    identity.status === 'PENDING_APPROVAL';
  const canSuspend = canTransitionIdentity(identity.status, 'SUSPENDED');
  const canReactivate =
    canTransitionIdentity(identity.status, 'ACTIVE') && identity.status === 'SUSPENDED';
  const canDeprovision = canTransitionIdentity(identity.status, 'DEPROVISIONED');

  return (
    <>
      <div className="page-header">
        <div>
          <p className="eyebrow">
            <Link href={`${base}/identities`}>Identities</Link> /{' '}
            {identity.type.replaceAll('_', ' ')}
          </p>
          <h1>{identity.displayName}</h1>
          <p className="small muted" style={{ marginTop: '0.35rem' }}>
            <span className={`badge ${STATUS_BADGES[identity.status] ?? ''}`}>
              {identity.status.replaceAll('_', ' ').toLowerCase()}
            </span>{' '}
            <span className="mono">{identity.identifier}</span>
          </p>
        </div>
      </div>

      {identity.status === 'PENDING_APPROVAL' ? (
        <p className="banner warning">
          This identity cannot authenticate yet.{' '}
          {isOwner ? 'Approve it below to activate it.' : 'An organization owner must approve it.'}
        </p>
      ) : null}

      <div className="grid">
        <div className="stat">
          <p className="stat-label">Risk</p>
          <p className="stat-value">
            <span className={`badge ${RISK_BADGES[identity.risk.level] ?? ''}`}>
              {identity.risk.level.toLowerCase()} · {identity.risk.score}
            </span>
          </p>
          <p className="small muted">
            {identity.risk.signals[0]?.detail ?? 'No risk signals observed.'}
          </p>
        </div>
        <div className="stat">
          <p className="stat-label">Criticality</p>
          <p className="stat-value">
            <span className={`badge ${RISK_BADGES[identity.criticality] ?? ''}`}>
              {identity.criticality.toLowerCase()}
            </span>
          </p>
          <p className="small muted">Declared business impact</p>
        </div>
        <div className="stat">
          <p className="stat-label">Accountable owner</p>
          <p className="stat-value small">{identity.owner?.name ?? 'Unowned'}</p>
          <p className="small muted">{identity.owner?.email ?? 'Assign an owner to reduce risk'}</p>
        </div>
        <div className="stat">
          <p className="stat-label">Linked console account</p>
          <p className="stat-value small">{identity.linkedUser?.name ?? 'Not linked'}</p>
          <p className="small muted">
            {identity.linkedUser?.email ?? 'This record is inventory-only'}
          </p>
        </div>
      </div>

      {canManage ? (
        <section className="card" style={{ marginTop: '1.5rem' }}>
          <h2>Lifecycle</h2>
          <p className="small muted">
            Every action is written to the tenant audit chain and this identity&apos;s timeline.
            Suspension and deprovisioning revoke all credentials in the same transaction.
          </p>
          <div className="row" style={{ gap: '0.5rem', flexWrap: 'wrap' }}>
            {canApprove ? (
              <ActionButton
                action={`${apiBase}/lifecycle`}
                label="Approve identity"
                body={{ action: 'APPROVE' }}
                confirmText={`Approve ${identity.displayName}? It will be able to authenticate with an issued credential.`}
                successMessage="Identity approved."
              />
            ) : null}
            {canSuspend ? (
              <ActionButton
                action={`${apiBase}/lifecycle`}
                label="Suspend"
                body={{ action: 'SUSPEND' }}
                variant="danger"
                confirmText={`Suspend ${identity.displayName} and revoke all of its credentials immediately?`}
                successMessage="Identity suspended."
              />
            ) : null}
            {canReactivate ? (
              <ActionButton
                action={`${apiBase}/lifecycle`}
                label="Reactivate"
                body={{ action: 'REACTIVATE' }}
                variant="secondary"
                successMessage="Identity reactivated."
              />
            ) : null}
            {canDeprovision ? (
              <ActionButton
                action={`${apiBase}/lifecycle`}
                label="Deprovision"
                body={{ action: 'DEPROVISION' }}
                variant="danger"
                confirmText={`Deprovision ${identity.displayName}? This is terminal and revokes every credential.`}
                successMessage="Identity deprovisioned."
              />
            ) : null}
            {!canApprove && !canSuspend && !canReactivate && !canDeprovision ? (
              <span className="small muted">No lifecycle transition is available.</span>
            ) : null}
          </div>
          {isMachine && !isOwner && identity.status === 'PENDING_APPROVAL' ? (
            <p className="small muted" style={{ marginTop: '0.5rem' }}>
              Only an owner sees the approval action.
            </p>
          ) : null}
        </section>
      ) : null}

      <section className="card" style={{ marginTop: '1.5rem' }}>
        <h2>Activity</h2>
        {isMachine ? (
          <p className="small muted">
            Derived from credential use. Last seen {formatDate(identity.lastSeenAt)}.
          </p>
        ) : (
          <div className="grid">
            <div className="stat">
              <p className="stat-label">Last sign-in</p>
              <p className="stat-value small">{formatDate(identity.activity.lastSignInAt)}</p>
            </div>
            <div className="stat">
              <p className="stat-label">Failed sign-ins (24h)</p>
              <p className="stat-value">{identity.activity.failedSignInsLast24h}</p>
            </div>
            <div className="stat">
              <p className="stat-label">Active sessions</p>
              <p className="stat-value">{identity.activity.activeSessions}</p>
              <p className="small muted">
                Last session {formatDate(identity.activity.lastSessionAt)}
              </p>
            </div>
            <div className="stat">
              <p className="stat-label">Inventory since</p>
              <p className="stat-value small">{formatDate(identity.createdAt)}</p>
            </div>
          </div>
        )}
        {identity.description ? <p className="small">{identity.description}</p> : null}
      </section>

      {canManage ? (
        <section className="card" style={{ marginTop: '1.5rem', maxWidth: '52rem' }}>
          <h2>Edit details</h2>
          <p className="small muted">
            Changing the approved scopes revokes any credential that holds a scope being removed.
          </p>
          <ActionForm
            action={apiBase}
            method="PATCH"
            fields={[
              {
                name: 'displayName',
                label: 'Display name',
                required: true,
                defaultValue: identity.displayName,
              },
              {
                name: 'department',
                label: 'Department',
                defaultValue: identity.department ?? '',
              },
              {
                name: 'criticality',
                label: 'Criticality',
                type: 'select',
                defaultValue: identity.criticality,
                options: [
                  { value: 'LOW', label: 'Low' },
                  { value: 'MEDIUM', label: 'Medium' },
                  { value: 'HIGH', label: 'High' },
                  { value: 'CRITICAL', label: 'Critical' },
                ],
              },
              {
                name: 'ownerUserId',
                label: 'Accountable owner',
                type: 'select',
                defaultValue: identity.owner?.id ?? '',
                options: [
                  { value: '', label: 'No owner (flagged at risk)' },
                  ...members.map((member) => ({
                    value: member.userId,
                    label: `${member.name} · ${member.email}`,
                  })),
                ],
              },
              {
                name: 'description',
                label: 'Description',
                type: 'textarea',
                full: true,
                defaultValue: identity.description ?? '',
              },
              ...(isMachine
                ? [
                    {
                      name: 'credentialTtlDays',
                      label: 'Default credential lifetime (days)',
                      type: 'number' as const,
                      min: 1,
                      max: CREDENTIAL_TTL_MAX_DAYS,
                      defaultValue: String(identity.credentialTtlDays),
                    },
                  ]
                : []),
            ]}
            submitLabel="Save details"
            successMessage="Identity updated."
          />

          {isMachine ? (
            <>
              <h3 style={{ marginTop: '1.5rem' }}>Approved scopes</h3>
              <ScopeEditor
                action={apiBase}
                scopes={IDENTITY_CREDENTIAL_SCOPES.map((scope) => ({
                  scope,
                  description: IDENTITY_CREDENTIAL_SCOPE_DETAILS[scope],
                }))}
                selected={identity.approvedScopes}
              />
            </>
          ) : null}
        </section>
      ) : null}

      {isMachine ? (
        <section className="card" style={{ marginTop: '1.5rem' }}>
          <h2>Machine credentials</h2>
          <p className="small muted">
            Only a SHA-256 hash is stored. A credential is shown once when issued or rotated, and it
            authenticates only through <span className="mono">GET /api/v1/identity/me</span> with
            the <span className="mono">identity.self.read</span> scope.
          </p>

          {identity.status === 'ACTIVE' && canManage ? (
            <div style={{ maxWidth: '34rem', marginBottom: '1rem' }}>
              <CredentialIssuer
                action={`${apiBase}/credentials`}
                approvedScopes={identity.approvedScopes}
                defaultTtlDays={identity.credentialTtlDays}
                ttlMaxDays={CREDENTIAL_TTL_MAX_DAYS}
              />
            </div>
          ) : null}

          {identity.credentials.length === 0 ? (
            <p className="small muted">No credentials have been issued.</p>
          ) : (
            <table className="data-table">
              <thead>
                <tr>
                  <th>Credential</th>
                  <th>Scopes</th>
                  <th>Status</th>
                  <th>Expires</th>
                  <th>Last used</th>
                  {canManage ? <th>Actions</th> : null}
                </tr>
              </thead>
              <tbody>
                {identity.credentials.map((credential) => (
                  <tr key={credential.id}>
                    <td>
                      {credential.name}
                      <div className="mono small muted">{credential.prefix}…</div>
                    </td>
                    <td className="mono small">{credential.scopes.join(', ')}</td>
                    <td>
                      <span
                        className={`badge ${
                          credential.status === 'ACTIVE'
                            ? 'success'
                            : credential.status === 'EXPIRED'
                              ? 'medium'
                              : 'denied'
                        }`}
                      >
                        {credential.status.toLowerCase()}
                      </span>
                      {credential.revokedReason ? (
                        <div className="small muted">
                          {credential.revokedReason.replaceAll('_', ' ')}
                        </div>
                      ) : null}
                    </td>
                    <td className="small">{formatDate(credential.expiresAt)}</td>
                    <td className="small">{formatDate(credential.lastUsedAt)}</td>
                    {canManage ? (
                      <td>
                        {credential.status === 'REVOKED' ? (
                          <span className="small muted">—</span>
                        ) : (
                          <div className="stack" style={{ gap: '0.4rem' }}>
                            <CredentialRotate
                              action={`${apiBase}/credentials/${credential.id}/rotate`}
                            />
                            <ActionButton
                              action={`${apiBase}/credentials/${credential.id}`}
                              method="DELETE"
                              label="Revoke"
                              variant="danger"
                              confirmText={`Revoke ${credential.prefix}…? Any workload using it stops authenticating immediately.`}
                              successMessage="Credential revoked."
                            />
                          </div>
                        )}
                      </td>
                    ) : null}
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </section>
      ) : null}

      <section className="card" style={{ marginTop: '1.5rem' }}>
        <h2>Timeline</h2>
        {identity.events.length === 0 ? (
          <p className="small muted">No events recorded.</p>
        ) : (
          <table className="data-table">
            <thead>
              <tr>
                <th>When</th>
                <th>Event</th>
                <th>Actor</th>
                <th>Detail</th>
              </tr>
            </thead>
            <tbody>
              {identity.events.map((event) => (
                <tr key={event.id}>
                  <td className="small">{formatDate(event.createdAt)}</td>
                  <td>
                    <span className="badge">{event.type.replaceAll('_', ' ').toLowerCase()}</span>
                  </td>
                  <td className="small">{event.actor?.name ?? 'System'}</td>
                  <td className="small">
                    {event.summary ?? '—'}
                    {event.metadata ? (
                      <details>
                        <summary className="muted">Metadata</summary>
                        <pre className="mono small">{JSON.stringify(event.metadata, null, 2)}</pre>
                      </details>
                    ) : null}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>

      <p className="small muted" style={{ marginTop: '1rem' }}>
        Created {formatDate(identity.createdAt)} by {identity.createdBy?.name ?? 'System'} ·
        approved {formatDate(identity.approvedAt)}
        {identity.approvedBy ? ` by ${identity.approvedBy.name}` : ''}
      </p>
    </>
  );
}
