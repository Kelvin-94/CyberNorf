'use client';

import Link from 'next/link';
import { useState, type FormEvent } from 'react';
import { api, ApiClientError } from '@/lib/api-client';

export interface ApiKeyOrganization {
  id: string;
  name: string;
  role: string;
}

export interface ApiKeyView {
  id: string;
  name: string;
  prefix: string;
  status: 'ACTIVE' | 'EXPIRED' | 'REVOKED';
  active: boolean;
  organization: { id: string; name: string; slug: string };
  createdAt: string;
  expiresAt: string;
  lastUsedAt: string | null;
  revokedAt: string | null;
}

interface CreatedResponse {
  key: string;
  apiKey: ApiKeyView;
}

const EXPIRY_CHOICES = [30, 90, 180, 365];
const BADGE_CLASS: Record<ApiKeyView['status'], string> = {
  ACTIVE: 'badge success',
  EXPIRED: 'badge medium',
  REVOKED: 'badge denied',
};

/** ISO timestamps are rendered in UTC so the server and client agree exactly. */
function formatTimestamp(iso: string): string {
  return `${iso.slice(0, 16).replace('T', ' ')} UTC`;
}

/**
 * Personal API keys. The plaintext credential is rendered once, immediately
 * after creation, and the list is updated from the same response so the panel
 * never needs to refetch (and never re-renders away the only copy).
 */
export function ApiKeysPanel({
  organizations,
  initialKeys,
  twoFactorEnabled,
}: {
  organizations: ApiKeyOrganization[];
  initialKeys: ApiKeyView[];
  twoFactorEnabled: boolean;
}) {
  const [keys, setKeys] = useState<ApiKeyView[]>(initialKeys);
  const [issued, setIssued] = useState<{ key: string; name: string } | null>(null);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const canCreate = twoFactorEnabled && organizations.length > 0;

  async function create(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    const data = new FormData(form);
    const name = String(data.get('name') ?? '').trim();
    const organizationId = String(data.get('organizationId') ?? '');
    const expiresInDays = Number(data.get('expiresInDays') ?? 90);

    if (organizationId.length === 0) {
      setError('Choose the organization this key may access.');
      return;
    }

    setPending(true);
    setError(null);
    setNotice(null);

    try {
      const result = await api.post<CreatedResponse>('/api/v1/me/api-keys', {
        name,
        organizationId,
        expiresInDays,
      });
      setKeys((current) => [result.apiKey, ...current]);
      setIssued({ key: result.key, name: result.apiKey.name });
      form.reset();
    } catch (caught) {
      setError(
        caught instanceof ApiClientError ? caught.displayMessage : 'Could not create the key.',
      );
    } finally {
      setPending(false);
    }
  }

  async function revoke(key: ApiKeyView) {
    const confirmed = window.confirm(
      `Revoke "${key.name}"? Any script using it stops working immediately.`,
    );
    if (!confirmed) {
      return;
    }

    setPending(true);
    setError(null);
    setNotice(null);

    try {
      const result = await api.del<{ apiKey: ApiKeyView }>(`/api/v1/me/api-keys/${key.id}`);
      setKeys((current) => current.map((row) => (row.id === key.id ? result.apiKey : row)));
      setNotice(`Revoked "${key.name}".`);
      if (issued?.name === key.name) {
        setIssued(null);
      }
    } catch (caught) {
      setError(
        caught instanceof ApiClientError ? caught.displayMessage : 'Could not revoke the key.',
      );
    } finally {
      setPending(false);
    }
  }

  return (
    <div className="stack">
      <p className="small muted">
        Keys authenticate the CyberNorf API as you, for one organization, using{' '}
        <code className="mono">Authorization: Bearer &lt;key&gt;</code>. They keep the permission of
        your current role and stop working as soon as you lose that role.
      </p>

      {twoFactorEnabled ? null : (
        <p className="banner warning" role="status">
          Two-factor authentication is required before you can create a key. Enable it above first.
        </p>
      )}

      {canCreate ? (
        <form onSubmit={create} className="stack">
          <div className="row">
            <label className="field" htmlFor="api-key-name">
              Key name
              <input
                id="api-key-name"
                name="name"
                type="text"
                required
                minLength={3}
                maxLength={60}
                placeholder="Nightly export script"
              />
            </label>
            <label className="field" htmlFor="api-key-org">
              Organization
              <select id="api-key-org" name="organizationId" defaultValue={organizations[0]?.id}>
                {organizations.map((organization) => (
                  <option key={organization.id} value={organization.id}>
                    {organization.name} ({organization.role})
                  </option>
                ))}
              </select>
            </label>
            <label className="field" htmlFor="api-key-expiry">
              Expires in
              <select id="api-key-expiry" name="expiresInDays" defaultValue={90}>
                {EXPIRY_CHOICES.map((days) => (
                  <option key={days} value={days}>
                    {days} days
                  </option>
                ))}
              </select>
            </label>
          </div>
          <div className="row">
            <button type="submit" disabled={pending}>
              {pending ? 'Working…' : 'Create API key'}
            </button>
          </div>
        </form>
      ) : null}

      {error ? (
        <p className="banner error" role="alert">
          {error}
        </p>
      ) : null}
      {notice ? (
        <p className="banner" role="status">
          {notice}
        </p>
      ) : null}

      {issued ? (
        <div className="stack">
          <p className="banner warning" role="status">
            Copy this key now. It is shown once and cannot be retrieved again.
          </p>
          <p className="small muted">Key &ldquo;{issued.name}&rdquo;</p>
          <code
            className="mono"
            style={{
              display: 'block',
              padding: '0.6rem 0.75rem',
              border: '1px solid rgba(255, 255, 255, 0.14)',
              borderRadius: '0.4rem',
              wordBreak: 'break-all',
              userSelect: 'all',
            }}
          >
            {issued.key}
          </code>
          <pre className="code-block">{`curl -H "Authorization: Bearer ${issued.key}" \\
  https://<your-cybernorf-host>/api/v1/me`}</pre>
          <div className="row">
            <button type="button" className="secondary" onClick={() => setIssued(null)}>
              I have copied it
            </button>
          </div>
        </div>
      ) : null}

      {keys.length === 0 ? (
        <p className="muted">You have no personal API keys.</p>
      ) : (
        <table className="data-table">
          <thead>
            <tr>
              <th scope="col">Name</th>
              <th scope="col">Organization</th>
              <th scope="col">Prefix</th>
              <th scope="col">Status</th>
              <th scope="col">Expires</th>
              <th scope="col">Last used</th>
              <th scope="col">Actions</th>
            </tr>
          </thead>
          <tbody>
            {keys.map((key) => (
              <tr key={key.id}>
                <td>{key.name}</td>
                <td>{key.organization.name}</td>
                <td className="mono">{key.prefix}…</td>
                <td>
                  <span className={BADGE_CLASS[key.status]}>{key.status}</span>
                </td>
                <td className="small">{formatTimestamp(key.expiresAt)}</td>
                <td className="small">
                  {key.lastUsedAt ? formatTimestamp(key.lastUsedAt) : 'Never'}
                </td>
                <td>
                  {key.active ? (
                    <button
                      type="button"
                      className="danger"
                      disabled={pending}
                      onClick={() => revoke(key)}
                    >
                      Revoke
                    </button>
                  ) : null}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      <p className="small muted">
        Need a team-wide integration instead? Manage <Link href="/app">monitoring agents</Link> from
        the console; their tokens are separate from your account.
      </p>
    </div>
  );
}
