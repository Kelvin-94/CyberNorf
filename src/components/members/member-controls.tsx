'use client';

import { useRouter } from 'next/navigation';
import { useState } from 'react';
import { api, ApiClientError } from '@/lib/api-client';

const ROLES = ['OWNER', 'ADMIN', 'ANALYST', 'VIEWER'];

export function MemberControls({
  action,
  role,
  assignableRoles,
}: {
  action: string;
  role: string;
  assignableRoles: string[];
}) {
  const router = useRouter();
  const [value, setValue] = useState(role);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  async function saveRole() {
    setPending(true);
    setError(null);
    setNotice(null);
    try {
      await api.patch(action, { role: value });
      setNotice('Role updated.');
      router.refresh();
    } catch (caught) {
      setError(
        caught instanceof ApiClientError ? caught.displayMessage : 'Could not change the role.',
      );
    } finally {
      setPending(false);
    }
  }

  async function remove() {
    if (!window.confirm('Remove this member? Their sessions are revoked immediately.')) {
      return;
    }
    setPending(true);
    setError(null);
    try {
      await api.del(action);
      router.refresh();
    } catch (caught) {
      setError(
        caught instanceof ApiClientError ? caught.displayMessage : 'Could not remove the member.',
      );
    } finally {
      setPending(false);
    }
  }

  return (
    <div className="stack" style={{ gap: '0.4rem' }}>
      <div className="row" style={{ gap: '0.4rem' }}>
        <select
          value={value}
          onChange={(event) => setValue(event.target.value)}
          aria-label="Role"
          style={{ width: 'auto' }}
          disabled={pending}
        >
          {ROLES.map((option) => (
            <option key={option} value={option} disabled={!assignableRoles.includes(option)}>
              {option}
            </option>
          ))}
        </select>
        <button
          type="button"
          className="secondary"
          onClick={saveRole}
          disabled={pending || value === role}
        >
          Save
        </button>
        <button type="button" className="danger" onClick={remove} disabled={pending}>
          Remove
        </button>
      </div>
      {error ? (
        <span className="small" role="alert" style={{ color: '#ffc2c8' }}>
          {error}
        </span>
      ) : null}
      {notice ? (
        <span className="small muted" role="status">
          {notice}
        </span>
      ) : null}
    </div>
  );
}
