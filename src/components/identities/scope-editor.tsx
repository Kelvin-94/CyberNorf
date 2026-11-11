'use client';

import { useRouter } from 'next/navigation';
import { useState, type FormEvent } from 'react';
import { api, ApiClientError } from '@/lib/api-client';

export function ScopeEditor({
  action,
  scopes,
  selected,
}: {
  action: string;
  scopes: Array<{ scope: string; description: string }>;
  selected: string[];
}) {
  const router = useRouter();
  const [values, setValues] = useState<string[]>(selected);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  function toggle(scope: string) {
    setValues((current) =>
      current.includes(scope) ? current.filter((value) => value !== scope) : [...current, scope],
    );
  }

  async function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setPending(true);
    setError(null);
    setNotice(null);
    try {
      await api.patch(action, { approvedScopes: values });
      setNotice(
        'Approved scopes saved. Credentials holding a removed scope were revoked immediately.',
      );
      router.refresh();
    } catch (caught) {
      setError(
        caught instanceof ApiClientError ? caught.displayMessage : 'Could not save the scopes.',
      );
    } finally {
      setPending(false);
    }
  }

  return (
    <form onSubmit={onSubmit} className="stack" style={{ gap: '0.5rem' }}>
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
      {scopes.map((option) => (
        <label
          key={option.scope}
          className="row"
          style={{ gap: '0.5rem', alignItems: 'flex-start' }}
        >
          <input
            type="checkbox"
            checked={values.includes(option.scope)}
            onChange={() => toggle(option.scope)}
            disabled={pending}
            style={{ width: 'auto', marginTop: '0.2rem' }}
          />
          <span className="small">
            <span className="mono">{option.scope}</span>
            <span className="muted"> — {option.description}</span>
          </span>
        </label>
      ))}
      <div className="row">
        <button type="submit" className="secondary" disabled={pending}>
          {pending ? 'Saving…' : 'Save approved scopes'}
        </button>
      </div>
    </form>
  );
}
