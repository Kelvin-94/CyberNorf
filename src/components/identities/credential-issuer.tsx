'use client';

import { useRouter } from 'next/navigation';
import { useState, type FormEvent } from 'react';
import { api, ApiClientError } from '@/lib/api-client';

export function CredentialIssuer({
  action,
  approvedScopes,
  defaultTtlDays,
  ttlMaxDays,
}: {
  action: string;
  approvedScopes: string[];
  defaultTtlDays: number;
  ttlMaxDays: number;
}) {
  const router = useRouter();
  const [selected, setSelected] = useState<string[]>(approvedScopes);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [issued, setIssued] = useState<{ token: string; prefix: string } | null>(null);
  const [copied, setCopied] = useState(false);

  if (approvedScopes.length === 0) {
    return (
      <p className="banner warning">
        No scopes are approved for this identity yet. Approve at least one scope before issuing a
        credential.
      </p>
    );
  }

  function toggle(scope: string) {
    setSelected((current) =>
      current.includes(scope) ? current.filter((value) => value !== scope) : [...current, scope],
    );
  }

  async function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const name = String(form.get('name') ?? '').trim();
    const ttlRaw = String(form.get('ttlDays') ?? '').trim();
    const ttlDays = ttlRaw.length > 0 ? Number(ttlRaw) : undefined;

    setPending(true);
    setError(null);
    setIssued(null);
    setCopied(false);
    try {
      const result = await api.post<{
        token: string;
        credential: { prefix: string };
      }>(action, {
        name,
        scopes: selected,
        ...(ttlDays !== undefined && Number.isFinite(ttlDays) ? { ttlDays } : {}),
      });
      setIssued({ token: result.token, prefix: result.credential.prefix });
      router.refresh();
    } catch (caught) {
      setError(
        caught instanceof ApiClientError
          ? caught.displayMessage
          : 'The credential could not be issued.',
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
      {issued ? (
        <div className="banner success" role="status">
          <p>
            Credential <span className="mono">{issued.prefix}…</span> issued. Copy it now — it is
            shown once and cannot be recovered.
          </p>
          <textarea
            readOnly
            value={issued.token}
            rows={2}
            className="mono"
            aria-label="Issued credential"
            onFocus={(event) => event.currentTarget.select()}
          />
          <button
            type="button"
            className="secondary"
            onClick={async () => {
              await navigator.clipboard.writeText(issued.token);
              setCopied(true);
            }}
          >
            {copied ? 'Copied' : 'Copy credential'}
          </button>
        </div>
      ) : null}

      <label className="field">
        Credential name
        <input
          name="name"
          required
          maxLength={120}
          placeholder="backup-job-prod"
          disabled={pending}
        />
        <span className="small muted">Describe the workload, not the person operating it.</span>
      </label>

      <label className="field">
        Lifetime (days)
        <input
          name="ttlDays"
          type="number"
          min={1}
          max={ttlMaxDays}
          defaultValue={defaultTtlDays}
          disabled={pending}
        />
      </label>

      <fieldset style={{ border: 'none', padding: 0, margin: 0 }}>
        <legend className="small">Scopes for this credential</legend>
        <div className="stack" style={{ gap: '0.35rem' }}>
          {approvedScopes.map((scope) => (
            <label key={scope} className="row" style={{ gap: '0.5rem' }}>
              <input
                type="checkbox"
                checked={selected.includes(scope)}
                onChange={() => toggle(scope)}
                disabled={pending}
                style={{ width: 'auto' }}
              />
              <span className="mono small">{scope}</span>
            </label>
          ))}
        </div>
        <p className="small muted">
          Narrowing the selection is allowed; the credential can never exceed the identity&apos;s
          approved scopes.
        </p>
      </fieldset>

      <div className="row">
        <button type="submit" disabled={pending || selected.length === 0}>
          {pending ? 'Issuing…' : 'Issue credential'}
        </button>
      </div>
    </form>
  );
}
