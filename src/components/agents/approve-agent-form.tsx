'use client';

import { useRouter } from 'next/navigation';
import { useState, type FormEvent } from 'react';
import { api, ApiClientError } from '@/lib/api-client';
import { AgentTokenPanel } from './agent-token-panel';

export interface ScopeOption {
  value: string;
  label: string;
  detail: string;
}

interface ApproveResponse {
  agent: { name: string; scopes: string[] };
  token: string;
  tokenExpiresAt: string;
}

interface IssuedState {
  agentName: string;
  token: string;
  expiresAt: string;
}

/**
 * Approval issues the first credential for an external agent. Every scope is
 * checked by default; unchecking one narrows the grant, which is the only
 * direction the server accepts.
 */
export function ApproveAgentForm({
  orgSlug,
  agentId,
  agentName,
  scopeOptions,
}: {
  orgSlug: string;
  agentId: string;
  agentName: string;
  scopeOptions: ScopeOption[];
}) {
  const router = useRouter();
  const [selected, setSelected] = useState<string[]>(scopeOptions.map((scope) => scope.value));
  const [note, setNote] = useState('');
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [issued, setIssued] = useState<IssuedState | null>(null);

  function toggle(value: string) {
    setSelected((current) =>
      current.includes(value) ? current.filter((scope) => scope !== value) : [...current, value],
    );
  }

  async function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (selected.length === 0) {
      setError('Select at least one scope before approving.');
      return;
    }

    setPending(true);
    setError(null);

    try {
      const result = await api.post<ApproveResponse>(
        `/api/v1/organizations/${orgSlug}/agents/${agentId}/approve`,
        selected.length === scopeOptions.length
          ? { ...(note.trim().length > 0 ? { note: note.trim() } : {}) }
          : { scopes: selected, ...(note.trim().length > 0 ? { note: note.trim() } : {}) },
      );
      setIssued({
        agentName: result.agent.name,
        token: result.token,
        expiresAt: result.tokenExpiresAt,
      });
      setNote('');
      // No refresh here: approving flips the agent to ACTIVE, which replaces this
      // form with the lifecycle controls on the server render and would unmount
      // the only copy of the new credential. "Continue" refreshes instead.
    } catch (caught) {
      setError(
        caught instanceof ApiClientError ? caught.displayMessage : 'Approval failed. Try again.',
      );
    } finally {
      setPending(false);
    }
  }

  return (
    <form onSubmit={onSubmit} className="stack" noValidate>
      {error ? (
        <p className="banner error" role="alert">
          {error}
        </p>
      ) : null}

      <fieldset className="stack" style={{ border: 'none', padding: 0, margin: 0 }}>
        <legend className="small muted">Scopes granted on approval</legend>
        {scopeOptions.map((scope) => (
          <label key={scope.value} className="row" style={{ gap: '0.6rem' }}>
            <input
              type="checkbox"
              checked={selected.includes(scope.value)}
              onChange={() => toggle(scope.value)}
            />
            <span>
              <span className="mono">{scope.value}</span>
              <span className="small muted" style={{ display: 'block' }}>
                {scope.detail}
              </span>
            </span>
          </label>
        ))}
      </fieldset>

      <label className="field" htmlFor="approval-note">
        Approval note (recorded in the audit trail)
        <textarea
          id="approval-note"
          value={note}
          onChange={(event) => setNote(event.target.value)}
          maxLength={300}
        />
      </label>

      <div className="row">
        <button type="submit" disabled={pending || selected.length === 0}>
          {pending ? 'Approving…' : `Approve ${agentName}`}
        </button>
      </div>

      {issued ? (
        <AgentTokenPanel
          agentName={issued.agentName}
          token={issued.token}
          expiresAt={issued.expiresAt}
          hint="Hand this credential to the external agent operator. Approving again is not possible; revoke and re-register if it is lost."
        />
      ) : null}

      {issued ? (
        <div className="row">
          <button
            type="button"
            className="secondary"
            onClick={() => {
              setIssued(null);
              router.refresh();
            }}
          >
            Continue
          </button>
        </div>
      ) : null}
    </form>
  );
}
