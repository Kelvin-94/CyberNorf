'use client';

import { useRouter } from 'next/navigation';
import { useState, type FormEvent } from 'react';
import { api, ApiClientError } from '@/lib/api-client';
import { AgentTokenPanel } from './agent-token-panel';

interface RotateResponse {
  agent: { name: string };
  token: string;
  tokenExpiresAt: string;
}

interface IssuedState {
  agentName: string;
  token: string;
  expiresAt: string;
}

/**
 * Rotation replaces the credential in place, so the agent keeps its history and
 * its check-to-control mappings; only the token and its signing key change.
 *
 * The panel deliberately does not refresh on success: refreshing would re-render
 * the server component and unmount the only copy of the new credential.
 */
export function RotateAgentTokenForm({
  orgSlug,
  agentId,
  agentName,
  tokenPrefix,
  expiresAt,
}: {
  orgSlug: string;
  agentId: string;
  agentName: string;
  tokenPrefix: string | null;
  expiresAt: string | null;
}) {
  const router = useRouter();
  const [confirming, setConfirming] = useState(false);
  const [note, setNote] = useState('');
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [issued, setIssued] = useState<IssuedState | null>(null);

  async function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!confirming) {
      setConfirming(true);
      return;
    }

    setPending(true);
    setError(null);

    try {
      const trimmed = note.trim();
      const result = await api.post<RotateResponse>(
        `/api/v1/organizations/${orgSlug}/agents/${agentId}/rotate`,
        trimmed.length > 0 ? { note: trimmed } : {},
      );
      setIssued({
        agentName: result.agent.name,
        token: result.token,
        expiresAt: result.tokenExpiresAt,
      });
      setNote('');
      setConfirming(false);
    } catch (caught) {
      setError(
        caught instanceof ApiClientError ? caught.displayMessage : 'Rotation failed. Try again.',
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

      <p className="small muted">
        Current credential <span className="mono">{tokenPrefix ?? 'not issued'}</span>, expiring{' '}
        {expiresAt ? new Date(expiresAt).toLocaleString() : '—'}. Rotating issues a new token and
        invalidates the old one immediately, including signatures made with it. Update the
        agent&apos;s environment before its next run.
      </p>

      <label className="field" htmlFor="rotation-note">
        Rotation note (recorded in the audit trail)
        <textarea
          id="rotation-note"
          value={note}
          onChange={(event) => setNote(event.target.value)}
          maxLength={300}
        />
      </label>

      <div className="row">
        <button type="submit" className={confirming ? 'danger' : 'secondary'} disabled={pending}>
          {pending
            ? 'Rotating…'
            : confirming
              ? `Confirm rotation for ${agentName}`
              : 'Rotate token'}
        </button>
        {confirming ? (
          <button type="button" className="secondary" onClick={() => setConfirming(false)}>
            Cancel
          </button>
        ) : null}
      </div>

      {issued ? (
        <AgentTokenPanel
          agentName={issued.agentName}
          token={issued.token}
          expiresAt={issued.expiresAt}
          hint="Store this credential in the agent's environment now; it is shown once and the previous token already stopped working."
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
