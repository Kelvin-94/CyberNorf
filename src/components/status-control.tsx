'use client';

import { useRouter } from 'next/navigation';
import { useState, type FormEvent } from 'react';
import { api, ApiClientError } from '@/lib/api-client';

export interface StatusControlProps {
  action: string;
  current: string;
  transitions: string[];
  withNote?: boolean;
  noteLabel?: string;
}

/**
 * Presents only the transitions the server allows, so the interface mirrors the
 * state machine instead of offering moves that would be rejected.
 */
export function StatusControl({
  action,
  current,
  transitions,
  withNote = false,
  noteLabel,
}: StatusControlProps) {
  const router = useRouter();
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const data = new FormData(event.currentTarget);
    const status = String(data.get('status') ?? '');
    const note = String(data.get('note') ?? '').trim();

    setPending(true);
    setError(null);

    try {
      await api.post(action, { status, ...(note.length > 0 ? { note } : {}) });
      router.refresh();
    } catch (caught) {
      setError(
        caught instanceof ApiClientError ? caught.displayMessage : 'The status change failed.',
      );
    } finally {
      setPending(false);
    }
  }

  if (transitions.length === 0) {
    return <p className="small muted">No further status changes are available from {current}.</p>;
  }

  return (
    <form onSubmit={onSubmit} className="stack">
      {error ? (
        <p className="banner error" role="alert">
          {error}
        </p>
      ) : null}
      <div className="row">
        <label className="field" htmlFor="next-status">
          Move to
          <select id="next-status" name="status" defaultValue={transitions[0]}>
            {transitions.map((status) => (
              <option key={status} value={status}>
                {status.replaceAll('_', ' ')}
              </option>
            ))}
          </select>
        </label>
        <button type="submit" disabled={pending}>
          {pending ? 'Updating…' : 'Update status'}
        </button>
      </div>
      {withNote ? (
        <label className="field" htmlFor="status-note">
          {noteLabel ?? 'Reason (recorded in the audit trail)'}
          <textarea id="status-note" name="note" maxLength={1000} />
        </label>
      ) : null}
    </form>
  );
}
