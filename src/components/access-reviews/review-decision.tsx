'use client';

import { useRouter } from 'next/navigation';
import { useState } from 'react';
import { api, ApiClientError } from '@/lib/api-client';

/**
 * Records one reviewer decision. The server rejects a self-decision and a
 * second decision on the same item, so the buttons stay disabled while the
 * request is in flight and after a conflict.
 */
export function ReviewDecisionControl({
  action,
  memberName,
}: {
  action: string;
  memberName: string;
}) {
  const router = useRouter();
  const [note, setNote] = useState('');
  const [pending, setPending] = useState<'RETAIN' | 'REVOKE' | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function decide(decision: 'RETAIN' | 'REVOKE') {
    if (
      decision === 'REVOKE' &&
      !window.confirm(
        `Revoke ${memberName}'s access when this review is completed? They will be removed from the organization.`,
      )
    ) {
      return;
    }
    setPending(decision);
    setError(null);
    try {
      await api.post(action, {
        decision,
        ...(note.trim().length > 0 ? { note: note.trim() } : {}),
      });
      setNote('');
      router.refresh();
    } catch (caught) {
      setError(
        caught instanceof ApiClientError ? caught.displayMessage : 'The decision was not saved.',
      );
    } finally {
      setPending(null);
    }
  }

  return (
    <div className="stack" style={{ gap: '0.35rem' }}>
      <input
        value={note}
        onChange={(event) => setNote(event.target.value)}
        placeholder="Optional note"
        maxLength={500}
        aria-label={`Decision note for ${memberName}`}
        disabled={pending !== null}
      />
      <div className="row" style={{ gap: '0.35rem' }}>
        <button
          type="button"
          className="secondary"
          onClick={() => decide('RETAIN')}
          disabled={pending !== null}
        >
          {pending === 'RETAIN' ? 'Saving…' : 'Retain'}
        </button>
        <button
          type="button"
          className="danger"
          onClick={() => decide('REVOKE')}
          disabled={pending !== null}
        >
          {pending === 'REVOKE' ? 'Saving…' : 'Revoke'}
        </button>
      </div>
      {error ? (
        <span className="small" role="alert" style={{ color: '#ffc2c8' }}>
          {error}
        </span>
      ) : null}
    </div>
  );
}
