'use client';

import { useRouter } from 'next/navigation';
import { useState } from 'react';
import { api, ApiClientError } from '@/lib/api-client';

export function CredentialRotate({ action }: { action: string }) {
  const router = useRouter();
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [issued, setIssued] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  async function rotate() {
    if (
      !window.confirm(
        'Rotate this credential? The current secret stops working immediately and the replacement is shown once.',
      )
    ) {
      return;
    }
    setPending(true);
    setError(null);
    setIssued(null);
    setCopied(false);
    try {
      const result = await api.post<{ token: string }>(action);
      setIssued(result.token);
      router.refresh();
    } catch (caught) {
      setError(caught instanceof ApiClientError ? caught.displayMessage : 'The rotation failed.');
    } finally {
      setPending(false);
    }
  }

  return (
    <div className="stack" style={{ gap: '0.35rem' }}>
      <button type="button" className="secondary" onClick={rotate} disabled={pending}>
        {pending ? 'Rotating…' : 'Rotate'}
      </button>
      {error ? (
        <span className="small" role="alert" style={{ color: '#ffc2c8' }}>
          {error}
        </span>
      ) : null}
      {issued ? (
        <div className="stack" style={{ gap: '0.35rem' }}>
          <span className="small">Replacement shown once:</span>
          <textarea
            readOnly
            value={issued}
            rows={2}
            className="mono"
            aria-label="Rotated credential"
            onFocus={(event) => event.currentTarget.select()}
          />
          <button
            type="button"
            className="secondary"
            onClick={async () => {
              await navigator.clipboard.writeText(issued);
              setCopied(true);
            }}
          >
            {copied ? 'Copied' : 'Copy credential'}
          </button>
        </div>
      ) : null}
    </div>
  );
}
