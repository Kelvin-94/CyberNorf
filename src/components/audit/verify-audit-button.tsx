'use client';

import { useState } from 'react';
import { api, ApiClientError } from '@/lib/api-client';

interface VerificationReport {
  valid: boolean;
  checked: number;
  eventCount: number;
  reason?: string;
  brokenAtSequence?: number;
}

export function VerifyAuditButton({ action }: { action: string }) {
  const [pending, setPending] = useState(false);
  const [report, setReport] = useState<VerificationReport | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function verify() {
    setPending(true);
    setError(null);
    try {
      setReport(await api.get<VerificationReport>(action));
    } catch (caught) {
      setError(caught instanceof ApiClientError ? caught.displayMessage : 'Verification failed.');
    } finally {
      setPending(false);
    }
  }

  return (
    <div className="stack" style={{ gap: '0.5rem' }}>
      <div className="row">
        <button type="button" className="secondary" onClick={verify} disabled={pending}>
          {pending ? 'Verifying…' : 'Verify hash chain'}
        </button>
      </div>
      {report ? (
        <p className={report.valid ? 'banner' : 'banner error'} role="status">
          {report.valid
            ? `Chain intact across ${report.checked} events.`
            : `Chain broken at sequence ${report.brokenAtSequence ?? '?'} (${report.reason ?? 'unknown reason'}).`}
        </p>
      ) : null}
      {error ? (
        <p className="banner error" role="alert">
          {error}
        </p>
      ) : null}
    </div>
  );
}
