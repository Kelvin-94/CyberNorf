'use client';

import { useRouter } from 'next/navigation';
import { useState } from 'react';
import { api, ApiClientError } from '@/lib/api-client';

/**
 * Deleting an advisory stops it matching future runs. Findings it already raised
 * are left in place so triage happens in the finding, not by deleting evidence.
 */
export function AdvisoryDeleteButton({
  orgSlug,
  advisoryId,
  label,
}: {
  orgSlug: string;
  advisoryId: string;
  label: string;
}) {
  const router = useRouter();
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function remove() {
    if (!window.confirm(`Remove advisory ${label}? Future runs will stop matching it.`)) {
      return;
    }
    setPending(true);
    setError(null);
    try {
      await api.del(`/api/v1/organizations/${orgSlug}/advisories/${advisoryId}`);
      router.refresh();
    } catch (caught) {
      setError(
        caught instanceof ApiClientError ? caught.displayMessage : 'The request failed. Try again.',
      );
    } finally {
      setPending(false);
    }
  }

  return (
    <>
      <button type="button" className="secondary" onClick={remove} disabled={pending}>
        {pending ? 'Removing…' : 'Remove'}
      </button>
      {error ? (
        <p className="banner error" role="alert">
          {error}
        </p>
      ) : null}
    </>
  );
}
