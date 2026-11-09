'use client';

import { useRouter } from 'next/navigation';
import { useState, type FormEvent } from 'react';
import { api, ApiClientError } from '@/lib/api-client';

export interface ControlOption {
  value: string;
  label: string;
}

/**
 * Maps one observed check to a control of an adopted framework. The check id is
 * sent verbatim: it is what future runs will report, so the mapping keeps
 * working without touching the agent.
 */
export function CheckMapForm({
  orgSlug,
  checkId,
  options,
}: {
  orgSlug: string;
  checkId: string;
  options: ControlOption[];
}) {
  const router = useRouter();
  const [value, setValue] = useState('');
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!value) {
      setError('Choose a control first.');
      return;
    }

    setPending(true);
    setError(null);
    try {
      await api.post(`/api/v1/organizations/${orgSlug}/check-maps`, {
        checkId,
        organizationControlId: value,
      });
      setValue('');
      router.refresh();
    } catch (caught) {
      setError(
        caught instanceof ApiClientError ? caught.displayMessage : 'Mapping failed. Try again.',
      );
    } finally {
      setPending(false);
    }
  }

  return (
    <form onSubmit={onSubmit} className="stack" style={{ gap: '0.35rem' }} noValidate>
      <div className="row" style={{ gap: '0.4rem' }}>
        <select
          value={value}
          onChange={(event) => setValue(event.target.value)}
          aria-label={`Control to map ${checkId} to`}
          disabled={pending}
        >
          <option value="">Map to control…</option>
          {options.map((option) => (
            <option key={option.value} value={option.value}>
              {option.label}
            </option>
          ))}
        </select>
        <button type="submit" className="secondary" disabled={pending || !value}>
          {pending ? 'Saving…' : 'Map'}
        </button>
      </div>
      {error ? (
        <span className="small" role="alert" style={{ color: '#ffc2c8' }}>
          {error}
        </span>
      ) : null}
    </form>
  );
}
