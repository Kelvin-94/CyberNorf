'use client';

import { useRouter } from 'next/navigation';
import { useState } from 'react';
import { api, ApiClientError } from '@/lib/api-client';

export interface ActionButtonProps {
  action: string;
  label: string;
  method?: 'POST' | 'PATCH' | 'DELETE';
  body?: unknown;
  confirmText?: string;
  variant?: 'primary' | 'secondary' | 'danger';
  redirectTo?: string;
  successMessage?: string;
}

export function ActionButton({
  action,
  label,
  method = 'POST',
  body,
  confirmText,
  variant = 'primary',
  redirectTo,
  successMessage,
}: ActionButtonProps) {
  const router = useRouter();
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  async function run() {
    if (confirmText && !window.confirm(confirmText)) {
      return;
    }
    setPending(true);
    setError(null);
    setNotice(null);
    try {
      if (method === 'DELETE') {
        await api.del(action);
      } else if (method === 'PATCH') {
        await api.patch(action, body ?? {});
      } else {
        await api.post(action, body ?? {});
      }
      if (successMessage) {
        setNotice(successMessage);
      }
      if (redirectTo) {
        router.push(redirectTo);
      }
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
    <span className="stack" style={{ gap: '0.45rem' }}>
      <button
        type="button"
        onClick={run}
        disabled={pending}
        className={variant === 'primary' ? undefined : variant}
      >
        {pending ? 'Working…' : label}
      </button>
      {error ? (
        <span className="small" role="alert" style={{ color: '#ffc2c8' }}>
          {error}
        </span>
      ) : null}
      {notice ? (
        <span className="small muted" role="status">
          {notice}
        </span>
      ) : null}
    </span>
  );
}
