'use client';

import { useRouter } from 'next/navigation';
import { useState } from 'react';
import { api, ApiClientError } from '@/lib/api-client';

interface TestResponse {
  delivery: { status: 'SENT' | 'PENDING' | 'FAILED'; error: string | null };
}

/**
 * Test and remove controls for one alert destination.
 *
 * A test delivery's result is the whole point of the button, so unlike the
 * generic action button this one reports what the endpoint answered instead of
 * a fixed success message.
 */
export function NotificationChannelActions({
  orgSlug,
  channelId,
  name,
}: {
  orgSlug: string;
  channelId: string;
  name: string;
}) {
  const router = useRouter();
  const [pending, setPending] = useState<'test' | 'delete' | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const base = `/api/v1/organizations/${orgSlug}/notification-channels/${channelId}`;

  async function sendTest() {
    setPending('test');
    setError(null);
    setMessage(null);
    try {
      const result = await api.post<TestResponse>(`${base}/test`);
      if (result.delivery.status === 'SENT') {
        setMessage('Delivered. The endpoint answered 2xx and the signature verified there.');
      } else if (result.delivery.status === 'PENDING') {
        setMessage(
          `Not delivered yet: ${result.delivery.error ?? 'the endpoint did not accept it'}. The sweep retries with backoff.`,
        );
      } else {
        setError(result.delivery.error ?? 'The endpoint refused the delivery.');
      }
      router.refresh();
    } catch (caught) {
      setError(
        caught instanceof ApiClientError ? caught.displayMessage : 'The request failed. Try again.',
      );
    } finally {
      setPending(null);
    }
  }

  async function remove() {
    if (
      !window.confirm(
        `Delete the alert destination "${name}"? Queued and past deliveries for it are removed too.`,
      )
    ) {
      return;
    }
    setPending('delete');
    setError(null);
    setMessage(null);
    try {
      await api.del(base);
      router.refresh();
    } catch (caught) {
      setError(
        caught instanceof ApiClientError ? caught.displayMessage : 'The request failed. Try again.',
      );
    } finally {
      setPending(null);
    }
  }

  return (
    <div className="stack" style={{ gap: '0.4rem' }}>
      <div className="row" style={{ flexWrap: 'wrap', gap: '0.5rem' }}>
        <button type="button" className="secondary" onClick={sendTest} disabled={pending !== null}>
          {pending === 'test' ? 'Sending…' : 'Send test'}
        </button>
        <button type="button" className="danger" onClick={remove} disabled={pending !== null}>
          {pending === 'delete' ? 'Working…' : 'Delete'}
        </button>
      </div>
      {error ? (
        <span className="small" role="alert" style={{ color: '#ffc2c8' }}>
          {error}
        </span>
      ) : null}
      {message ? (
        <span className="small muted" role="status">
          {message}
        </span>
      ) : null}
    </div>
  );
}
