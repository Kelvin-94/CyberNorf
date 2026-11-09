'use client';

import { useRouter } from 'next/navigation';
import { useState, type FormEvent } from 'react';
import { api, ApiClientError } from '@/lib/api-client';

const PRESET_INTERVALS: ReadonlyArray<{ minutes: number; label: string }> = [
  { minutes: 5, label: 'Every 5 minutes' },
  { minutes: 15, label: 'Every 15 minutes' },
  { minutes: 30, label: 'Every 30 minutes' },
  { minutes: 60, label: 'Every hour' },
  { minutes: 240, label: 'Every 4 hours' },
  { minutes: 720, label: 'Every 12 hours' },
  { minutes: 1440, label: 'Every day' },
];

/**
 * Cadence selector. A preset list rather than a free-text number keeps an
 * accidental `1` from turning every sweep into an outage alert, and "Off" is an
 * explicit choice instead of an empty field the browser silently omits.
 */
export function AgentHeartbeatForm({
  orgSlug,
  agentId,
  currentIntervalMinutes,
}: {
  orgSlug: string;
  agentId: string;
  currentIntervalMinutes: number | null;
}) {
  const router = useRouter();
  const options = PRESET_INTERVALS.some((preset) => preset.minutes === currentIntervalMinutes)
    ? PRESET_INTERVALS
    : currentIntervalMinutes
      ? [
          ...PRESET_INTERVALS,
          { minutes: currentIntervalMinutes, label: `Every ${currentIntervalMinutes} minutes` },
        ].sort((a, b) => a.minutes - b.minutes)
      : PRESET_INTERVALS;

  const [value, setValue] = useState(currentIntervalMinutes ? String(currentIntervalMinutes) : '');
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  async function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setPending(true);
    setError(null);
    setNotice(null);
    try {
      const expectedIntervalMinutes = value === '' ? null : Number(value);
      await api.patch(`/api/v1/organizations/${orgSlug}/agents/${agentId}`, {
        expectedIntervalMinutes,
      });
      setNotice(
        expectedIntervalMinutes === null
          ? 'Offline detection disabled for this agent.'
          : `Expecting a report every ${expectedIntervalMinutes} minutes.`,
      );
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
    <form onSubmit={onSubmit} className="stack" noValidate>
      {error ? (
        <p className="banner error" role="alert">
          {error}
        </p>
      ) : null}
      {notice ? (
        <p className="banner" role="status">
          {notice}
        </p>
      ) : null}

      <label className="field" htmlFor="expected-interval">
        Expected reporting interval
        <select
          id="expected-interval"
          name="expectedIntervalMinutes"
          value={value}
          onChange={(event) => setValue(event.target.value)}
        >
          <option value="">Off — do not watch this agent</option>
          {options.map((preset) => (
            <option key={preset.minutes} value={preset.minutes}>
              {preset.label}
            </option>
          ))}
        </select>
        <span className="small muted">
          One missed interval is STALE, two are OFFLINE and raise an alert to every enabled
          destination.
        </span>
      </label>

      <div className="row">
        <button type="submit" disabled={pending}>
          {pending ? 'Working…' : 'Save interval'}
        </button>
      </div>
    </form>
  );
}
