'use client';

import { useRouter } from 'next/navigation';
import { useState, type FormEvent } from 'react';
import { api, ApiClientError } from '@/lib/api-client';

export interface FormField {
  name: string;
  label?: string;
  type?:
    | 'text'
    | 'email'
    | 'password'
    | 'number'
    | 'date'
    | 'datetime-local'
    | 'textarea'
    | 'select'
    | 'checkbox'
    | 'json'
    | 'hidden';
  options?: Array<{ value: string; label: string }>;
  placeholder?: string;
  defaultValue?: string;
  required?: boolean;
  full?: boolean;
  min?: number;
  max?: number;
  step?: number;
  maxLength?: number;
  help?: string;
  /** Renders an explicit blank option first; set it on optional selects. */
  allowEmpty?: boolean;
  rows?: number;
}

export interface ActionFormReveal {
  label: string;
  /** Dotted path into the response body, e.g. `connector.token`. */
  key: string;
}

function resolvePath(value: unknown, path: string): unknown {
  let current: unknown = value;
  for (const segment of path.split('.')) {
    if (typeof current !== 'object' || current === null || Array.isArray(current)) {
      return undefined;
    }
    current = (current as Record<string, unknown>)[segment];
  }
  return current;
}

function renderRevealed(value: unknown): string {
  if (typeof value === 'string') return value;
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  return JSON.stringify(value, null, 2);
}

export interface ActionFormProps {
  action: string;
  method?: 'POST' | 'PATCH' | 'PUT';
  fields: FormField[];
  submitLabel: string;
  successMessage?: string;
  resetOnSuccess?: boolean;
  redirectTo?: string;
  compact?: boolean;
  /** Asked before submitting; use it for actions that invalidate something. */
  confirmText?: string;
  /** Values from the response to show once, such as a registration token. */
  reveal?: ActionFormReveal[];
}

function coerce(field: FormField, raw: string): unknown {
  const value = raw.trim();
  if (value.length === 0) {
    // Empty text areas clear an optional value; other inputs are simply omitted.
    return field.type === 'textarea' ? null : undefined;
  }
  if (field.type === 'number') {
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : undefined;
  }
  if (field.type === 'datetime-local') {
    // toISOString() throws on an unparseable value, so an invalid date is sent
    // as absent and reported by server-side validation instead of crashing.
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? undefined : date.toISOString();
  }
  return value;
}

export function ActionForm({
  action,
  method = 'POST',
  fields,
  submitLabel,
  successMessage,
  resetOnSuccess = false,
  redirectTo,
  compact = false,
  confirmText,
  reveal = [],
}: ActionFormProps) {
  const router = useRouter();
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [secrets, setSecrets] = useState<Array<{ label: string; value: string }>>([]);

  async function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (confirmText && !window.confirm(confirmText)) {
      return;
    }
    const form = event.currentTarget;
    const data = new FormData(form);
    const payload: Record<string, unknown> = {};

    for (const field of fields) {
      if (field.type === 'hidden') {
        // A hidden field is part of the request, not just layout: routes such as
        // adopting a framework take the id from the payload, so omitting it made
        // those forms fail validation while looking correct in the browser.
        if (field.defaultValue !== undefined) {
          payload[field.name] = field.defaultValue;
        }
        continue;
      }
      const raw = data.get(field.name);

      if (field.type === 'checkbox') {
        payload[field.name] = raw !== null;
        continue;
      }

      if (field.type === 'json') {
        // Typed by hand, so a parse error is reported here rather than sent as a
        // string the server would reject with a less specific message.
        const text = typeof raw === 'string' ? raw.trim() : '';
        if (text.length === 0) {
          continue;
        }
        try {
          payload[field.name] = JSON.parse(text);
        } catch {
          setError(`${field.label ?? field.name} must be valid JSON.`);
          return;
        }
        continue;
      }

      const value = coerce(field, typeof raw === 'string' ? raw : '');
      if (value !== undefined) {
        payload[field.name] = value;
      }
    }

    setPending(true);
    setError(null);
    setNotice(null);
    setSecrets([]);

    try {
      const result =
        method === 'PATCH'
          ? await api.patch<unknown>(action, payload)
          : method === 'PUT'
            ? await api.put<unknown>(action, payload)
            : await api.post<unknown>(action, payload);

      if (reveal.length > 0) {
        setSecrets(
          reveal
            .map((entry) => {
              const value = resolvePath(result, entry.key);
              return value === undefined || value === null || value === ''
                ? null
                : { label: entry.label, value: renderRevealed(value) };
            })
            .filter((entry): entry is { label: string; value: string } => entry !== null),
        );
      }

      setNotice(successMessage ?? 'Saved.');
      if (resetOnSuccess) {
        form.reset();
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
      {secrets.length > 0 ? (
        <div className="note">
          <p className="small" style={{ marginTop: 0 }}>
            <strong>Copy now.</strong> These values are returned once and are not stored in readable
            form.
          </p>
          {secrets.map((entry) => (
            <p key={entry.label} className="small" style={{ margin: '0.4rem 0 0' }}>
              <span className="muted">{entry.label}:</span>{' '}
              <code className="mono" style={{ wordBreak: 'break-all' }}>
                {entry.value}
              </code>
            </p>
          ))}
        </div>
      ) : null}

      <div className={compact ? 'stack' : 'form-grid'}>
        {fields.map((field) => {
          const id = `field-${field.name}`;
          const label = field.label ?? field.name;

          if (field.type === 'hidden') {
            return (
              <input
                key={field.name}
                type="hidden"
                name={field.name}
                defaultValue={field.defaultValue}
              />
            );
          }

          return (
            <label
              className={`field${field.full ? ' span-full' : ''}`}
              key={field.name}
              htmlFor={id}
            >
              {label}
              {field.type === 'checkbox' ? (
                <input
                  id={id}
                  name={field.name}
                  type="checkbox"
                  defaultChecked={field.defaultValue === 'true'}
                  style={{ width: 'auto' }}
                />
              ) : field.type === 'textarea' || field.type === 'json' ? (
                <textarea
                  id={id}
                  name={field.name}
                  defaultValue={field.defaultValue}
                  placeholder={field.placeholder}
                  required={field.required}
                  maxLength={field.maxLength}
                  rows={field.rows ?? (field.type === 'json' ? 6 : undefined)}
                  className={field.type === 'json' ? 'mono' : undefined}
                />
              ) : field.type === 'select' ? (
                <select
                  id={id}
                  name={field.name}
                  defaultValue={field.defaultValue}
                  required={field.required}
                >
                  {field.allowEmpty ? <option value="">—</option> : null}
                  {field.options?.map((option) => (
                    <option key={option.value} value={option.value}>
                      {option.label}
                    </option>
                  ))}
                </select>
              ) : (
                <input
                  id={id}
                  name={field.name}
                  type={field.type ?? 'text'}
                  defaultValue={field.defaultValue}
                  placeholder={field.placeholder}
                  required={field.required}
                  min={field.min}
                  max={field.max}
                  step={field.step}
                  maxLength={field.maxLength}
                />
              )}
              {field.help ? <span className="small muted">{field.help}</span> : null}
            </label>
          );
        })}
      </div>

      <div className="row">
        <button type="submit" disabled={pending}>
          {pending ? 'Working…' : submitLabel}
        </button>
      </div>
    </form>
  );
}
