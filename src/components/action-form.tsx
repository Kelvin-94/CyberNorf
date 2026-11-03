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
}

export interface ActionFormProps {
  action: string;
  method?: 'POST' | 'PATCH';
  fields: FormField[];
  submitLabel: string;
  successMessage?: string;
  resetOnSuccess?: boolean;
  redirectTo?: string;
  compact?: boolean;
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
    return new Date(value).toISOString();
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
}: ActionFormProps) {
  const router = useRouter();
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  async function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    const data = new FormData(form);
    const payload: Record<string, unknown> = {};

    for (const field of fields) {
      if (field.type === 'hidden') {
        continue;
      }
      const raw = data.get(field.name);
      const value = coerce(field, typeof raw === 'string' ? raw : '');
      if (value !== undefined) {
        payload[field.name] = value;
      }
    }

    setPending(true);
    setError(null);
    setNotice(null);

    try {
      if (method === 'PATCH') {
        await api.patch(action, payload);
      } else {
        await api.post(action, payload);
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
              {field.type === 'textarea' ? (
                <textarea
                  id={id}
                  name={field.name}
                  defaultValue={field.defaultValue}
                  placeholder={field.placeholder}
                  required={field.required}
                  maxLength={field.maxLength}
                />
              ) : field.type === 'select' ? (
                <select
                  id={id}
                  name={field.name}
                  defaultValue={field.defaultValue}
                  required={field.required}
                >
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
