'use client';

import { useRouter } from 'next/navigation';
import { useState, type FormEvent } from 'react';
import { api, ApiClientError } from '@/lib/api-client';

interface ImportSkippedItem {
  index: number;
  title: string;
  reason: string;
}

interface ImportResult {
  created: number;
  updated: number;
  skipped: ImportSkippedItem[];
}

function describeReason(reason: string): string {
  switch (reason) {
    case 'asset_not_found':
      return 'the referenced asset does not belong to this organization';
    case 'asset_identifier_not_found':
      return 'the asset identifier is not registered in this organization';
    case 'duplicate_in_payload':
      return 'the same finding appears earlier in this document';
    default:
      return reason.replaceAll('_', ' ');
  }
}

/**
 * Accepts a JSON document of the form {"findings": [...]} (or a bare array) and
 * submits it to the import endpoint. Parsing happens in the browser so the
 * analyst sees a syntax error before a request is sent; the server re-validates
 * every item regardless.
 */
export function ImportFindingsForm({ action }: { action: string }) {
  const router = useRouter();
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<ImportResult | null>(null);

  async function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    const raw = String(new FormData(form).get('document') ?? '').trim();

    setError(null);
    setResult(null);

    if (raw.length === 0) {
      setError('Paste a JSON document before importing.');
      return;
    }

    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch {
      setError('The document is not valid JSON.');
      return;
    }

    const findings = Array.isArray(parsed)
      ? parsed
      : parsed !== null &&
          typeof parsed === 'object' &&
          Array.isArray((parsed as { findings?: unknown }).findings)
        ? (parsed as { findings: unknown[] }).findings
        : null;

    if (findings === null) {
      setError('Expected {"findings": [...]} or a JSON array of findings.');
      return;
    }

    setPending(true);
    try {
      const response = await api.post<ImportResult>(action, { findings });
      setResult(response);
      form.reset();
      router.refresh();
    } catch (caught) {
      setError(
        caught instanceof ApiClientError ? caught.displayMessage : 'The import failed. Try again.',
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

      {result ? (
        <div className="banner" role="status">
          <strong>
            Import complete: {result.created} created, {result.updated} updated,{' '}
            {result.skipped.length} skipped.
          </strong>
          {result.skipped.length > 0 ? (
            <ul className="small" style={{ marginTop: '0.5rem', paddingLeft: '1.1rem' }}>
              {result.skipped.slice(0, 20).map((item) => (
                <li key={`${item.index}-${item.title}`}>
                  #{item.index + 1} “{item.title}” — {describeReason(item.reason)}
                </li>
              ))}
              {result.skipped.length > 20 ? <li>…and {result.skipped.length - 20} more.</li> : null}
            </ul>
          ) : null}
        </div>
      ) : null}

      <label className="field" htmlFor="import-document">
        JSON document
        <textarea
          id="import-document"
          name="document"
          required
          spellCheck={false}
          placeholder={
            '{"findings": [{"title": "Reflected XSS in /search", "severity": "HIGH", "assetIdentifier": "app.example.com"}]}'
          }
        />
      </label>

      <div className="row">
        <button type="submit" disabled={pending}>
          {pending ? 'Importing…' : 'Import findings'}
        </button>
      </div>
    </form>
  );
}
