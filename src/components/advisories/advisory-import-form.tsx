'use client';

import { useRouter } from 'next/navigation';
import { useState, type FormEvent } from 'react';
import { api, ApiClientError } from '@/lib/api-client';

interface ImportResult {
  created: number;
  updated: number;
  total: number;
}

const EXAMPLE = JSON.stringify(
  [
    {
      identifier: 'CVE-2024-21538',
      packageName: 'cross-spawn',
      ecosystem: 'NPM',
      summary: 'ReDoS in cross-spawn regular expression parsing',
      severity: 'HIGH',
      affectedRange: '>= 7.0.0, < 7.0.5',
      fixedVersion: '7.0.5',
      cvssScore: 7.5,
      referenceUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2024-21538',
    },
  ],
  null,
  2,
);

/**
 * Offline advisory import. The feed is pasted rather than fetched because the
 * platform deliberately has no outbound path to a vulnerability database: an
 * operator brings the data in on their own schedule and keeps the audit trail.
 */
export function AdvisoryImportForm({ orgSlug }: { orgSlug: string }) {
  const router = useRouter();
  const [text, setText] = useState('');
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  async function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);
    setNotice(null);

    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch {
      setError('That is not valid JSON. Paste the advisory array exactly as exported.');
      return;
    }

    const advisories =
      Array.isArray(parsed) && parsed.length > 0
        ? parsed
        : parsed &&
            typeof parsed === 'object' &&
            Array.isArray((parsed as { advisories?: unknown }).advisories)
          ? (parsed as { advisories: unknown[] }).advisories
          : null;

    if (!advisories) {
      setError('Provide a JSON array of advisories, or an object with an "advisories" array.');
      return;
    }

    setPending(true);
    try {
      const result = await api.post<ImportResult>(`/api/v1/organizations/${orgSlug}/advisories`, {
        advisories,
      });
      setNotice(
        `Imported ${result.total} advisor${result.total === 1 ? 'y' : 'ies'}: ${result.created} new, ${result.updated} updated.`,
      );
      setText('');
      router.refresh();
    } catch (caught) {
      setError(
        caught instanceof ApiClientError
          ? caught.displayMessage
          : 'The import failed. Check the payload and try again.',
      );
    } finally {
      setPending(false);
    }
  }

  return (
    <form onSubmit={onSubmit} className="stack">
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

      <label className="field" htmlFor="advisories">
        Advisory JSON
        <textarea
          id="advisories"
          value={text}
          onChange={(event) => setText(event.target.value)}
          rows={10}
          spellCheck={false}
          placeholder='[{"identifier":"CVE-2024-21538","packageName":"cross-spawn","ecosystem":"NPM",...}]'
        />
        <span className="small muted">
          Each row needs identifier, packageName, ecosystem, summary, severity and affectedRange.
          Optional: fixedVersion, cvssScore, referenceUrl, publishedAt. Up to 500 rows per import;
          re-importing the same identifier and package updates it instead of duplicating.
        </span>
      </label>

      <div className="row">
        <button type="submit" disabled={pending}>
          {pending ? 'Importing…' : 'Import advisories'}
        </button>
        <button type="button" className="secondary" onClick={() => setText(EXAMPLE)}>
          Insert example
        </button>
      </div>
    </form>
  );
}
