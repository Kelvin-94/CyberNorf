'use client';

import { useRouter } from 'next/navigation';
import { useState, type FormEvent } from 'react';
import { api, ApiClientError } from '@/lib/api-client';

/** Shape of the options payload returned by the compliance options endpoint. */
export interface EvidenceTargets {
  findings: Array<{ id: string; title: string; severity: string }>;
  incidents: Array<{ id: string; title: string }>;
  assets: Array<{ id: string; name: string; identifier: string }>;
}

type EvidenceKind = 'FINDING' | 'INCIDENT' | 'ASSET' | 'REFERENCE';

const KINDS: Array<{ value: EvidenceKind; label: string }> = [
  { value: 'FINDING', label: 'Finding' },
  { value: 'INCIDENT', label: 'Incident' },
  { value: 'ASSET', label: 'Asset' },
  { value: 'REFERENCE', label: 'External reference / document' },
];

/**
 * Evidence is attached to a control by pointing at exactly one record. The
 * inputs are switched by kind so the form can only produce the shape the API
 * accepts, instead of letting the operator fill the wrong target field.
 */
export function EvidenceForm({ action, options }: { action: string; options: EvidenceTargets }) {
  const router = useRouter();
  const [kind, setKind] = useState<EvidenceKind>('FINDING');
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  async function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    const data = new FormData(form);
    const payload: Record<string, unknown> = { kind };

    const target =
      kind === 'FINDING'
        ? data.get('findingId')
        : kind === 'INCIDENT'
          ? data.get('incidentId')
          : kind === 'ASSET'
            ? data.get('assetId')
            : data.get('reference');

    if (typeof target !== 'string' || target.trim().length === 0) {
      setError('Select or enter the record this evidence points at.');
      return;
    }
    payload[kind === 'REFERENCE' ? 'reference' : `${kind.toLowerCase()}Id`] = target.trim();

    const note = data.get('note');
    if (typeof note === 'string' && note.trim().length > 0) {
      payload.note = note.trim();
    }

    setPending(true);
    setError(null);
    setNotice(null);

    try {
      await api.post(action, payload);
      setNotice('Evidence attached.');
      form.reset();
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

      <div className="row">
        <label className="field" htmlFor="evidence-kind">
          Evidence type
          <select
            id="evidence-kind"
            value={kind}
            onChange={(event) => setKind(event.target.value as EvidenceKind)}
          >
            {KINDS.map((entry) => (
              <option key={entry.value} value={entry.value}>
                {entry.label}
              </option>
            ))}
          </select>
        </label>

        {kind === 'FINDING' ? (
          <label className="field" htmlFor="evidence-finding" style={{ flex: '1 1 16rem' }}>
            Finding
            <select id="evidence-finding" name="findingId" required>
              <option value="">Select a finding…</option>
              {options.findings.map((finding) => (
                <option key={finding.id} value={finding.id}>
                  {finding.severity} · {finding.title}
                </option>
              ))}
            </select>
          </label>
        ) : null}

        {kind === 'INCIDENT' ? (
          <label className="field" htmlFor="evidence-incident" style={{ flex: '1 1 16rem' }}>
            Incident
            <select id="evidence-incident" name="incidentId" required>
              <option value="">Select an incident…</option>
              {options.incidents.map((incident) => (
                <option key={incident.id} value={incident.id}>
                  {incident.title}
                </option>
              ))}
            </select>
          </label>
        ) : null}

        {kind === 'ASSET' ? (
          <label className="field" htmlFor="evidence-asset" style={{ flex: '1 1 16rem' }}>
            Asset
            <select id="evidence-asset" name="assetId" required>
              <option value="">Select an asset…</option>
              {options.assets.map((asset) => (
                <option key={asset.id} value={asset.id}>
                  {asset.name} ({asset.identifier})
                </option>
              ))}
            </select>
          </label>
        ) : null}

        {kind === 'REFERENCE' ? (
          <label className="field" htmlFor="evidence-reference" style={{ flex: '1 1 16rem' }}>
            Reference
            <input
              id="evidence-reference"
              name="reference"
              placeholder="https://… or ticket:SEC-1042"
              maxLength={500}
              required
            />
          </label>
        ) : null}
      </div>

      <label className="field" htmlFor="evidence-note">
        Note (optional)
        <input id="evidence-note" name="note" maxLength={500} />
      </label>

      <div className="row">
        <button type="submit" disabled={pending}>
          {pending ? 'Attaching…' : 'Attach evidence'}
        </button>
      </div>
    </form>
  );
}
