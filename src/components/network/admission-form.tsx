'use client';

import { useState, type FormEvent } from 'react';
import { api, ApiClientError } from '@/lib/api-client';

interface AdmissionResponse {
  decision?: {
    decision?: { verdict?: string; riskScore?: number; matchedRuleId?: string | null };
    outcome?: {
      reason?: string;
      obligations?: string[];
      explanation?: { summary?: string };
    };
  };
  admission?: {
    admitted?: boolean;
    assignedZone?: string | null;
    quarantine?: boolean;
    reason?: string;
  };
  segmentId?: string | null;
}

export interface AdmissionOption {
  value: string;
  label: string;
}

/**
 * Interactive admission test.
 *
 * Admission takes a nested subject and resource, which the generic action form
 * does not model, and the answer is a verdict plus a network consequence that
 * is worth showing in place rather than as a toast.
 */
export function AdmissionForm({
  action,
  zoneOptions,
  sensitivityOptions,
  subjectKinds,
  devices,
  members,
  connectors,
}: {
  action: string;
  zoneOptions: AdmissionOption[];
  sensitivityOptions: AdmissionOption[];
  subjectKinds: Array<'USER' | 'DEVICE' | 'IDENTITY'>;
  devices: AdmissionOption[];
  members: AdmissionOption[];
  connectors: AdmissionOption[];
}) {
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<AdmissionResponse | null>(null);
  const [subjectKind, setSubjectKind] = useState<'USER' | 'DEVICE' | 'IDENTITY'>(
    subjectKinds[0] ?? 'DEVICE',
  );

  const subjectOptions =
    subjectKind === 'USER' ? members : subjectKind === 'DEVICE' ? devices : members;

  async function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const data = new FormData(event.currentTarget);

    const deviceId = String(data.get('deviceId') ?? '').trim();
    const subjectId = String(data.get('subjectId') ?? '').trim();
    const connectorId = String(data.get('connectorId') ?? '').trim();
    const sourceAddress = String(data.get('sourceAddress') ?? '').trim();

    const payload = {
      deviceId,
      subject: { kind: subjectKind, id: subjectId },
      action: String(data.get('action') ?? 'network.admit'),
      requestedZone: String(data.get('requestedZone') ?? ''),
      sourceAddress: sourceAddress.length > 0 ? sourceAddress : null,
      connectorId: connectorId.length > 0 ? connectorId : null,
      mfaSatisfied: data.get('mfaSatisfied') !== null,
      resource: {
        type: 'network_segment',
        sensitivity: String(data.get('sensitivity') ?? 'INTERNAL'),
      },
    };

    setPending(true);
    setError(null);
    setResult(null);
    try {
      setResult(await api.post<AdmissionResponse>(action, payload));
    } catch (caught) {
      setError(caught instanceof ApiClientError ? caught.displayMessage : 'The request failed.');
    } finally {
      setPending(false);
    }
  }

  const verdict = result?.decision?.decision?.verdict;
  const admitted = result?.admission?.admitted ?? false;

  return (
    <div className="stack">
      <form onSubmit={onSubmit} className="stack" noValidate>
        {error ? (
          <p className="banner error" role="alert">
            {error}
          </p>
        ) : null}

        <div className="form-grid">
          <label className="field">
            Device
            <select name="deviceId" required defaultValue="">
              <option value="">Select a registered device…</option>
              {devices.map((device) => (
                <option key={device.value} value={device.value}>
                  {device.label}
                </option>
              ))}
            </select>
          </label>

          <label className="field">
            Subject kind
            <select
              name="subjectKind"
              value={subjectKind}
              onChange={(event) =>
                setSubjectKind(event.target.value as 'USER' | 'DEVICE' | 'IDENTITY')
              }
            >
              {subjectKinds.map((kind) => (
                <option key={kind} value={kind}>
                  {kind.toLowerCase()}
                </option>
              ))}
            </select>
          </label>

          <label className="field">
            Subject
            <select name="subjectId" required defaultValue="">
              <option value="">Select a subject…</option>
              {subjectOptions.map((option) => (
                <option key={option.value} value={option.value}>
                  {option.label}
                </option>
              ))}
            </select>
          </label>

          <label className="field">
            Action
            <input name="action" defaultValue="network.admit" />
          </label>

          <label className="field">
            Requested zone
            <select name="requestedZone" required defaultValue="CORPORATE">
              {zoneOptions.map((zone) => (
                <option key={zone.value} value={zone.value}>
                  {zone.label}
                </option>
              ))}
            </select>
          </label>

          <label className="field">
            Source address
            <input name="sourceAddress" placeholder="10.20.4.31" />
            <span className="small muted">
              Resolved to a segment here; a body-supplied zone is never trusted.
            </span>
          </label>

          <label className="field">
            Connector
            <select name="connectorId" defaultValue="">
              <option value="">No connector</option>
              {connectors.map((connector) => (
                <option key={connector.value} value={connector.value}>
                  {connector.label}
                </option>
              ))}
            </select>
          </label>

          <label className="field">
            Resource sensitivity
            <select name="sensitivity" defaultValue="INTERNAL">
              {sensitivityOptions.map((option) => (
                <option key={option.value} value={option.value}>
                  {option.label}
                </option>
              ))}
            </select>
            <span className="small muted">Overridden by the segment when one matches.</span>
          </label>

          <label
            className="field"
            style={{ flexDirection: 'row', alignItems: 'center', gap: '0.5rem' }}
          >
            <input name="mfaSatisfied" type="checkbox" style={{ width: 'auto' }} />
            <span>Second factor satisfied</span>
          </label>
        </div>

        <div className="row">
          <button type="submit" disabled={pending}>
            {pending ? 'Evaluating…' : 'Evaluate admission'}
          </button>
        </div>
      </form>

      {result ? (
        <section className="card">
          <div className="row" style={{ justifyContent: 'space-between', flexWrap: 'wrap' }}>
            <h3 style={{ margin: 0 }}>Result</h3>
            <div className="row" style={{ gap: '0.4rem' }}>
              <span
                className={`badge ${verdict === 'ALLOW' ? 'success' : verdict === 'DENY' ? 'critical' : 'medium'}`}
              >
                {verdict?.toLowerCase() ?? 'no verdict'}
              </span>
              <span className={`badge ${admitted ? 'success' : 'critical'}`}>
                {admitted ? 'admitted' : 'not admitted'}
              </span>
            </div>
          </div>
          <dl className="detail-grid" style={{ marginTop: '0.75rem' }}>
            <div>
              <dt>Network outcome</dt>
              <dd>{result.admission?.reason?.replaceAll('_', ' ') ?? '—'}</dd>
            </div>
            <div>
              <dt>Assigned zone</dt>
              <dd>{result.admission?.assignedZone?.toLowerCase() ?? '—'}</dd>
            </div>
            <div>
              <dt>Quarantine</dt>
              <dd>{result.admission?.quarantine ? 'yes' : 'no'}</dd>
            </div>
            <div>
              <dt>Risk score</dt>
              <dd>{result.decision?.decision?.riskScore ?? '—'}</dd>
            </div>
            <div>
              <dt>Matched rule</dt>
              <dd className="mono small">{result.decision?.decision?.matchedRuleId ?? 'none'}</dd>
            </div>
            <div>
              <dt>Segment</dt>
              <dd className="mono small">{result.segmentId ?? 'none'}</dd>
            </div>
          </dl>
          {result.decision?.outcome?.explanation?.summary ? (
            <p className="small muted">{result.decision.outcome.explanation.summary}</p>
          ) : null}
        </section>
      ) : null}
    </div>
  );
}
