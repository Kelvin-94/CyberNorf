'use client';

import { useRouter } from 'next/navigation';
import { useState, type FormEvent } from 'react';
import { api, ApiClientError } from '@/lib/api-client';

export interface IdentityOptionMember {
  userId: string;
  name: string;
  email: string;
  role: string;
}

export interface IdentityOptionType {
  type: string;
  description: string;
  kind: 'HUMAN' | 'MACHINE';
}

export interface IdentityOptionScope {
  scope: string;
  description: string;
}

export function IdentityCreateForm({
  action,
  basePath,
  members,
  types,
  scopes,
  defaultTtlDays,
  ttlMaxDays,
}: {
  action: string;
  basePath: string;
  members: IdentityOptionMember[];
  types: IdentityOptionType[];
  scopes: IdentityOptionScope[];
  defaultTtlDays: number;
  ttlMaxDays: number;
}) {
  const router = useRouter();
  const [kind, setKind] = useState<'HUMAN' | 'MACHINE'>('MACHINE');
  const [type, setType] = useState('SERVICE_ACCOUNT');
  const [selectedScopes, setSelectedScopes] = useState<string[]>([]);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const availableTypes = types.filter((option) => option.kind === kind);
  const isMachine = kind === 'MACHINE';

  function changeKind(next: 'HUMAN' | 'MACHINE') {
    setKind(next);
    setType(next === 'HUMAN' ? 'USER' : 'SERVICE_ACCOUNT');
    setError(null);
  }

  function toggleScope(scope: string) {
    setSelectedScopes((current) =>
      current.includes(scope) ? current.filter((value) => value !== scope) : [...current, scope],
    );
  }

  async function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const text = (name: string) => {
      const value = form.get(name);
      return typeof value === 'string' ? value.trim() : '';
    };

    const payload: Record<string, unknown> = {
      kind,
      type,
      displayName: text('displayName'),
      identifier: text('identifier'),
      criticality: text('criticality') || 'MEDIUM',
    };
    for (const name of ['description', 'department', 'ownerUserId', 'linkedUserId']) {
      const value = text(name);
      if (value.length > 0) {
        payload[name] = value;
      }
    }
    if (isMachine) {
      const ttl = Number(text('credentialTtlDays'));
      if (Number.isFinite(ttl) && ttl > 0) {
        payload.credentialTtlDays = ttl;
      }
      payload.approvedScopes = selectedScopes;
    }

    setPending(true);
    setError(null);
    try {
      const result = await api.post<{ identity: { id: string } }>(action, payload);
      router.push(`${basePath}/${result.identity.id}`);
      router.refresh();
    } catch (caught) {
      setError(
        caught instanceof ApiClientError
          ? caught.displayMessage
          : 'The identity could not be created.',
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

      <div className="form-grid">
        <label className="field">
          Kind
          <select
            value={kind}
            onChange={(event) => changeKind(event.target.value as 'HUMAN' | 'MACHINE')}
            disabled={pending}
          >
            <option value="MACHINE">Non-human (workload, service, device)</option>
            <option value="HUMAN">Human (person with a console account)</option>
          </select>
          <span className="small muted">
            {isMachine
              ? 'Non-human identities start pending an owner approval and cannot sign in to the console.'
              : 'Human identities become active immediately but do not create or grant console access by themselves.'}
          </span>
        </label>

        <label className="field">
          Type
          <select
            name="type"
            value={type}
            onChange={(event) => setType(event.target.value)}
            disabled={pending}
          >
            {availableTypes.map((option) => (
              <option key={option.type} value={option.type}>
                {option.type.replaceAll('_', ' ').toLowerCase()}
              </option>
            ))}
          </select>
          <span className="small muted">
            {availableTypes.find((option) => option.type === type)?.description}
          </span>
        </label>

        <label className="field">
          Display name
          <input name="displayName" required maxLength={120} disabled={pending} />
        </label>

        <label className="field">
          Identifier
          <input
            name="identifier"
            required
            maxLength={200}
            placeholder={isMachine ? 'svc-backup-prod' : 'person@example.com'}
            disabled={pending}
          />
          <span className="small muted">
            Stored lower-cased and unique within this organization. A human identifier that matches
            an active member&apos;s email is linked automatically.
          </span>
        </label>

        <label className="field">
          Department
          <input name="department" maxLength={120} disabled={pending} />
        </label>

        <label className="field">
          Criticality
          <select name="criticality" defaultValue="MEDIUM" disabled={pending}>
            <option value="LOW">Low</option>
            <option value="MEDIUM">Medium</option>
            <option value="HIGH">High</option>
            <option value="CRITICAL">Critical</option>
          </select>
        </label>

        <label className="field">
          Accountable owner
          <select name="ownerUserId" defaultValue="" disabled={pending}>
            <option value="">No owner (flagged at risk)</option>
            {members.map((member) => (
              <option key={member.userId} value={member.userId}>
                {member.name} · {member.email}
              </option>
            ))}
          </select>
        </label>

        {isMachine ? (
          <label className="field">
            Credential lifetime (days)
            <input
              name="credentialTtlDays"
              type="number"
              min={1}
              max={ttlMaxDays}
              defaultValue={defaultTtlDays}
              disabled={pending}
            />
            <span className="small muted">Maximum {ttlMaxDays} days.</span>
          </label>
        ) : (
          <label className="field">
            Linked console account
            <select name="linkedUserId" defaultValue="" disabled={pending}>
              <option value="">None</option>
              {members.map((member) => (
                <option key={member.userId} value={member.userId}>
                  {member.name} · {member.email}
                </option>
              ))}
            </select>
            <span className="small muted">
              Links this inventory record to an existing member. It does not grant or remove access.
            </span>
          </label>
        )}

        <label className="field span-full">
          Description
          <textarea name="description" maxLength={1000} disabled={pending} />
        </label>

        {isMachine ? (
          <fieldset className="field span-full" style={{ border: 'none', padding: 0, margin: 0 }}>
            <legend className="small">Approved scopes</legend>
            <p className="small muted">
              A credential can never exceed these scopes. Leaving this empty is valid, but no
              credential can be issued until at least one scope is approved.
            </p>
            <div className="stack" style={{ gap: '0.4rem' }}>
              {scopes.map((option) => (
                <label
                  key={option.scope}
                  className="row"
                  style={{ gap: '0.5rem', alignItems: 'flex-start' }}
                >
                  <input
                    type="checkbox"
                    checked={selectedScopes.includes(option.scope)}
                    onChange={() => toggleScope(option.scope)}
                    disabled={pending}
                    style={{ width: 'auto', marginTop: '0.2rem' }}
                  />
                  <span className="small">
                    <span className="mono">{option.scope}</span>
                    <span className="muted"> — {option.description}</span>
                  </span>
                </label>
              ))}
            </div>
          </fieldset>
        ) : null}
      </div>

      <div className="row">
        <button type="submit" disabled={pending}>
          {pending ? 'Creating…' : 'Create identity'}
        </button>
      </div>
    </form>
  );
}
