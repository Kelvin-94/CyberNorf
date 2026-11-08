'use client';

import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { useState, type FormEvent } from 'react';
import { api, ApiClientError } from '@/lib/api-client';
import { AgentTokenPanel } from './agent-token-panel';

const SOURCE_OPTIONS = [
  { value: 'BUILTIN', label: 'Builtin monitor (scripts/agent/monitor.mjs)' },
  { value: 'OPENAI', label: 'OpenAI / ChatGPT' },
  { value: 'ANTHROPIC', label: 'Anthropic / Claude' },
  { value: 'CUSTOM', label: 'Custom script or platform' },
  { value: 'OTHER', label: 'Other market source' },
] as const;

interface RegisterResponse {
  agent: { id: string; name: string; source: string; status: string };
  token: string | null;
  tokenExpiresAt: string | null;
}

interface IssuedState {
  agentId: string;
  agentName: string;
  token: string;
  expiresAt: string | null;
}

export function RegisterAgentForm({ orgSlug }: { orgSlug: string }) {
  const router = useRouter();
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [issued, setIssued] = useState<IssuedState | null>(null);
  const [awaiting, setAwaiting] = useState<string | null>(null);

  async function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    const data = new FormData(form);
    const description = String(data.get('description') ?? '').trim();

    setPending(true);
    setError(null);
    setIssued(null);
    setAwaiting(null);

    try {
      const result = await api.post<RegisterResponse>(`/api/v1/organizations/${orgSlug}/agents`, {
        name: String(data.get('name') ?? '').trim(),
        source: String(data.get('source') ?? 'BUILTIN'),
        ...(description.length > 0 ? { description } : {}),
      });

      if (result.token) {
        setIssued({
          agentId: result.agent.id,
          agentName: result.agent.name,
          token: result.token,
          expiresAt: result.tokenExpiresAt,
        });
        // The credential lives in client state, so re-rendering the server list
        // keeps the reveal on screen while the counters catch up.
        router.refresh();
      } else {
        // External agents are created inert: no credential exists until an
        // owner approves the specific agent.
        setAwaiting(
          `“${result.agent.name}” is registered and waits for the organization owner to approve it. No credential has been issued yet.`,
        );
        router.refresh();
      }
      form.reset();
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
      {awaiting ? (
        <p className="banner" role="status">
          {awaiting}
        </p>
      ) : null}

      <div className="form-grid">
        <label className="field" htmlFor="agent-name">
          Name
          <input
            id="agent-name"
            name="name"
            required
            maxLength={60}
            placeholder="build-host-monitor"
          />
        </label>
        <label className="field" htmlFor="agent-source">
          Source
          <select id="agent-source" name="source" defaultValue="BUILTIN">
            {SOURCE_OPTIONS.map((option) => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </select>
        </label>
        <label className="field span-full" htmlFor="agent-description">
          Description
          <textarea
            id="agent-description"
            name="description"
            maxLength={500}
            placeholder="What this agent checks and where it runs"
          />
        </label>
      </div>

      <p className="small muted">
        Both scopes are requested by default: <span className="mono">monitor.report</span> and{' '}
        <span className="mono">monitor.read</span>. Approval can only narrow that set.
      </p>

      <div className="row">
        <button type="submit" disabled={pending}>
          {pending ? 'Registering…' : 'Register agent'}
        </button>
      </div>

      {issued ? (
        <>
          <AgentTokenPanel
            agentName={issued.agentName}
            token={issued.token}
            expiresAt={issued.expiresAt}
            hint="Run: CYBERNORF_AGENT_TOKEN=<token> node scripts/agent/monitor.mjs --org-url <your CyberNorf URL>"
          />
          <div className="row" style={{ gap: '0.75rem' }}>
            <button
              type="button"
              className="secondary"
              onClick={() => {
                setIssued(null);
                router.refresh();
              }}
            >
              Continue
            </button>
            <Link href={`/app/${orgSlug}/agents/${issued.agentId}`}>Open the agent record</Link>
          </div>
        </>
      ) : null}
    </form>
  );
}
