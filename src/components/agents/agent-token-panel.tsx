'use client';

import { useState } from 'react';

export interface AgentTokenPanelProps {
  agentName: string;
  token: string;
  expiresAt: string | null;
  hint: string | null;
}

/**
 * The plaintext credential exists only in this response. It is never stored, so
 * the panel is the single opportunity to copy it and says so explicitly.
 */
export function AgentTokenPanel({ agentName, token, expiresAt, hint }: AgentTokenPanelProps) {
  const [copied, setCopied] = useState(false);

  async function copy() {
    try {
      await navigator.clipboard.writeText(token);
      setCopied(true);
    } catch {
      // Clipboard access can be blocked; the token stays selectable either way.
      setCopied(false);
    }
  }

  return (
    <div className="stack" style={{ marginTop: '0.75rem' }}>
      <p className="banner warning" role="status">
        Copy this credential now. It is shown once and cannot be retrieved again.
      </p>
      <p className="small muted">
        Agent <strong>{agentName}</strong>
        {expiresAt ? ` · expires ${new Date(expiresAt).toLocaleString()}` : ''}
      </p>
      <code
        className="mono"
        style={{
          display: 'block',
          padding: '0.6rem 0.75rem',
          border: '1px solid rgba(255, 255, 255, 0.14)',
          borderRadius: '0.4rem',
          wordBreak: 'break-all',
          userSelect: 'all',
        }}
      >
        {token}
      </code>
      <div className="row">
        <button type="button" className="secondary" onClick={copy}>
          {copied ? 'Copied' : 'Copy token'}
        </button>
      </div>
      {hint ? <p className="small muted">{hint}</p> : null}
    </div>
  );
}
