import { createHash, randomBytes } from 'node:crypto';
import type { AgentRunStatus, AgentSource, AgentStatus } from '@/generated/prisma/client';

/**
 * Agent domain rules.
 *
 * Monitoring agents run where the monitored hosts are, which may be a network
 * with no outbound Internet access at all. CyberNorf therefore never calls a
 * model provider: the builtin agent collects evidence locally and the same
 * scoped report endpoint accepts runs from any external agent (ChatGPT, Claude,
 * a custom script) that an operator chose to connect. Credentials are bearer
 * tokens, so every rule about scope, lifetime and approval lives here rather
 * than in the route handlers.
 */

export const AGENT_SOURCES = ['BUILTIN', 'OPENAI', 'ANTHROPIC', 'CUSTOM', 'OTHER'] as const;

/** What an agent credential is allowed to do. Requests outside this set fail. */
export const AGENT_SCOPES = ['monitor.report', 'monitor.read'] as const;
export type AgentScope = (typeof AGENT_SCOPES)[number];

export const AGENT_SCOPE_DETAILS: Readonly<Record<AgentScope, string>> = {
  'monitor.report': 'Submit monitoring runs and raise findings from failed checks.',
  'monitor.read': 'Read the agent record and its own run history.',
};

export const TOKEN_PREFIX = 'cna_';
const TOKEN_RANDOM_BYTES = 32;
/** Characters of the token kept in clear for display, after the `cna_` prefix. */
const TOKEN_DISPLAY_CHARS = 6;

/** Builtin agents are installed by an operator on their own host. */
export const BUILTIN_TOKEN_TTL_DAYS = 365;
/** External agents are third-party integrations, so their tokens rotate sooner. */
export const EXTERNAL_TOKEN_TTL_DAYS = 90;

export const AGENT_STATUS_TRANSITIONS: Readonly<Record<AgentStatus, readonly AgentStatus[]>> = {
  PENDING_APPROVAL: ['ACTIVE', 'REVOKED'],
  ACTIVE: ['SUSPENDED', 'REVOKED'],
  SUSPENDED: ['ACTIVE', 'REVOKED'],
  REVOKED: [],
};

export interface IssuedAgentToken {
  /** Plaintext credential. Returned to the caller exactly once, never stored. */
  token: string;
  /** SHA-256 of the token, which is what the database keeps. */
  hash: string;
  /** Short clear-text display prefix, e.g. `cna_8Kd2xQ`. */
  prefix: string;
  expiresAt: Date;
}

export function hashAgentToken(token: string): string {
  return createHash('sha256').update(token, 'utf8').digest('hex');
}

/** Cheap shape check so malformed Authorization headers never touch the database. */
export function isAgentTokenShape(token: string): boolean {
  return /^cna_[A-Za-z0-9_-]{40,64}$/.test(token);
}

export function agentTokenTtlDays(source: AgentSource): number {
  return source === 'BUILTIN' ? BUILTIN_TOKEN_TTL_DAYS : EXTERNAL_TOKEN_TTL_DAYS;
}

export function issueAgentToken(source: AgentSource, now: Date = new Date()): IssuedAgentToken {
  const token = `${TOKEN_PREFIX}${randomBytes(TOKEN_RANDOM_BYTES).toString('base64url')}`;
  const ttlMs = agentTokenTtlDays(source) * 24 * 60 * 60 * 1000;

  return {
    token,
    hash: hashAgentToken(token),
    prefix: token.slice(0, TOKEN_PREFIX.length + TOKEN_DISPLAY_CHARS),
    expiresAt: new Date(now.getTime() + ttlMs),
  };
}

export function canTransitionAgent(from: AgentStatus, to: AgentStatus): boolean {
  return AGENT_STATUS_TRANSITIONS[from].includes(to);
}

/**
 * Builtin agents are registered by an OWNER or ADMIN and run against hosts the
 * organization already owns, so they start working immediately. Every external
 * source stays inert until an OWNER approves the specific agent.
 */
export function initialAgentStatus(source: AgentSource): AgentStatus {
  return source === 'BUILTIN' ? 'ACTIVE' : 'PENDING_APPROVAL';
}

/**
 * Both scopes are granted by default so an agent can verify its own credential
 * and read its run history. Approval can narrow the set, and nothing outside it
 * is reachable.
 */
export function defaultAgentScopes(): AgentScope[] {
  return ['monitor.report', 'monitor.read'];
}

export function isAgentScope(value: string): value is AgentScope {
  return (AGENT_SCOPES as readonly string[]).includes(value);
}

export function agentHasScope(scopes: readonly string[], scope: AgentScope): boolean {
  return scopes.includes(scope);
}

export interface AgentCheckCounts {
  checkCount: number;
  passCount: number;
  failCount: number;
  skipCount: number;
}

/**
 * A run is PARTIAL when any check could not be evaluated (for example a
 * platform-specific command that is missing) and FAILED when the agent could
 * not evaluate anything at all, which is the signal that a host is unmonitored.
 */
export function runStatusForCounts(counts: AgentCheckCounts): AgentRunStatus {
  if (counts.checkCount === 0) {
    return 'FAILED';
  }
  return counts.skipCount > 0 ? 'PARTIAL' : 'COMPLETED';
}

export function summarizeChecks(statuses: readonly string[]): AgentCheckCounts {
  let passCount = 0;
  let failCount = 0;
  let skipCount = 0;
  for (const status of statuses) {
    if (status === 'PASS') {
      passCount += 1;
    } else if (status === 'FAIL') {
      failCount += 1;
    } else {
      skipCount += 1;
    }
  }
  return { checkCount: statuses.length, passCount, failCount, skipCount };
}
