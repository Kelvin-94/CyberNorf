import { createHash, createHmac, timingSafeEqual } from 'node:crypto';

/**
 * Request signing for agent submissions.
 *
 * A bearer token authenticates the caller but says nothing about the body that
 * arrived: a captured submission can be replayed, and a token that leaks through
 * a proxy log is enough to inject findings. Signing binds the exact bytes the
 * agent collected to the credential, with a timestamp so an old body cannot be
 * presented again long afterwards.
 *
 * The signing key is derived from the agent's own credential, which is only ever
 * held by the agent and its hash on the server. Rotating the token therefore
 * rotates the signing key in the same step.
 */

export const AGENT_SIGNATURE_HEADER = 'x-cybernorf-signature';
export const AGENT_TIMESTAMP_HEADER = 'x-cybernorf-timestamp';

/** Clock skew and replay window for a signed submission. */
export const SIGNATURE_TOLERANCE_SECONDS = 300;

const KEY_CONTEXT = 'cybernorf-agent-signing:v1:';

export function agentSigningKey(credential: string): Buffer {
  return createHash('sha256').update(`${KEY_CONTEXT}${credential}`, 'utf8').digest();
}

/** `sha256=` plus the hex HMAC of `timestamp.body`. */
export function signAgentBody(
  credential: string,
  timestampSeconds: number,
  rawBody: string,
): string {
  const mac = createHmac('sha256', agentSigningKey(credential))
    .update(`${timestampSeconds}.`, 'utf8')
    .update(rawBody, 'utf8')
    .digest('hex');
  return `sha256=${mac}`;
}

export interface SignedRequestInput {
  /** Plaintext agent credential presented in the Authorization header. */
  credential: string;
  rawBody: string;
  signature: string | null;
  timestamp: string | null;
  now?: Date;
  toleranceSeconds?: number;
}

export type SignatureCheck =
  | { status: 'valid'; timestamp: number }
  | { status: 'absent' }
  | { status: 'invalid'; reason: 'malformed' | 'stale' | 'mismatch' };

/**
 * Checks a signed body without throwing, so the caller decides whether an
 * unsigned submission is tolerated (compatibility) or rejected (enforced).
 */
export function checkAgentSignature(input: SignedRequestInput): SignatureCheck {
  const { signature, timestamp } = input;
  if (!signature && !timestamp) {
    return { status: 'absent' };
  }
  if (!signature || !timestamp) {
    return { status: 'invalid', reason: 'malformed' };
  }

  const match = /^sha256=([0-9a-f]{64})$/.exec(signature.trim());
  const seconds = Number.parseInt(timestamp.trim(), 10);
  if (!match || !Number.isFinite(seconds) || seconds <= 0) {
    return { status: 'invalid', reason: 'malformed' };
  }

  const tolerance = input.toleranceSeconds ?? SIGNATURE_TOLERANCE_SECONDS;
  const nowSeconds = Math.floor((input.now?.getTime() ?? Date.now()) / 1000);
  if (Math.abs(nowSeconds - seconds) > tolerance) {
    return { status: 'invalid', reason: 'stale' };
  }

  const expected = signAgentBody(input.credential, seconds, input.rawBody);
  const received = signature.trim();
  // Both values are the same length once the shape check above passed, so the
  // comparison itself cannot leak the expected MAC through its timing.
  const matches = timingSafeEqual(Buffer.from(expected, 'utf8'), Buffer.from(received, 'utf8'));
  return matches
    ? { status: 'valid', timestamp: seconds }
    : { status: 'invalid', reason: 'mismatch' };
}
