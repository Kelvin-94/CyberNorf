import {
  AGENT_SIGNATURE_HEADER,
  AGENT_TIMESTAMP_HEADER,
  checkAgentSignature,
} from '@/server/domain/agent-signature';
import { AppError } from '@/server/errors';

/**
 * When `AGENT_REQUIRE_SIGNED_RUNS` is true, unsigned submissions are refused.
 *
 * Verification is always performed when an agent signs, so a deployment that
 * turns the flag on does not have to change anything on the agents that already
 * sign, and a deployment that leaves it off still rejects a signature that
 * arrives but does not verify.
 */
export function agentSignaturesRequired(): boolean {
  return (process.env.AGENT_REQUIRE_SIGNED_RUNS ?? '').trim().toLowerCase() === 'true';
}

export function assertAgentRequestSignature(
  request: Request,
  credential: string,
  rawBody: string,
): void {
  const result = checkAgentSignature({
    credential,
    rawBody,
    signature: request.headers.get(AGENT_SIGNATURE_HEADER),
    timestamp: request.headers.get(AGENT_TIMESTAMP_HEADER),
  });

  if (result.status === 'valid') {
    return;
  }
  if (result.status === 'absent' && !agentSignaturesRequired()) {
    return;
  }

  throw new AppError(401, 'UNAUTHENTICATED', 'The request signature is missing or invalid.');
}
