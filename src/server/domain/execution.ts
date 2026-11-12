import { isIP } from 'node:net';

/**
 * Scope and execution policy.
 *
 * Everything here is pure: it decides whether a target is inside an engagement,
 * whether an authorization is still valid, whether a redirect left the scope,
 * and whether a worker may reach an address. The services call these functions
 * at dispatch *and* again at execution start, because the answer can change
 * between the two (an authorization expires, a scope entry is removed, DNS
 * starts returning a different address).
 *
 * Three rules are deliberately conservative:
 *
 * 1. An exclusion always wins, even when a narrower inclusion would also match.
 *    A customer who excludes a host expects it excluded, not re-included by a
 *    later rule.
 * 2. A URL rule pins scheme, host, port and a path prefix. A DOMAIN rule covers
 *    the host and its subdomains on any port. Neither is widened at match time.
 * 3. An empty or unparseable rule set allows nothing. There is no wildcard
 *    fallback, because "allow everything" is the one answer a scope engine must
 *    never guess.
 */

export const SCOPE_TARGET_TYPES = ['DOMAIN', 'IP_ADDRESS', 'CIDR', 'URL'] as const;
export type ScopeTargetType = (typeof SCOPE_TARGET_TYPES)[number];

export const SCOPE_ENTRY_KINDS = ['INCLUDE', 'EXCLUDE'] as const;
export type ScopeEntryKind = (typeof SCOPE_ENTRY_KINDS)[number];

export const EXECUTION_CAPABILITIES = [
  'DNS_LOOKUP',
  'HTTP_PROBE',
  'TLS_INSPECTION',
  'PORT_SCAN',
] as const;
export type ExecutionCapability = (typeof EXECUTION_CAPABILITIES)[number];

export type ExecutionRisk = 'LOW' | 'MEDIUM' | 'HIGH';

export interface ScopeRule {
  kind: ScopeEntryKind;
  targetType: ScopeTargetType;
  value: string;
}

export interface ScopeCandidate {
  targetType: ScopeTargetType;
  value: string;
}

export type ScopeDenialReason =
  | 'allowed'
  | 'invalid_target'
  | 'out_of_scope'
  | 'excluded'
  | 'engagement_not_active'
  | 'engagement_not_started'
  | 'engagement_ended'
  | 'no_authorization'
  | 'authorization_pending'
  | 'authorization_rejected'
  | 'authorization_revoked'
  | 'authorization_expired'
  | 'address_changed'
  | 'egress_not_allowed'
  | 'no_eligible_worker'
  | 'dns_resolution_failed'
  | 'review_required'
  | 'review_rejected'
  | 'review_not_approved'
  | 'duration_limit_exceeded'
  | 'lease_expired';

export interface ScopeDecision {
  allowed: boolean;
  reason: ScopeDenialReason;
  /** The first rule that decided the outcome, formatted for audit metadata. */
  matchedRule: string | null;
}

/**
 * Denials are shown to operators, so each reason gets one sentence that says
 * what actually went wrong. The machine-readable reason stays in the event
 * metadata and the audit log; this text is only for humans reading the job.
 */
export function describeDenial(reason: ScopeDenialReason): string {
  switch (reason) {
    case 'allowed':
      return 'Execution is permitted.';
    case 'invalid_target':
      return 'Execution denied: the target could not be parsed.';
    case 'out_of_scope':
      return 'Execution denied: the target is outside the authorized scope.';
    case 'excluded':
      return 'Execution denied: the target matches an exclusion entry.';
    case 'engagement_not_active':
      return 'Execution denied: the engagement is not active.';
    case 'engagement_not_started':
      return 'Execution denied: the engagement window has not opened.';
    case 'engagement_ended':
      return 'Execution denied: the engagement window has closed.';
    case 'no_authorization':
      return 'Execution denied: the engagement has no approved authorization.';
    case 'authorization_pending':
      return 'Execution denied: the authorization is still awaiting a decision.';
    case 'authorization_rejected':
      return 'Execution denied: the authorization was rejected.';
    case 'authorization_revoked':
      return 'Execution denied: the authorization was revoked.';
    case 'authorization_expired':
      return 'Execution denied: the authorization expired.';
    case 'address_changed':
      return 'Execution denied: the DNS answer changed since dispatch.';
    case 'egress_not_allowed':
      return 'Execution denied: the worker egress allowlist does not cover the target.';
    case 'no_eligible_worker':
      return 'Execution denied: no eligible worker can reach that target.';
    case 'dns_resolution_failed':
      return 'Execution denied: the target could not be resolved.';
    case 'review_required':
      return 'Execution denied: this job needs human review before it can run.';
    case 'review_rejected':
      return 'Execution denied: a reviewer rejected this job.';
    case 'review_not_approved':
      return 'Execution denied: the review did not approve this job.';
    case 'duration_limit_exceeded':
      return 'Execution stopped: the job exceeded its duration limit.';
    case 'lease_expired':
      return 'Execution denied: the queue lease expired before a worker picked the job up.';
    default:
      return `Execution denied: ${reason}.`;
  }
}

export class ScopeFormatError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ScopeFormatError';
  }
}

const HOST_LABEL = /^(?!-)[a-z0-9-]{1,63}(?<!-)$/;
const MAX_HOST_LENGTH = 253;

// The project targets ES2017, which does not allow BigInt literals (`0n`).
// Named constants keep the address arithmetic readable without changing the
// compiler target for the whole application.
const B0 = BigInt(0);
const B1 = BigInt(1);
const B8 = BigInt(8);
const B16 = BigInt(16);
const B24 = BigInt(24);
const B112 = BigInt(112);
const B255 = BigInt(255);
const B65535 = BigInt(65535);

export function normalizeHostname(input: string): string {
  const trimmed = input.trim().toLowerCase();
  if (trimmed.length === 0 || trimmed.length > MAX_HOST_LENGTH) {
    throw new ScopeFormatError('A hostname must be between 1 and 253 characters.');
  }
  const withoutRoot = trimmed.endsWith('.') ? trimmed.slice(0, -1) : trimmed;
  if (withoutRoot.includes('://') || /[/@\s?#]/.test(withoutRoot)) {
    throw new ScopeFormatError('Enter a bare hostname, not a URL or path.');
  }
  const labels = withoutRoot.split('.');
  if (!labels.every((label) => HOST_LABEL.test(label))) {
    throw new ScopeFormatError('The hostname contains an invalid label.');
  }
  return withoutRoot;
}

/** Normalizes a DOMAIN rule; `*.example.com` matches subdomains only. */
export function normalizeDomainRule(input: string): string {
  const trimmed = input.trim().toLowerCase();
  if (trimmed.startsWith('*.')) {
    return `*.${normalizeHostname(trimmed.slice(2))}`;
  }
  return normalizeHostname(trimmed);
}

function parseIpv4ToBigInt(value: string): bigint | null {
  const parts = value.split('.');
  if (parts.length !== 4) {
    return null;
  }
  let result = B0;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) {
      return null;
    }
    const octet = Number(part);
    if (octet > 255) {
      return null;
    }
    result = (result << B8) | BigInt(octet);
  }
  return result;
}

function parseIpv6ToBigInt(input: string): bigint | null {
  let value = input.toLowerCase();
  if (value.includes('%')) {
    return null;
  }
  if (value.includes('.')) {
    const lastColon = value.lastIndexOf(':');
    if (lastColon < 0) {
      return null;
    }
    const v4 = parseIpv4ToBigInt(value.slice(lastColon + 1));
    if (v4 === null) {
      return null;
    }
    const high = ((v4 >> B16) & B65535).toString(16);
    const low = (v4 & B65535).toString(16);
    value = `${value.slice(0, lastColon + 1)}${high}:${low}`;
  }
  const halves = value.split('::');
  if (halves.length > 2) {
    return null;
  }
  const head = halves[0] ? halves[0].split(':') : [];
  const tail = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  if (halves.length === 1 && head.length !== 8) {
    return null;
  }
  const missing = 8 - head.length - tail.length;
  if (halves.length === 2 && missing < 1) {
    return null;
  }
  const groups =
    halves.length === 2 ? [...head, ...Array<string>(missing).fill('0'), ...tail] : head;
  if (groups.length !== 8) {
    return null;
  }
  let result = B0;
  for (const group of groups) {
    if (!/^[0-9a-f]{1,4}$/.test(group)) {
      return null;
    }
    result = (result << B16) | BigInt(Number.parseInt(group, 16));
  }
  return result;
}

function ipToBigInt(value: string): bigint | null {
  const family = isIP(value);
  if (family === 4) {
    return parseIpv4ToBigInt(value);
  }
  if (family === 6) {
    return parseIpv6ToBigInt(value);
  }
  return null;
}

function bigIntToIpv4(value: bigint): string {
  return [B24, B16, B8, B0].map((shift) => Number((value >> shift) & B255)).join('.');
}

function bigIntToIpv6(value: bigint): string {
  const groups: string[] = [];
  for (let shift = B112; shift >= B0; shift -= B16) {
    groups.push(((value >> shift) & B65535).toString(16));
  }
  return groups.join(':');
}

/** Returns a comparable canonical form: dotted quad for IPv4, 8-group hex for IPv6. */
export function normalizeIpAddress(input: string): string {
  const trimmed = input.trim();
  const family = isIP(trimmed);
  const numeric = ipToBigInt(trimmed);
  if (family === 0 || numeric === null) {
    throw new ScopeFormatError('Enter a single IPv4 or IPv6 address.');
  }
  return family === 4 ? bigIntToIpv4(numeric) : bigIntToIpv6(numeric);
}

export function sameIpAddress(left: string, right: string): boolean {
  const a = ipToBigInt(left);
  const b = ipToBigInt(right);
  return a !== null && b !== null && a === b;
}

interface ParsedCidr {
  network: bigint;
  prefix: number;
  bits: number;
}

function parseCidr(input: string): ParsedCidr {
  const trimmed = input.trim();
  const slash = trimmed.lastIndexOf('/');
  if (slash <= 0) {
    throw new ScopeFormatError('Enter a CIDR range such as 203.0.113.0/24.');
  }
  const address = trimmed.slice(0, slash);
  const prefixText = trimmed.slice(slash + 1);
  if (!/^\d{1,3}$/.test(prefixText)) {
    throw new ScopeFormatError('The CIDR prefix must be a number.');
  }
  const family = isIP(address);
  const numeric = ipToBigInt(address);
  if (family === 0 || numeric === null) {
    throw new ScopeFormatError('The CIDR address is invalid.');
  }
  const bits = family === 4 ? 32 : 128;
  const prefix = Number(prefixText);
  if (prefix > bits) {
    throw new ScopeFormatError(`The CIDR prefix must be between 0 and ${bits}.`);
  }
  const hostBits = BigInt(bits - prefix);
  const full = (B1 << BigInt(bits)) - B1;
  const mask = hostBits === B0 ? full : full ^ ((B1 << hostBits) - B1);
  return { network: numeric & mask, prefix, bits };
}

export function normalizeCidr(input: string): string {
  const parsed = parseCidr(input);
  const address = parsed.bits === 32 ? bigIntToIpv4(parsed.network) : bigIntToIpv6(parsed.network);
  return `${address}/${parsed.prefix}`;
}

export function cidrContainsAddress(cidr: string, address: string): boolean {
  const parsed = parseCidr(cidr);
  const numeric = ipToBigInt(address);
  if (numeric === null) {
    return false;
  }
  const bits = isIP(address) === 4 ? 32 : 128;
  if (bits !== parsed.bits) {
    return false;
  }
  const hostBits = BigInt(parsed.bits - parsed.prefix);
  const full = (B1 << BigInt(parsed.bits)) - B1;
  const mask = hostBits === B0 ? full : full ^ ((B1 << hostBits) - B1);
  return (numeric & mask) === parsed.network;
}

/** True when every address in `inner` is covered by `outer`. */
export function cidrContainsCidr(outer: string, inner: string): boolean {
  const a = parseCidr(outer);
  const b = parseCidr(inner);
  if (a.bits !== b.bits || a.prefix > b.prefix) {
    return false;
  }
  return cidrContainsAddress(
    outer,
    b.bits === 32 ? bigIntToIpv4(b.network) : bigIntToIpv6(b.network),
  );
}

export function hostMatchesDomain(host: string, rule: string): boolean {
  const normalizedHost = host.toLowerCase();
  const normalizedRule = rule.toLowerCase();
  if (normalizedRule.startsWith('*.')) {
    const base = normalizedRule.slice(2);
    return normalizedHost !== base && normalizedHost.endsWith(`.${base}`);
  }
  return normalizedHost === normalizedRule || normalizedHost.endsWith(`.${normalizedRule}`);
}

interface NormalizedUrl {
  protocol: string;
  hostname: string;
  port: string;
  path: string;
  href: string;
}

function normalizeUrl(input: string): NormalizedUrl {
  let parsed: URL;
  try {
    parsed = new URL(input.trim());
  } catch {
    throw new ScopeFormatError('Enter an absolute http(s) URL.');
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new ScopeFormatError('Only http and https URLs can be in scope.');
  }
  if (parsed.username !== '' || parsed.password !== '') {
    throw new ScopeFormatError('URLs with embedded credentials are not allowed.');
  }
  if (parsed.hostname === '') {
    throw new ScopeFormatError('The URL must include a hostname.');
  }
  const defaultPort = parsed.protocol === 'https:' ? '443' : '80';
  const port = parsed.port === '' ? defaultPort : parsed.port;
  const path = parsed.pathname === '' ? '/' : parsed.pathname.replace(/\/+$/, '') || '/';
  return {
    protocol: parsed.protocol,
    hostname: parsed.hostname.toLowerCase(),
    port,
    path,
    href: `${parsed.protocol}//${parsed.hostname}${parsed.port === '' ? '' : `:${parsed.port}`}${parsed.pathname}${parsed.search}`,
  };
}

/** Normalizes the stored form of a scope entry or job target. */
export function normalizeScopeValue(targetType: ScopeTargetType, value: string): string {
  switch (targetType) {
    case 'DOMAIN':
      return normalizeDomainRule(value);
    case 'IP_ADDRESS':
      return normalizeIpAddress(value);
    case 'CIDR':
      return normalizeCidr(value);
    case 'URL': {
      const normalized = normalizeUrl(value);
      return `${normalized.protocol}//${normalized.hostname}${normalized.port === (normalized.protocol === 'https:' ? '443' : '80') ? '' : `:${normalized.port}`}${normalized.path === '/' ? '' : normalized.path}`;
    }
    default:
      throw new ScopeFormatError('Unknown target type.');
  }
}

export function normalizeScopeCandidate(candidate: ScopeCandidate): string {
  return normalizeScopeValue(candidate.targetType, candidate.value);
}

function pathPrefixMatches(candidatePath: string, rulePath: string): boolean {
  if (rulePath === '/' || rulePath === '') {
    return true;
  }
  return candidatePath === rulePath || candidatePath.startsWith(`${rulePath}/`);
}

function ruleMatchesCandidate(rule: ScopeRule, candidate: ScopeCandidate): boolean {
  const ruleValue = normalizeScopeValue(rule.targetType, rule.value);
  const candidateValue = normalizeScopeValue(candidate.targetType, candidate.value);

  if (rule.targetType === 'URL') {
    const ruleUrl = normalizeUrl(ruleValue);
    const candidateUrl = candidate.targetType === 'URL' ? normalizeUrl(candidateValue) : null;
    if (candidateUrl === null) {
      return false;
    }
    return (
      candidateUrl.protocol === ruleUrl.protocol &&
      candidateUrl.hostname === ruleUrl.hostname &&
      candidateUrl.port === ruleUrl.port &&
      pathPrefixMatches(candidateUrl.path, ruleUrl.path)
    );
  }

  if (rule.targetType === 'DOMAIN') {
    if (candidate.targetType === 'DOMAIN') {
      return hostMatchesDomain(candidateValue, ruleValue);
    }
    if (candidate.targetType === 'URL') {
      return hostMatchesDomain(normalizeUrl(candidateValue).hostname, ruleValue);
    }
    return false;
  }

  if (rule.targetType === 'IP_ADDRESS') {
    if (candidate.targetType === 'IP_ADDRESS') {
      return sameIpAddress(ruleValue, candidateValue);
    }
    if (candidate.targetType === 'URL') {
      const hostname = normalizeUrl(candidateValue).hostname;
      return isIP(hostname) !== 0 && sameIpAddress(ruleValue, hostname);
    }
    return false;
  }

  // CIDR rule.
  if (candidate.targetType === 'IP_ADDRESS') {
    return cidrContainsAddress(ruleValue, candidateValue);
  }
  if (candidate.targetType === 'CIDR') {
    return cidrContainsCidr(ruleValue, candidateValue);
  }
  if (candidate.targetType === 'URL') {
    const hostname = normalizeUrl(candidateValue).hostname;
    return isIP(hostname) !== 0 && cidrContainsAddress(ruleValue, hostname);
  }
  return false;
}

function describeRule(rule: ScopeRule): string {
  return `${rule.kind}:${rule.targetType}:${rule.value}`;
}

/** A stored rule that no longer parses must not grant access. */
function ruleMatchesSafely(rule: ScopeRule, candidate: ScopeCandidate): boolean {
  try {
    return ruleMatchesCandidate(rule, candidate);
  } catch {
    return false;
  }
}

/**
 * Evaluates one target against the engagement's rules. Includes are checked
 * first so a target outside every inclusion is `out_of_scope`; any matching
 * exclusion then overrides an inclusion.
 */
export function evaluateScope(
  rules: readonly ScopeRule[],
  candidate: ScopeCandidate,
): ScopeDecision {
  try {
    normalizeScopeValue(candidate.targetType, candidate.value);
  } catch {
    return { allowed: false, reason: 'invalid_target', matchedRule: null };
  }

  const matchingIncludes: ScopeRule[] = [];
  const matchingExcludes: ScopeRule[] = [];
  for (const rule of rules) {
    if (!ruleMatchesSafely(rule, candidate)) {
      continue;
    }
    if (rule.kind === 'EXCLUDE') {
      matchingExcludes.push(rule);
    } else {
      matchingIncludes.push(rule);
    }
  }

  if (matchingExcludes.length > 0) {
    return { allowed: false, reason: 'excluded', matchedRule: describeRule(matchingExcludes[0]!) };
  }
  if (matchingIncludes.length === 0) {
    return { allowed: false, reason: 'out_of_scope', matchedRule: null };
  }
  return { allowed: true, reason: 'allowed', matchedRule: describeRule(matchingIncludes[0]!) };
}

export interface AuthorizationState {
  status: 'PENDING' | 'APPROVED' | 'REJECTED' | 'REVOKED';
  expiresAt: Date;
}

export function evaluateAuthorization(
  authorization: AuthorizationState | null,
  now: Date,
): { allowed: boolean; reason: ScopeDenialReason } {
  if (authorization === null) {
    return { allowed: false, reason: 'no_authorization' };
  }
  if (authorization.status === 'PENDING') {
    return { allowed: false, reason: 'authorization_pending' };
  }
  if (authorization.status === 'REJECTED') {
    return { allowed: false, reason: 'authorization_rejected' };
  }
  if (authorization.status === 'REVOKED') {
    return { allowed: false, reason: 'authorization_revoked' };
  }
  if (authorization.expiresAt.getTime() <= now.getTime()) {
    return { allowed: false, reason: 'authorization_expired' };
  }
  return { allowed: true, reason: 'allowed' };
}

export interface EngagementWindow {
  status: 'DRAFT' | 'ACTIVE' | 'PAUSED' | 'CLOSED';
  startsAt: Date;
  endsAt: Date;
}

export function evaluateEngagementWindow(
  engagement: EngagementWindow,
  now: Date,
): { allowed: boolean; reason: ScopeDenialReason } {
  if (engagement.status !== 'ACTIVE') {
    return { allowed: false, reason: 'engagement_not_active' };
  }
  if (now.getTime() < engagement.startsAt.getTime()) {
    return { allowed: false, reason: 'engagement_not_started' };
  }
  if (now.getTime() >= engagement.endsAt.getTime()) {
    return { allowed: false, reason: 'engagement_ended' };
  }
  return { allowed: true, reason: 'allowed' };
}

export interface DispatchEvaluationInput {
  now: Date;
  engagement: EngagementWindow;
  authorization: AuthorizationState | null;
  rules: readonly ScopeRule[];
  candidate: ScopeCandidate;
}

/**
 * Full pre-flight check used at dispatch and repeated at execution start.
 * The order matters: an inactive engagement reports that first, then
 * authorization, then scope, so the denial reason names the earliest control
 * that failed rather than the last one checked.
 */
export function evaluateDispatch(input: DispatchEvaluationInput): ScopeDecision {
  const engagement = evaluateEngagementWindow(input.engagement, input.now);
  if (!engagement.allowed) {
    return { allowed: false, reason: engagement.reason, matchedRule: null };
  }
  const authorization = evaluateAuthorization(input.authorization, input.now);
  if (!authorization.allowed) {
    return { allowed: false, reason: authorization.reason, matchedRule: null };
  }
  return evaluateScope(input.rules, input.candidate);
}

/**
 * Follows a redirect chain. Every hop is evaluated against the same scope, so a
 * redirect to a host that is not listed is denied even though the first URL was
 * allowed. The final URL is returned only when the whole chain is in scope.
 */
export function evaluateRedirectChain(
  rules: readonly ScopeRule[],
  startUrl: string,
  locations: readonly string[],
): { allowed: boolean; reason: ScopeDenialReason; url: string; deniedAtHop: number | null } {
  let current = startUrl;
  try {
    normalizeScopeValue('URL', current);
  } catch {
    return { allowed: false, reason: 'invalid_target', url: startUrl, deniedAtHop: null };
  }

  const initial = evaluateScope(rules, { targetType: 'URL', value: current });
  if (!initial.allowed) {
    return { allowed: false, reason: initial.reason, url: current, deniedAtHop: 0 };
  }

  for (let index = 0; index < locations.length; index += 1) {
    const location = locations[index]!;
    let next: string;
    try {
      next = new URL(location, current).toString();
    } catch {
      return { allowed: false, reason: 'invalid_target', url: current, deniedAtHop: index + 1 };
    }
    const decision = evaluateScope(rules, { targetType: 'URL', value: next });
    if (!decision.allowed) {
      return { allowed: false, reason: decision.reason, url: next, deniedAtHop: index + 1 };
    }
    current = next;
  }

  return { allowed: true, reason: 'allowed', url: current, deniedAtHop: null };
}

/** True when the addresses observed at execution differ from those at dispatch. */
export function addressSetsDiffer(
  approved: readonly string[],
  observed: readonly string[],
): boolean {
  const canonical = (values: readonly string[]) =>
    values
      .map((value) => {
        try {
          return normalizeIpAddress(value);
        } catch {
          return null;
        }
      })
      .filter((value): value is string => value !== null)
      .sort();
  const left = canonical(approved);
  const right = canonical(observed);
  if (left.length === 0 || right.length === 0) {
    return true;
  }
  return left.length !== right.length || left.some((value, index) => value !== right[index]);
}

export type EgressEntry =
  | { kind: 'DOMAIN'; value: string }
  | { kind: 'IP_ADDRESS'; value: string }
  | { kind: 'CIDR'; value: string };

export function parseEgressEntry(input: string): EgressEntry {
  const trimmed = input.trim();
  if (trimmed.includes('/')) {
    return { kind: 'CIDR', value: normalizeCidr(trimmed) };
  }
  if (isIP(trimmed) !== 0) {
    return { kind: 'IP_ADDRESS', value: normalizeIpAddress(trimmed) };
  }
  return { kind: 'DOMAIN', value: normalizeDomainRule(trimmed) };
}

/**
 * A worker may reach a target when the allowlist names the host (name-based
 * egress) or when every resolved address sits inside an allowed IP or CIDR
 * (address-pinned egress, the stronger mode).
 */
export function workerEgressAllows(
  allowlist: readonly string[],
  target: { host: string; addresses: readonly string[] },
): boolean {
  if (allowlist.length === 0) {
    return false;
  }
  let entries: EgressEntry[];
  try {
    entries = allowlist.map(parseEgressEntry);
  } catch {
    return false;
  }

  let host: string;
  try {
    host = target.host.toLowerCase();
  } catch {
    return false;
  }

  const nameAllowed = entries.some(
    (entry) => entry.kind === 'DOMAIN' && hostMatchesDomain(host, entry.value),
  );
  if (nameAllowed) {
    return true;
  }

  if (target.addresses.length === 0) {
    return false;
  }
  return target.addresses.every((address) =>
    entries.some((entry) => {
      if (entry.kind === 'IP_ADDRESS') {
        return sameIpAddress(entry.value, address);
      }
      if (entry.kind === 'CIDR') {
        return cidrContainsAddress(entry.value, address);
      }
      return false;
    }),
  );
}

/** CIDR targets cannot be expanded to addresses, so an allowlist CIDR must cover the whole range. */
export function workerEgressAllowsCidr(allowlist: readonly string[], cidr: string): boolean {
  if (allowlist.length === 0) {
    return false;
  }
  try {
    return allowlist.some((entry) => {
      const parsed = parseEgressEntry(entry);
      return parsed.kind === 'CIDR' && cidrContainsCidr(parsed.value, cidr);
    });
  } catch {
    return false;
  }
}

export function riskForCapability(capability: ExecutionCapability): ExecutionRisk {
  switch (capability) {
    case 'DNS_LOOKUP':
      return 'LOW';
    case 'HTTP_PROBE':
    case 'TLS_INSPECTION':
      return 'MEDIUM';
    case 'PORT_SCAN':
      return 'HIGH';
    default:
      return 'HIGH';
  }
}

export interface JobLimits {
  maxDurationSeconds: number;
  maxRequests: number;
  maxBytes: number;
  maxConcurrency: number;
}

export const JOB_LIMIT_CEILINGS: Readonly<JobLimits> = {
  maxDurationSeconds: 900,
  maxRequests: 1000,
  maxBytes: 52_428_800,
  maxConcurrency: 8,
};

export const DEFAULT_JOB_LIMITS: Readonly<Record<ExecutionRisk, JobLimits>> = {
  LOW: { maxDurationSeconds: 30, maxRequests: 20, maxBytes: 1_048_576, maxConcurrency: 1 },
  MEDIUM: { maxDurationSeconds: 120, maxRequests: 100, maxBytes: 5_242_880, maxConcurrency: 2 },
  HIGH: { maxDurationSeconds: 300, maxRequests: 300, maxBytes: 10_485_760, maxConcurrency: 4 },
};

/**
 * Applies defaults for the capability's risk level and rejects any value above
 * the hard ceiling. A lower limit is always allowed: the requester may narrow a
 * job, never widen it beyond the platform cap.
 */
export type PartialJobLimits = { [K in keyof JobLimits]?: number | undefined };

export function normalizeJobLimits(
  risk: ExecutionRisk,
  input: PartialJobLimits | null | undefined,
): JobLimits {
  const base = DEFAULT_JOB_LIMITS[risk];
  const merged: JobLimits = { ...base };
  if (!input) {
    return merged;
  }
  for (const key of Object.keys(base) as Array<keyof JobLimits>) {
    const value = input[key];
    if (value === undefined) {
      continue;
    }
    if (!Number.isInteger(value) || value < 1) {
      throw new ScopeFormatError(`${key} must be a positive integer.`);
    }
    if (value > JOB_LIMIT_CEILINGS[key]) {
      throw new ScopeFormatError(`${key} cannot exceed ${JOB_LIMIT_CEILINGS[key]}.`);
    }
    merged[key] = value;
  }
  return merged;
}

export function durationLimitExceeded(
  startedAt: Date,
  finishedAt: Date,
  limits: JobLimits,
): boolean {
  return finishedAt.getTime() - startedAt.getTime() > limits.maxDurationSeconds * 1000;
}
