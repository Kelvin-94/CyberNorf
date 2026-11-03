import type { FindingStatus, IncidentStatus } from '@/generated/prisma/client';

const FINDING_TRANSITIONS: Readonly<Record<FindingStatus, readonly FindingStatus[]>> = {
  OPEN: ['TRIAGED', 'IN_PROGRESS', 'RESOLVED', 'ACCEPTED_RISK', 'FALSE_POSITIVE'],
  TRIAGED: ['IN_PROGRESS', 'RESOLVED', 'ACCEPTED_RISK', 'FALSE_POSITIVE'],
  IN_PROGRESS: ['TRIAGED', 'RESOLVED', 'ACCEPTED_RISK', 'FALSE_POSITIVE'],
  RESOLVED: ['OPEN', 'TRIAGED'],
  ACCEPTED_RISK: ['OPEN', 'TRIAGED'],
  FALSE_POSITIVE: ['OPEN', 'TRIAGED'],
};

const INCIDENT_TRANSITIONS: Readonly<Record<IncidentStatus, readonly IncidentStatus[]>> = {
  OPEN: ['INVESTIGATING', 'CONTAINED', 'CLOSED'],
  INVESTIGATING: ['CONTAINED', 'RESOLVED', 'CLOSED'],
  CONTAINED: ['INVESTIGATING', 'RESOLVED'],
  RESOLVED: ['CLOSED', 'OPEN'],
  CLOSED: ['OPEN'],
};

export const FINDING_STATUSES = Object.keys(FINDING_TRANSITIONS) as FindingStatus[];
export const INCIDENT_STATUSES = Object.keys(INCIDENT_TRANSITIONS) as IncidentStatus[];

export function canTransitionFinding(from: FindingStatus, to: FindingStatus): boolean {
  return FINDING_TRANSITIONS[from].includes(to);
}

export function allowedFindingTransitions(from: FindingStatus): readonly FindingStatus[] {
  return FINDING_TRANSITIONS[from];
}

export function canTransitionIncident(from: IncidentStatus, to: IncidentStatus): boolean {
  return INCIDENT_TRANSITIONS[from].includes(to);
}

export function allowedIncidentTransitions(from: IncidentStatus): readonly IncidentStatus[] {
  return INCIDENT_TRANSITIONS[from];
}

export function isTerminalFindingStatus(status: FindingStatus): boolean {
  return status === 'RESOLVED' || status === 'ACCEPTED_RISK' || status === 'FALSE_POSITIVE';
}

export function isTerminalIncidentStatus(status: IncidentStatus): boolean {
  return status === 'RESOLVED' || status === 'CLOSED';
}
