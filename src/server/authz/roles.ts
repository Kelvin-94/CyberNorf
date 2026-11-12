/**
 * Central capability policy. Every server-side operation resolves a capability
 * from this module; anything not listed is denied by default.
 *
 * Subscription tiers are stored on the organization but do not gate any v1
 * capability, because no tier-restricted feature is implemented yet. Tier
 * checks must be added here together with the feature they protect.
 */

export const ORG_ROLES = ['OWNER', 'ADMIN', 'ANALYST', 'VIEWER'] as const;
export type OrgRole = (typeof ORG_ROLES)[number];

export const CAPABILITIES = [
  'organization.read',
  'organization.update',
  'organization.manage_members',
  'asset.read',
  'asset.create',
  'asset.update',
  'asset.delete',
  'finding.read',
  'finding.create',
  'finding.update',
  'finding.import',
  'finding.delete',
  'incident.read',
  'incident.create',
  'incident.update',
  'incident.note',
  'incident.delete',
  'audit.read',
  'compliance.read',
  'compliance.evidence',
  'compliance.manage',
  'agent.read',
  'agent.manage',
  'notification.read',
  'notification.manage',
  'advisory.read',
  'advisory.manage',
  'identity.read',
  'identity.manage',
  'access_review.read',
  'access_review.manage',
  'indicator.read',
  'indicator.manage',
  'indicator.delete',
  'export.download',
  'engagement.read',
  'engagement.manage',
  'engagement.authorize',
  'execution.read',
  'execution.dispatch',
  'execution.review',
  'execution.cancel',
  'execution.worker_manage',
  'retention.read',
  'retention.manage',
] as const;

export type Capability = (typeof CAPABILITIES)[number];

/** Capabilities that change tenant data and therefore require a second factor. */
export const MUTATING_CAPABILITIES: ReadonlySet<Capability> = new Set<Capability>([
  'organization.update',
  'organization.manage_members',
  'asset.create',
  'asset.update',
  'asset.delete',
  'finding.create',
  'finding.update',
  'finding.import',
  'finding.delete',
  'incident.create',
  'incident.update',
  'incident.note',
  'incident.delete',
  'compliance.evidence',
  'compliance.manage',
  'agent.manage',
  'notification.manage',
  'advisory.manage',
  'identity.manage',
  'access_review.manage',
  'indicator.manage',
  'engagement.manage',
  'engagement.authorize',
  'execution.dispatch',
  'execution.review',
  'execution.cancel',
  'execution.worker_manage',
  'retention.manage',
]);

const READ_ONLY_CAPABILITIES: readonly Capability[] = [
  'organization.read',
  'asset.read',
  'finding.read',
  'incident.read',
  'audit.read',
  'compliance.read',
  'agent.read',
  'notification.read',
  'advisory.read',
  'identity.read',
  'access_review.read',
  'indicator.read',
  'engagement.read',
  'execution.read',
  'retention.read',
];

const ANALYST_CAPABILITIES: readonly Capability[] = [
  ...READ_ONLY_CAPABILITIES,
  'asset.create',
  'asset.update',
  'finding.create',
  'finding.update',
  'finding.import',
  'incident.create',
  'incident.update',
  'incident.note',
  // Analysts may attach evidence but not attest controls or adopt frameworks.
  'compliance.evidence',
  // Analysts record, update and link indicators; deleting one removes the
  // provenance of every linked record, which is reserved for administrators.
  'indicator.manage',
  // Analysts may open an engagement, inspect its scope, and request a job
  // within an approved authorization. They cannot change scope, approve an
  // authorization, review their own high-risk request, or manage workers.
  'engagement.read',
  'execution.read',
  'execution.dispatch',
  'execution.cancel',
  'retention.read',
];

const ADMIN_CAPABILITIES: readonly Capability[] = [
  ...ANALYST_CAPABILITIES,
  'organization.update',
  'organization.manage_members',
  'asset.delete',
  'finding.delete',
  'incident.delete',
  'compliance.manage',
  // Admins may register and manage agent records, but approval, suspension and
  // revocation of an agent remain owner-only decisions enforced in the service.
  'agent.manage',
  // Alert destinations receive organization telemetry, so analysts and viewers
  // can read the delivery log but only administrators can add or remove a URL.
  'notification.manage',
  // An advisory feed decides which hosts are reported as vulnerable, so the
  // whole organization can read it but only administrators can replace it.
  'advisory.manage',
  // The identity inventory is readable by every role, but lifecycle changes,
  // credential issuance and access-review decisions are administrator actions.
  'identity.read',
  'identity.manage',
  'access_review.read',
  'access_review.manage',
  // Deleting an indicator destroys the provenance of everything linked to it,
  // so it is an administrator action even though analysts may record and link.
  'indicator.delete',
  // Scope, authorization decisions and worker eligibility decide where traffic
  // may go, so changing them is an administrator action. Authorization approval
  // is deliberately reserved for owners in the owner capability set below.
  'engagement.manage',
  'execution.review',
  'execution.worker_manage',
  'retention.manage',
];

// Exporting is deliberately *not* a viewer capability even though every record it
// contains is individually readable by a viewer. A whole-organization export is
// one file with every member's email and the complete audit trail, which is the
// shape of an insider data-theft event rather than of ordinary reading. Keeping it
// at analyst and above preserves the invariant that a viewer can only read.
export const ROLE_CAPABILITIES: Readonly<Record<OrgRole, ReadonlySet<Capability>>> = {
  OWNER: new Set<Capability>([...ADMIN_CAPABILITIES, 'export.download', 'engagement.authorize']),
  ADMIN: new Set<Capability>([...ADMIN_CAPABILITIES, 'export.download']),
  ANALYST: new Set<Capability>([...ANALYST_CAPABILITIES, 'export.download']),
  VIEWER: new Set<Capability>(READ_ONLY_CAPABILITIES),
};

/** Roles that must have a second factor enrolled before mutating tenant data. */
const MFA_ENFORCED_ROLES: ReadonlySet<OrgRole> = new Set<OrgRole>(['OWNER', 'ADMIN']);

export function isOrgRole(value: unknown): value is OrgRole {
  return typeof value === 'string' && (ORG_ROLES as readonly string[]).includes(value);
}

export function can(role: OrgRole, capability: Capability): boolean {
  // Unknown roles fail closed instead of throwing, so a corrupt or unexpected
  // membership row denies access rather than turning into a server error.
  const granted = ROLE_CAPABILITIES[role];
  return granted ? granted.has(capability) : false;
}

export function isMutating(capability: Capability): boolean {
  return MUTATING_CAPABILITIES.has(capability);
}

export function requiresSecondFactor(role: OrgRole, capability: Capability): boolean {
  return MFA_ENFORCED_ROLES.has(role) && MUTATING_CAPABILITIES.has(capability);
}

export function isAtLeast(role: OrgRole, minimum: OrgRole): boolean {
  const order: OrgRole[] = ['VIEWER', 'ANALYST', 'ADMIN', 'OWNER'];
  return order.indexOf(role) >= order.indexOf(minimum);
}
