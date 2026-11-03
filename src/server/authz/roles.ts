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
]);

const READ_ONLY_CAPABILITIES: readonly Capability[] = [
  'organization.read',
  'asset.read',
  'finding.read',
  'incident.read',
  'audit.read',
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
];

const ADMIN_CAPABILITIES: readonly Capability[] = [
  ...ANALYST_CAPABILITIES,
  'organization.update',
  'organization.manage_members',
  'asset.delete',
  'finding.delete',
  'incident.delete',
];

export const ROLE_CAPABILITIES: Readonly<Record<OrgRole, ReadonlySet<Capability>>> = {
  OWNER: new Set<Capability>([...ADMIN_CAPABILITIES]),
  ADMIN: new Set<Capability>(ADMIN_CAPABILITIES),
  ANALYST: new Set<Capability>(ANALYST_CAPABILITIES),
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
