/**
 * Package ecosystems shared by the software inventory and the advisory feed.
 *
 * The list mirrors the Prisma `PackageEcosystem` enum. An agent tags every
 * package it collects with one of these values and an imported advisory names
 * the same value, so matching compares two enumerated values instead of
 * guessing at "brew" vs "homebrew" string conventions.
 */

export const PACKAGE_ECOSYSTEMS = [
  'APT',
  'RPM',
  'BREW',
  'NPM',
  'PYPI',
  'GO',
  'CARGO',
  'RUBYGEMS',
  'MAVEN',
  'NUGET',
  'OTHER',
] as const;

export type PackageEcosystem = (typeof PACKAGE_ECOSYSTEMS)[number];

export const PACKAGE_ECOSYSTEM_LABELS: Readonly<Record<PackageEcosystem, string>> = {
  APT: 'Debian/Ubuntu (dpkg)',
  RPM: 'Red Hat family (rpm)',
  BREW: 'Homebrew',
  NPM: 'npm',
  PYPI: 'Python (pip)',
  GO: 'Go modules',
  CARGO: 'Cargo',
  RUBYGEMS: 'RubyGems',
  MAVEN: 'Maven',
  NUGET: 'NuGet',
  OTHER: 'Other',
};

export function isPackageEcosystem(value: unknown): value is PackageEcosystem {
  return typeof value === 'string' && (PACKAGE_ECOSYSTEMS as readonly string[]).includes(value);
}

/** Human label for console pages; unknown values fall back to the raw value. */
export function packageEcosystemLabel(value: string): string {
  return isPackageEcosystem(value) ? PACKAGE_ECOSYSTEM_LABELS[value] : value;
}
