/**
 * Version comparison and advisory range matching.
 *
 * Vulnerability matching is only useful if "installed 4.17.20 is inside
 * `>= 4.17.15, < 4.17.21`" is decided the same way twice, on every platform, with
 * no network access and no dependency on a registry. This module therefore
 * implements a small, deterministic comparator rather than trusting a package
 * manager to answer the question.
 *
 * Ordering rules:
 * - A leading `v` and a leading epoch (`1:`) are ignored; build metadata after
 *   `+` is ignored, because it never changes which version is newer.
 * - The numeric core is compared segment by segment, missing segments counting
 *   as zero, so `1.2` equals `1.2.0`.
 * - A `-suffix` is read as a pre-release when it contains a pre-release word
 *   (`alpha`, `beta`, `rc`, `pre`, `preview`, `dev`, `snapshot`, `nightly`,
 *   `canary`, `next`, `milestone`), which makes `1.0.0-rc.1` older than `1.0.0`.
 * - Any other suffix is treated as a package revision (`8+deb12u1`, `2ubuntu3`,
 *   `1.el9`): its leading numbers are appended to the core, so
 *   `2.36.1-8+deb12u1` counts as newer than `2.36.1`. This is the opposite of
 *   strict SemVer, where `1.0.0-1` is a pre-release, and it is deliberate: Debian
 *   and RPM rebuild versions must not be reported as older than the fixed
 *   release they contain.
 * - Versions that cannot be parsed never match. An unparseable version or range
 *   produces "not affected" rather than a finding, so a bad import cannot spray
 *   false positives across a fleet.
 */

const PRERELEASE_WORDS = new Set([
  'alpha',
  'beta',
  'rc',
  'pre',
  'preview',
  'dev',
  'snapshot',
  'nightly',
  'canary',
  'next',
  'milestone',
]);

export interface ParsedVersion {
  segments: number[];
  /** Pre-release identifiers, or null when the version is a release. */
  prerelease: string[] | null;
}

export type RangeOperator = '<' | '<=' | '>' | '>=' | '=';

export interface VersionConstraint {
  operator: RangeOperator;
  version: ParsedVersion;
}

/**
 * A range is a disjunction of conjunctions: comma or space separated
 * constraints are ANDed, `||` separates alternatives.
 */
export interface VersionRange {
  alternatives: VersionConstraint[][];
}

function prereleaseFromText(text: string): string[] | null {
  const identifiers = text.split(/[.\-_~]+/).filter((part) => part.length > 0);
  if (identifiers.length === 0) {
    return null;
  }
  const looksPreRelease = identifiers.some((identifier) =>
    PRERELEASE_WORDS.has(identifier.replace(/[^a-z]/g, '')),
  );
  return looksPreRelease ? identifiers : null;
}

export function parseVersion(raw: string): ParsedVersion | null {
  if (typeof raw !== 'string') {
    return null;
  }
  let value = raw.trim().toLowerCase();
  if (value.length === 0) {
    return null;
  }
  // Package manager prefixes and build metadata carry no ordering information.
  value = value.replace(/^[=v\s]+/, '');
  value = value.replace(/^\d+:/, '');
  const buildIndex = value.indexOf('+');
  if (buildIndex >= 0) {
    value = value.slice(0, buildIndex);
  }

  const dashIndex = value.indexOf('-');
  const core = dashIndex >= 0 ? value.slice(0, dashIndex) : value;
  const suffix = dashIndex >= 0 ? value.slice(dashIndex + 1) : '';
  if (core.length === 0) {
    return null;
  }

  const segments: number[] = [];
  let trailingPreRelease: string[] | null = null;
  for (const part of core.split('.')) {
    const match = /^(\d+)(.*)$/.exec(part);
    if (!match) {
      return null;
    }
    segments.push(Number.parseInt(match[1] as string, 10));
    const rest = (match[2] ?? '').trim();
    if (rest.length > 0) {
      // `1.0.0rc1` has no separator, but the letters still mean pre-release.
      trailingPreRelease = prereleaseFromText(rest) ?? [rest];
    }
  }

  if (suffix.length > 0) {
    const suffixPreRelease = prereleaseFromText(suffix);
    if (suffixPreRelease) {
      return {
        segments,
        prerelease: trailingPreRelease
          ? [...trailingPreRelease, ...suffixPreRelease]
          : suffixPreRelease,
      };
    }
    // Revision: keep the leading numbers of every suffix identifier.
    for (const part of suffix.split(/[.\-_~]+/)) {
      const digits = /^\d+/.exec(part);
      if (digits) {
        segments.push(Number.parseInt(digits[0], 10));
      }
    }
  }

  return { segments, prerelease: trailingPreRelease };
}

function compareNumbers(a: number[], b: number[]): number {
  const length = Math.max(a.length, b.length);
  for (let index = 0; index < length; index += 1) {
    const left = a[index] ?? 0;
    const right = b[index] ?? 0;
    if (left !== right) {
      return left < right ? -1 : 1;
    }
  }
  return 0;
}

function comparePrerelease(a: string[], b: string[]): number {
  const length = Math.max(a.length, b.length);
  for (let index = 0; index < length; index += 1) {
    const left = a[index];
    const right = b[index];
    // A longer pre-release list wins when every preceding identifier is equal.
    if (left === undefined) {
      return -1;
    }
    if (right === undefined) {
      return 1;
    }
    const leftNumeric = /^\d+$/.test(left);
    const rightNumeric = /^\d+$/.test(right);
    if (leftNumeric && rightNumeric) {
      const difference = Number.parseInt(left, 10) - Number.parseInt(right, 10);
      if (difference !== 0) {
        return difference < 0 ? -1 : 1;
      }
      continue;
    }
    // Numeric identifiers sort below alphanumeric ones.
    if (leftNumeric !== rightNumeric) {
      return leftNumeric ? -1 : 1;
    }
    if (left !== right) {
      return left < right ? -1 : 1;
    }
  }
  return 0;
}

export function compareParsedVersions(a: ParsedVersion, b: ParsedVersion): number {
  const core = compareNumbers(a.segments, b.segments);
  if (core !== 0) {
    return core;
  }
  if (a.prerelease && b.prerelease) {
    return comparePrerelease(a.prerelease, b.prerelease);
  }
  if (a.prerelease) {
    return -1;
  }
  if (b.prerelease) {
    return 1;
  }
  return 0;
}

/** Returns -1, 0 or 1, or null when either side cannot be parsed. */
export function compareVersions(a: string, b: string): number | null {
  const left = parseVersion(a);
  const right = parseVersion(b);
  if (!left || !right) {
    return null;
  }
  return compareParsedVersions(left, right);
}

function caretUpperBound(version: ParsedVersion): ParsedVersion {
  const [major = 0, minor = 0, patch = 0] = version.segments;
  if (major > 0) {
    return { segments: [major + 1, 0, 0], prerelease: null };
  }
  if (minor > 0) {
    return { segments: [0, minor + 1, 0], prerelease: null };
  }
  return { segments: [0, 0, patch + 1], prerelease: null };
}

function tildeUpperBound(version: ParsedVersion): ParsedVersion {
  const [major = 0, minor = 0] = version.segments;
  // `~1` allows any 1.x, `~1.2` only 1.2.x.
  if (version.segments.length <= 1) {
    return { segments: [major + 1, 0, 0], prerelease: null };
  }
  return { segments: [major, minor + 1, 0], prerelease: null };
}

const OPERATORS = ['>=', '<=', '>', '<', '=', '^', '~'] as const;

function parseConstraintToken(token: string): VersionConstraint[] | null {
  let operator: RangeOperator | '^' | '~' | null = null;
  let versionText = token;
  for (const candidate of OPERATORS) {
    if (token.startsWith(candidate)) {
      operator = candidate;
      versionText = token.slice(candidate.length);
      break;
    }
  }
  if (versionText.trim().length === 0) {
    return null;
  }
  const version = parseVersion(versionText);
  if (!version) {
    return null;
  }
  switch (operator) {
    case '^':
      return [
        { operator: '>=', version },
        { operator: '<', version: caretUpperBound(version) },
      ];
    case '~':
      return [
        { operator: '>=', version },
        { operator: '<', version: tildeUpperBound(version) },
      ];
    case '>=':
    case '<=':
    case '>':
    case '<':
    case '=':
      return [{ operator, version }];
    default:
      // A bare version means exactly that release.
      return [{ operator: '=', version }];
  }
}

/**
 * Parses an advisory range such as `>= 1.2.0, < 1.4.5`, `^2.0.0` or
 * `1.0.0 - 1.2.3 || >= 2.0.0`. Returns null when any token is unusable, so an
 * import cannot silently store a range that would match everything.
 */
export function parseVersionRange(raw: string): VersionRange | null {
  if (typeof raw !== 'string') {
    return null;
  }
  const text = raw.trim();
  if (text.length === 0) {
    return null;
  }

  const alternatives: VersionConstraint[][] = [];
  for (const group of text.split('||')) {
    const tokens = group
      .trim()
      .split(/[\s,]+/)
      .filter((token) => token.length > 0);
    if (tokens.length === 0) {
      return null;
    }
    const constraints: VersionConstraint[] = [];
    for (let index = 0; index < tokens.length; index += 1) {
      const token = tokens[index] as string;
      if (token === '*' || token.toLowerCase() === 'x') {
        continue;
      }
      // Hyphen range: `1.0.0 - 1.2.3` means `>= 1.0.0, <= 1.2.3`.
      if (token === '-') {
        const previous = constraints.pop();
        const nextToken = tokens[index + 1];
        if (!previous || previous.operator !== '=' || !nextToken) {
          return null;
        }
        constraints.push({ operator: '>=', version: previous.version });
        const upper = parseConstraintToken(`<=${nextToken}`);
        if (!upper) {
          return null;
        }
        constraints.push(...upper);
        index += 1;
        continue;
      }
      if (OPERATORS.includes(token as (typeof OPERATORS)[number])) {
        // Operator separated from its version by whitespace: `>= 1.2.3`.
        const nextToken = tokens[index + 1];
        if (!nextToken) {
          return null;
        }
        const combined = parseConstraintToken(`${token}${nextToken}`);
        if (!combined) {
          return null;
        }
        constraints.push(...combined);
        index += 1;
        continue;
      }
      const parsed = parseConstraintToken(token);
      if (!parsed) {
        return null;
      }
      constraints.push(...parsed);
    }
    // A group that is only a wildcard keeps an empty constraint list, which
    // matches every version ("all releases are affected").
    alternatives.push(constraints);
  }

  if (alternatives.length === 0) {
    return null;
  }
  return { alternatives };
}

function testConstraint(version: ParsedVersion, constraint: VersionConstraint): boolean {
  const order = compareParsedVersions(version, constraint.version);
  switch (constraint.operator) {
    case '<':
      return order < 0;
    case '<=':
      return order <= 0;
    case '>':
      return order > 0;
    case '>=':
      return order >= 0;
    case '=':
      return order === 0;
    default:
      return false;
  }
}

/** True when `version` falls inside `range`; false when either cannot be parsed. */
export function satisfiesRange(version: string, range: string): boolean {
  const parsedVersion = parseVersion(version);
  const parsedRange = parseVersionRange(range);
  if (!parsedVersion || !parsedRange) {
    return false;
  }
  return parsedRange.alternatives.some((group) =>
    group.every((constraint) => testConstraint(parsedVersion, constraint)),
  );
}

/** Import-time check so a stored advisory always has an evaluable range. */
export function isValidVersionRange(range: string): boolean {
  return parseVersionRange(range) !== null;
}
