import { prisma } from '@/lib/prisma';
import {
  QUOTA_RESOURCE_LABELS,
  QUOTA_RESOURCES,
  TIER_QUOTAS,
  describeLimit,
  type QuotaResource,
} from '@/server/domain/quotas';
import { getQuotaUsage, setQuotaOverride } from '@/server/services/quotas';

/**
 * Operator CLI for per-tenant quotas.
 *
 *   npm run quota -- show                      # every organization, one line each
 *   npm run quota -- show acme                 # one tenant, every resource
 *   npm run quota -- set acme findings 5000    # dry run, prints the change
 *   npm run quota -- set acme findings 5000 --apply
 *   npm run quota -- set acme findings none --apply   # back to the tier default
 *
 * A limit is never changed without `--apply`, so a mistyped slug or number shows
 * the diff and stops. Applying writes `quota.override_changed` to the tenant's
 * audit chain with the previous and new value.
 */

interface Options {
  command: 'show' | 'set';
  organization: string | null;
  resource: QuotaResource | null;
  limit: number | null;
  apply: boolean;
}

function usage(message?: string): never {
  if (message) {
    console.error(`Error: ${message}`);
  }
  console.error(
    'Usage: npm run quota -- show [<slug-or-id>]\n' +
      '       npm run quota -- set <slug-or-id> <resource> <limit|none> [--apply]\n' +
      `       resources: ${QUOTA_RESOURCES.join(', ')}`,
  );
  process.exit(1);
}

function parseLimit(raw: string): number | null {
  if (raw === 'none' || raw === 'default') {
    return null;
  }
  const value = Number(raw);
  if (!Number.isInteger(value) || value <= 0) {
    usage(`"${raw}" is not a positive whole number, and is not "none".`);
  }
  return value;
}

function parseArgs(argv: string[]): Options {
  const [command, ...rest] = argv;
  if (command !== 'show' && command !== 'set') {
    usage(command ? `unknown command "${command}".` : undefined);
  }

  const apply = rest.includes('--apply');
  const positional = rest.filter((argument) => !argument.startsWith('--'));

  if (command === 'show') {
    if (positional.length > 1) {
      usage('show takes at most one organization.');
    }
    return {
      command,
      organization: positional[0] ?? null,
      resource: null,
      limit: null,
      apply,
    };
  }

  if (positional.length !== 3) {
    usage('set takes an organization, a resource, and a limit.');
  }

  const [organization, resource, rawLimit] = positional as [string, string, string];
  if (!(QUOTA_RESOURCES as readonly string[]).includes(resource)) {
    usage(`unknown resource "${resource}".`);
  }

  return {
    command,
    organization,
    resource: resource as QuotaResource,
    limit: parseLimit(rawLimit),
    apply,
  };
}

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

async function resolveOrganization(reference: string) {
  const bySlug = await prisma.organization.findUnique({
    where: { slug: reference },
    select: { id: true, slug: true, name: true, tier: true },
  });
  if (bySlug || !UUID_PATTERN.test(reference)) {
    return bySlug;
  }
  return prisma.organization.findUnique({
    where: { id: reference },
    select: { id: true, slug: true, name: true, tier: true },
  });
}

function operatorLabel(): string {
  return `cli:quota:${process.env.USER ?? process.env.LOGNAME ?? 'operator'}`;
}

function percent(used: number, limit: number | null): string {
  if (limit === null) {
    return '';
  }
  return `${Math.round((used / limit) * 100)}%`;
}

async function showAll(): Promise<void> {
  const organizations = await prisma.organization.findMany({
    orderBy: { slug: 'asc' },
    select: { id: true, slug: true, tier: true },
  });

  if (organizations.length === 0) {
    console.log('No organizations.');
    return;
  }

  for (const organization of organizations) {
    const { usage } = await getQuotaUsage(organization.id, organization.tier);
    const cells = usage.map((entry) => {
      const share = percent(entry.used, entry.limit);
      return `${entry.resource}=${entry.used}/${entry.limit ?? '∞'}${share ? ` (${share})` : ''}`;
    });
    console.log(`${organization.slug} [${organization.tier}]`);
    console.log(`  ${cells.join('  ')}`);
  }
}

async function showOne(reference: string): Promise<void> {
  const organization = await resolveOrganization(reference);
  if (!organization) {
    console.error(`No organization matches "${reference}".`);
    process.exitCode = 1;
    return;
  }

  const { usage } = await getQuotaUsage(organization.id, organization.tier);
  console.log(`${organization.name} (${organization.slug}) [${organization.tier}]`);
  for (const entry of usage) {
    const share = percent(entry.used, entry.limit);
    console.log(
      `  ${QUOTA_RESOURCE_LABELS[entry.resource].padEnd(22)} ` +
        `${String(entry.used).padStart(8)} / ${describeLimit(entry.limit, entry.resource)}` +
        `${share ? `  ${share}` : ''}`,
    );
  }
}

async function applySet(options: Options): Promise<void> {
  const reference = options.organization as string;
  const resource = options.resource as QuotaResource;
  const organization = await resolveOrganization(reference);
  if (!organization) {
    console.error(`No organization matches "${reference}".`);
    process.exitCode = 1;
    return;
  }

  const before = await getQuotaUsage(organization.id, organization.tier);
  const current = before.usage.find((entry) => entry.resource === resource);
  const label = QUOTA_RESOURCE_LABELS[resource];

  console.log(`${organization.slug} [${organization.tier}] ${label}`);
  console.log(`  current: ${describeLimit(current?.limit ?? null, resource)}`);
  console.log(
    `  new:     ${
      options.limit === null
        ? `tier default (${describeLimit(TIER_QUOTAS[organization.tier][resource], resource)})`
        : describeLimit(options.limit, resource)
    }`,
  );

  if (!options.apply) {
    console.log('Dry run. Re-run with --apply to write this change.');
    return;
  }

  await setQuotaOverride(organization.id, resource, options.limit, {
    actorLabel: operatorLabel(),
  });
  console.log(
    `Applied. Wrote ${resource} override for ${organization.slug} (audited as quota.override_changed).`,
  );
}

async function main(): Promise<void> {
  const options = parseArgs(process.argv.slice(2));

  if (options.command === 'show') {
    if (options.organization) {
      await showOne(options.organization);
    } else {
      await showAll();
    }
    return;
  }

  await applySet(options);
}

main()
  .catch((error: unknown) => {
    console.error(error instanceof Error ? error.message : error);
    process.exitCode = 1;
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
