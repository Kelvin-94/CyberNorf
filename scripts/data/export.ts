import { writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { prisma } from '@/lib/prisma';
import { exportOrganization } from '@/server/services/export';

/**
 * Writes one organization's records to a JSON file.
 *
 *   npm run data:export -- --org acme
 *   npm run data:export -- --org acme --out /secure/acme.json
 *
 * Read-only: the script never mutates the database. The file is written with
 * owner-only permissions because it contains member email addresses, findings,
 * and the audit trail (but no credentials — see src/server/services/export.ts).
 */

interface Options {
  org: string;
  out: string | null;
}

function usage(message?: string): never {
  if (message) {
    console.error(`Error: ${message}`);
  }
  console.error('Usage: npm run data:export -- --org <slug-or-id> [--out <file.json>]');
  process.exit(1);
}

function parseArgs(argv: string[]): Options {
  let org: string | null = null;
  let out: string | null = null;

  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === '--org') {
      org = argv[index + 1] ?? null;
      index += 1;
    } else if (arg === '--out') {
      out = argv[index + 1] ?? null;
      index += 1;
    } else if (arg === '--help' || arg === '-h') {
      usage();
    } else {
      usage(`unknown argument "${arg}"`);
    }
  }

  if (!org) {
    usage('--org is required');
  }
  return { org, out };
}

async function main(): Promise<void> {
  const options = parseArgs(process.argv.slice(2));

  const organization = await prisma.organization.findFirst({
    where: { OR: [{ slug: options.org }, { id: options.org }] },
    select: { id: true, slug: true },
  });
  if (!organization) {
    throw new Error(`No organization matches "${options.org}".`);
  }

  const payload = await exportOrganization(organization.id);
  const stamp = new Date().toISOString().slice(0, 10);
  const target = resolve(options.out ?? `cybernorf-export-${organization.slug}-${stamp}.json`);

  await writeFile(target, `${JSON.stringify(payload, null, 2)}\n`, { mode: 0o600 });

  console.log(`Exported organization "${organization.slug}" to ${target}`);
  for (const [key, value] of Object.entries(payload.meta.counts)) {
    console.log(`  ${key}: ${value}`);
  }
  console.log(`Excluded by design: ${payload.meta.excludes.join('; ')}`);
}

main()
  .catch((error: unknown) => {
    console.error(error instanceof Error ? error.message : error);
    process.exitCode = 1;
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
