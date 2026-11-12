import { randomUUID } from 'node:crypto';
import { prisma } from '@/lib/prisma';
import { planRetention, pruneRateLimitWindows, purgeRetention } from '@/server/services/retention';

/**
 * Applies the data-retention policy to derived history.
 *
 *   npm run data:retention -- --org acme --days 90          # dry run
 *   npm run data:retention -- --org acme --days 90 --apply  # delete
 *   npm run data:retention -- --days 90 --apply             # every organization
 *
 * Findings, incidents, assets, compliance evidence, and audit events are never
 * touched: they are business records or the append-only chain. What is removed
 * is agent runs, terminal alert deliveries, and software inventory rows from agents
 * that stopped reporting. Each purge appends `retention.purged` with the cutoff
 * and the counts, so the chain explains where the history went.
 */

interface Options {
  org: string | null;
  days: number;
  apply: boolean;
}

function usage(message?: string): never {
  if (message) {
    console.error(`Error: ${message}`);
  }
  console.error(
    'Usage: npm run data:retention -- [--org <slug-or-id>] [--days <n>] [--apply] [--prune-rate-limits]',
  );
  process.exit(1);
}

function parseArgs(argv: string[]): Options & { pruneRateLimits: boolean } {
  let org: string | null = null;
  let days = 90;
  let apply = false;
  let pruneRateLimits = false;

  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === '--org') {
      org = argv[index + 1] ?? null;
      index += 1;
    } else if (arg === '--days') {
      const raw = argv[index + 1] ?? '';
      index += 1;
      const parsed = Number.parseInt(raw, 10);
      if (!Number.isInteger(parsed) || parsed < 1) {
        usage(`--days must be a positive integer, got "${raw}"`);
      }
      days = parsed;
    } else if (arg === '--apply') {
      apply = true;
    } else if (arg === '--prune-rate-limits') {
      pruneRateLimits = true;
    } else if (arg === '--help' || arg === '-h') {
      usage();
    } else {
      usage(`unknown argument "${arg}"`);
    }
  }

  return { org, days, apply, pruneRateLimits };
}

async function main(): Promise<void> {
  const options = parseArgs(process.argv.slice(2));

  const organizations = await prisma.organization.findMany({
    where: options.org ? { OR: [{ slug: options.org }, { id: options.org }] } : {},
    select: { id: true, slug: true },
    orderBy: { slug: 'asc' },
  });

  if (organizations.length === 0) {
    throw new Error(`No organization matches "${options.org ?? ''}".`);
  }

  const meta = {
    requestId: randomUUID(),
    ipAddress: null,
    userAgent: 'cybernorf-retention-cli',
  };

  console.log(
    `${options.apply ? 'Purging' : 'Dry run (add --apply to delete)'} history older than ${options.days} days.`,
  );

  for (const organization of organizations) {
    const summary = options.apply
      ? await purgeRetention(organization.id, { days: options.days }, meta)
      : await planRetention(organization.id, { days: options.days });

    console.log(
      `  ${organization.slug}: cutoff ${summary.cutoff.slice(0, 10)}, ` +
        `${summary.runs} runs, ${summary.notificationEvents} alert deliveries, ` +
        `${summary.softwareItems} software inventory rows`,
    );
  }

  if (options.pruneRateLimits) {
    if (options.apply) {
      const removed = await pruneRateLimitWindows();
      console.log(`Pruned ${removed} expired rate-limit windows.`);
    } else {
      console.log('Rate-limit windows older than 24 hours would be pruned (dry run).');
    }
  }
}

main()
  .catch((error: unknown) => {
    console.error(error instanceof Error ? error.message : error);
    process.exitCode = 1;
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
