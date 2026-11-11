import { prisma } from '@/lib/prisma';
import { sweepEvidenceIntegrity } from '@/server/services/evidence-files';
import { evidenceRoot } from '@/server/services/evidence-storage';

/**
 * Re-verifies stored evidence against the hash recorded at upload time.
 *
 *   npm run evidence:verify                      # oldest 50 unchecked/failed files
 *   npm run evidence:verify -- --limit 500       # a bigger batch
 *   npm run evidence:verify -- --all             # drain the backlog in batches
 *   npm run evidence:verify -- --org acme --all  # one tenant
 *
 * The sweep writes the outcome to each row and does not append an audit event per
 * file (that would flood the chain); the per-file verification an auditor asks
 * for is the API route, which does audit. This command is the scheduled check, so
 * its exit code is the alert: any MISMATCH or MISSING exits 1 and prints the
 * counts, and a scheduler that pages on non-zero gets a signal without parsing
 * output.
 *
 * A MISSING file is not automatically an incident — a restore that dropped the
 * evidence volume and a deliberate deletion look the same from here. It is a
 * finding to explain, which is why it is reported rather than swallowed.
 *
 * An unset EVIDENCE_DIR is only an error when stored files exist. A deployment
 * that never enabled attachments should not page every night, but a deployment
 * that lost the variable after uploading must, because its files are now
 * unverifiable.
 */

interface Options {
  organization: string | null;
  limit: number;
  all: boolean;
}

function usage(message?: string): never {
  if (message) {
    console.error(`Error: ${message}`);
  }
  console.error('Usage: npm run evidence:verify -- [--org <slug-or-id>] [--limit <n>] [--all]');
  process.exit(1);
}

function parseArgs(argv: string[]): Options {
  let organization: string | null = null;
  let limit = 50;
  let all = false;

  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === '--all') {
      all = true;
      continue;
    }
    if (argument === '--org' || argument === '--limit') {
      const value = argv[index + 1];
      if (!value || value.startsWith('--')) {
        usage(`${argument} needs a value.`);
      }
      index += 1;
      if (argument === '--org') {
        organization = value;
      } else {
        const parsed = Number(value);
        if (!Number.isInteger(parsed) || parsed <= 0 || parsed > 5_000) {
          usage('--limit must be a whole number between 1 and 5000.');
        }
        limit = parsed;
      }
      continue;
    }
    usage(`unknown argument "${argument}".`);
  }

  return { organization, limit, all };
}

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

async function resolveOrganization(reference: string): Promise<{ id: string; slug: string }> {
  const bySlug = await prisma.organization.findUnique({
    where: { slug: reference },
    select: { id: true, slug: true },
  });
  if (bySlug) {
    return bySlug;
  }
  if (UUID_PATTERN.test(reference)) {
    const byId = await prisma.organization.findUnique({
      where: { id: reference },
      select: { id: true, slug: true },
    });
    if (byId) {
      return byId;
    }
  }
  usage(`no organization matches "${reference}".`);
}

async function main(): Promise<void> {
  const options = parseArgs(process.argv.slice(2));
  const organization = options.organization
    ? await resolveOrganization(options.organization)
    : null;

  const scope = organization ? `organization ${organization.slug}` : 'all organizations';

  if (!evidenceRoot()) {
    const stored = await prisma.controlEvidence.count({
      where: {
        kind: 'FILE',
        ...(organization ? { organizationId: organization.id } : {}),
        blobKey: { not: null },
      },
    });
    if (stored === 0) {
      console.log(
        `Evidence integrity (${scope}): EVIDENCE_DIR is not set and no stored files exist, so there is nothing to verify.`,
      );
      return;
    }
    console.error(
      `EVIDENCE_DIR is not set, but ${stored} stored evidence file(s) exist in ${scope}. ` +
        'Point it at the volume that holds them before trusting this deployment.',
    );
    process.exitCode = 1;
    return;
  }

  const totals = { checked: 0, intact: 0, mismatched: 0, missing: 0, skipped: 0 };
  const maxBatches = options.all ? 100 : 1;
  let batches = 0;

  while (batches < maxBatches) {
    const batch = await sweepEvidenceIntegrity({
      ...(organization ? { organizationId: organization.id } : {}),
      limit: options.limit,
    });
    batches += 1;

    totals.checked += batch.checked;
    totals.intact += batch.intact;
    totals.mismatched += batch.mismatched;
    totals.missing += batch.missing;
    totals.skipped += batch.skipped;

    // A batch that checked nothing means the backlog is drained, or every
    // candidate lacked a blob key. Either way another pass would repeat it.
    if (batch.checked === 0 || !options.all) {
      break;
    }
  }

  console.log(
    `Evidence integrity (${scope}): ${totals.checked} checked, ${totals.intact} intact, ` +
      `${totals.mismatched} mismatched, ${totals.missing} missing, ${totals.skipped} skipped ` +
      `in ${batches} batch${batches === 1 ? '' : 'es'}.`,
  );

  if (totals.mismatched > 0 || totals.missing > 0) {
    console.error(
      'Evidence that does not match its recorded hash, or is no longer on disk, needs an explanation before the next audit.',
    );
    process.exitCode = 1;
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
