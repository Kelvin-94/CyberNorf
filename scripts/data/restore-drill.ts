import { spawn } from 'node:child_process';
import { createReadStream, createWriteStream, readFileSync } from 'node:fs';
import { mkdtemp, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { PrismaPg } from '@prisma/adapter-pg';
import { Client } from 'pg';
import { PrismaClient } from '@/generated/prisma/client';
import { verifyAuditChain } from '@/server/audit/audit';

/**
 * Proves that a database dump can actually be restored and that the restored
 * copy still enforces the guarantees the application depends on.
 *
 *   npm run db:restore-drill
 *   npm run db:restore-drill -- --docker-exec cybernorf-database-1
 *   npm run db:restore-drill -- --docker-exec cybernorf-database-1 --keep --report drill.json
 *
 * The drill creates a throwaway database on the same server as DATABASE_URL,
 * dumps the source with pg_dump, restores it with pg_restore --exit-on-error,
 * and then compares the restored schema with the source. It fails if the table
 * set, column definitions, constraints, triggers, or migration history differ,
 * if any organization's audit chain no longer verifies, or if the append-only
 * triggers stop rejecting UPDATE on audit_events, auth_events, or
 * identity_events.
 *
 * Backups that have never been restored are a hope, not a control. Run this
 * after every schema change and on a schedule; archive the JSON report as the
 * evidence that the drill passed on a given date.
 *
 * Safety: the drill refuses to touch a database whose name does not carry the
 * drill prefix, and it only drops the database it created in this run.
 */

const DRILL_PREFIX = 'cybernorf_drill_';

/** Tables whose UPDATE must be rejected by the append-only trigger. */
const APPEND_ONLY_TABLES = [
  { table: 'audit_events', column: 'summary' },
  { table: 'auth_events', column: 'outcome' },
  { table: 'identity_events', column: 'type' },
];

type CheckStatus = 'pass' | 'fail' | 'skip' | 'warn';

interface Check {
  name: string;
  status: CheckStatus;
  detail: string;
}

interface Options {
  keep: boolean;
  dockerExec: string | null;
  org: string | null;
  report: string | null;
}

interface SourceTarget {
  database: string;
  host: string;
  port: number;
  user: string;
  password: string;
  schema: string;
  ssl: false | { ca?: Buffer; rejectUnauthorized: boolean } | undefined;
}

function usage(message?: string): never {
  if (message) {
    console.error(`Error: ${message}`);
  }
  console.error(
    'Usage: npm run db:restore-drill -- [--docker-exec <container>] [--org <slug-or-id>] [--keep] [--report <file.json>]',
  );
  process.exit(1);
}

function parseArgs(argv: string[]): Options {
  const options: Options = { keep: false, dockerExec: null, org: null, report: null };

  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === '--keep') {
      options.keep = true;
    } else if (arg === '--docker-exec') {
      options.dockerExec = argv[index + 1] ?? usage('--docker-exec needs a container name');
      index += 1;
    } else if (arg === '--org') {
      options.org = argv[index + 1] ?? usage('--org needs a value');
      index += 1;
    } else if (arg === '--report') {
      options.report = argv[index + 1] ?? usage('--report needs a path');
      index += 1;
    } else if (arg === '--help' || arg === '-h') {
      usage();
    } else {
      usage(`unknown argument "${arg}"`);
    }
  }

  return options;
}

function readSourceTarget(): SourceTarget {
  const raw = process.env.DATABASE_URL;
  if (!raw) {
    throw new Error('DATABASE_URL is not set. Pass --env-file=.env or export it first.');
  }

  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new Error('DATABASE_URL is not a valid URL.');
  }
  if (url.protocol !== 'postgresql:' && url.protocol !== 'postgres:') {
    throw new Error(`DATABASE_URL must be a postgresql:// URL, not ${url.protocol}`);
  }

  const database = decodeURIComponent(url.pathname.replace(/^\//, ''));
  if (!database) {
    throw new Error('DATABASE_URL does not name a database.');
  }
  if (database.startsWith(DRILL_PREFIX)) {
    throw new Error(
      `Refusing to dump "${database}": drill databases are throwaway and must never be a source of truth.`,
    );
  }

  const sslmode = url.searchParams.get('sslmode');
  const certPath = url.searchParams.get('sslrootcert');
  let ssl: SourceTarget['ssl'];
  if (sslmode === 'disable') {
    ssl = false;
  } else if (sslmode) {
    // Every encrypting mode verifies the server certificate, `require`
    // included: current `pg` releases treat it as `verify-full` (ADR 0004), and
    // a drill that accepted any certificate would not prove the production path
    // works. A database with a self-signed certificate needs `sslrootcert`
    // pointing at its CA, exactly as the deployment does.
    ssl = certPath
      ? { ca: readFileSync(certPath), rejectUnauthorized: true }
      : { rejectUnauthorized: true };
  }

  return {
    database,
    host: url.hostname,
    port: url.port ? Number(url.port) : 5432,
    user: decodeURIComponent(url.username),
    password: decodeURIComponent(url.password),
    schema: url.searchParams.get('schema') ?? 'public',
    ssl,
  };
}

function quoteIdent(name: string): string {
  return `"${name.replace(/"/g, '""')}"`;
}

function drillDatabaseName(): string {
  const now = new Date();
  const stamp = now.toISOString().replace(/[-:T]/g, '').slice(0, 14);
  return `${DRILL_PREFIX}${stamp}`;
}

interface RunOptions {
  label: string;
  stdinFile?: string;
  stdoutFile?: string;
  env?: NodeJS.ProcessEnv;
}

/**
 * Runs one external command with optional file plumbing. pg_dump writes to
 * stdout and pg_restore reads from stdin so the same path works on the host and
 * through `docker exec`, where a host file path does not exist.
 */
function runCommand(command: string, args: string[], options: RunOptions): Promise<void> {
  return new Promise((resolvePromise, reject) => {
    const child = spawn(command, args, {
      stdio: ['pipe', 'pipe', 'pipe'],
      env: options.env ?? process.env,
    });

    const streams: Promise<void>[] = [];
    let stderr = '';
    let settled = false;

    child.stderr.on('data', (chunk: Buffer) => {
      if (stderr.length < 8000) {
        stderr += chunk.toString();
      }
    });

    if (options.stdoutFile) {
      const out = createWriteStream(options.stdoutFile);
      streams.push(
        new Promise((done, failed) => {
          out.on('finish', () => done());
          out.on('error', failed);
        }),
      );
      child.stdout.pipe(out);
    } else {
      child.stdout.resume();
    }

    const stdin = child.stdin;
    if (options.stdinFile && stdin) {
      const input = createReadStream(options.stdinFile);
      streams.push(
        new Promise((done, failed) => {
          input.on('end', () => done());
          input.on('error', failed);
        }),
      );
      input.pipe(stdin);
    } else {
      stdin?.end();
    }

    const settle = (error: Error | null): void => {
      if (settled) {
        return;
      }
      settled = true;
      if (error) {
        reject(error);
      } else {
        resolvePromise();
      }
    };

    child.on('error', (error) => {
      settle(new Error(`${options.label} could not start: ${error.message}`));
    });

    child.on('close', (code) => {
      Promise.all(streams)
        .then(() => {
          if (code === 0) {
            settle(null);
          } else {
            const suffix = stderr.trim() ? `: ${stderr.trim().slice(0, 2000)}` : '';
            settle(new Error(`${options.label} exited with code ${code}${suffix}`));
          }
        })
        .catch((error: unknown) => {
          settle(error instanceof Error ? error : new Error(String(error)));
        });
    });
  });
}

function pgArgs(target: SourceTarget, database: string): string[] {
  return ['-h', target.host, '-p', String(target.port), '-U', target.user, '-d', database];
}

/** pg_dump / pg_restore arguments; inside a container the socket is used. */
function dumpArgs(target: SourceTarget, docker: boolean): string[] {
  const base = ['--format=custom', '--no-owner', '--no-privileges'];
  return docker
    ? [...base, '-U', target.user, '-d', target.database]
    : [...base, ...pgArgs(target, target.database)];
}

function restoreArgs(target: SourceTarget, database: string, docker: boolean): string[] {
  const base = ['--no-owner', '--no-privileges', '--exit-on-error'];
  return docker
    ? [...base, '-U', target.user, '-d', database]
    : [...base, ...pgArgs(target, database)];
}

function toolCommand(
  tool: string,
  dockerExec: string | null,
): { command: string; prefix: string[] } {
  return dockerExec
    ? { command: 'docker', prefix: ['exec', '-i', dockerExec, tool] }
    : { command: tool, prefix: [] };
}

async function connect(target: SourceTarget, database: string): Promise<Client> {
  const client = new Client({
    host: target.host,
    port: target.port,
    user: target.user,
    password: target.password,
    database,
    ssl: target.ssl,
  });
  await client.connect();
  return client;
}

function diffSets(
  source: string[],
  restored: string[],
): {
  missing: string[];
  extra: string[];
  matched: number;
} {
  const sourceSet = new Set(source);
  const restoredSet = new Set(restored);
  const missing = [...sourceSet].filter((value) => !restoredSet.has(value));
  const extra = [...restoredSet].filter((value) => !sourceSet.has(value));
  return { missing, extra, matched: sourceSet.size - missing.length };
}

function describeDiff(missing: string[], extra: string[], limit = 5): string {
  const parts: string[] = [];
  if (missing.length > 0) {
    parts.push(`missing ${missing.slice(0, limit).join(', ')}${missing.length > limit ? '…' : ''}`);
  }
  if (extra.length > 0) {
    parts.push(`unexpected ${extra.slice(0, limit).join(', ')}${extra.length > limit ? '…' : ''}`);
  }
  return parts.join('; ');
}

async function introspect(
  client: Client,
  schema: string,
): Promise<{
  tables: string[];
  columns: string[];
  constraints: string[];
  triggers: string[];
  migrations: string[];
}> {
  const tables = await client.query<{ table_name: string }>(
    `SELECT table_name FROM information_schema.tables
      WHERE table_schema = $1 AND table_type = 'BASE TABLE' ORDER BY 1`,
    [schema],
  );
  const columns = await client.query<{ sig: string }>(
    `SELECT table_name || '.' || column_name || ':' || data_type || ':' || is_nullable || ':' ||
            coalesce(column_default, '') AS sig
       FROM information_schema.columns WHERE table_schema = $1 ORDER BY 1`,
    [schema],
  );
  const constraints = await client.query<{ sig: string }>(
    `SELECT cls.relname || ' ' || con.conname || ' ' || con.contype::text || ' ' ||
            pg_get_constraintdef(con.oid) AS sig
       FROM pg_constraint con
       JOIN pg_class cls ON cls.oid = con.conrelid
       JOIN pg_namespace ns ON ns.oid = cls.relnamespace
      WHERE ns.nspname = $1 AND con.contype IN ('c', 'f', 'u', 'p', 'x') ORDER BY 1`,
    [schema],
  );
  const triggers = await client.query<{ sig: string }>(
    `SELECT cls.relname || ' ' || trg.tgname || ' ' || pg_get_triggerdef(trg.oid) AS sig
       FROM pg_trigger trg
       JOIN pg_class cls ON cls.oid = trg.tgrelid
       JOIN pg_namespace ns ON ns.oid = cls.relnamespace
      WHERE ns.nspname = $1 AND NOT trg.tgisinternal ORDER BY 1`,
    [schema],
  );

  let migrations: string[] = [];
  try {
    const result = await client.query<{ sig: string }>(
      `SELECT migration_name || ':' || (finished_at IS NOT NULL)::text || ':' ||
              (rolled_back_at IS NOT NULL)::text || ':' || applied_steps_count::text AS sig
         FROM "_prisma_migrations" ORDER BY 1`,
    );
    migrations = result.rows.map((row) => row.sig);
  } catch (error) {
    const code = (error as { code?: string }).code;
    if (code !== '42P01') {
      throw error;
    }
  }

  return {
    tables: tables.rows.map((row) => row.table_name),
    columns: columns.rows.map((row) => row.sig),
    constraints: constraints.rows.map((row) => row.sig),
    triggers: triggers.rows.map((row) => row.sig),
    migrations,
  };
}

async function countRows(client: Client, schema: string, table: string): Promise<number> {
  const result = await client.query<{ count: string }>(
    `SELECT count(*)::text AS count FROM ${quoteIdent(schema)}.${quoteIdent(table)}`,
  );
  return Number(result.rows[0]?.count ?? 0);
}

async function appendsAreBlocked(
  client: Client,
  schema: string,
  table: string,
  column: string,
): Promise<'blocked' | 'allowed' | 'empty'> {
  const qualified = `${quoteIdent(schema)}.${quoteIdent(table)}`;
  const count = await client.query<{ count: string }>(
    `SELECT count(*)::text AS count FROM ${qualified}`,
  );
  if (Number(count.rows[0]?.count ?? 0) === 0) {
    return 'empty';
  }

  await client.query('BEGIN');
  try {
    await client.query(
      `UPDATE ${qualified} SET ${quoteIdent(column)} = ${quoteIdent(column)}
        WHERE id = (SELECT id FROM ${qualified} LIMIT 1)`,
    );
    return 'allowed';
  } catch {
    return 'blocked';
  } finally {
    await client.query('ROLLBACK').catch(() => undefined);
  }
}

function createDrillPrisma(database: string): PrismaClient {
  const url = new URL(process.env.DATABASE_URL as string);
  url.pathname = `/${database}`;
  // Keep the driver's TLS behaviour aligned with the source connection.
  const adapter = new PrismaPg({ connectionString: url.toString() });
  return new PrismaClient({ adapter });
}

async function main(): Promise<void> {
  const options = parseArgs(process.argv.slice(2));
  const target = readSourceTarget();
  const drillDb = drillDatabaseName();
  const startedAt = new Date();

  const checks: Check[] = [];
  const warnings: string[] = [];
  let dumpDir: string | null = null;
  let drillDatabaseCreated = false;
  let sourceClient: Client | null = null;
  let drillClient: Client | null = null;
  let drillPrisma: PrismaClient | null = null;

  const record = (name: string, status: CheckStatus, detail: string): void => {
    checks.push({ name, status, detail });
    const marker = status.padEnd(4, ' ');
    console.log(`  [${marker}] ${name}${detail ? ` — ${detail}` : ''}`);
  };

  console.log(
    `Restore drill for "${target.database}" at ${target.host}:${target.port} (schema ${target.schema})`,
  );
  console.log(`  drill database: ${drillDb}`);
  console.log(`  container:      ${options.dockerExec ?? 'none (using host PostgreSQL tools)'}`);

  try {
    sourceClient = await connect(target, target.database);
    record('source database reachable', 'pass', `connected as ${target.user}`);

    const sourceFacts = await introspect(sourceClient, target.schema);
    if (sourceFacts.migrations.length === 0) {
      throw new Error(
        'Source has no _prisma_migrations history. Run `npx prisma migrate deploy` against it first.',
      );
    }
    record(
      'source snapshot captured',
      'pass',
      `${sourceFacts.tables.length} tables, ${sourceFacts.migrations.length} migrations`,
    );

    // Create the throwaway database on the same server.
    const admin = await connect(target, 'postgres');
    try {
      await admin.query(`CREATE DATABASE ${quoteIdent(drillDb)}`);
      drillDatabaseCreated = true;
    } finally {
      await admin.end();
    }
    record('drill database created', 'pass', drillDb);

    // Dump.
    dumpDir = await mkdtemp(join(tmpdir(), 'cybernorf-drill-'));
    const dumpFile = join(dumpDir, `${target.database}.dump`);
    const dumpTool = toolCommand('pg_dump', options.dockerExec);
    const dumpEnv = options.dockerExec
      ? process.env
      : { ...process.env, PGPASSWORD: target.password };
    await runCommand(
      dumpTool.command,
      [...dumpTool.prefix, ...dumpArgs(target, Boolean(options.dockerExec))],
      {
        label: 'pg_dump',
        stdoutFile: dumpFile,
        env: dumpEnv,
      },
    );
    const dumpSize = (await stat(dumpFile)).size;
    record('dump created', 'pass', `${(dumpSize / 1024).toFixed(1)} KiB custom-format archive`);

    // Row counts are captured after the dump so restored counts compare against
    // the state that was actually archived.
    const sourceCounts = new Map<string, number>();
    for (const table of sourceFacts.tables) {
      sourceCounts.set(table, await countRows(sourceClient, target.schema, table));
    }

    // Restore.
    const restoreTool = toolCommand('pg_restore', options.dockerExec);
    const restoreEnv = options.dockerExec
      ? process.env
      : { ...process.env, PGPASSWORD: target.password };
    await runCommand(
      restoreTool.command,
      [...restoreTool.prefix, ...restoreArgs(target, drillDb, Boolean(options.dockerExec))],
      { label: 'pg_restore', stdinFile: dumpFile, env: restoreEnv },
    );
    record('restore completed', 'pass', 'pg_restore --exit-on-error');

    // Compare the restored schema with the source.
    drillClient = await connect(target, drillDb);
    const restoredFacts = await introspect(drillClient, target.schema);

    const tableDiff = diffSets(sourceFacts.tables, restoredFacts.tables);
    if (tableDiff.missing.length === 0 && tableDiff.extra.length === 0) {
      record('table set matches', 'pass', `${restoredFacts.tables.length} tables`);
    } else {
      record('table set matches', 'fail', describeDiff(tableDiff.missing, tableDiff.extra));
    }

    const columnDiff = diffSets(sourceFacts.columns, restoredFacts.columns);
    if (columnDiff.missing.length === 0 && columnDiff.extra.length === 0) {
      record('column definitions match', 'pass', `${restoredFacts.columns.length} columns`);
    } else {
      record(
        'column definitions match',
        'fail',
        describeDiff(columnDiff.missing, columnDiff.extra),
      );
    }

    const constraintDiff = diffSets(sourceFacts.constraints, restoredFacts.constraints);
    if (constraintDiff.missing.length === 0 && constraintDiff.extra.length === 0) {
      record('constraints match', 'pass', `${restoredFacts.constraints.length} constraints`);
    } else {
      record(
        'constraints match',
        'fail',
        describeDiff(constraintDiff.missing, constraintDiff.extra),
      );
    }

    const triggerDiff = diffSets(sourceFacts.triggers, restoredFacts.triggers);
    if (triggerDiff.missing.length === 0 && triggerDiff.extra.length === 0) {
      record('triggers match', 'pass', `${restoredFacts.triggers.length} triggers`);
    } else {
      record('triggers match', 'fail', describeDiff(triggerDiff.missing, triggerDiff.extra));
    }

    const migrationDiff = diffSets(sourceFacts.migrations, restoredFacts.migrations);
    if (migrationDiff.missing.length === 0 && migrationDiff.extra.length === 0) {
      record(
        'migration history matches',
        'pass',
        `${restoredFacts.migrations.length} migrations applied`,
      );
    } else {
      record(
        'migration history matches',
        'fail',
        describeDiff(migrationDiff.missing, migrationDiff.extra),
      );
    }

    // Row counts drift if the source is written to during the drill; that is a
    // warning, not a failure, because the archive itself was consistent.
    const drift: string[] = [];
    for (const table of sourceFacts.tables) {
      const restored = await countRows(drillClient, target.schema, table);
      const source = sourceCounts.get(table) ?? 0;
      if (restored !== source) {
        drift.push(`${table} (source ${source}, restored ${restored})`);
      }
    }
    if (drift.length === 0) {
      record('row counts match', 'pass', `${sourceCounts.size} tables compared`);
    } else {
      record(
        'row counts match',
        'warn',
        `${drift.length} table(s) changed during the drill: ${drift.slice(0, 5).join(', ')}`,
      );
      warnings.push(
        'Row counts drifted while the drill ran; re-run against an idle database to confirm.',
      );
    }

    // The append-only triggers must still reject writes after a restore.
    for (const { table, column } of APPEND_ONLY_TABLES) {
      const outcome = await appendsAreBlocked(drillClient, target.schema, table, column);
      if (outcome === 'blocked') {
        record(
          `append-only trigger rejects UPDATE on ${table}`,
          'pass',
          'statement raised, rolled back',
        );
      } else if (outcome === 'empty') {
        record(`append-only trigger rejects UPDATE on ${table}`, 'skip', 'table is empty');
      } else {
        record(`append-only trigger rejects UPDATE on ${table}`, 'fail', 'UPDATE was accepted');
      }
    }

    // The audit chain must verify in the restored copy, using the application's
    // own verification code rather than a copy of the algorithm.
    const organizations = await drillClient.query<{ id: string; slug: string }>(
      `SELECT id, slug FROM ${quoteIdent(target.schema)}.organizations ORDER BY "createdAt" ASC`,
    );
    const selected = options.org
      ? organizations.rows.filter((row) => row.id === options.org || row.slug === options.org)
      : organizations.rows;

    if (options.org && selected.length === 0) {
      record('audit chain verifies', 'fail', `no organization matches "${options.org}"`);
    } else if (selected.length === 0) {
      record('audit chain verifies', 'skip', 'restored database has no organizations');
    } else {
      drillPrisma = createDrillPrisma(drillDb);
      let events = 0;
      const broken: string[] = [];
      for (const organization of selected) {
        const result = await verifyAuditChain(organization.id, drillPrisma);
        events += result.checked;
        if (!result.valid) {
          broken.push(
            `${organization.slug}: ${result.reason ?? 'invalid'} at sequence ${result.brokenAtSequence ?? '?'}`,
          );
        }
      }
      if (broken.length === 0) {
        record(
          'audit chain verifies',
          'pass',
          `${selected.length} organization(s), ${events} events recomputed`,
        );
      } else {
        record('audit chain verifies', 'fail', broken.join('; '));
      }
    }
  } catch (error) {
    record('drill aborted', 'fail', error instanceof Error ? error.message : String(error));
  } finally {
    if (drillPrisma) {
      await drillPrisma.$disconnect().catch(() => undefined);
    }
    if (drillClient) {
      await drillClient.end().catch(() => undefined);
    }
    if (sourceClient) {
      await sourceClient.end().catch(() => undefined);
    }

    if (drillDatabaseCreated && !options.keep) {
      try {
        const admin = await connect(target, 'postgres');
        try {
          if (drillDb.startsWith(DRILL_PREFIX)) {
            await admin.query(`DROP DATABASE IF EXISTS ${quoteIdent(drillDb)}`);
            console.log(`  dropped drill database ${drillDb}`);
          }
        } finally {
          await admin.end();
        }
      } catch (error) {
        warnings.push(
          `Could not drop ${drillDb}: ${error instanceof Error ? error.message : String(error)}`,
        );
      }
    } else if (drillDatabaseCreated && options.keep) {
      console.log(`  kept drill database ${drillDb}`);
    }

    if (dumpDir && !options.keep) {
      await rm(dumpDir, { recursive: true, force: true }).catch(() => undefined);
    } else if (dumpDir) {
      console.log(`  kept dump directory ${dumpDir}`);
    }
  }

  const failed = checks.filter((check) => check.status === 'fail');
  const passed = checks.filter((check) => check.status === 'pass');
  const skipped = checks.filter((check) => check.status === 'skip');
  const warned = checks.filter((check) => check.status === 'warn');
  const verdict = failed.length === 0 ? 'PASS' : 'FAIL';
  const finishedAt = new Date();

  console.log('');
  console.log(
    `Verdict: ${verdict} — ${passed.length} passed, ${failed.length} failed, ${skipped.length} skipped, ${warned.length} warnings ` +
      `(${((finishedAt.getTime() - startedAt.getTime()) / 1000).toFixed(1)}s)`,
  );
  if (failed.length > 0) {
    for (const check of failed) {
      console.log(`  failed: ${check.name} — ${check.detail}`);
    }
  }
  for (const warning of warnings) {
    console.log(`  note: ${warning}`);
  }

  if (options.report) {
    const reportPath = resolve(options.report);
    const report = {
      drill: {
        verdict,
        startedAt: startedAt.toISOString(),
        finishedAt: finishedAt.toISOString(),
        durationSeconds: Number(((finishedAt.getTime() - startedAt.getTime()) / 1000).toFixed(2)),
      },
      source: {
        host: target.host,
        port: target.port,
        database: target.database,
        schema: target.schema,
        user: target.user,
      },
      drillDatabase: { name: drillDb, retained: options.keep && drillDatabaseCreated },
      checks,
      warnings,
    };
    await writeFile(reportPath, `${JSON.stringify(report, null, 2)}\n`, { mode: 0o600 });
    console.log(`  report written to ${reportPath}`);
  }

  if (failed.length > 0) {
    process.exitCode = 1;
  }
}

main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.message : error);
  process.exitCode = 1;
});
