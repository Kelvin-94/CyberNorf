#!/usr/bin/env node
/**
 * Reviews a pull-request diff for code that has no legitimate place in this
 * repository: remote script execution, encoded payloads, obfuscation, secrets,
 * dangerous CI permissions, dependency-confusion sources and new install-time
 * scripts.
 *
 * Design constraints:
 * - No dependencies and no install step. The workflow that runs this must not
 *   execute the pull request's code or install its packages: a malicious
 *   `postinstall` script would otherwise run before the review.
 * - The diff is untrusted data. It is only read and pattern-matched; nothing in
 *   it is executed.
 * - High-severity findings fail the check. Medium findings are surfaced for the
 *   reviewer but do not block, so ordinary dependency and workflow edits remain
 *   possible.
 *
 * Usage:
 *   node scripts/security/contributor-risk.mjs <diff-file> \
 *     [--markdown <report.md>] [--json <report.json>]
 *
 * Exit codes: 0 no blocking finding, 2 at least one high-severity finding.
 */

import { readFileSync, writeFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

const MAX_FINDINGS = 200;
const MAX_EVIDENCE = 160;

const BINARY_EXTENSIONS = [
  '.exe',
  '.dll',
  '.so',
  '.dylib',
  '.node',
  '.bin',
  '.jar',
  '.class',
  '.msi',
  '.bat',
  '.cmd',
  '.scr',
  '.ps1',
  '.vbs',
];

/**
 * Each line rule receives the added text and the file path. Patterns are
 * bounded and linear: this runs on attacker-controlled input.
 */
const LINE_RULES = [
  {
    id: 'remote-shell-execution',
    severity: 'high',
    title: 'Remote content piped into a shell',
    test: (line) =>
      /(?:curl|wget)[^\n|]{0,160}\|\s*(?:sudo\s+)?(?:bash|sh|zsh|python[0-9.]*)\b/.test(line),
  },
  {
    id: 'powershell-download-execution',
    severity: 'high',
    title: 'PowerShell downloads and executes remote content',
    test: (line) =>
      /\b(?:iex|Invoke-Expression)\s*\([^\n)]{0,120}(?:iwr|Invoke-WebRequest|irm|Invoke-RestMethod|DownloadString)/i.test(
        line,
      ),
  },
  {
    id: 'encoded-pipe-execution',
    severity: 'high',
    title: 'Base64-decoded content piped into a shell',
    test: (line) => /base64\s+(?:-d|--decode|-D)[^\n|]{0,80}\|\s*(?:bash|sh|zsh)\b/.test(line),
  },
  {
    id: 'dynamic-code-execution',
    severity: 'high',
    title: 'Dynamic code evaluation',
    test: (line) => /\beval\s*\(/.test(line) || /\bnew\s+Function\s*\(/.test(line),
  },
  {
    id: 'shell-interpolation',
    severity: 'high',
    title: 'Interpolated string passed to a shell',
    test: (line) => /\b(?:exec|execSync|spawn|spawnSync)\s*\(\s*[`'"][^`'"]{0,200}\$\{/.test(line),
  },
  {
    id: 'child-process',
    severity: 'medium',
    title: 'Child process execution',
    test: (line) => /(?:node:)?child_process/.test(line),
  },
  {
    id: 'write-all-permissions',
    severity: 'high',
    title: 'Workflow grants write-all permissions',
    test: (line) => /permissions\s*:\s*write-all/.test(line),
  },
  {
    id: 'pull-request-target',
    severity: 'high',
    title: 'pull_request_target exposes repository secrets to fork code',
    test: (line) => /^\s*(?:on\s*:\s*|-\s*)?pull_request_target\s*:?\s*$/.test(line),
  },
  {
    id: 'secret-in-run-step',
    severity: 'high',
    title: 'Secret interpolated directly into a shell step',
    test: (line) => /run\s*:.*\$\{\{\s*secrets\./.test(line),
  },
  {
    id: 'unpinned-action',
    severity: 'medium',
    title: 'Action is referenced by a mutable tag',
    test: (line, file) =>
      file.startsWith('.github/workflows/') &&
      /uses\s*:\s*[A-Za-z0-9_.-]+\/[A-Za-z0-9_./-]+@(?![0-9a-f]{40}\b)\S+/.test(line),
  },
  {
    id: 'tls-verification-disabled',
    severity: 'high',
    title: 'TLS certificate verification is disabled',
    test: (line) =>
      /NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0|rejectUnauthorized\s*:\s*false/.test(line),
  },
  {
    id: 'trojan-source',
    severity: 'high',
    title: 'Bidirectional or zero-width control characters',
    test: (line) => /[\u202A-\u202E\u2066-\u2069\u200B-\u200F\uFEFF]/.test(line),
  },
  {
    id: 'obfuscated-payload',
    severity: 'high',
    title: 'Long encoded blob (possible obfuscated payload)',
    test: (line) => /[A-Za-z0-9+/]{240,}={0,2}/.test(line) || /[0-9a-fA-F]{240,}/.test(line),
  },
  {
    id: 'private-key-material',
    severity: 'high',
    title: 'Private key material committed',
    test: (line) => /-----BEGIN [A-Z ]{0,40}PRIVATE KEY-----/.test(line),
  },
  {
    id: 'known-credential',
    severity: 'high',
    title: 'Credential-shaped string committed',
    test: (line) =>
      /\bgh[pousr]_[A-Za-z0-9]{20,255}\b|\bgithub_pat_[A-Za-z0-9_]{20,255}\b|\bAKIA[0-9A-Z]{16}\b|\bxox[abprs]-[A-Za-z0-9-]{10,255}\b/.test(
        line,
      ),
  },
  {
    id: 'world-writable',
    severity: 'medium',
    title: 'World-writable permissions',
    test: (line) => /chmod\s+(?:-R\s+)?777\b/.test(line),
  },
  {
    id: 'security-step-removed',
    severity: 'high',
    title: 'Security-relevant line removed from a workflow',
    checkRemoved: true,
    test: (line) => /(?:npm audit|gitleaks|secret-scan|persist-credentials:\s*false)/.test(line),
  },
];

function finding(rule, file, line, text) {
  const evidence = text
    .replace(/\s+/g, ' ')
    .replace(/\\/g, '\\\\')
    .replace(/\|/g, '\\|')
    .replace(/`/g, "'")
    .slice(0, MAX_EVIDENCE);
  return {
    id: rule.id,
    severity: rule.severity,
    title: rule.title,
    file,
    line,
    evidence: evidence.trim(),
  };
}

/**
 * Parses a unified diff into added-line records. Deletions are kept separately
 * because removing a security control is itself a finding.
 */
export function parseUnifiedDiff(diffText) {
  const added = [];
  const removed = [];
  const files = new Set();
  let file = null;
  let newLine = 0;
  let oldLine = 0;

  for (const raw of diffText.split('\n')) {
    if (raw.startsWith('diff --git ')) {
      const match = /^diff --git a\/(.+?) b\/(.+)$/.exec(raw);
      if (match && match[2]) {
        file = match[2];
        files.add(file);
      }
      continue;
    }
    if (raw.startsWith('+++ ')) {
      const target = raw.slice(4).trim();
      file = target === '/dev/null' ? null : target.replace(/^b\//, '');
      if (file) {
        files.add(file);
      }
      continue;
    }
    if (raw.startsWith('--- ')) {
      continue;
    }

    const hunk = /^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@/.exec(raw);
    if (hunk) {
      oldLine = Number(hunk[1]);
      newLine = Number(hunk[2]);
      continue;
    }

    if (!file || raw.startsWith('\\')) {
      continue;
    }
    if (raw.startsWith('+')) {
      added.push({ file, line: newLine, text: raw.slice(1) });
      newLine += 1;
    } else if (raw.startsWith('-')) {
      removed.push({ file, line: oldLine, text: raw.slice(1) });
      oldLine += 1;
    } else {
      oldLine += 1;
      newLine += 1;
    }
  }

  return { added, removed, files: [...files] };
}

function isBinaryPath(file) {
  const lower = file.toLowerCase();
  return BINARY_EXTENSIONS.some((extension) => lower.endsWith(extension));
}

function packageLineFinding(file, line, text) {
  if (file !== 'package.json' && !file.endsWith('/package.json')) {
    return null;
  }
  if (/^\s*"(?:pre|post)?install"\s*:/.test(text) || /^\s*"prepare"\s*:/.test(text)) {
    return {
      id: 'install-lifecycle-script',
      severity: 'high',
      title: 'Install-time lifecycle script added or changed',
      file,
      line,
      evidence: text.trim().slice(0, MAX_EVIDENCE),
    };
  }
  const dependency = /^\s*"([^"]{1,120})"\s*:\s*"([^"]{1,300})"/.exec(text);
  if (!dependency) {
    return null;
  }
  const [, name, version] = dependency;
  if (/^(?:git\+|https?:\/\/|file:|link:)/.test(version ?? '')) {
    return {
      id: 'dependency-from-direct-source',
      severity: 'high',
      title: 'Dependency resolves outside the registry',
      file,
      line,
      evidence: `${name}: ${version}`,
    };
  }
  if (name && !['name', 'version', 'description', 'license', 'type'].includes(name)) {
    return {
      id: 'dependency-manifest-change',
      severity: 'medium',
      title: 'Dependency manifest changed (review the new package)',
      file,
      line,
      evidence: `${name}: ${version}`,
    };
  }
  return null;
}

/** Analyses parsed changes and returns deduplicated findings. */
export function analyzeChanges({ added, removed, files }) {
  const findings = [];
  const seen = new Set();
  const push = (item) => {
    if (!item) {
      return;
    }
    const key = `${item.id}:${item.file}:${item.line}:${item.evidence}`;
    if (seen.has(key) || findings.length >= MAX_FINDINGS) {
      return;
    }
    seen.add(key);
    findings.push(item);
  };

  for (const file of files) {
    if (isBinaryPath(file)) {
      push({
        id: 'binary-artifact',
        severity: 'high',
        title: 'Binary artifact added to the repository',
        file,
        line: 0,
        evidence: file,
      });
    }
    if (file.startsWith('.github/workflows/')) {
      push({
        id: 'workflow-modified',
        severity: 'medium',
        title: 'CI workflow modified',
        file,
        line: 0,
        evidence: file,
      });
    }
  }

  for (const change of added) {
    for (const rule of LINE_RULES) {
      if (rule.checkRemoved) {
        continue;
      }
      if (rule.test(change.text, change.file)) {
        push(finding(rule, change.file, change.line, change.text));
      }
    }
    push(packageLineFinding(change.file, change.line, change.text));

    const lockfile = /"resolved"\s*:\s*"(https?:[^"]{1,300})"/.exec(change.text);
    if (change.file.endsWith('package-lock.json') && lockfile?.[1]) {
      if (!lockfile[1].startsWith('https://registry.npmjs.org/')) {
        push({
          id: 'lockfile-foreign-registry',
          severity: 'high',
          title: 'Lockfile resolves a package from an unexpected source',
          file: change.file,
          line: change.line,
          evidence: lockfile[1],
        });
      }
    }
  }

  for (const change of removed) {
    for (const rule of LINE_RULES) {
      if (!rule.checkRemoved) {
        continue;
      }
      if (rule.test(change.text, change.file)) {
        push(finding(rule, change.file, change.line, change.text));
      }
    }
  }

  return findings;
}

export function summarize(findings) {
  const counts = { high: 0, medium: 0, low: 0 };
  for (const item of findings) {
    counts[item.severity] += 1;
  }
  return {
    verdict: counts.high > 0 ? 'block' : counts.medium > 0 ? 'review' : 'clean',
    counts,
    total: findings.length,
  };
}

function escapeCell(value) {
  return String(value).replace(/\r?\n/g, ' ').replace(/\\/g, '\\\\').replace(/\|/g, '\\|');
}

export function renderMarkdown(findings, summary) {
  const heading =
    summary.verdict === 'block'
      ? `**Verdict: BLOCK** — ${summary.counts.high} high-risk finding(s) must be resolved.`
      : summary.verdict === 'review'
        ? `**Verdict: REVIEW** — ${summary.counts.medium} item(s) need a reviewer's judgement.`
        : '**Verdict: CLEAN** — no suspicious code patterns detected.';

  const lines = [
    '<!-- cybernorf-contributor-risk -->',
    '## Contributor risk review',
    '',
    heading,
    '',
    'This check inspects the proposed diff only. It does not install or execute pull-request code.',
    '',
    `- High: ${summary.counts.high}`,
    `- Medium: ${summary.counts.medium}`,
    `- Total: ${summary.total}`,
  ];

  if (findings.length > 0) {
    lines.push('', '| Severity | Finding | Location | Evidence |', '|---|---|---|---|');
    for (const item of findings.slice(0, 50)) {
      lines.push(
        `| ${escapeCell(item.severity)} | ${escapeCell(item.title)} (\`${item.id}\`) | \`${escapeCell(item.file)}:${item.line}\` | \`${escapeCell(item.evidence)}\` |`,
      );
    }
    if (findings.length > 50) {
      lines.push('', `_Showing 50 of ${findings.length} findings; see the JSON artifact._`);
    }
  }

  lines.push(
    '',
    'High-severity findings block the merge. If one is a false positive, a maintainer must document why before overriding the check.',
  );

  return `${lines.join('\n')}\n`;
}

function main(argv) {
  const args = argv.slice(2);
  const diffPath = args.find((argument) => !argument.startsWith('--'));
  if (!diffPath) {
    console.error('Usage: contributor-risk.mjs <diff-file> [--markdown out.md] [--json out.json]');
    return 2;
  }

  const diff = readFileSync(diffPath, 'utf8');
  const changes = parseUnifiedDiff(diff);
  const findings = analyzeChanges(changes);
  const summary = summarize(findings);
  const report = {
    generatedAt: new Date().toISOString(),
    changedFiles: changes.files.length,
    addedLines: changes.added.length,
    removedLines: changes.removed.length,
    ...summary,
    findings,
  };

  const markdownIndex = args.indexOf('--markdown');
  if (markdownIndex !== -1 && args[markdownIndex + 1]) {
    writeFileSync(args[markdownIndex + 1], renderMarkdown(findings, summary));
  }
  const jsonIndex = args.indexOf('--json');
  if (jsonIndex !== -1 && args[jsonIndex + 1]) {
    writeFileSync(args[jsonIndex + 1], `${JSON.stringify(report, null, 2)}\n`);
  }

  console.log(
    `contributor-risk: ${summary.verdict} (high ${summary.counts.high}, medium ${summary.counts.medium}) across ${changes.files.length} file(s)`,
  );
  for (const item of findings.slice(0, 20)) {
    console.log(`  [${item.severity}] ${item.id} ${item.file}:${item.line} — ${item.evidence}`);
  }

  return summary.verdict === 'block' ? 2 : 0;
}

const invokedDirectly =
  Boolean(process.argv[1]) && import.meta.url === pathToFileURL(process.argv[1]).href;
if (invokedDirectly) {
  process.exitCode = main(process.argv);
}
