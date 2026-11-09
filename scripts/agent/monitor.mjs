#!/usr/bin/env node
/**
 * CyberNorf builtin host monitor.
 *
 * Runs on the host that is being monitored, not on the CyberNorf server. It
 * performs local checks only: no package installation, no scanning of other
 * hosts, and no calls to any model provider. The single network action is the
 * optional HTTPS/HTTP request to your own CyberNorf instance, so the monitor
 * works on an isolated network and also works air-gapped:
 *
 *   node monitor.mjs --out report.json          # collect only, nothing sent
 *   node monitor.mjs --in report.json --token … # submit a carried report
 *
 * Usage:
 *   node monitor.mjs [--token <cna_…>] [--org-url <url>] [--out <file>]
 *                    [--in <file>] [--dry-run] [--quiet]
 *
 * The token can also come from CYBERNORF_AGENT_TOKEN and the URL from
 * CYBERNORF_ORG_URL. Exit codes: 0 success, 1 submission failed, 2 bad usage.
 */

import { execFileSync } from 'node:child_process';
import { createHash, createHmac } from 'node:crypto';
import { existsSync, readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const SCHEMA_VERSION = 1;
const COMMAND_TIMEOUT_MS = 10_000;
/** Matches the server cap: 800 packages per report (MAX_INVENTORY_ITEMS). */
const MAX_INVENTORY_ITEMS = 800;
const RISKY_PORTS = new Map([
  [21, 'FTP'],
  [23, 'Telnet'],
  [445, 'SMB'],
  [3389, 'RDP'],
  [5900, 'VNC'],
]);

const argv = process.argv.slice(2);

function argValue(flag) {
  const index = process.argv.indexOf(flag);
  if (index === -1) {
    return undefined;
  }
  const value = process.argv[index + 1];
  if (!value || value.startsWith('--')) {
    usageError(`${flag} requires a value.`);
  }
  return value;
}

function hasFlag(flag) {
  return argv.includes(flag);
}

function usageError(message) {
  console.error(`monitor: ${message}`);
  console.error(
    'usage: node monitor.mjs [--token <cna_…>] [--org-url <url>] [--out <file>] [--in <file>] [--dry-run] [--quiet]',
  );
  process.exit(2);
}

const options = {
  token: argValue('--token') ?? process.env.CYBERNORF_AGENT_TOKEN ?? null,
  orgUrl: (
    argValue('--org-url') ??
    process.env.CYBERNORF_ORG_URL ??
    'http://localhost:3000'
  ).replace(/\/+$/, ''),
  out: argValue('--out') ?? null,
  input: argValue('--in') ?? null,
  dryRun: hasFlag('--dry-run'),
  quiet: hasFlag('--quiet'),
};

function log(message) {
  if (!options.quiet) {
    console.log(message);
  }
}

/** Runs a local command and returns stdout, or throws. Never touches the network. */
function run(command, args = [], timeout = COMMAND_TIMEOUT_MS) {
  return execFileSync(command, args, {
    encoding: 'utf8',
    timeout,
    stdio: ['ignore', 'pipe', 'pipe'],
    maxBuffer: 4 * 1024 * 1024,
  });
}

/** Like run(), but returns null instead of throwing when the command is absent. */
function tryRun(command, args = [], timeout = COMMAND_TIMEOUT_MS) {
  try {
    return run(command, args, timeout);
  } catch {
    return null;
  }
}

const isMac = process.platform === 'darwin';
const isLinux = process.platform === 'linux';

function pass(detail, remediation = null) {
  return { status: 'PASS', detail, remediation };
}

function fail(detail, remediation) {
  return { status: 'FAIL', detail, remediation };
}

function skip(detail) {
  return { status: 'SKIP', detail };
}

/** Reads a config file, returning null when it is missing or unreadable. */
function readConfig(file) {
  try {
    return readFileSync(file, 'utf8');
  } catch {
    return null;
  }
}

/** Reads `Key value` / `Key=value` style sshd_config directives. */
function sshdDirectives(text) {
  const directives = new Map();
  for (const rawLine of text.split('\n')) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) {
      continue;
    }
    const [key, ...rest] = line.split(/\s+/);
    if (!key || rest.length === 0) {
      continue;
    }
    // sshd uses the first occurrence of a keyword for most options.
    const name = key.toLowerCase();
    if (!directives.has(name)) {
      directives.set(name, rest.join(' ').split(/\s+/)[0]);
    }
  }
  return directives;
}

// ---------------------------------------------------------------------------
// Checks
// ---------------------------------------------------------------------------

const checks = [
  {
    id: 'auth.uid-zero-accounts',
    title: 'Root-equivalent (UID 0) accounts',
    findingTitle: 'Additional UID 0 (root-equivalent) account exists',
    severity: 'CRITICAL',
    remediation:
      'Remove the duplicate account or reassign a non-zero UID, then review how it was created.',
    run() {
      const passwd = readConfig('/etc/passwd');
      if (passwd === null) {
        return skip('/etc/passwd is not readable by this user.');
      }
      const extra = passwd
        .split('\n')
        .filter((line) => line && !line.startsWith('#'))
        .map((line) => line.split(':'))
        .filter((fields) => fields.length >= 4 && fields[2] === '0' && fields[0] !== 'root')
        .map((fields) => fields[0]);

      if (extra.length > 0) {
        return fail(
          `Additional accounts with UID 0: ${extra.join(', ')}`,
          'Every UID 0 account is root-equivalent. Remove it or assign a unique UID.',
        );
      }
      return pass('Only the root account has UID 0.');
    },
  },
  {
    id: 'auth.ssh-password-authentication',
    title: 'SSH password authentication',
    findingTitle: 'SSH accepts password authentication',
    severity: 'HIGH',
    remediation:
      'Set "PasswordAuthentication no" in /etc/ssh/sshd_config, keep key-based logins, and restart sshd.',
    run() {
      const config = readConfig('/etc/ssh/sshd_config');
      if (config === null) {
        return skip('SSH server configuration not found or not readable.');
      }
      const directives = sshdDirectives(config);
      const value = (directives.get('passwordauthentication') ?? 'yes').toLowerCase();
      const keyboard = (directives.get('kbdinteractiveauthentication') ?? 'no').toLowerCase();

      if (value === 'no' && keyboard !== 'yes') {
        return pass('PasswordAuthentication is disabled.');
      }
      return fail(
        `PasswordAuthentication=${value}${keyboard === 'yes' ? ', KbdInteractiveAuthentication=yes' : ''}`,
        'Password logins are brute-forceable. Disable them and require SSH keys.',
      );
    },
  },
  {
    id: 'auth.ssh-root-login',
    title: 'Direct SSH root login',
    findingTitle: 'SSH permits direct root login',
    severity: 'HIGH',
    remediation: 'Set "PermitRootLogin no" in /etc/ssh/sshd_config and restart sshd.',
    run() {
      const config = readConfig('/etc/ssh/sshd_config');
      if (config === null) {
        return skip('SSH server configuration not found or not readable.');
      }
      const value = (
        sshdDirectives(config).get('permitrootlogin') ?? 'prohibit-password'
      ).toLowerCase();
      if (value === 'no') {
        return pass('PermitRootLogin=no');
      }
      if (value === 'yes') {
        return fail('PermitRootLogin=yes allows direct root sessions.', 'Set PermitRootLogin no.');
      }
      return pass(`PermitRootLogin=${value} (key-based root access only).`);
    },
  },
  {
    id: 'access.sudo-nopasswd',
    title: 'Passwordless sudo grants',
    findingTitle: 'Passwordless sudo grants exist',
    severity: 'HIGH',
    remediation:
      'Remove NOPASSWD entries from /etc/sudoers and /etc/sudoers.d/* so privilege escalation requires a password.',
    run() {
      const files = ['/etc/sudoers'];
      if (existsSync('/etc/sudoers.d')) {
        for (const entry of readdirSync('/etc/sudoers.d')) {
          files.push(path.join('/etc/sudoers.d', entry));
        }
      }
      const offenders = [];
      let readable = 0;
      for (const file of files) {
        const content = readConfig(file);
        if (content === null) {
          continue;
        }
        readable += 1;
        if (/NOPASSWD\s*:/i.test(content)) {
          offenders.push(file);
        }
      }
      if (readable === 0) {
        return skip('Sudoers files are not readable by this user; run the monitor as root.');
      }
      if (offenders.length > 0) {
        return fail(
          `NOPASSWD grants in: ${offenders.join(', ')}`,
          'Passwordless sudo turns any account compromise into root. Remove the grant.',
        );
      }
      return pass(`No NOPASSWD entries in ${readable} sudoers file(s).`);
    },
  },
  {
    id: 'access.sudoers-file-permissions',
    title: 'Sudoers file permissions',
    findingTitle: 'Sudoers files are group- or world-writable',
    severity: 'MEDIUM',
    remediation: 'Restore 0440 ownership root:root on /etc/sudoers and its drop-in files.',
    run() {
      const files = ['/etc/sudoers'];
      if (existsSync('/etc/sudoers.d')) {
        for (const entry of readdirSync('/etc/sudoers.d')) {
          files.push(path.join('/etc/sudoers.d', entry));
        }
      }
      const weak = [];
      let seen = 0;
      for (const file of files) {
        try {
          const mode = statSync(file).mode & 0o777;
          seen += 1;
          if ((mode & 0o022) !== 0) {
            weak.push(`${file} ${mode.toString(8).padStart(3, '0')}`);
          }
        } catch {
          // Missing drop-in files are expected on minimal hosts.
        }
      }
      if (seen === 0) {
        return skip('No sudoers file could be stat-ed by this user.');
      }
      if (weak.length > 0) {
        return fail(
          `Group- or world-writable: ${weak.join(', ')}`,
          'chmod 0440 the affected files.',
        );
      }
      return pass(`Checked ${seen} sudoers file(s).`);
    },
  },
  {
    id: 'access.sensitive-file-permissions',
    title: 'Sensitive identity file permissions',
    findingTitle: 'Sensitive identity files are group- or world-writable',
    severity: 'MEDIUM',
    remediation:
      'Restore default permissions: /etc/passwd 0644, /etc/shadow 0640, /etc/sudoers 0440.',
    run() {
      const expected = ['/etc/passwd', '/etc/shadow', '/etc/sudoers', '/etc/hosts'];
      const weak = [];
      let seen = 0;
      for (const file of expected) {
        try {
          const mode = statSync(file).mode & 0o777;
          seen += 1;
          if ((mode & 0o022) !== 0) {
            weak.push(`${file} ${mode.toString(8).padStart(3, '0')}`);
          }
        } catch {
          // macOS has no /etc/shadow; absence is not a finding.
        }
      }
      if (seen === 0) {
        return skip('Sensitive files could not be stat-ed by this user.');
      }
      if (weak.length > 0) {
        return fail(
          `Group- or world-writable: ${weak.join(', ')}`,
          'A writable passwd/shadow file allows account takeover.',
        );
      }
      return pass(`Checked ${seen} sensitive file(s).`);
    },
  },
  {
    id: 'access.guest-account',
    title: 'macOS guest account',
    findingTitle: 'Guest account is enabled',
    severity: 'MEDIUM',
    remediation: 'Disable the guest account in System Settings > Users & Groups.',
    run() {
      if (!isMac) {
        return skip('Guest account check is macOS-specific.');
      }
      try {
        const value = run('defaults', [
          'read',
          '/Library/Preferences/com.apple.loginwindow',
          'GuestEnabled',
        ]).trim();
        if (value === '1') {
          return fail('GuestEnabled=1', 'A guest session gives an unauthenticated local shell.');
        }
        return pass(`GuestEnabled=${value || 'unset'}`);
      } catch {
        return pass('GuestEnabled is not set (guest account disabled).');
      }
    },
  },
  {
    id: 'access.automatic-login',
    title: 'macOS automatic login',
    findingTitle: 'Automatic login is enabled',
    severity: 'HIGH',
    remediation: 'Turn off automatic login so a reboot does not open an authenticated session.',
    run() {
      if (!isMac) {
        return skip('Automatic login check is macOS-specific.');
      }
      try {
        const value = run('defaults', [
          'read',
          '/Library/Preferences/com.apple.loginwindow',
          'autoLoginUser',
        ]).trim();
        if (value.length > 0) {
          return fail(
            `autoLoginUser=${value}`,
            'Automatic login bypasses the login prompt entirely.',
          );
        }
        return pass('autoLoginUser is empty.');
      } catch {
        return pass('autoLoginUser is not configured.');
      }
    },
  },
  {
    id: 'access.host-firewall',
    title: 'Host firewall state',
    findingTitle: 'Host firewall is disabled',
    severity: 'HIGH',
    remediation: 'Enable the firewall (macOS: System Settings > Network > Firewall).',
    run() {
      if (!isMac) {
        return skip('Firewall check is implemented for macOS in this release.');
      }
      // socketfilterfw reports the live state; the preference domain is only a
      // fallback because newer macOS releases do not always write it.
      try {
        const state = run('/usr/libexec/ApplicationFirewall/socketfilterfw', [
          '--getglobalstate',
        ]).trim();
        if (/enabled/i.test(state)) {
          return pass(state.split('\n')[0]);
        }
        if (/disabled/i.test(state)) {
          return fail(state.split('\n')[0], 'Enable the application firewall.');
        }
      } catch {
        // Fall through to the preference domain below.
      }
      try {
        const value = run('defaults', [
          'read',
          '/Library/Preferences/com.apple.alf',
          'globalstate',
        ]).trim();
        if (value === '0') {
          return fail(
            'com.apple.alf globalstate=0 (firewall off)',
            'Enable the application firewall.',
          );
        }
        return pass(`com.apple.alf globalstate=${value} (firewall enabled)`);
      } catch {
        // Unknown is not the same as off: report reduced coverage instead of a
        // finding the host may not deserve.
        return skip('Firewall state could not be read by this user.');
      }
    },
  },
  {
    id: 'vuln.disk-encryption',
    title: 'Full-disk encryption (FileVault)',
    findingTitle: 'Full-disk encryption is disabled',
    severity: 'HIGH',
    remediation: 'Enable FileVault (macOS) or LUKS (Linux) so a stolen disk is unreadable.',
    run() {
      if (isMac) {
        try {
          const value = run('fdesetup', ['status']).trim();
          if (/FileVault is On/i.test(value)) {
            return pass(value.split('\n')[0]);
          }
          if (/FileVault is Off/i.test(value)) {
            return fail(value.split('\n')[0], 'A stolen disk without FileVault exposes all data.');
          }
          return skip(value.split('\n')[0] || 'fdesetup returned no state.');
        } catch (error) {
          return skip(`fdesetup failed: ${error instanceof Error ? error.message : 'unknown'}`);
        }
      }
      if (isLinux) {
        try {
          const devices = run('lsblk', ['-o', 'NAME,TYPE,FSTYPE', '-n']).toLowerCase();
          if (devices.includes('crypto_luks')) {
            return pass('LUKS-encrypted block device detected.');
          }
          return fail('No LUKS device detected.', 'Encrypt the data volume with LUKS.');
        } catch {
          return skip('lsblk is unavailable; cannot evaluate disk encryption.');
        }
      }
      return skip('Disk encryption check is not implemented for this platform.');
    },
  },
  {
    id: 'vuln.listeners-risky-ports',
    title: 'Legacy service listeners',
    findingTitle: 'Risky legacy services are listening',
    severity: 'HIGH',
    remediation:
      'Stop the legacy service (FTP/Telnet/SMB/RDP/VNC) and expose remote access only through SSH or a VPN.',
    run() {
      let output;
      try {
        output = run('lsof', ['-nP', '-iTCP', '-sTCP:LISTEN', '-F', 'n']);
      } catch (error) {
        return skip(`lsof is unavailable: ${error instanceof Error ? error.message : 'unknown'}`);
      }

      const listening = new Set();
      for (const line of output.split('\n')) {
        const match = /^n.*:(\d+)$/.exec(line.trim());
        if (match) {
          listening.add(Number.parseInt(match[1], 10));
        }
      }

      const risky = [...listening]
        .filter((port) => RISKY_PORTS.has(port))
        .sort((a, b) => a - b)
        .map((port) => `${port}/${RISKY_PORTS.get(port)}`);

      if (risky.length > 0) {
        return fail(
          `Listening legacy services: ${risky.join(', ')}`,
          'These protocols send credentials in clear text or are routinely exploited. Disable them.',
        );
      }
      if (listening.size === 0) {
        return skip('lsof reported no listening TCP sockets.');
      }
      return pass(`No risky ports among ${listening.size} listening TCP socket(s).`);
    },
  },
];

/**
 * Software inventory for advisory matching.
 *
 * Only local package managers are queried, with no registry or network access:
 * Homebrew (formulae and casks), npm global packages, pip, dpkg and rpm. Absent
 * managers are skipped silently, because an uninstalled package manager is not
 * a security finding. The result is a snapshot of the host that the platform
 * replaces on every run.
 */
function collectInventory() {
  const items = [];
  const seen = new Set();

  function add(ecosystem, name, version) {
    if (items.length >= MAX_INVENTORY_ITEMS) {
      return;
    }
    const cleanName = String(name ?? '').trim();
    const cleanVersion = String(version ?? '').trim();
    if (!/^[A-Za-z0-9@][A-Za-z0-9@._+/:-]*$/.test(cleanName)) {
      return;
    }
    if (!/^[0-9A-Za-z][0-9A-Za-z.+~:_-]*$/.test(cleanVersion)) {
      return;
    }
    const key = `${ecosystem}::${cleanName.toLowerCase()}`;
    if (seen.has(key)) {
      return;
    }
    seen.add(key);
    items.push({ ecosystem, name: cleanName, version: cleanVersion });
  }

  // `brew list --versions` prints "name version [older versions…]"; the newest
  // installed build is the last field, which is what an advisory applies to.
  for (const args of [
    ['list', '--versions'],
    ['list', '--cask', '--versions'],
  ]) {
    const output = tryRun('brew', args);
    if (!output) {
      continue;
    }
    for (const line of output.split('\n')) {
      const fields = line.trim().split(/\s+/).filter(Boolean);
      if (fields.length >= 2) {
        add('BREW', fields[0], fields[fields.length - 1]);
      }
    }
  }

  const npmListing = tryRun('npm', ['ls', '-g', '--json', '--depth=0']);
  if (npmListing) {
    try {
      const parsed = JSON.parse(npmListing);
      for (const [name, dependency] of Object.entries(parsed?.dependencies ?? {})) {
        if (dependency && typeof dependency === 'object' && dependency.version) {
          add('NPM', name, dependency.version);
        }
      }
    } catch {
      // Unparseable npm output is reported by the inventory count, not a check.
    }
  }

  for (const python of ['python3', 'python']) {
    const output = tryRun(python, ['-m', 'pip', 'list', '--format=freeze']);
    if (!output) {
      continue;
    }
    for (const line of output.split('\n')) {
      const separator = line.indexOf('==');
      if (separator > 0) {
        add('PYPI', line.slice(0, separator), line.slice(separator + 2));
      }
    }
    break;
  }

  // dpkg-query format strings are passed as argv, so no shell expansion occurs.
  const dpkg = tryRun('dpkg-query', ['-W', '-f=${Package} ${Version}\n']);
  if (dpkg) {
    for (const line of dpkg.split('\n')) {
      const fields = line.trim().split(/\s+/);
      if (fields.length >= 2) {
        add('APT', fields[0], fields[1]);
      }
    }
  }

  const rpm = tryRun('rpm', ['-qa', '--qf', '%{NAME} %{VERSION}-%{RELEASE}\n']);
  if (rpm) {
    for (const line of rpm.split('\n')) {
      const fields = line.trim().split(/\s+/);
      if (fields.length >= 2) {
        add('RPM', fields[0], fields[1]);
      }
    }
  }

  return items;
}

function collect() {
  const startedAt = new Date();
  const hostname = os.hostname();
  const results = [];

  for (const check of checks) {
    const base = {
      id: check.id,
      title: check.title,
      findingTitle: check.findingTitle,
      severity: check.severity,
      target: hostname,
    };
    try {
      const outcome = check.run();
      results.push({
        ...base,
        status: outcome.status,
        detail: outcome.detail ?? null,
        remediation: outcome.status === 'FAIL' ? (outcome.remediation ?? check.remediation) : null,
      });
    } catch (error) {
      // A check that throws is unknown, not a pass: report it as SKIP so the
      // console shows reduced coverage instead of false assurance.
      results.push({
        ...base,
        status: 'SKIP',
        detail: `Check failed to run: ${error instanceof Error ? error.message : 'unknown error'}`,
        remediation: null,
      });
    }
  }

  const finishedAt = new Date();
  return {
    schemaVersion: SCHEMA_VERSION,
    hostname,
    platform: `${os.type()} ${os.release()} (${process.platform}/${os.arch()})`,
    startedAt: startedAt.toISOString(),
    finishedAt: finishedAt.toISOString(),
    durationMs: finishedAt.getTime() - startedAt.getTime(),
    checks: results,
    inventory: collectInventory(),
  };
}

function summarize(report) {
  const counts = { PASS: 0, FAIL: 0, SKIP: 0 };
  for (const check of report.checks) {
    counts[check.status] += 1;
  }
  return counts;
}

function printReport(report) {
  const counts = summarize(report);
  log(
    `CyberNorf monitor on ${report.hostname}: ${counts.PASS} pass, ${counts.FAIL} fail, ${counts.SKIP} skip`,
  );
  if (Array.isArray(report.inventory) && report.inventory.length > 0) {
    log(`  inventory: ${report.inventory.length} packages collected for advisory matching`);
  }
  for (const check of report.checks) {
    if (check.status === 'FAIL') {
      log(`  FAIL  ${check.id} — ${check.detail ?? check.title}`);
    } else if (!options.quiet && check.status === 'SKIP') {
      log(`  skip  ${check.id} — ${check.detail ?? ''}`);
    }
  }
}

function loadReport(file) {
  let raw;
  try {
    raw = readFileSync(file, 'utf8');
  } catch (error) {
    usageError(`cannot read ${file}: ${error instanceof Error ? error.message : 'unknown'}`);
  }
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    usageError(`${file} is not valid JSON.`);
  }
  if (!parsed || !Array.isArray(parsed.checks)) {
    usageError(`${file} is not a monitor report (missing "checks").`);
  }
  return {
    schemaVersion: SCHEMA_VERSION,
    hostname: typeof parsed.hostname === 'string' ? parsed.hostname : os.hostname(),
    platform: typeof parsed.platform === 'string' ? parsed.platform : null,
    startedAt: typeof parsed.startedAt === 'string' ? parsed.startedAt : new Date().toISOString(),
    finishedAt:
      typeof parsed.finishedAt === 'string' ? parsed.finishedAt : new Date().toISOString(),
    durationMs: Number.isFinite(parsed.durationMs) ? parsed.durationMs : undefined,
    inventory: Array.isArray(parsed.inventory)
      ? parsed.inventory
          .filter(
            (item) =>
              item &&
              typeof item.ecosystem === 'string' &&
              item.name &&
              typeof item.version === 'string',
          )
          .slice(0, MAX_INVENTORY_ITEMS)
          .map((item) => ({
            ecosystem: item.ecosystem,
            name: String(item.name),
            version: String(item.version),
          }))
      : [],
    checks: parsed.checks.map((check) => ({
      id: String(check.id ?? ''),
      title: String(check.title ?? ''),
      ...(typeof check.findingTitle === 'string' ? { findingTitle: check.findingTitle } : {}),
      status: check.status,
      severity: check.severity,
      target: check.target ?? parsed.hostname,
      detail: check.detail ?? null,
      remediation: check.remediation ?? null,
    })),
  };
}

function payloadOf(report) {
  // The server derives counts itself; only observations are sent.
  const body = {
    hostname: report.hostname,
    startedAt: report.startedAt,
    checks: report.checks.map((check) => ({
      id: check.id,
      title: check.title,
      ...(check.findingTitle ? { findingTitle: check.findingTitle } : {}),
      status: check.status,
      severity: check.severity,
      ...(check.target ? { target: check.target } : {}),
      ...(check.detail ? { detail: check.detail } : {}),
      ...(check.status === 'FAIL' && check.remediation ? { remediation: check.remediation } : {}),
    })),
  };
  if (report.platform) {
    body.platform = report.platform;
  }
  if (report.finishedAt) {
    body.finishedAt = report.finishedAt;
  }
  if (Number.isFinite(report.durationMs)) {
    body.durationMs = report.durationMs;
  }
  if (Array.isArray(report.inventory) && report.inventory.length > 0) {
    body.inventory = report.inventory;
  }
  return body;
}

/**
 * Signs the exact bytes that will be sent. The key is derived from the agent
 * token, matching `src/server/domain/agent-signature.ts`, so rotating the token
 * on the server invalidates signatures made with the previous one.
 */
function signSubmission(token, timestampSeconds, body) {
  const key = createHash('sha256').update(`cybernorf-agent-signing:v1:${token}`, 'utf8').digest();
  const mac = createHmac('sha256', key)
    .update(`${timestampSeconds}.`, 'utf8')
    .update(body, 'utf8')
    .digest('hex');
  return `sha256=${mac}`;
}

async function submit(report) {
  if (!options.token) {
    log('No token supplied; report was not submitted. Use --token or CYBERNORF_AGENT_TOKEN.');
    return true;
  }
  if (!/^https?:\/\//i.test(options.orgUrl)) {
    usageError('--org-url must start with http:// or https://');
  }

  const url = `${options.orgUrl}/api/v1/agents/me/runs`;
  const body = JSON.stringify(payloadOf(report));
  const timestamp = Math.floor(Date.now() / 1000);
  let response;
  try {
    response = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${options.token}`,
        'User-Agent': 'cybernorf-monitor/1.0',
        'x-cybernorf-timestamp': String(timestamp),
        'x-cybernorf-signature': signSubmission(options.token, timestamp, body),
      },
      body,
      signal: AbortSignal.timeout(30_000),
    });
  } catch (error) {
    console.error(
      `monitor: could not reach ${url}: ${error instanceof Error ? error.message : 'unknown error'}`,
    );
    console.error('The report was kept locally. Re-run with --in to submit it later.');
    return false;
  }

  const text = await response.text();
  let payload = null;
  if (text) {
    try {
      payload = JSON.parse(text);
    } catch {
      payload = null;
    }
  }

  if (!response.ok) {
    const message = payload?.error?.message ?? `HTTP ${response.status}`;
    console.error(`monitor: submission rejected: ${message}`);
    return false;
  }

  log(
    `Report accepted: run ${payload?.run?.id ?? '(unknown)'} (${payload?.counts?.checkCount ?? '?'} checks, ` +
      `${payload?.findingsCreated ?? 0} new findings, ${payload?.findingsRefreshed ?? 0} refreshed, ` +
      `${payload?.findingsSuppressed ?? 0} already triaged, ` +
      `${payload?.inventoryCount ?? 0} packages, ${payload?.advisoryMatches ?? 0} advisory matches).`,
  );
  return true;
}

async function main() {
  let report;
  if (options.input) {
    report = loadReport(options.input);
    log(`Loaded report from ${options.input}`);
  } else {
    report = collect();
  }

  printReport(report);

  if (options.out) {
    writeFileSync(options.out, `${JSON.stringify(report, null, 2)}\n`, { mode: 0o600 });
    log(`Report written to ${options.out}`);
  }

  if (options.dryRun) {
    log('Dry run: nothing was submitted.');
    return 0;
  }

  const ok = await submit(report);
  return ok ? 0 : 1;
}

main()
  .then((code) => {
    process.exitCode = code;
  })
  .catch((error) => {
    console.error(`monitor: ${error instanceof Error ? error.message : 'unexpected failure'}`);
    process.exitCode = 1;
  });
