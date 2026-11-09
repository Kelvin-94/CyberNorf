/**
 * Runtime audit for CyberNorf: exercises every API route and page with valid,
 * invalid, adversarial, and concurrent input against a running server.
 */
import { createHmac } from 'node:crypto';

const BASE = process.env.BASE_URL ?? 'http://localhost:3000';
const results = [];
let failures = 0;

function check(name, condition, detail = '') {
  const ok = Boolean(condition);
  if (!ok) failures += 1;
  const line = `${ok ? 'PASS' : 'FAIL'} ${name}${detail ? ` — ${detail}` : ''}`;
  results.push(line);
  console.log(line);
  return ok;
}

function base32Decode(input) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const clean = input.replace(/=+$/, '').toUpperCase();
  let bits = 0;
  let value = 0;
  const bytes = [];
  for (const char of clean) {
    const idx = alphabet.indexOf(char);
    if (idx === -1) throw new Error('invalid base32');
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(bytes);
}

function totp(secret, offsetSteps = 0) {
  const counter = Math.floor(Date.now() / 1000 / 30) + offsetSteps;
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(counter));
  const hmac = createHmac('sha1', base32Decode(secret)).update(buf).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  return ((hmac.readUInt32BE(offset) & 0x7fffffff) % 1000000).toString().padStart(6, '0');
}

class Client {
  constructor(label) {
    this.label = label;
    this.cookies = new Map();
  }

  async call(path, { method = 'GET', body, raw, origin = BASE, headers = {}, contentType } = {}) {
    const h = { ...headers };
    if (origin) h.origin = origin;
    if (body !== undefined || raw !== undefined)
      h['content-type'] = contentType ?? 'application/json';
    if (this.cookies.size > 0) {
      h.cookie = [...this.cookies].map(([k, v]) => `${k}=${v}`).join('; ');
    }
    const init = { method, headers: h, redirect: 'manual' };
    if (raw !== undefined) init.body = raw;
    else if (body !== undefined) init.body = JSON.stringify(body);

    const response = await fetch(`${BASE}${path}`, init);
    for (const cookie of response.headers.getSetCookie()) {
      const pair = cookie.split(';')[0];
      const i = pair.indexOf('=');
      const name = pair.slice(0, i);
      const value = pair.slice(i + 1);
      if (value === '' || value === 'deleted') this.cookies.delete(name);
      else this.cookies.set(name, value);
    }
    const text = await response.text();
    let json = text;
    try {
      json = JSON.parse(text);
    } catch {
      /* html */
    }
    return { status: response.status, json, text, headers: response.headers };
  }
}

const password = 'Correct-Horse-Battery-9';
const stamp = Date.now();

async function register(client, name, email) {
  // Sign-up is rate limited per address (5/min), so back-to-back runs must wait
  // for the window instead of failing the whole audit.
  for (let attempt = 0; attempt < 4; attempt += 1) {
    const res = await client.call('/api/auth/sign-up/email', {
      method: 'POST',
      body: { name, email, password },
    });
    if (res.status !== 429) return res;
    const wait = Number(res.headers.get('retry-after') ?? 15) + 1;
    console.log(`… sign-up throttled (429), waiting ${wait}s`);
    await new Promise((resolve) => setTimeout(resolve, wait * 1000));
  }
  throw new Error(`sign-up for ${email} stayed rate limited`);
}

async function enableTotp(client) {
  const enabled = await client.call('/api/auth/two-factor/enable', {
    method: 'POST',
    body: { password },
  });
  const uri = enabled.json?.totpURI;
  if (typeof uri !== 'string')
    throw new Error(`TOTP enable failed: ${JSON.stringify(enabled.json)}`);
  const secret = new URL(uri).searchParams.get('secret');
  const verify = await client.call('/api/auth/two-factor/verify-totp', {
    method: 'POST',
    body: { code: totp(secret) },
  });
  if (verify.status !== 200) throw new Error(`TOTP verify failed: ${JSON.stringify(verify.json)}`);
  return secret;
}

async function main() {
  const owner = new Client('owner');
  await register(owner, 'Audit Owner', `audit-owner-${stamp}@cybernorf.test`);
  await enableTotp(owner);

  const orgRes = await owner.call('/api/v1/organizations', {
    method: 'POST',
    body: { name: 'Runtime Audit', slug: `audit-${stamp}` },
  });
  const slug = orgRes.json?.organization?.slug;
  check('organization created', res201(orgRes) && Boolean(slug), `status ${orgRes.status}`);
  if (!slug) throw new Error('no slug');

  const org = `/api/v1/organizations/${slug}`;

  // ---------- assets ----------
  const assetRes = await owner.call(`${org}/assets`, {
    method: 'POST',
    body: {
      name: 'Portal',
      type: 'WEB_APPLICATION',
      identifier: `portal-${stamp}.example`,
      criticality: 'HIGH',
    },
  });
  const assetId = assetRes.json?.asset?.id;
  check('asset created', res201(assetRes) && Boolean(assetId), `status ${assetRes.status}`);

  const dupAsset = await owner.call(`${org}/assets`, {
    method: 'POST',
    body: {
      name: 'Portal duplicate',
      type: 'WEB_APPLICATION',
      identifier: `portal-${stamp}.example`,
    },
  });
  check(
    'duplicate asset identifier rejected with 409',
    dupAsset.status === 409,
    `status ${dupAsset.status}`,
  );

  const badAsset = await owner.call(`${org}/assets`, { method: 'POST', body: { name: '' } });
  check(
    'invalid asset payload rejected with 422',
    badAsset.status === 422,
    `status ${badAsset.status}`,
  );
  check(
    'validation error lists field details',
    Array.isArray(badAsset.json?.error?.details) ||
      typeof badAsset.json?.error?.message === 'string',
    JSON.stringify(badAsset.json?.error).slice(0, 120),
  );

  const listAssets = await owner.call(`${org}/assets?page=1&pageSize=5&sort=name&direction=asc`);
  check(
    'asset list paginates',
    listAssets.status === 200 && Array.isArray(listAssets.json?.items),
    `status ${listAssets.status}`,
  );
  check(
    'asset list exposes openFindings',
    typeof listAssets.json?.items?.[0]?.openFindings === 'number',
  );

  const badSort = await owner.call(`${org}/assets?sort=identifier;DROP TABLE assets`);
  check(
    'invalid sort rejected (no SQL passthrough)',
    badSort.status === 422,
    `status ${badSort.status}`,
  );

  const beyondPage = await owner.call(`${org}/assets?page=999`);
  check(
    'page beyond range returns an empty page',
    beyondPage.status === 200 && beyondPage.json?.items?.length === 0,
    `status ${beyondPage.status}`,
  );

  // ---------- findings ----------
  const findingRes = await owner.call(`${org}/findings`, {
    method: 'POST',
    body: {
      title: 'Reflected XSS',
      severity: 'HIGH',
      assetId,
      cvssScore: 7.5,
      cveId: 'cve-2026-9999',
    },
  });
  const findingId = findingRes.json?.finding?.id;
  check('finding created', res201(findingRes) && Boolean(findingId), `status ${findingRes.status}`);
  check(
    'CVE normalized to upper case',
    findingRes.json?.finding?.cveId === 'CVE-2026-9999',
    String(findingRes.json?.finding?.cveId),
  );

  const badCvss = await owner.call(`${org}/findings`, {
    method: 'POST',
    body: { title: 'Bad cvss', severity: 'LOW', cvssScore: 12 },
  });
  check('out-of-range CVSS rejected with 422', badCvss.status === 422, `status ${badCvss.status}`);

  const dupFinding = await owner.call(`${org}/findings`, {
    method: 'POST',
    body: { title: 'Reflected XSS', severity: 'HIGH', assetId },
  });
  check(
    'duplicate finding rejected with 409',
    dupFinding.status === 409,
    `status ${dupFinding.status}`,
  );

  const crossAsset = await owner.call(`${org}/findings`, {
    method: 'POST',
    body: { title: 'Ghost asset', severity: 'LOW', assetId: 'nonexistentid' },
  });
  check(
    'unknown asset reference rejected with 404',
    crossAsset.status === 404,
    `status ${crossAsset.status}`,
  );

  const patchRes = await owner.call(`${org}/findings/${findingId}`, {
    method: 'PATCH',
    body: { severity: 'CRITICAL', remediation: 'Encode output.' },
  });
  check(
    'finding updated',
    patchRes.status === 200 && patchRes.json?.finding?.severity === 'CRITICAL',
    `status ${patchRes.status}`,
  );

  const statusRes = await owner.call(`${org}/findings/${findingId}/status`, {
    method: 'POST',
    body: { status: 'TRIAGED', note: 'Validated' },
  });
  check(
    'finding status transition accepted',
    statusRes.status === 200,
    `status ${statusRes.status}`,
  );

  const badStatus = await owner.call(`${org}/findings/${findingId}/status`, {
    method: 'POST',
    body: { status: 'OPEN' },
  });
  check(
    'undefined transition rejected with 409',
    badStatus.status === 409,
    `status ${badStatus.status}`,
  );

  const detail = await owner.call(`${org}/findings/${findingId}`);
  check(
    'finding detail includes history',
    detail.status === 200 && detail.json?.finding?.history?.length >= 2,
    `events ${detail.json?.finding?.history?.length}`,
  );

  // ---------- import ----------
  const importRes = await owner.call(`${org}/findings/import`, {
    method: 'POST',
    body: {
      findings: [
        {
          title: 'TLS 1.0 enabled',
          severity: 'MEDIUM',
          assetIdentifier: `portal-${stamp}.example`,
        },
      ],
    },
  });
  check(
    'import creates findings',
    importRes.status === 200 && importRes.json?.created === 1,
    `status ${importRes.status} body ${JSON.stringify(importRes.json).slice(0, 100)}`,
  );

  const importAgain = await owner.call(`${org}/findings/import`, {
    method: 'POST',
    body: {
      findings: [
        {
          title: 'TLS 1.0 enabled',
          severity: 'MEDIUM',
          assetIdentifier: `portal-${stamp}.example`,
        },
      ],
    },
  });
  check(
    're-import deduplicates',
    importAgain.status === 200 && importAgain.json?.updated === 1,
    `status ${importAgain.status}`,
  );

  const repeatedInPayload = await owner.call(`${org}/findings/import`, {
    method: 'POST',
    body: {
      findings: [
        { title: `Repeated ${stamp}`, severity: 'LOW' },
        { title: `REPEATED  ${stamp}`, severity: 'HIGH' },
      ],
    },
  });
  check(
    'identical items inside one payload are skipped, not fatal',
    repeatedInPayload.status === 200 &&
      repeatedInPayload.json?.created === 1 &&
      repeatedInPayload.json?.skipped?.length === 1,
    `status ${repeatedInPayload.status} body ${JSON.stringify(repeatedInPayload.json).slice(0, 120)}`,
  );

  // concurrent duplicate imports: check-then-insert race
  const [raceA, raceB] = await Promise.all([
    owner.call(`${org}/findings/import`, {
      method: 'POST',
      body: { findings: [{ title: `Race ${stamp}`, severity: 'LOW' }] },
    }),
    owner.call(`${org}/findings/import`, {
      method: 'POST',
      body: { findings: [{ title: `Race ${stamp}`, severity: 'LOW' }] },
    }),
  ]);
  check(
    'concurrent duplicate imports do not 500',
    raceA.status < 500 && raceB.status < 500,
    `statuses ${raceA.status}/${raceB.status} body ${(raceA.status >= 500 ? raceA : raceB).json?.error?.code ?? ''}`,
  );

  const tooMany = Array.from({ length: 501 }, (_, i) => ({ title: `Bulk ${i}`, severity: 'LOW' }));
  const tooManyRes = await owner.call(`${org}/findings/import`, {
    method: 'POST',
    body: { findings: tooMany },
  });
  check(
    'import over 500 items rejected with 422',
    tooManyRes.status === 422,
    `status ${tooManyRes.status}`,
  );

  // ---------- incidents ----------
  const incidentRes = await owner.call(`${org}/incidents`, {
    method: 'POST',
    body: { title: 'XSS investigation', severity: 'HIGH' },
  });
  const incidentId = incidentRes.json?.incident?.id;
  check(
    'incident created',
    res201(incidentRes) && Boolean(incidentId),
    `status ${incidentRes.status}`,
  );

  const noteRes = await owner.call(`${org}/incidents/${incidentId}/notes`, {
    method: 'POST',
    body: { body: 'Reproduced in staging.' },
  });
  check('incident note created', res201(noteRes), `status ${noteRes.status}`);

  const linkRes = await owner.call(`${org}/incidents/${incidentId}/findings`, {
    method: 'POST',
    body: { findingIds: [findingId] },
  });
  check(
    'findings linked to incident',
    linkRes.status === 200 && linkRes.json?.linked === 1,
    `status ${linkRes.status}`,
  );

  const linkBad = await owner.call(`${org}/incidents/${incidentId}/findings`, {
    method: 'POST',
    body: { findingIds: ['missingfinding'] },
  });
  check(
    'linking unknown finding rejected with 404',
    linkBad.status === 404,
    `status ${linkBad.status}`,
  );

  const incidentStatus = await owner.call(`${org}/incidents/${incidentId}/status`, {
    method: 'POST',
    body: { status: 'INVESTIGATING' },
  });
  check(
    'incident status transition accepted',
    incidentStatus.status === 200,
    `status ${incidentStatus.status}`,
  );

  const incidentDetail = await owner.call(`${org}/incidents/${incidentId}`);
  check(
    'incident detail has notes and findings',
    incidentDetail.status === 200 &&
      incidentDetail.json?.incident?.notes?.length === 1 &&
      incidentDetail.json?.incident?.findings?.length === 1,
    `notes ${incidentDetail.json?.incident?.notes?.length} findings ${incidentDetail.json?.incident?.findings?.length}`,
  );

  // ---------- members ----------
  const analyst = new Client('analyst');
  await register(analyst, 'Audit Analyst', `audit-analyst-${stamp}@cybernorf.test`);
  const analystMe = await analyst.call('/api/v1/me');
  const analystUserId = analystMe.json?.user?.id;

  const addMember = await owner.call(`${org}/members`, {
    method: 'POST',
    body: { email: `audit-analyst-${stamp}@cybernorf.test`, role: 'ANALYST' },
  });
  check('member added', res201(addMember), `status ${addMember.status}`);

  const addAgain = await owner.call(`${org}/members`, {
    method: 'POST',
    body: { email: `audit-analyst-${stamp}@cybernorf.test`, role: 'ANALYST' },
  });
  check('duplicate member rejected with 409', addAgain.status === 409, `status ${addAgain.status}`);

  const addUnknown = await owner.call(`${org}/members`, {
    method: 'POST',
    body: { email: `nobody-${stamp}@cybernorf.test`, role: 'ANALYST' },
  });
  check(
    'unknown email rejected with 400',
    addUnknown.status === 400,
    `status ${addUnknown.status}`,
  );

  const mixedCaseEmail = await owner.call(`${org}/members`, {
    method: 'POST',
    body: { email: `AUDIT-ANALYST-${stamp}@cybernorf.test`, role: 'VIEWER' },
  });
  check(
    'member add is case-insensitive on email',
    mixedCaseEmail.status === 409,
    `status ${mixedCaseEmail.status} (expected 409 duplicate, not 400)`,
  );

  // analyst (no MFA) can create findings but not admin actions
  const analystCreate = await analyst.call(`${org}/findings`, {
    method: 'POST',
    body: { title: 'Analyst finding', severity: 'LOW' },
  });
  check(
    'analyst without MFA can create findings',
    res201(analystCreate),
    `status ${analystCreate.status}`,
  );

  const analystMemberAdd = await analyst.call(`${org}/members`, {
    method: 'POST',
    body: { email: `audit-analyst-${stamp}@cybernorf.test`, role: 'ANALYST' },
  });
  check(
    'analyst cannot manage members',
    analystMemberAdd.status === 403,
    `status ${analystMemberAdd.status}`,
  );

  const analystAsset = await analyst.call(`${org}/assets`, {
    method: 'POST',
    body: { name: 'Audit subdomain', type: 'DOMAIN', identifier: `x-${stamp}.example` },
  });
  check('analyst can register assets', res201(analystAsset), `status ${analystAsset.status}`);

  const analystDelete = await analyst.call(`${org}/assets/${assetId}`, { method: 'DELETE' });
  check(
    'analyst cannot delete assets',
    analystDelete.status === 403,
    `status ${analystDelete.status}`,
  );

  // viewer
  const viewer = new Client('viewer');
  await register(viewer, 'Audit Viewer', `audit-viewer-${stamp}@cybernorf.test`);
  const addViewer = await owner.call(`${org}/members`, {
    method: 'POST',
    body: { email: `audit-viewer-${stamp}@cybernorf.test`, role: 'VIEWER' },
  });
  check('viewer added', res201(addViewer), `status ${addViewer.status}`);

  const viewerRead = await viewer.call(`${org}/findings`);
  check('viewer can read findings', viewerRead.status === 200, `status ${viewerRead.status}`);

  const viewerWrite = await viewer.call(`${org}/findings`, {
    method: 'POST',
    body: { title: 'Viewer attempt', severity: 'LOW' },
  });
  check(
    'viewer cannot create findings',
    viewerWrite.status === 403,
    `status ${viewerWrite.status}`,
  );

  const viewerPage = await viewer.call(`/app/${slug}/findings`);
  check(
    'viewer can open the findings page',
    viewerPage.status === 200 && /findings/i.test(viewerPage.text),
    `status ${viewerPage.status}`,
  );

  // ---------- role change + session revocation ----------
  const members = await owner.call(`${org}/members`);
  const analystMembership = members.json?.members?.find((m) => m.userId === analystUserId);
  const viewerMembership = members.json?.members?.find(
    (m) => m.email === `audit-viewer-${stamp}@cybernorf.test`,
  );

  const roleChange = await owner.call(`${org}/members/${analystMembership.membershipId}`, {
    method: 'PATCH',
    body: { role: 'VIEWER' },
  });
  check('owner can change a member role', roleChange.status === 200, `status ${roleChange.status}`);
  const analystAfterDowngrade = await analyst.call(`${org}/findings`, {
    method: 'POST',
    body: { title: 'After downgrade', severity: 'LOW' },
  });
  check(
    'downgraded member loses write access',
    analystAfterDowngrade.status === 403,
    `status ${analystAfterDowngrade.status}`,
  );

  const selfDemote = await owner.call(`${org}/members/${viewerMembership.membershipId}`, {
    method: 'PATCH',
    body: { role: 'ADMIN' },
  });
  check('owner can promote to admin', selfDemote.status === 200, `status ${selfDemote.status}`);

  const removeViewer = await owner.call(`${org}/members/${viewerMembership.membershipId}`, {
    method: 'DELETE',
  });
  check('member removed', removeViewer.status === 204, `status ${removeViewer.status}`);
  const afterRemoval = await viewer.call(`${org}/findings`);
  check(
    'removed member session is revoked',
    afterRemoval.status === 401 || afterRemoval.status === 404,
    `status ${afterRemoval.status}`,
  );

  // ---------- settings ----------
  const settings = await owner.call(`${org}/settings`, {
    method: 'PATCH',
    body: { name: 'Runtime Audit Renamed' },
  });
  check(
    'settings updated',
    settings.status === 200 && settings.json?.organization?.name === 'Runtime Audit Renamed',
    `status ${settings.status}`,
  );

  // ---------- audit ----------
  const audit = await owner.call(`${org}/audit?pageSize=100`);
  check(
    'audit trail lists events',
    audit.status === 200 && audit.json?.items?.length >= 10,
    `events ${audit.json?.items?.length}`,
  );

  const auditFiltered = await owner.call(`${org}/audit?outcome=DENIED`);
  check(
    'audit denies are recorded',
    auditFiltered.status === 200 && auditFiltered.json?.total >= 2,
    `denied ${auditFiltered.json?.total}`,
  );

  const verify = await owner.call(`${org}/audit/verify`);
  check(
    'audit chain verifies',
    verify.status === 200 && verify.json?.valid === true,
    JSON.stringify(verify.json).slice(0, 160),
  );

  // concurrent writes must keep the chain linear
  await Promise.all(
    Array.from({ length: 12 }, (_, i) =>
      owner.call(`${org}/findings`, {
        method: 'POST',
        body: { title: `Concurrent ${i}`, severity: 'LOW' },
      }),
    ),
  );
  const verifyAfter = await owner.call(`${org}/audit/verify`);
  check(
    'audit chain stays valid after concurrent writes',
    verifyAfter.status === 200 && verifyAfter.json?.valid === true,
    JSON.stringify(verifyAfter.json).slice(0, 200),
  );

  // ---------- personal API keys ----------
  const orgId = orgRes.json?.organization?.id;
  const secondOrg = await owner.call('/api/v1/organizations', {
    method: 'POST',
    body: { name: 'Runtime Audit Second', slug: `audit-second-${stamp}` },
  });
  const secondSlug = secondOrg.json?.organization?.slug;
  check(
    'second organization created for key binding',
    Boolean(secondSlug),
    `status ${secondOrg.status}`,
  );

  const keyCreate = await owner.call('/api/v1/me/api-keys', {
    method: 'POST',
    body: { name: `runtime key ${stamp}`, organizationId: orgId, expiresInDays: 30 },
  });
  const plaintextKey = keyCreate.json?.key;
  check(
    'personal API key created with a one-time credential',
    res201(keyCreate) && typeof plaintextKey === 'string' && plaintextKey.startsWith('cnk_'),
    `status ${keyCreate.status}`,
  );
  check(
    'key creation response carries no digest',
    typeof keyCreate.json?.apiKey?.prefix === 'string' &&
      !JSON.stringify(keyCreate.json?.apiKey).includes(plaintextKey),
    '',
  );

  const keyList = await owner.call('/api/v1/me/api-keys');
  check(
    'key list shows a prefix but not the credential',
    keyList.status === 200 &&
      typeof keyList.json?.apiKeys?.[0]?.prefix === 'string' &&
      !keyList.text.includes(plaintextKey),
    `status ${keyList.status}`,
  );

  const keyClient = new Client('api-key');
  const bearerHeaders = { authorization: `Bearer ${plaintextKey}` };
  const keyRead = await keyClient.call(`${org}/findings`, { origin: null, headers: bearerHeaders });
  check(
    'bearer key reads its organization without a session or Origin header',
    keyRead.status === 200,
    `status ${keyRead.status}`,
  );

  const keyWrite = await keyClient.call(`${org}/assets`, {
    origin: null,
    headers: bearerHeaders,
    method: 'POST',
    body: { name: 'Keyed asset', type: 'HOSTNAME', identifier: `keyed-${stamp}.example` },
  });
  check(
    'bearer key writes without an Origin header',
    res201(keyWrite),
    `status ${keyWrite.status}`,
  );

  const keyMe = await keyClient.call('/api/v1/me', { origin: null, headers: bearerHeaders });
  check(
    'bearer key sees only its own organization on /me',
    keyMe.status === 200 &&
      keyMe.json?.organizations?.length === 1 &&
      keyMe.json?.organizations?.[0]?.id === orgId,
    `status ${keyMe.status} orgs ${keyMe.json?.organizations?.length}`,
  );

  const keyOtherOrg = await keyClient.call(`/api/v1/organizations/${secondSlug}/findings`, {
    origin: null,
    headers: bearerHeaders,
  });
  check(
    'bearer key is refused another tenant with 404',
    keyOtherOrg.status === 404,
    `status ${keyOtherOrg.status}`,
  );

  const keyMintsKey = await keyClient.call('/api/v1/me/api-keys', {
    origin: null,
    headers: bearerHeaders,
    method: 'POST',
    body: { name: 'escalate', organizationId: orgId, expiresInDays: 30 },
  });
  check(
    'bearer key cannot mint another key',
    keyMintsKey.status === 403,
    `status ${keyMintsKey.status}`,
  );

  const tamperedKey = `${plaintextKey.slice(0, -1)}${plaintextKey.endsWith('A') ? 'B' : 'A'}`;
  const tamperedRead = await keyClient.call(`${org}/findings`, {
    origin: null,
    headers: { authorization: `Bearer ${tamperedKey}` },
  });
  check(
    'tampered key rejected with 401',
    tamperedRead.status === 401,
    `status ${tamperedRead.status}`,
  );

  const keyRevoke = await owner.call(`/api/v1/me/api-keys/${keyCreate.json?.apiKey?.id}`, {
    method: 'DELETE',
  });
  check(
    'key revoked',
    keyRevoke.status === 200 && keyRevoke.json?.apiKey?.status === 'REVOKED',
    `status ${keyRevoke.status}`,
  );
  const afterKeyRevoke = await keyClient.call(`${org}/findings`, {
    origin: null,
    headers: bearerHeaders,
  });
  check(
    'revoked key rejected with 401',
    afterKeyRevoke.status === 401,
    `status ${afterKeyRevoke.status}`,
  );

  const keyAudit = await owner.call(`${org}/audit?action=api_key.created&pageSize=5`);
  check(
    'key lifecycle is audited',
    keyAudit.status === 200 && (keyAudit.json?.items?.length ?? 0) >= 1,
    `status ${keyAudit.status} items ${keyAudit.json?.items?.length}`,
  );

  // ---------- pages ----------
  const pages = [
    ['/app', owner],
    [`/app/${slug}`, owner],
    [`/app/${slug}/assets`, owner],
    [`/app/${slug}/assets/${assetId}`, owner],
    [`/app/${slug}/findings`, owner],
    [`/app/${slug}/findings/${findingId}`, owner],
    [`/app/${slug}/incidents`, owner],
    [`/app/${slug}/incidents/${incidentId}`, owner],
    [`/app/${slug}/audit`, owner],
    [`/app/${slug}/members`, owner],
    [`/app/${slug}/settings`, owner],
    ['/account/security', owner],
    [`/app/${slug}/findings?search=XSS&severity=CRITICAL`, owner],
    [`/app/${slug}/incidents?status=INVESTIGATING`, owner],
  ];
  for (const [path, client] of pages) {
    const res = await client.call(path);
    check(
      `page ${path}`,
      res.status === 200 && !/Application error|Internal Server Error/.test(res.text),
      `status ${res.status}`,
    );
  }

  for (const path of [
    `/app/${slug}/findings?severity=NOPE`,
    `/app/${slug}/incidents?status=NOPE`,
    `/app/${slug}/assets?type=NOPE`,
  ]) {
    const res = await owner.call(path);
    check(`page ${path} ignores invalid filters`, res.status === 200, `status ${res.status}`);
  }

  const missingPage = await owner.call(`/app/${slug}/findings/nonexistent`);
  check(
    'unknown finding page returns 404',
    missingPage.status === 404,
    `status ${missingPage.status}`,
  );

  // ---------- transport edge cases ----------
  const anon = new Client('anon');
  const anonApi = await anon.call(`${org}/findings`);
  check('anonymous API call rejected with 401', anonApi.status === 401, `status ${anonApi.status}`);

  const crossOrigin = await owner.call(`${org}/findings`, {
    method: 'POST',
    origin: 'https://evil.example',
    body: { title: 'CSRF', severity: 'LOW' },
  });
  check(
    'cross-site POST rejected with 403',
    crossOrigin.status === 403,
    `status ${crossOrigin.status}`,
  );

  const crossSiteHeader = await owner.call(`${org}/findings`, {
    method: 'POST',
    origin: null,
    headers: { 'sec-fetch-site': 'cross-site' },
    body: { title: 'CSRF2', severity: 'LOW' },
  });
  check(
    'Sec-Fetch-Site cross-site rejected with 403',
    crossSiteHeader.status === 403,
    `status ${crossSiteHeader.status}`,
  );

  const noOrigin = await owner.call(`${org}/findings`, {
    method: 'POST',
    origin: null,
    body: { title: `No origin ${stamp}`, severity: 'LOW' },
  });
  check('non-browser client (no Origin) accepted', res201(noOrigin), `status ${noOrigin.status}`);

  const wrongType = await owner.call(`${org}/findings`, {
    method: 'POST',
    raw: 'title=x',
    contentType: 'application/x-www-form-urlencoded',
  });
  check(
    'wrong content type rejected with 415',
    wrongType.status === 415,
    `status ${wrongType.status}`,
  );

  const malformed = await owner.call(`${org}/findings`, { method: 'POST', raw: '{"title":' });
  check('malformed JSON rejected with 400', malformed.status === 400, `status ${malformed.status}`);

  const tooLarge = await owner.call(`${org}/findings`, {
    method: 'POST',
    raw: JSON.stringify({ title: 'x'.repeat(300 * 1024) }),
  });
  check('oversize body rejected with 413', tooLarge.status === 413, `status ${tooLarge.status}`);

  const other = new Client('other');
  await register(other, 'Other', `audit-other-${stamp}@cybernorf.test`);
  // An OWNER must hold a second factor before mutating, so enrol one through the
  // application flow; otherwise the 403 would come from MFA, not tenancy.
  await enableTotp(other);
  const otherOrg = await other.call('/api/v1/organizations', {
    method: 'POST',
    body: { name: 'Other', slug: `other-${stamp}` },
  });
  const otherSlug = otherOrg.json?.organization?.slug;
  const foreignRead = await other.call(`/api/v1/organizations/${otherSlug}/findings/${findingId}`);
  check(
    'cross-tenant finding read returns 404',
    foreignRead.status === 404,
    `status ${foreignRead.status}`,
  );
  const foreignWrite = await other.call(`/api/v1/organizations/${otherSlug}/findings`, {
    method: 'POST',
    body: { title: 'Steal', severity: 'LOW', assetId },
  });
  check(
    'cross-tenant asset reference rejected',
    foreignWrite.status === 404,
    `status ${foreignWrite.status}`,
  );
  const foreignPage = await other.call(`/app/${slug}/audit`);
  check(
    'cross-tenant page is not rendered',
    foreignPage.status === 404 || /do not have access/i.test(foreignPage.text),
    `status ${foreignPage.status}`,
  );

  // ---------- asset cascade ----------
  const deleteAsset = await owner.call(`${org}/assets/${assetId}`, { method: 'DELETE' });
  check('owner can delete an asset', deleteAsset.status === 204, `status ${deleteAsset.status}`);
  const findingAfterAssetDelete = await owner.call(`${org}/findings/${findingId}`);
  check(
    'finding survives asset deletion',
    findingAfterAssetDelete.status === 200,
    `status ${findingAfterAssetDelete.status}`,
  );
  const verifyAfterDelete = await owner.call(`${org}/audit/verify`);
  check(
    'chain valid after deletions',
    verifyAfterDelete.json?.valid === true,
    JSON.stringify(verifyAfterDelete.json).slice(0, 120),
  );

  // ---------- rate limiting ----------
  const limited = [];
  for (let i = 0; i < 16; i += 1) {
    limited.push(
      await owner.call(`${org}/findings/import`, {
        method: 'POST',
        body: { findings: [{ title: `Limit ${i} ${stamp}`, severity: 'LOW' }] },
      }),
    );
  }
  const throttled = limited.find((res) => res.status === 429);
  check(
    'per-user import limit returns 429',
    Boolean(throttled),
    `statuses ${limited.map((r) => r.status).join(',')}`,
  );
  check(
    '429 includes Retry-After',
    throttled ? Number(throttled.headers.get('retry-after')) >= 1 : false,
    String(throttled?.headers.get('retry-after')),
  );
  check(
    '429 body uses the uniform error shape',
    throttled?.json?.error?.code === 'RATE_LIMITED',
    JSON.stringify(throttled?.json?.error).slice(0, 100),
  );

  // ---------- error shape ----------
  check(
    'error responses carry a request id header',
    anonApi.headers.get('x-request-id')?.length > 0,
    String(anonApi.headers.get('x-request-id')),
  );
  check(
    'no stack traces leak',
    !/at \w+ \(.+:\d+:\d+\)/.test(String(donor(anonApi, badAsset, wrongType))),
    '',
  );

  console.log(results.join('\n'));
  console.log(
    `\n${failures === 0 ? 'ALL RUNTIME CHECKS PASSED' : `${failures} RUNTIME CHECK(S) FAILED`} (${results.length} total)`,
  );
  process.exit(failures === 0 ? 0 : 1);
}

function res201(res) {
  return res.status === 201 || res.status === 200;
}

function donor(...responses) {
  return responses.map((r) => JSON.stringify(r.json)).join('\n');
}

await main();
