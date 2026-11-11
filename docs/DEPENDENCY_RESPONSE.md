# Dependency update and vulnerability response

This is the process that turns a vulnerability report about a dependency into a dated
decision. The automation half already exists; this document is the human half the roadmap
was missing.

## Scope

- npm packages in `package.json` / `package-lock.json`, runtime and development.
- GitHub Actions used by `.github/workflows/`.
- The Node.js base image and OS packages in the application container.
- PostgreSQL image and the proxy image in `compose.prod.yaml`.
- Advisory feeds the product ingests are **not** in scope here: those are tenant data, and
  a bad feed entry is handled as a product-data issue, not a dependency decision.

## What is automated

| Control | Where | What it catches |
| --- | --- | --- |
| Dependabot, weekly, with cooldown | `.github/dependabot.yml` | Version updates; security updates ignore the cooldown, so a CVE fix is not delayed by it. Major and minor/patch cooldowns exist to let a compromised or broken release be yanked before adoption. |
| Grouped development updates | `.github/dependabot.yml` | One PR for the lint/test toolchain instead of a per-package flood. |
| `npm audit --audit-level=low` | `.github/workflows/ci.yml` | Known advisories in the installed tree, failing the build at any severity. |
| gitleaks history scan | `.github/workflows/ci.yml` | Committed secrets, including ones a dependency bump might introduce in test fixtures. |
| Runtime audit against a live server | `.github/workflows/ci.yml`, `npm run audit:runtime` | Headers, cookie flags and exposed endpoints of the actual running build, so a framework upgrade that silently changes a default is caught. |
| Full suite + production build | `.github/workflows/ci.yml` | A bump that compiles but breaks behaviour. |

Dependabot does not watch the Docker ecosystems here: the base image and the compose
images are updated by hand. That is a known gap, recorded below.

## Triage

The clock starts when an advisory is published or Dependabot opens a security PR,
whichever comes first. The decision deadline is stricter than the patch deadline on
purpose: "accept" is a decision, and an undocumented non-decision is the failure mode this
process exists to prevent.

| Severity (CVSS / advisory) | Decide within | Patch or mitigate within | Notes |
| --- | --- | --- | --- |
| Critical (9.0–10.0) | 24 hours | 72 hours | Out-of-band release; do not wait for the weekly train |
| High (7.0–8.9) | 3 days | 14 days | Out-of-band if the affected path is reachable from an unauthenticated request |
| Medium (4.0–6.9) | 14 days | 60 days | May ride the normal release train |
| Low (0.1–3.9) | 30 days | Next scheduled dependency sweep | Batch with other low-risk updates |

Severity is a starting point, not the answer. Reachability decides the real urgency: a
critical advisory in a build-only tool that never runs in production is not a production
incident, and a medium advisory in the session or authorization path can be worse than a
critical one in a test helper.

## Decision record

Every advisory that is not patched immediately gets a row in the table below, appended by
the person who made the call. An empty table means no decision has been recorded yet, not
that no advisories have appeared.

| Date | Advisory | Package / version | Reachable? | Decision | Owner | Review by |
| --- | --- | --- | --- | --- | --- | --- |
| — | — | — | — | — | — | — |

Decision values:

- **Patch** — upgrade to the fixed version. Link the PR.
- **Mitigate** — cannot upgrade yet; a control compensates (feature disabled, network
  restriction, input validation). State the control and how it is verified.
- **Accept** — the exposure is understood and not worth fixing now. State why (not
  reachable, build-only, no fix exists, breaking upgrade), the residual risk, and a review
  date. An "accept" without a review date is invalid.
- **Not affected** — the advisory does not apply to the installed version or usage. Say
  what was checked.

## Emergency patch procedure

1. Branch from the deployed commit, not from `main`'s tip.
2. Update the single package (`npm install <pkg>@<version>`) or add an `overrides` entry for
   a transitive dependency that has no direct upgrade path.
3. Run `npm ci`, `npm audit --audit-level=low`, `npm run lint`, `npm run typecheck`,
   `npm test`, and `npm run build`. A patch that skips the suite is not a patch.
4. Deploy through the normal procedure in [DEPLOYMENT.md](DEPLOYMENT.md), then run
   `npm run audit:runtime` against the live build and check `/api/ready`.
5. Record the advisory, the version, the deploy time and the verification in the decision
   table and in the release notes.
6. If no fixed version exists, choose a mitigation and write it down. Disabling the
   affected feature is a legitimate answer; pretending the risk is zero is not.

## Customer advisories

Notify customers when a vulnerability in the shipped product could affect their data or
availability, or when an incident exposed tenant data. The same path is used for both
([INCIDENT_RESPONSE.md](INCIDENT_RESPONSE.md#after-any-incident)).

- **Who:** the operator of each affected deployment. There is no hosted service, so the
  operator is the customer contact.
- **When:** within 24 hours of confirming a SEV1, within 72 hours for a SEV2. Do not wait
  for a perfect root cause; send what is known and when the next update will come.
- **What:** affected versions, what an attacker could do, whether the deployment is
  affected, the fixed version or mitigation, and the action required. Never include exploit
  details before a fix is available.
- **Where:** the same channel used for operational notices, plus the repository security
  advisory when the issue is in the open-source code.

## Review cadence

- Weekly: triage Dependabot PRs and any new advisory against the SLA table.
- Monthly: read the decision table, close rows whose review date has passed, and update the
  base image and compose images.
- Each release: confirm the decision table has no overdue row and that the runtime audit
  passed against the build being shipped.

## Known gaps

- No automated container or base-image updates; the Dockerfile base and compose images are
  reviewed monthly by hand.
- No SBOM is produced. Generating one per release would make "are we affected?" a query
  instead of a manual search.
- The SLAs are targets for a single maintainer, not a staffed security team; a critical
  advisory landing during an absence will miss the 72-hour patch window, and the decision
  table should say so rather than silently slipping.
- No customer advisory has been sent yet; the template and timing above are untested.
