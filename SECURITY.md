# Security Policy

## Current status

CyberNorf is an early-stage project. Do not assume it has undergone a security audit, is suitable for production, or safely handles sensitive data. Do not use it to process real secrets, regulated data, or customer information until the relevant protections have been implemented and reviewed.

## Transport security

The application expects TLS to be terminated in front of it and enforces the boundary rather than assuming it:

- A production build refuses to serve requests when `BETTER_AUTH_URL` is a plain-http origin on a non-loopback host, or when `DATABASE_URL` reaches a remote database without `sslmode`. The check runs from `src/instrumentation.ts` before the first request.
- `src/proxy.ts` returns `308` to `https://` for any request that does not arrive with `x-forwarded-proto: https`, so a proxy misconfiguration cannot silently serve sessions in cleartext.
- Every response carries HSTS (production), a per-response CSP with a script nonce, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: strict-origin-when-cross-origin`, `Cross-Origin-Opener-Policy: same-origin`, `Cross-Origin-Resource-Policy: same-origin`, `Origin-Agent-Cluster: ?1`, `X-Permitted-Cross-Domain-Policies: none`, `X-DNS-Prefetch-Control: off` and a restrictive `Permissions-Policy`; the `X-Powered-By` banner is disabled.
- Session cookies are `HttpOnly`, `SameSite=Lax` and `Secure` in production, and the session cookie cache is disabled so server-side revocation takes effect immediately.

`script-src` carries a fresh 128-bit nonce per response and no `'unsafe-inline'`. `src/proxy.ts` builds the policy with `src/server/security/csp.ts` and sets it on both the request and the response, so Next.js stamps the same nonce onto the scripts it renders; a policy on the response alone would leave them blocked. `style-src` keeps `'unsafe-inline'` because React and Next write style attributes, which a nonce cannot cover and which cannot execute script. Framing, plugins, `<base>` injection and cross-origin form posts are blocked by the same policy.

## Outbound webhooks

A notification destination is an operator-supplied URL, so it is treated as a potential SSRF target. It must be an absolute https URL with no embedded credentials (plain http is accepted only outside production), and the host must not be, or resolve to, a loopback, private, link-local, multicast or documentation address. A deployment that genuinely needs an internal collector opts in with `NOTIFY_ALLOW_PRIVATE_WEBHOOKS=true`.

The addresses that pass that check are handed to the delivery socket's resolver (`src/server/security/webhook-transport.ts`), so the name is never looked up a second time at connect time and a DNS record that changes between validation and delivery cannot point the request inward. Redirects are not followed and each delivery has a 5 second budget.

## Dependencies and CI

`npm audit --audit-level=low` gates every CI run, so any advisory in the runtime or build dependency tree fails the build rather than waiting for a high-severity threshold. Dependabot alerts, security updates and secret scanning with push protection are enabled on the repository, and CodeQL default setup scans pushes and pull requests. Every action in `.github/workflows/` is pinned to a full commit SHA with a version comment, and each job declares `permissions: contents: read`.

## Reporting a vulnerability

Please report suspected vulnerabilities privately to the project maintainer through a verified private contact channel associated with the repository owner. If no private contact channel is published, contact the maintainer before sharing sensitive technical details. Do not place credentials, personal data, or weaponized proof-of-concept material in public issues.

A useful report includes:

- affected component, version, or commit;
- a concise description of impact;
- minimal reproduction steps in a lab or other authorized environment;
- relevant logs or screenshots with secrets and personal data removed;
- any known prerequisites and suggested mitigations.

Please allow time for triage and coordinated remediation before public disclosure. No response-time or remediation SLA is currently promised.

## Scope and safe testing

- Test only systems you own or are explicitly authorized to assess.
- Keep reproduction minimal and avoid accessing, changing, or deleting other people's data.
- Do not perform denial-of-service testing, destructive actions, persistence, credential theft, or broad scanning against project infrastructure.
- Stop testing if you encounter data that is not yours or an unexpected impact.
- Do not upload live malware, credentials, tokens, or confidential customer material to this repository.

## Maintainer handling

The project should acknowledge reports, validate the issue in a controlled environment, assess severity and impact, track remediation, and coordinate disclosure where appropriate. Reports and private correspondence should only be shared with people who need access to resolve the issue.

## Supported versions

No formal release or supported-version policy exists yet. Support status will be documented when tagged releases are introduced.
