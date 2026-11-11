# Contributing to CyberNorf

Thank you for your interest in contributing. CyberNorf is an early-stage project, so proposals that improve security, clarity, testability, and maintainability are especially valuable.

## Before contributing

1. Check existing issues and pull requests to avoid duplicate work.
2. For a substantial change, open an issue describing the problem, proposed solution, alternatives, and security implications.
3. Never commit API keys, access tokens, passwords, private keys, production data, or other secrets. Use local environment variables and an untracked environment file for development.
4. Do not include confidential information, real customer logs, or unapproved malware samples.

## Pull requests

Keep changes focused and explain:

- what changed and why;
- how the change was tested;
- any configuration or migration requirements;
- security and privacy impact;
- limitations or follow-up work.

Include tests for new behavior and regression tests for fixed bugs. Update documentation when behavior or configuration changes. Avoid claiming a test passes unless it was actually run.

## Security expectations

- Enforce authentication and authorization in backend code; never rely on hiding UI controls.
- Prefer explicit allowlists and deny-by-default behavior for sensitive operations.
- Validate input at trust boundaries and handle failures safely.
- Avoid logging credentials, tokens, sensitive payloads, or unnecessary personal data.
- Treat uploaded files, tool output, external feeds, and user-supplied text as untrusted.
- Do not add functionality intended for unauthorized access, destructive attacks, indiscriminate targeting, or stealthy persistence.
- Add tests for denied access, invalid scope, expired authorization, and failure conditions where relevant.

## Review and provenance controls

`main` is protected by an active ruleset. Every change reaches it through a
pull request, with linear history and either a squash or rebase merge. Direct
pushes and force pushes are rejected.

- **Signed commits are required.** Configure Git to sign your commits (`git config commit.gpgsign true` with a registered GPG, SSH, or S/MIME key). Commits created by GitHub's squash-merge are signed by GitHub.
- **Code owners are recorded in `.github/CODEOWNERS`.** Review from the owner becomes mandatory once a second maintainer is appointed; the repository owner cannot approve their own pull request, so self-authored changes rely on the automated gates described here.
- **Every pull request runs `Contributor risk review`.** The check reads the proposed diff on the base revision without installing or executing pull-request code. It blocks remote script execution, encoded payloads, dynamic code evaluation, obfuscation, committed credentials, binary artifacts, `write-all` workflow permissions, `pull_request_target`, secrets interpolated into shell steps, install-time lifecycle scripts, dependencies resolved outside the npm registry, and removal of existing security steps (audit, secret scan, credential persistence).
- **Medium findings are advisory, not blocking.** Modified workflows, unpinned action tags, new dependencies, and child-process use are reported to the reviewer with file and line evidence. Resolve or justify them in the pull request.
- **The gate cannot be weakened from outside.** A pull request that modifies the review workflow fails that workflow unless it is authored by the repository owner, so an external contributor cannot disable the check that inspects their own change.
- **Contributor context is attached to every review.** The bot comment records the author's association, account age, and public repository count; accounts younger than 30 days are flagged for identity review.
- **False positives need a written rationale.** A maintainer who overrides a high-severity finding must record why in the pull request. Do not add patterns to an ignore list to make a red check green.

Report a suspected vulnerability through the process in [SECURITY.md](SECURITY.md)
rather than in a public issue or pull request.

## Development quality

Follow the formatting, linting, test, and build commands documented in [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md). Every pull request must pass `npm run format:check`, `npm run lint`, `npm run typecheck`, `npm test`, and `npm run build` before it is merged.

## Licensing

CyberNorf is currently licensed under AGPL-3.0-or-later. By submitting a contribution, you agree that your contribution is provided under the same license, subject to applicable law and any explicit agreement made with the project. Submit only work you have the right to contribute. Third-party code and assets must have compatible terms and their origin and license should be documented. If the project later considers dual licensing or a different license, the maintainer must obtain the necessary rights or permissions; this file alone does not transfer copyright ownership.
