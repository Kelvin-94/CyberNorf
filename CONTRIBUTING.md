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

## Development quality

Follow the formatting, linting, test, and build commands documented by the relevant package. If these have not yet been established, propose a reproducible toolchain and add the commands to the project documentation.

## Licensing

CyberNorf is currently licensed under AGPL-3.0-or-later. By submitting a contribution, you agree that your contribution is provided under the same license, subject to applicable law and any explicit agreement made with the project. Submit only work you have the right to contribute. Third-party code and assets must have compatible terms and their origin and license should be documented. If the project later considers dual licensing or a different license, the maintainer must obtain the necessary rights or permissions; this file alone does not transfer copyright ownership.
