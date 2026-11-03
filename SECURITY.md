# Security Policy

## Current status

CyberNorf is an early-stage project. Do not assume it has undergone a security audit, is suitable for production, or safely handles sensitive data. Do not use it to process real secrets, regulated data, or customer information until the relevant protections have been implemented and reviewed.

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
