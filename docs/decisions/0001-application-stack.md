# ADR 0001: v1 application foundation stack

- **Status:** Accepted
- **Date:** 2026-10-23

## Context

The approved v1 build directive selects Next.js with TypeScript, PostgreSQL accessed through Prisma, and Next.js server-side API routes. The repository architecture and threat model remain the source of product and security requirements. This decision establishes tooling only; it does not imply that security controls or product workflows exist.

## Decision

- Use Next.js App Router and TypeScript for the web application and server-side routes.
- Use Node.js 24 LTS as the supported runtime and npm. Commit the npm lockfile with dependency changes.
- Use PostgreSQL 17 for local development and Prisma ORM 7 with the `pg` driver adapter and checked-in migrations.
- Keep the initial Prisma schema free of domain entities until the Phase 1 data model is reviewed. The migration configuration and PostgreSQL migration lock are in place.
- Use ESLint, Prettier, Node.js's built-in test runner, and TypeScript strict checks in local development and continuous integration.

## Consequences

- Local development requires Node.js 24+, npm, and Docker Compose or a compatible PostgreSQL 17 instance.
- The repository contains only an application shell and health liveness endpoint. Authentication, authorization, tenant isolation, domain modules, and active security functions remain out of scope for this foundation.
- The first application schema migration will be created with `prisma migrate dev --name init` after the reviewed Phase 1 models are introduced. No placeholder tables are added solely to create a migration.
- Deployment model, tenancy model, integrations, data retention, and execution boundaries remain open decisions.
