# ADR 0002: Identity, sessions, and second factors

- **Status:** Accepted
- **Date:** 2026-11-02

## Context

Phase 1 requires real authentication before any tenant data can be exposed. The store must own credentials, issue and revoke sessions, support a second factor for privileged roles, and persist state in the PostgreSQL database that already backs the application. Rolling a bespoke credential and session implementation would concentrate the highest-risk code in the project inside hand-written crypto and session plumbing.

## Decision

- Use [Better Auth](https://www.better-auth.com/) with its Prisma adapter as the identity provider for email and password accounts. Credentials, sessions, accounts, verification records, second factors, and Better Auth's own rate-limit counters live in the existing PostgreSQL database through the generated `User`, `Session`, `Account`, `Verification`, `TwoFactor`, and `RateLimit` models.
- Enforce a 12-character minimum password length (128 maximum) and keep email verification and email-based account recovery out of v1, because no transactional email provider has been approved. Accounts are created with a password and cannot change email or self-delete in v1.
- Sessions last eight hours, slide forward at most every fifteen minutes, and are marked fresh for one hour. Cookie caching is disabled so that server-side revocation takes effect immediately.
- Cookies are `HttpOnly`, `SameSite=Lax`, scoped to `/`, and marked `Secure` when `NODE_ENV=production`. `BETTER_AUTH_URL` is the only trusted origin; every mutating API request additionally passes a same-origin check against it.
- Require a TOTP second factor (6 digits, 30-second period) with ten single-use backup codes for `OWNER` and `ADMIN` memberships before they can perform mutating capabilities. The gate is enforced in the authorization layer, not in the UI, and returns `403 MFA_REQUIRED`.
- Keep Better Auth responsible for authentication only. It does not decide what an authenticated user may do; that stays in the capability policy described in [ADR 0003](0003-authorization-and-audit.md).

## Consequences

- `BETTER_AUTH_SECRET` (32+ characters in production) and `BETTER_AUTH_URL` are required configuration. Missing or weak secrets fail at startup instead of silently using a development default.
- Rotating `BETTER_AUTH_SECRET` invalidates all existing sessions.
- Because Better Auth owns its tables, schema changes to those models come from the library's generator and are checked into `prisma/schema.prisma` with a migration.
- Public sign-up is open in v1. Organization membership is still required to reach any tenant data, and self-service organization creation makes a new account an `OWNER` of an empty organization only.
- Password reset, email verification, SSO, and passkeys remain future work and must not be described as available.
