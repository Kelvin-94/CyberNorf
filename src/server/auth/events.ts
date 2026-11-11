import { isAPIError } from 'better-auth/api';
import { prisma } from '@/lib/prisma';
import { redactError, redactString } from '@/server/security/redaction';

/**
 * Authentication activity is recorded separately from the organization audit
 * chain, because a sign-in happens before any tenant is known. These rows are
 * not hash-chained; the table itself is append-only (a database trigger rejects
 * UPDATE and DELETE), and every row is written best-effort so a logging problem
 * can never block a sign-in or a second-factor check.
 */
export const AuthEventActions = {
  SIGNED_IN: 'auth.signed_in',
  SIGN_IN_FAILED: 'auth.sign_in_failed',
  SESSION_ENDED: 'auth.session_ended',
  SECOND_FACTOR_SUCCEEDED: 'auth.second_factor_succeeded',
  SECOND_FACTOR_FAILED: 'auth.second_factor_failed',
  TWO_FACTOR_DISABLED: 'auth.two_factor_disabled',
} as const;

export type AuthEventAction = (typeof AuthEventActions)[keyof typeof AuthEventActions];

export const AUTH_EVENT_LABELS: Record<AuthEventAction, string> = {
  [AuthEventActions.SIGNED_IN]: 'Signed in',
  [AuthEventActions.SIGN_IN_FAILED]: 'Sign-in failed',
  [AuthEventActions.SESSION_ENDED]: 'Session ended or rotated',
  [AuthEventActions.SECOND_FACTOR_SUCCEEDED]: 'Second factor verified',
  [AuthEventActions.SECOND_FACTOR_FAILED]: 'Second factor rejected',
  [AuthEventActions.TWO_FACTOR_DISABLED]: 'Two-factor authentication disabled',
};

const MAX_IP_LENGTH = 64;
const MAX_USER_AGENT_LENGTH = 256;

function bounded(value: unknown, max: number): string | null {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  if (trimmed.length === 0) return null;
  return redactString(trimmed).slice(0, max);
}

/** Everything the hook layer knows about one authentication request. */
export interface AuthActivityInput {
  path: string;
  failed: boolean;
  errorCode?: string | null;
  /** True only when the request created a new session, i.e. it really signed in. */
  newSession?: boolean;
}

export interface AuthActivity {
  action: AuthEventAction;
  outcome: 'SUCCESS' | 'FAILURE';
  metadata: Record<string, string>;
}

function failure(action: AuthEventAction, metadata: Record<string, string>): AuthActivity {
  return { action, outcome: 'FAILURE', metadata };
}

/**
 * Maps a Better Auth request to the activity it represents. Pure so the rules
 * can be tested without a running identity provider.
 *
 * A request that failed to create a session is never reported as a sign-in even
 * when the endpoint returned 200: the two-factor challenge, for example, is a
 * successful password check that has not signed anybody in yet.
 */
export function describeAuthActivity(input: AuthActivityInput): AuthActivity | null {
  const code = input.errorCode ? { code: input.errorCode } : {};

  // Sign-up auto-signs-in, so the account's very first session is recorded
  // too; a rejected sign-up is a validation problem, not a sign-in failure.
  if (input.path === '/sign-up/email') {
    if (input.failed || !input.newSession) return null;
    return {
      action: AuthEventActions.SIGNED_IN,
      outcome: 'SUCCESS',
      metadata: { method: 'password', via: 'sign_up' },
    };
  }

  if (input.path === '/sign-in/email') {
    if (input.failed)
      return failure(AuthEventActions.SIGN_IN_FAILED, { method: 'password', ...code });
    if (!input.newSession) return null;
    return {
      action: AuthEventActions.SIGNED_IN,
      outcome: 'SUCCESS',
      metadata: { method: 'password' },
    };
  }

  if (input.path.startsWith('/callback/') || input.path.startsWith('/oauth2/callback/')) {
    if (input.failed) return failure(AuthEventActions.SIGN_IN_FAILED, { method: 'oidc', ...code });
    if (!input.newSession) return null;
    return { action: AuthEventActions.SIGNED_IN, outcome: 'SUCCESS', metadata: { method: 'oidc' } };
  }

  if (input.path === '/two-factor/verify-totp' || input.path === '/two-factor/verify-backup-code') {
    const secondFactor = {
      method: input.path.endsWith('backup-code') ? 'backup_code' : 'totp',
    };
    if (input.failed)
      return failure(AuthEventActions.SECOND_FACTOR_FAILED, { ...secondFactor, ...code });
    return {
      action: AuthEventActions.SECOND_FACTOR_SUCCEEDED,
      outcome: 'SUCCESS',
      metadata: secondFactor,
    };
  }

  if (input.path === '/two-factor/disable') {
    // Only the change of state is recorded. A refused disable (a stale session,
    // a wrong password) changes nothing and is not evidence about a second
    // factor, so turning it into "second factor rejected" would mislead.
    if (input.failed) return null;
    return { action: AuthEventActions.TWO_FACTOR_DISABLED, outcome: 'SUCCESS', metadata: {} };
  }

  return null;
}

export interface AuthEventInput extends AuthActivity {
  userId?: string | null;
  ipAddress?: string | null;
  userAgent?: string | null;
}

/**
 * Writes one activity row. Failures are logged and swallowed: authentication
 * must not depend on the audit path being available.
 */
export async function recordAuthEvent(input: AuthEventInput): Promise<void> {
  try {
    await prisma.authEvent.create({
      data: {
        userId: input.userId ?? null,
        action: input.action,
        outcome: input.outcome,
        ipAddress: bounded(input.ipAddress, MAX_IP_LENGTH),
        userAgent: bounded(input.userAgent, MAX_USER_AGENT_LENGTH),
        metadata: input.metadata,
      },
    });
  } catch (error) {
    console.error('[auth-event] failed to record authentication activity:', redactError(error));
  }
}

/**
 * Records the end of a session. Better Auth deletes session rows both on an
 * explicit sign-out and on revocation, so the event says "session ended" rather
 * than claiming which of the two happened.
 */
export async function recordSessionEnded(input: {
  userId?: string | null;
  headers?: Headers | undefined;
}): Promise<void> {
  await recordAuthEvent({
    action: AuthEventActions.SESSION_ENDED,
    outcome: 'SUCCESS',
    userId: input.userId ?? null,
    metadata: {},
    ipAddress: clientAddress(input.headers),
    userAgent: header(input.headers, 'user-agent'),
  });
}

/** The subset of the Better Auth request context this module reads. */
export interface AuthHookContext {
  path?: string | null;
  body?: unknown;
  headers?: Headers | undefined;
  context?: {
    returned?: unknown;
    newSession?: { user?: { id?: string | null } | null } | null;
    session?: { user?: { id?: string | null } | null } | null;
  };
}

function header(headers: Headers | undefined, name: string): string | null {
  return headers?.get(name) ?? null;
}

function clientAddress(headers: Headers | undefined): string | null {
  // Only informational: the first hop of `x-forwarded-for` is what the reverse
  // proxy saw, and a direct client can forge it when it is not behind one.
  const forwarded = header(headers, 'x-forwarded-for')?.split(',')[0];
  return forwarded ?? header(headers, 'x-real-ip');
}

function emailFrom(body: unknown): string | null {
  if (typeof body !== 'object' || body === null) return null;
  const email = (body as { email?: unknown }).email;
  if (typeof email !== 'string') return null;
  const normalized = email.trim().toLowerCase();
  if (normalized.length === 0 || normalized.length > 320) return null;
  return normalized;
}

/**
 * Hook entry point. Resolves the account for a failed password sign-in so the
 * event can be attributed without storing the address the attacker typed;
 * an address that matches no account is recorded without an identifier.
 */
export async function recordAuthActivity(ctx: AuthHookContext): Promise<void> {
  try {
    const path = typeof ctx.path === 'string' ? ctx.path : '';
    const returned = ctx.context?.returned;
    const failed = isAPIError(returned);
    const errorCode = failed
      ? ((returned as unknown as { body?: { code?: unknown } }).body?.code as string | undefined)
      : null;
    const newSession = ctx.context?.newSession ?? null;
    let userId = newSession?.user?.id ?? ctx.context?.session?.user?.id ?? null;

    if (!userId && failed && path === '/sign-in/email') {
      const email = emailFrom(ctx.body);
      if (email) {
        const user = await prisma.user.findUnique({ where: { email }, select: { id: true } });
        userId = user?.id ?? null;
      }
    }

    const activity = describeAuthActivity({
      path,
      failed,
      errorCode: errorCode ?? null,
      newSession: newSession !== null,
    });
    if (!activity) return;

    await recordAuthEvent({
      ...activity,
      userId,
      ipAddress: clientAddress(ctx.headers),
      userAgent: header(ctx.headers, 'user-agent'),
    });
  } catch (error) {
    console.error('[auth-event] failed to describe authentication activity:', redactError(error));
  }
}

export interface AuthEventView {
  id: string;
  action: string;
  label: string;
  outcome: 'SUCCESS' | 'DENIED' | 'FAILURE';
  ipAddress: string | null;
  userAgent: string | null;
  createdAt: Date;
}

/** Recent activity for one account. Never spans accounts or tenants. */
export async function listRecentAuthEvents(userId: string, limit = 15): Promise<AuthEventView[]> {
  const boundedLimit = Math.min(Math.max(limit, 1), 50);
  const rows = await prisma.authEvent.findMany({
    where: { userId },
    orderBy: { createdAt: 'desc' },
    take: boundedLimit,
    select: {
      id: true,
      action: true,
      outcome: true,
      ipAddress: true,
      userAgent: true,
      createdAt: true,
    },
  });

  return rows.map((row) => ({
    ...row,
    label: AUTH_EVENT_LABELS[row.action as AuthEventAction] ?? row.action,
  }));
}
