import { randomUUID } from 'node:crypto';
import { prisma } from '@/lib/prisma';
import type { AuthenticatedUser, TenantContext } from '@/server/authz/context';
import type { OrgRole } from '@/server/authz/roles';
import { getRequestMeta } from '@/server/http/request-meta';

/**
 * Database-backed tests refuse to run against anything that is not obviously a
 * test database, so a misconfigured DATABASE_URL cannot truncate real data.
 */
export function assertTestDatabase(): void {
  const url = process.env.DATABASE_URL ?? '';
  const databaseName = url.split('?')[0]?.split('/').pop() ?? '';
  if (!/test/i.test(databaseName)) {
    throw new Error(
      `Refusing to run database tests: DATABASE_URL points at "${databaseName || '(unset)'}" instead of a test database.`,
    );
  }
}

/**
 * Empties every tenant table. TRUNCATE is used because the audit table rejects
 * row-level deletes by design; the trigger bypass here is limited to test
 * resets. The global compliance catalog (frameworks and their controls) is
 * seeded by migration and shared by every tenant, so it is left in place.
 */
export async function resetDatabase(): Promise<void> {
  assertTestDatabase();
  const tables = await prisma.$queryRaw<Array<{ tablename: string }>>`
    SELECT tablename FROM pg_tables
    WHERE schemaname = 'public'
      AND tablename NOT IN ('_prisma_migrations', 'frameworks', 'framework_controls')
  `;
  if (tables.length === 0) {
    return;
  }
  const list = tables.map((row) => `"${row.tablename.replace(/"/g, '""')}"`).join(', ');
  await prisma.$executeRawUnsafe(`TRUNCATE TABLE ${list} RESTART IDENTITY CASCADE`);
}

let userCounter = 0;

export async function createUser(
  options: { twoFactorEnabled?: boolean; name?: string } = {},
): Promise<AuthenticatedUser> {
  userCounter += 1;
  const unique = randomUUID();
  const user = await prisma.user.create({
    data: {
      id: `usr_${unique}`,
      name: options.name ?? `Test User ${userCounter}`,
      email: `user-${userCounter}-${unique}@cybernorf.test`,
      emailVerified: true,
      twoFactorEnabled: options.twoFactorEnabled ?? false,
    },
  });

  return {
    id: user.id,
    name: user.name,
    email: user.email,
    twoFactorEnabled: user.twoFactorEnabled === true,
    sessionId: `ses_${unique}`,
  };
}

export function testMeta(): TenantContext['meta'] {
  return getRequestMeta(
    new Request('http://localhost:3000/api/v1/test', {
      headers: { 'user-agent': 'cybernorf-test-suite', 'x-forwarded-for': '203.0.113.10' },
    }),
  );
}

export function testHeaders(): Headers {
  return new Headers({ 'user-agent': 'cybernorf-test-suite', 'x-forwarded-for': '203.0.113.10' });
}

export interface TestTenant {
  user: AuthenticatedUser;
  organization: TenantContext['organization'];
  membership: TenantContext['membership'];
  ctx: TenantContext;
}

export async function createTenant(options: {
  name?: string;
  slug?: string;
  role: OrgRole;
  twoFactorEnabled?: boolean;
}): Promise<TestTenant> {
  const user = await createUser(
    options.twoFactorEnabled === undefined ? {} : { twoFactorEnabled: options.twoFactorEnabled },
  );
  const unique = randomUUID().slice(0, 8);
  const organization = await prisma.organization.create({
    data: {
      name: options.name ?? `Tenant ${unique}`,
      slug: options.slug ?? `tenant-${unique}`,
      memberships: { create: { userId: user.id, role: options.role, status: 'ACTIVE' } },
    },
    select: { id: true, name: true, slug: true, tier: true },
  });

  const membership = await prisma.membership.findUniqueOrThrow({
    where: { userId_organizationId: { userId: user.id, organizationId: organization.id } },
    select: { id: true, role: true },
  });

  return {
    user,
    organization,
    membership,
    ctx: { user, organization, membership, meta: testMeta() },
  };
}

/** Asserts that a promise rejects with an AppError carrying the expected status. */
export async function expectAppError(
  promise: Promise<unknown>,
  expected: { statusCode: number; code?: string },
): Promise<void> {
  const { AppError } = await import('@/server/errors');
  try {
    await promise;
  } catch (error) {
    if (!(error instanceof AppError)) {
      throw new Error(`Expected an AppError, received: ${String(error)}`, { cause: error });
    }
    if (error.statusCode !== expected.statusCode) {
      throw new Error(
        `Expected status ${expected.statusCode}, received ${error.statusCode} (${error.code}).`,
        {
          cause: error,
        },
      );
    }
    if (expected.code && error.code !== expected.code) {
      throw new Error(`Expected code ${expected.code}, received ${error.code}.`, { cause: error });
    }
    return;
  }
  throw new Error(
    `Expected the call to fail with status ${expected.statusCode}, but it succeeded.`,
  );
}

export { prisma };
