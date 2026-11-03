import assert from 'node:assert/strict';
import { test } from 'node:test';
import { ZodError } from 'zod';
import {
  changeFindingStatusSchema,
  createFindingSchema,
  findingQuerySchema,
  importFindingsSchema,
  updateFindingSchema,
} from './findings.ts';
import { createAssetSchema, createOrganizationSchema } from './organizations.ts';

function isValidationError(error: unknown): error is ZodError {
  return error instanceof ZodError;
}

test('finding input rejects malformed values', () => {
  assert.throws(
    () => createFindingSchema.parse({ title: 'ab', severity: 'HIGH' }),
    isValidationError,
  );
  assert.throws(
    () => createFindingSchema.parse({ title: 'Valid title', severity: 'SEVERE' }),
    isValidationError,
  );
  assert.throws(
    () => createFindingSchema.parse({ title: 'Valid title', severity: 'HIGH', cvssScore: 10.05 }),
    isValidationError,
  );
  assert.throws(
    () => createFindingSchema.parse({ title: 'Valid title', severity: 'HIGH', cvssScore: 11 }),
    isValidationError,
  );
  assert.throws(
    () => createFindingSchema.parse({ title: 'Valid title', severity: 'HIGH', cveId: '2026-1234' }),
    isValidationError,
  );
});

test('finding input normalizes CVE identifiers and keeps one CVSS decimal', () => {
  const parsed = createFindingSchema.parse({
    title: 'SQL injection in login form',
    severity: 'CRITICAL',
    cveId: 'cve-2026-12345',
    cvssScore: 9.8,
  });
  assert.equal(parsed.cveId, 'CVE-2026-12345');
  assert.equal(parsed.cvssScore, 9.8);
});

test('updates require at least one field and status changes require a known status', () => {
  assert.throws(() => updateFindingSchema.parse({}), isValidationError);
  assert.throws(() => changeFindingStatusSchema.parse({ status: 'DELETED' }), isValidationError);
  assert.deepEqual(changeFindingStatusSchema.parse({ status: 'RESOLVED' }), { status: 'RESOLVED' });
});

test('list queries apply safe defaults and bounded page sizes', () => {
  const defaults = findingQuerySchema.parse({});
  assert.equal(defaults.page, 1);
  assert.equal(defaults.pageSize, 20);
  assert.equal(defaults.sort, 'createdAt');
  assert.equal(defaults.direction, 'desc');
  assert.throws(() => findingQuerySchema.parse({ pageSize: 5000 }), isValidationError);
});

test('import documents are bounded and require a severity per item', () => {
  assert.throws(() => importFindingsSchema.parse({ findings: [] }), isValidationError);
  assert.throws(
    () => importFindingsSchema.parse({ findings: [{ title: 'No severity' }] }),
    isValidationError,
  );
  const tooMany = Array.from({ length: 501 }, (_, index) => ({
    title: `Finding number ${index}`,
    severity: 'LOW',
  }));
  assert.throws(() => importFindingsSchema.parse({ findings: tooMany }), isValidationError);

  const single = importFindingsSchema.parse({
    findings: [{ title: 'Reflected XSS', severity: 'HIGH', assetIdentifier: 'App.Example.com' }],
  });
  assert.equal(single.findings[0]?.assetIdentifier, 'app.example.com');
});

test('asset identifiers reject characters that would confuse proxy configuration', () => {
  assert.throws(
    () =>
      createAssetSchema.parse({
        name: 'Web app',
        type: 'WEB_APPLICATION',
        identifier: 'https://example.com/App"',
      }),
    isValidationError,
  );
  const parsed = createAssetSchema.parse({
    name: 'Web app',
    type: 'WEB_APPLICATION',
    identifier: 'app.example.com',
  });
  assert.equal(parsed.criticality, 'MEDIUM');
  assert.equal(parsed.status, 'ACTIVE');
});

test('organization slugs are restricted to lowercase hostname-safe characters', () => {
  assert.throws(
    () => createOrganizationSchema.parse({ name: 'Acme', slug: 'Acme Corp' }),
    isValidationError,
  );
  assert.throws(
    () => createOrganizationSchema.parse({ name: 'Acme', slug: '-leading' }),
    isValidationError,
  );
  assert.equal(
    createOrganizationSchema.parse({ name: 'Acme Security', slug: 'acme-security' }).slug,
    'acme-security',
  );
});
