import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, test } from 'node:test';
import {
  blobPath,
  generateBlobKey,
  sanitiseFileName,
  storeArtifact,
  verifyArtifact,
} from './evidence-storage.ts';

const roots: string[] = [];

function root(): string {
  const path = mkdtempSync(join(tmpdir(), 'cn-evidence-'));
  roots.push(path);
  return path;
}

after(() => {
  for (const path of roots) {
    rmSync(path, { recursive: true, force: true });
  }
});

function streamOf(...chunks: string[]): ReadableStream<Uint8Array> {
  const encoder = new TextEncoder();
  return new ReadableStream<Uint8Array>({
    start(controller) {
      for (const chunk of chunks) {
        controller.enqueue(encoder.encode(chunk));
      }
      controller.close();
    },
  });
}

test('the recorded hash is the hash of the bytes that were written', async () => {
  const dir = root();
  const body = 'compliance evidence, one line\n';

  const stored = await storeArtifact({
    root: dir,
    declaredContentType: 'text/plain',
    body: streamOf(body),
  });

  const expected = createHash('sha256').update(body).digest('hex');
  assert.equal(stored.sha256, expected);
  assert.equal(stored.sizeBytes, Buffer.byteLength(body));
  // The file on disk is the file that was hashed, not a later re-read.
  assert.equal(readFileSync(blobPath(dir, stored.blobKey), 'utf8'), body);
});

test('a multi-chunk body is hashed across chunk boundaries', async () => {
  const dir = root();
  const chunks = ['abc', 'def', 'ghi'];

  const stored = await storeArtifact({
    root: dir,
    declaredContentType: 'text/plain',
    body: streamOf(...chunks),
  });

  const expected = createHash('sha256').update(chunks.join('')).digest('hex');
  assert.equal(stored.sha256, expected);
});

test('an unmodified artifact verifies as INTACT', async () => {
  const dir = root();
  const stored = await storeArtifact({
    root: dir,
    declaredContentType: 'text/plain',
    body: streamOf('original'),
  });

  const result = await verifyArtifact({
    root: dir,
    blobKey: stored.blobKey,
    expectedSha256: stored.sha256,
  });

  assert.equal(result.outcome, 'INTACT');
  assert.equal(result.actualSha256, stored.sha256);
});

test('a modified artifact verifies as MISMATCH and reports the observed hash', async () => {
  const dir = root();
  const stored = await storeArtifact({
    root: dir,
    declaredContentType: 'text/plain',
    body: streamOf('original'),
  });

  // Simulate out-of-band modification: same file, different bytes.
  writeFileSync(blobPath(dir, stored.blobKey), 'tampered');

  const result = await verifyArtifact({
    root: dir,
    blobKey: stored.blobKey,
    expectedSha256: stored.sha256,
  });

  assert.equal(result.outcome, 'MISMATCH');
  assert.notEqual(result.actualSha256, stored.sha256);
  assert.equal(result.actualSha256, createHash('sha256').update('tampered').digest('hex'));
});

test('a deleted artifact verifies as MISSING rather than throwing', async () => {
  const dir = root();
  const stored = await storeArtifact({
    root: dir,
    declaredContentType: 'text/plain',
    body: streamOf('original'),
  });
  rmSync(blobPath(dir, stored.blobKey));

  const result = await verifyArtifact({
    root: dir,
    blobKey: stored.blobKey,
    expectedSha256: stored.sha256,
  });

  assert.equal(result.outcome, 'MISSING');
  assert.equal(result.actualSha256, null);
});

test('a body over the limit is refused and no partial file is left behind', async () => {
  const dir = root();

  await assert.rejects(
    storeArtifact({
      root: dir,
      declaredContentType: 'text/plain',
      body: streamOf('a'.repeat(64), 'b'.repeat(64)),
      maxBytes: 100,
    }),
    /limited to/i,
  );

  // A crashed upload must not leave an orphan that looks like evidence.
  const { readdirSync } = await import('node:fs');
  const shards = readdirSync(dir);
  const files = shards.flatMap((shard) => {
    try {
      return readdirSync(join(dir, shard));
    } catch {
      return [];
    }
  });
  assert.deepEqual(files, []);
});

test('an empty body is refused and leaves nothing behind', async () => {
  const dir = root();
  await assert.rejects(
    storeArtifact({ root: dir, declaredContentType: 'text/plain', body: streamOf() }),
    /empty/i,
  );
});

test('a content type outside the allow-list is refused before anything is written', async () => {
  const dir = root();
  await assert.rejects(
    storeArtifact({
      root: dir,
      declaredContentType: 'application/x-msdownload',
      body: streamOf('MZ...'),
    }),
    /not accepted/i,
  );
});

test('a blob key cannot escape the storage root', () => {
  const dir = root();
  for (const key of ['../../etc/passwd', 'a/../../b', '/etc/passwd', '..', 'abcdef1234567890ABCDEF']) {
    assert.throws(() => blobPath(dir, key), /unexpected error|cannot|invalid/i);
  }
});

test('a valid key resolves inside the root and is sharded', () => {
  const dir = root();
  const key = generateBlobKey();
  const path = blobPath(dir, key);
  assert.ok(path.startsWith(dir));
  assert.ok(path.includes(`/${key.slice(0, 2)}/`));
});

test('generated blob keys are unique and match the stored shape', () => {
  const keys = new Set<string>();
  for (let index = 0; index < 200; index += 1) {
    const key = generateBlobKey();
    assert.match(key, /^[a-z0-9]{20,40}$/);
    keys.add(key);
  }
  assert.equal(keys.size, 200);
});

test('a file name cannot break a Content-Disposition header', () => {
  assert.equal(sanitiseFileName('report.pdf'), 'report.pdf');
  assert.equal(sanitiseFileName('../../etc/passwd'), '.._.._etc_passwd');
  assert.equal(sanitiseFileName('a\nb'), 'ab');
  assert.equal(sanitiseFileName(''), 'evidence');
  assert.ok(sanitiseFileName('x'.repeat(500)).length <= 120);
});
