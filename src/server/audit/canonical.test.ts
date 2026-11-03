import assert from 'node:assert/strict';
import { test } from 'node:test';
import { canonicalize } from './canonical.ts';

test('object keys are serialized in a stable order', () => {
  const a = canonicalize({ b: 2, a: 1, c: { z: 1, y: [3, 2, 1] } });
  const b = canonicalize({ c: { y: [3, 2, 1], z: 1 }, a: 1, b: 2 });
  assert.equal(a, b);
  assert.equal(a, '{"a":1,"b":2,"c":{"y":[3,2,1],"z":1}}');
});

test('undefined members are dropped so absent and undefined hash alike', () => {
  assert.equal(canonicalize({ a: 1, b: undefined }), canonicalize({ a: 1 }));
});

test('null, arrays, strings and dates keep their JSON representation', () => {
  assert.equal(canonicalize(null), 'null');
  assert.equal(canonicalize([1, 'two', false]), '[1,"two",false]');
  assert.equal(canonicalize('x'), '"x"');
  assert.equal(canonicalize(new Date('2026-11-02T10:00:00.000Z')), '"2026-11-02T10:00:00.000Z"');
  assert.equal(canonicalize({ metadata: null }), '{"metadata":null}');
});

test('nested key order changes would be detectable by the hash', () => {
  const left = canonicalize({ a: { x: 1, y: 2 } });
  const right = canonicalize({ a: { y: 2, x: 1 } });
  assert.equal(left, right);

  const tampered = canonicalize({ a: { x: 1, y: 3 } });
  assert.notEqual(left, tampered);
});
