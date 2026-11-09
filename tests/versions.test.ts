import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  compareVersions,
  isValidVersionRange,
  parseVersion,
  satisfiesRange,
} from '@/server/domain/versions';

/**
 * The comparator decides which hosts get a vulnerability finding, so these
 * cases pin the ordering rules that a bad implementation would get wrong
 * (numeric vs lexical ordering, pre-releases, package revisions, epochs).
 */

test('numeric segments are compared as numbers, not strings', () => {
  assert.equal(compareVersions('1.2.3', '1.2.10'), -1);
  assert.equal(compareVersions('1.10.0', '1.9.0'), 1);
  assert.equal(compareVersions('1.2', '1.2.0'), 0);
  assert.equal(compareVersions('2', '2.0.0.0'), 0);
});

test('prefixes carry no ordering information', () => {
  assert.equal(compareVersions('v1.2.3', '1.2.3'), 0);
  assert.equal(compareVersions('1:2.36.1', '2.36.1'), 0);
  assert.equal(compareVersions('1.2.3+build.9', '1.2.3'), 0);
});

test('pre-releases sort below the release they precede', () => {
  assert.equal(compareVersions('1.0.0-rc.1', '1.0.0'), -1);
  assert.equal(compareVersions('1.0.0-beta.2', '1.0.0-rc.1'), -1);
  assert.equal(compareVersions('1.0.0-rc.1', '1.0.0-rc.2'), -1);
  assert.equal(compareVersions('1.0.0-alpha.1', '1.0.0-alpha.2'), -1);
  assert.equal(compareVersions('1.0.0-rc', '1.0.0-rc.1'), -1);
  assert.equal(compareVersions('2.0.0-1', '2.0.0-2'), -1);
});

test('package revisions make a build newer than the plain release', () => {
  assert.equal(compareVersions('2.36.1-8+deb12u1', '2.36.1'), 1);
  assert.equal(compareVersions('1.0.0-0ubuntu1', '1.0.0'), 0);
  assert.equal(compareVersions('3.0.7-1.el9', '3.0.7'), 1);
});

test('unparseable versions never compare', () => {
  assert.equal(parseVersion('latest'), null);
  assert.equal(parseVersion(''), null);
  assert.equal(parseVersion('   '), null);
  assert.equal(compareVersions('latest', '1.0.0'), null);
});

test('compound ranges are ANDed', () => {
  const range = '>= 4.17.15, < 4.17.21';
  assert.equal(satisfiesRange('4.17.14', range), false);
  assert.equal(satisfiesRange('4.17.15', range), true);
  assert.equal(satisfiesRange('4.17.20', range), true);
  assert.equal(satisfiesRange('4.17.21', range), false);
  assert.equal(satisfiesRange('4.17.20+deb12u1', range), true);
});

test('caret and tilde ranges follow the usual expansion rules', () => {
  assert.equal(satisfiesRange('1.5.0', '^1.2.3'), true);
  assert.equal(satisfiesRange('2.0.0', '^1.2.3'), false);
  assert.equal(satisfiesRange('1.2.2', '^1.2.3'), false);
  assert.equal(satisfiesRange('0.2.5', '^0.2.3'), true);
  assert.equal(satisfiesRange('0.3.0', '^0.2.3'), false);
  assert.equal(satisfiesRange('1.2.9', '~1.2.3'), true);
  assert.equal(satisfiesRange('1.3.0', '~1.2.3'), false);
  assert.equal(satisfiesRange('1.9.9', '~1'), true);
  assert.equal(satisfiesRange('2.0.0', '~1'), false);
});

test('alternatives and hyphen ranges are both accepted', () => {
  assert.equal(satisfiesRange('2.5.0', '< 1.0.0 || >= 2.0.0'), true);
  assert.equal(satisfiesRange('1.5.0', '< 1.0.0 || >= 2.0.0'), false);
  assert.equal(satisfiesRange('1.1.0', '1.0.0 - 1.2.3'), true);
  assert.equal(satisfiesRange('1.2.4', '1.0.0 - 1.2.3'), false);
  assert.equal(satisfiesRange('9.9.9', '*'), true);
});

test('bare versions mean an exact release', () => {
  assert.equal(satisfiesRange('1.2.3', '1.2.3'), true);
  assert.equal(satisfiesRange('1.2.4', '1.2.3'), false);
  assert.equal(satisfiesRange('=1.2.3', '1.2.3'), true);
});

test('an unusable range matches nothing instead of everything', () => {
  for (const range of ['', '   ', '>= banana', '>= 1.0.0 ||', '1.0.0 -', '|| 1.0.0']) {
    assert.equal(satisfiesRange('1.0.0', range), false, `range ${JSON.stringify(range)}`);
    assert.equal(isValidVersionRange(range), false, `range ${JSON.stringify(range)}`);
  }
  assert.equal(isValidVersionRange('>= 1.0.0, < 2.0.0'), true);
});
