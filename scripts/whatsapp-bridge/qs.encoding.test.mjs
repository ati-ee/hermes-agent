import { strict as assert } from 'node:assert';
import test from 'node:test';
import qs from 'qs';

test('empty-array keys remain data through query and URL serialization', () => {
  for (const input of [
    { q: 'hi', 'x&apiKey=synthetic&y': [], 'x#': [] },
    { outer: { 'x&apiKey=synthetic&y': [] } },
  ]) {
    const serialized = qs.stringify(input, { allowEmptyArrays: true });
    const url = new URL(`http://synthetic.invalid/?${serialized}`);
    assert.equal(url.hash, '');
    assert.deepEqual(qs.parse(url.search.slice(1), { allowEmptyArrays: true }), input);
  }
});
