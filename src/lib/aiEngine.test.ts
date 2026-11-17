import { test } from 'node:test';
import assert from 'node:assert/strict';
import { predictRisk } from './aiEngine';

const vuln = (id: string, cvssVector: string | null) => ({
  vulnerabilityId: id, cvssVector, cvssScore: 9.8, cweIds: [], publishedDate: null, description: null,
});

test('predictRisk sends only CVEs with a vector and puts scores back in the right place', async (t) => {
  let sent: { id: string }[] = [];
  t.mock.method(globalThis, 'fetch', async (_url: string, init: RequestInit) => {
    sent = JSON.parse(String(init.body));
    return Response.json(sent.map((c) => ({ id: c.id, risk: c.id === 'A' ? 0.9 : 0.1, reasons: ['r'] })));
  });

  const out = await predictRisk([vuln('A', 'CVSS:3.1/AV:N'), vuln('NO-VECTOR', null), vuln('B', 'CVSS:3.1/AV:L')]);

  assert.deepEqual(sent.map((c) => c.id), ['A', 'B']);
  assert.deepEqual(out, [{ risk: 0.9, reasons: ['r'] }, null, { risk: 0.1, reasons: ['r'] }]);
});

test('predictRisk returns nulls instead of failing the scan when the engine is down', async (t) => {
  t.mock.method(globalThis, 'fetch', async () => { throw new Error('ECONNREFUSED'); });
  t.mock.method(console, 'error', () => {});
  assert.deepEqual(await predictRisk([vuln('A', 'CVSS:3.1/AV:N')]), [null]);
});
