import { test } from 'node:test';
import assert from 'node:assert/strict';
import { pickCvss } from './trivy';

const base = { VulnerabilityID: 'CVE-1', PkgName: 'p', InstalledVersion: '1', Severity: 'HIGH' };

test('pickCvss prefers NVD, falls back to another source, and handles no CVSS', () => {
  const nvd = { V3Vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', V3Score: 9.8 };
  const redhat = { V3Vector: 'CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', V3Score: 8.1 };

  assert.equal(pickCvss({ ...base, CVSS: { redhat, nvd } }), nvd);
  assert.equal(pickCvss({ ...base, CVSS: { nvd: { V3Score: 5 }, redhat } }), redhat);
  assert.equal(pickCvss(base), undefined);
});
