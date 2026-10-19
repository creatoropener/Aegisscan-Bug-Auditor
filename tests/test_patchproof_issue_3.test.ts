import test from 'node:test';
import assert from 'node:assert/strict';
import { runSastCodeScan } from '@/src/server/sastEngine.ts';

test('detects vulnerable Axios version 0.19.2 in package.json', async () => {
  const code = `{ \"name\": \"test\", \"version\": \"1.0.0\", \"dependencies\": { \"axios\": \"0.19.2\" } }`;
  const report = runSastCodeScan({ filename: 'package.json', code });
  const vuln = report.findings.find(f => f.id.startsWith('SAST-PKG-AXIOS'));
  assert.ok(vuln, 'Expected Axios vulnerability finding');
  assert.equal(vuln.severity, 'HIGH');
  assert.equal(vuln.cvssScore, 7.4);
});
