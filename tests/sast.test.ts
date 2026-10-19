import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runSastCodeScan } from '../src/server/sastEngine.ts';
import { DEMO_CODE_SNIPPETS } from '../src/server/demoScenarios.ts';

test('flags the vulnerable API demo with critical findings and a failing grade', () => {
  const { filename, code } = DEMO_CODE_SNIPPETS.vulnerable_api;
  const report = runSastCodeScan({ filename, code });

  assert.equal(report.targetType, 'SOURCE_CODE');
  assert.equal(report.target, filename);
  assert.ok(report.findings.length > 0, 'expected at least one finding');
  assert.ok(report.scorecard.criticalCount > 0, 'expected a critical finding');
  assert.equal(report.scorecard.grade, 'F');
  assert.equal(report.scorecard.totalFindings, report.findings.length);
});

test('detects a hardcoded AWS access key and reports its line', () => {
  const report = runSastCodeScan({
    filename: 'config.ts',
    code: 'const AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE";',
  });

  const hit = report.findings.find((f) => f.id.startsWith('SAST-SECRET-AWS-01'));
  assert.ok(hit, 'expected the AWS key rule to fire');
  assert.equal(hit.location?.line, 1);
  assert.equal(hit.severity, 'CRITICAL');
  assert.ok(hit.observedEvidence.startsWith('Line 1:'));
});

test('clean code produces no findings and an A+ grade', () => {
  const report = runSastCodeScan({
    filename: 'clean.ts',
    code: 'export const add = (a: number, b: number): number => a + b;\n',
  });

  assert.equal(report.findings.length, 0);
  assert.equal(report.scorecard.numericScore, 100);
  assert.equal(report.scorecard.grade, 'A+');
});

test('skips comment-only lines', () => {
  const report = runSastCodeScan({
    filename: 'commented.ts',
    code: '// const AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE";\n',
  });

  assert.equal(report.findings.length, 0);
});

test('handles empty input without throwing', () => {
  const report = runSastCodeScan({ code: '' });

  assert.equal(report.findings.length, 0);
  assert.equal(report.target, 'source-code-snippet.ts');
});
