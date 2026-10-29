const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const source = fs.readFileSync(path.join(__dirname, 'risk-utils.js'), 'utf8');
const context = vm.createContext({});
vm.runInContext(source, context);

test('new domain with a credential form becomes high risk', () => {
  const result = context.mergePageSignals(
    { classification: 'Suspicious', risk_score: 35, threat_types: ['new_or_unverified_domain'] },
    { has_credential_form: true, has_login_cue: true, brand_mismatches: [] },
  );
  assert.equal(result.classification, 'High Risk');
  assert.equal(result.risk_score, 70);
  assert.ok(result.threat_types.includes('credential_theft'));
});

test('brand mismatch with a sign-in cue produces a stronger warning', () => {
  const result = context.mergePageSignals(
    { classification: 'No Known Threat Detected', risk_score: 10, threat_types: [] },
    { has_credential_form: false, has_login_cue: true, brand_mismatches: ['Interbank'] },
  );
  assert.equal(result.classification, 'High Risk');
  assert.equal(result.risk_score, 90);
  assert.ok(result.threat_types.includes('brand_impersonation'));
});

test('page cues alone do not promote an unrelated page', () => {
  const original = { classification: 'No Known Threat Detected', risk_score: 5, threat_types: [] };
  const result = context.mergePageSignals(
    original,
    { has_credential_form: true, has_login_cue: true, brand_mismatches: [] },
  );
  assert.equal(result.classification, original.classification);
  assert.equal(result.risk_score, original.risk_score);
});

test('password form submitted to another hostname is elevated', () => {
  const result = context.mergePageSignals(
    { classification: 'No Known Threat Detected', risk_score: 5, threat_types: [] },
    { has_credential_form: true, has_external_credential_action: true, has_login_cue: false, brand_mismatches: [] },
  );
  assert.equal(result.classification, 'Suspicious');
  assert.equal(result.risk_score, 55);
  assert.ok(result.indicators.some((item) => item.includes('different hostname')));
});
