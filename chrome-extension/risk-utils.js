function mergePageSignals(result, signals) {
  if (!signals) return result;
  const brands = Array.isArray(signals.brand_mismatches) ? signals.brand_mismatches : [];
  const mismatch = brands.length > 0 && signals.has_credential_form;
  const externalCredentialAction = Boolean(signals.has_credential_form && signals.has_external_credential_action);
  const newDomainLogin = Boolean(signals.has_credential_form && signals.has_login_cue
    && (result.threat_types || []).includes('new_or_unverified_domain'));
  if (!mismatch && !externalCredentialAction && !newDomainLogin) return result;

  const reason = mismatch
    ? `Page content appears to show ${brands.join(', ')} branding with a sign-in or credential form, but the hostname is not an official brand domain.`
    : externalCredentialAction
      ? 'The page submits a password form to a different hostname. Verify the destination before entering credentials.'
    : 'A new or unverified domain presents a sign-in or credential form. Verify the organization through an independent channel before entering credentials.';
  const indicators = [...new Set([...(result.indicators || []), reason])];
  const reasons = [...new Set([...(result.reasons || []), reason])];
  const threatTypes = [...new Set([...(result.threat_types || []), ...(mismatch ? ['brand_impersonation'] : []), 'credential_theft'])];
  return {
    ...result,
    classification: mismatch || newDomainLogin ? 'High Risk' : 'Suspicious',
    status: mismatch || newDomainLogin ? 'High Risk' : 'Suspicious',
    risk_level: mismatch || newDomainLogin ? 'high' : 'suspicious',
    risk_score: Math.max(Number(result.risk_score) || 0, mismatch ? 90 : newDomainLogin ? 70 : 55),
    indicators,
    reasons,
    threat_types: threatTypes,
    extension_page_signals: signals,
  };
}
