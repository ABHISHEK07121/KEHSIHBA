const PRIMARY_COLOR = [125, 31, 50];

function clean(value) {
  if (value === null || value === undefined || value === '') return 'Not available';
  return String(value).replace(/\s+/g, ' ').trim();
}

function reportSections(result, reportType) {
  const isEmail = reportType === 'email';
  const analysisType = { email: 'Email', url: 'URL' }[reportType] || 'Scan';
  const sections = [{
    title: 'Executive summary',
    rows: [
      `Classification: ${result.classification || result.status || 'Unknown'}`,
      `Risk score: ${clean(result.risk_score)}/100`,
      `Analysis type: ${analysisType}`,
      `Generated: ${new Date().toLocaleString()}`,
      `Recommendation: ${clean(result.recommendation)}`,
      `Explanation: ${clean(result.explanation)}`,
    ],
  }];

  if (isEmail) {
    sections.push({
      title: 'Email details',
      rows: [
        `From: ${clean(result.headers?.from)}`,
        `Subject: ${clean(result.headers?.subject)}`,
        `Model probability (estimated phishing likelihood, not a definitive verdict): ${result.model_score == null ? clean(result.model_note) : `${result.model_score}%`}`,
        `Spam score: ${clean(result.spam_score)}/100`,
        `Scam score: ${clean(result.scam_score)}/100`,
        `Threat types: ${(result.threat_types || []).join(', ') || 'None reported'}`,
      ],
    });
    sections.push({
      title: 'Embedded URLs',
      rows: (result.embedded_url_results || []).map((item) => (
        `${item.classification || 'Unknown'} - ${item.url || 'URL unavailable'} - risk ${clean(item.risk_score)}/100. ${item.reputation_status || ''}`
      )),
    });
    sections.push({
      title: 'Extracted URLs',
      rows: result.extracted_urls?.length ? result.extracted_urls : ['No URLs were extracted.'],
    });
  } else {
    sections.push({
      title: 'URL details',
      rows: [
        `Submitted URL: ${clean(result.submitted_url || result.url)}`,
        `Normalized URL: ${clean(result.normalized_url || result.url)}`,
        `Hostname: ${clean(result.hostname)}`,
        `Category: ${clean(result.category)}`,
        `Risk level: ${clean(result.risk_level)}`,
        `Confidence: ${result.confidence == null ? 'Not calculated' : clean(result.confidence)}`,
        ...Object.entries(result.url_components || {}).map(([key, value]) => `URL component ${key}: ${clean(value)}`),
        `Local model output (uncalibrated score, not a probability): ${typeof result.model_probability === 'number' ? `${(result.model_probability * 100).toFixed(1)}/100` : clean(result.model_note)}`,
        `Threat feeds: ${(result.intelligence_sources || []).join(', ') || 'No match reported'}`,
        `Google Safe Browsing: ${clean(result.google_safe_browsing?.status)} — ${clean(result.google_safe_browsing?.message)}`,
        `Google threat types: ${(result.google_safe_browsing?.threat_types || []).join(', ') || 'None reported'}`,
        `Google Safe Browsing checked at: ${clean(result.google_safe_browsing?.checked_at)}`,
        `VirusTotal checked at: ${clean(result.virustotal?.checked_at)}`,
        `VirusTotal flagged engines: ${(result.virustotal?.vendor_results || []).map((item) => `${item.engine}: ${item.category}${item.result ? ` (${item.result})` : ''}`).join('; ') || 'No flagged engine details returned'}`,
        `Reputation status: ${clean(result.reputation_status)}`,
        `Analysis time: ${result.scan_timestamp ? new Date(result.scan_timestamp).toLocaleString() : 'Not available'}`,
      ],
    });
    sections.push({
      title: 'Analysis check statuses',
      rows: Object.entries(result.checks || {}).map(([name, status]) => `${name}: ${status}`),
    });
    sections.push({
      title: 'Limitations',
      rows: result.limitations?.length ? result.limitations : ['No additional limitations reported.'],
    });
    if (result.redirect_chain?.length) {
      sections.push({
        title: 'Redirect chain',
        rows: [
          `Final destination: ${clean(result.final_url)}`,
          ...result.redirect_chain.map((hop, index) => `Hop ${index + 1}: ${hop.status_code || 'Unknown status'} — ${hop.url}${hop.location ? ` → ${hop.location}` : ''}`),
        ],
      });
    }
    const domain = result.domain_intelligence || {};
    const dns = domain.dns || {};
    const rdap = domain.rdap || {};
    const ssl = domain.ssl || {};
    const geo = domain.ip_geolocation || {};
    const geoResults = geo.results || [];
    const addresses = domain.public_addresses || [...(dns.records?.A || []), ...(dns.records?.AAAA || [])];
    sections.push({
      title: 'Domain and network details (plain-language summary)',
      rows: [
        `Page hostname: ${clean(result.hostname || domain.hostname)}`,
        `Registered domain: ${clean(domain.registered_domain)}`,
        `Public IP address(es): ${addresses.join(', ') || 'No public address resolved'}`,
        `Network owner / ASN: ${geoResults.map((item) => [item.organization || item.isp, item.asn ? `AS${item.asn}` : null].filter(Boolean).join(' · ')).filter(Boolean).join(' | ') || 'Not reported'}`,
        `Approximate server region: ${geoResults.map((item) => [item.city, item.region, item.country].filter(Boolean).join(', ')).filter(Boolean).join(' | ') || 'Not available'}`,
        `Domain registration age: ${Number.isInteger(rdap.domain_age_days) ? `${rdap.domain_age_days} days` : 'Unavailable'}`,
        `TLS/HTTPS certificate: ${ssl.checked ? (ssl.valid ? `Valid through ${clean(ssl.not_after)}` : 'Invalid or expired') : 'Unavailable'}`,
        clean(geo.note || 'IP location is approximate and may identify a hosting provider, VPN, proxy, or CDN rather than a person.'),
        'An ASN identifies the network operator announcing an IP range; it does not necessarily identify the website owner. Multiple IPs may be normal for load balancing or a CDN.',
      ],
    });
    const records = dns.records || {};
    sections.push({
      title: 'Technical network details',
      rows: [
        `Hostname: ${clean(result.hostname || domain.hostname)}`,
        `Registered domain: ${clean(domain.registered_domain)}`,
        ...['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT'].map((type) => `DNS ${type}: ${(records[type] || []).join(', ') || 'No records returned'}`),
        `DNS status: ${clean(dns.status)}`,
        ...geoResults.map((item) => `IP ${item.ip}: ${[item.organization, item.isp, item.asn ? `AS${item.asn}` : null, item.city, item.region, item.country].filter(Boolean).join(' · ') || 'No network details reported'}`),
        `TLS certificate issuer: ${clean(ssl.issuer)}`,
        `TLS validity: ${clean(ssl.not_before)} to ${clean(ssl.not_after)}`,
        `Domain registered: ${clean(rdap.created_at)}`,
        `Registrar: ${clean(rdap.registrar)}`,
        `RDAP status: ${rdap.checked ? 'Checked' : 'Unavailable'}`,
      ],
    });
  }

  const findings = [...(result.reasons || []), ...(result.indicators || [])]
    .filter((item, index, items) => items.indexOf(item) === index);
  sections.push({
    title: 'Findings and limitations',
    rows: [
      ...findings.map((item) => `Finding: ${item}`),
      ...(result.warnings || []).map((item) => `Limitation: ${item}`),
      ...(result.domain_intelligence?.warnings || []).map((item) => `Limitation: ${item}`),
      ...(result.domain_intelligence?.checks || []).map((item) => `Website check (${item.severity || 'unknown'}): ${item.message}`),
      ...(!findings.length ? ['No findings were reported by the analysis response.'] : []),
    ],
  });
  return sections;
}

export async function createScanReportPdf(result, reportType) {
  const { jsPDF } = await import('jspdf');
  const document = new jsPDF({ unit: 'pt', format: 'a4' });
  const margin = 46;
  const pageHeight = document.internal.pageSize.getHeight();
  const contentWidth = document.internal.pageSize.getWidth() - margin * 2;
  let y = 82;

  document.setFillColor(...PRIMARY_COLOR);
  document.rect(0, 0, document.internal.pageSize.getWidth(), 58, 'F');
  document.setTextColor(255, 255, 255);
  document.setFont('helvetica', 'bold');
  document.setFontSize(16);
  document.text('KESHIHBA Security Analysis Report', margin, 37);
  document.setTextColor(35, 35, 35);
  document.setFont('helvetica', 'normal');
  document.setFontSize(10);

  const addParagraph = (text, indent = 0) => {
    const lines = document.splitTextToSize(clean(text), contentWidth - indent);
    const lineHeight = 14;
    if (y + lines.length * lineHeight > pageHeight - margin) {
      document.addPage();
      y = margin;
    }
    document.text(lines, margin + indent, y);
    y += lines.length * lineHeight + 4;
  };

  for (const section of reportSections(result, reportType)) {
    if (!section.rows.length) continue;
    if (y + 34 > pageHeight - margin) {
      document.addPage();
      y = margin;
    }
    document.setTextColor(...PRIMARY_COLOR);
    document.setFont('helvetica', 'bold');
    document.setFontSize(12);
    document.text(section.title, margin, y);
    y += 18;
    document.setTextColor(35, 35, 35);
    document.setFont('helvetica', 'normal');
    document.setFontSize(10);
    for (const row of section.rows) addParagraph(row, 8);
    y += 7;
  }

  document.setTextColor(105, 100, 96);
  document.setFontSize(8);
  document.text(
    'Triage report only. A low-risk or unknown result is not proof that a message or URL is safe.',
    margin,
    pageHeight - 24,
  );
  return document;
}

function base64FromBytes(bytes) {
  let binary = '';
  const chunkSize = 0x8000;
  for (let index = 0; index < bytes.length; index += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(index, index + chunkSize));
  }
  return btoa(binary);
}

export function scanReportPdfBase64(pdf) {
  return base64FromBytes(new Uint8Array(pdf.output('arraybuffer')));
}
