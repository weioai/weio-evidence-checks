// One row per checked address. Flags anything a visitor would notice, or a certificate ending within WARN_DAYS.
const WARN_DAYS = 21;
const out = [];
for (const item of $input.all()) {
  const r = item.json;
  if (!r || r.ok !== true || !Array.isArray(r.results)) {
    out.push({ json: { domain: r && r.domain || '(unknown)', host: '', status: 'CHECK FAILED', detail: (r && r.error) || 'no result' } });
    continue;
  }
  for (const a of r.results) {
    const daysLeft = typeof a.expired_days === 'number' ? -a.expired_days : null;
    const problems = [];
    if (a.visible === 'interstitial') problems.push('visitors see a full-page privacy warning');
    if (a.visible === 'not_secure') problems.push('browser shows Not secure');
    if (daysLeft !== null && daysLeft <= WARN_DAYS) problems.push(daysLeft < 0 ? 'certificate expired' : `certificate ends in ${daysLeft} days`);
    out.push({ json: {
      domain: r.domain, host: a.host, status: problems.length ? 'ACTION NEEDED' : 'OK',
      problems: problems.join('; '), cause: a.cause, browser: a.visible,
      certificate_valid_until: a.not_after || '', days_left: daysLeft, explanation: a.plain || '',
    } });
  }
}
out.sort((x, y) => (x.json.status === 'OK') - (y.json.status === 'OK'));
return out;
