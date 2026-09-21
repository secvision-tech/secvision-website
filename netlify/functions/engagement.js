// #592: Engagement-model classifier — is this posting open to Corp-to-Corp (C2C) vendors?
// Pure regex, no LLM: runs at harvest (job-search.js / apify.js), on backfill (job-db.js) and is cheap
// enough to run on every save. Returns the verdict PLUS the phrase that decided it so the UI can show why.
//   model:      'C2C' | 'C2C-likely' | 'W2-contract' | 'Direct-hire' | 'Unknown'
//   offshoreOk: 'yes' | 'no' | 'unknown'
//   evidence:   short human-readable reason
var RX = {
  c2cExplicit: /\b(c2c|corp[\s-]*to[\s-]*corp|corp[\s-]*2[\s-]*corp|c2c\s*\/\s*w2|w2\s*\/\s*c2c|c2c\s*or\s*1099|1099\s*or\s*c2c|vendors?\s+(are\s+)?welcome|third[\s-]*party\s+vendors?\s+(are\s+)?(accepted|welcome|ok)|sub[\s-]*contract(or|ing)?|implementation\s+partner|prime\s+vendor|open\s+to\s+(all\s+)?vendors)\b/i,
  c2cExcluded: /\b(w2\s*only|w-2\s*only|no\s+c2c|no\s+corp[\s-]*to[\s-]*corp|no\s+third[\s-]*party|no\s+3rd[\s-]*party|no\s+(agencies|recruiters|vendors)|not\s+open\s+to\s+(c2c|vendors|third[\s-]*party)|direct\s+(hire|employment)\s+only|must\s+be\s+(a\s+)?(us|u\.s\.)\s+citizen|(active\s+)?(secret|top\s+secret|ts\/sci|dod)\s+clearance\s+(required|is\s+required))\b/i,
  c2cLikely: /\b(staff\s+augmentation|staff\s+aug|t\s*&\s*m|time\s+and\s+materials|all\s+visas?\s+(accepted|ok|welcome)|h[\s-]?1b|ead|gc\s*\/\s*usc|usc\s*\/\s*gc|opt\s*\/\s*cpt|hourly\s+rate|rate\s*[:\-]\s*\$?\d|\$\s?\d{2,3}\s*\/\s*(hr|hour)|duration\s*[:\-]|\d+\s*(\+)?\s*months?\s+(contract|extension)|extension\s+possible|contract\s+to\s+hire|c2h)\b/i,
  w2Contract: /\b(w2\s+contract|w-2\s+contract|contract\s+w2|on\s+our\s+w2|w2\s+hourly|benefits\s+eligible\s+contract)\b/i,
  directHire: /\b(direct\s+hire|permanent\s+(position|role|employee)|full[\s-]*time\s+employee|fte\b|salary\s*[:\-]|annual\s+salary|401\s*\(?k\)?|paid\s+time\s+off|\bpto\b|health\s+insurance|equity|stock\s+options|bonus\s+eligible)\b/i,
  offshoreYes: /\b(offshore|off-shore|nearshore|remote\s*[\-–:]\s*india|from\s+india|india[\s-]*based|work\s+from\s+india|global\s+remote|remote\s*[\-–:]\s*(anywhere|worldwide|global)|any\s+location|ist\s+(overlap|hours|shift)|overlap\s+with\s+(us|est|pst|edt|pdt)|us\s+hours\s+overlap|night\s+shift\s+ist)\b/i,
  offshoreNo: /\b(must\s+(be\s+)?(located|reside|residing|based)\s+in\s+(the\s+)?(us|u\.s\.|usa|united\s+states)|us[\s-]*based\s+only|remote\s*[\-–:(]\s*(us|usa|u\.s\.)\s*(only)?|anywhere\s+in\s+the\s+(us|usa|united\s+states)|no\s+offshore|onshore\s+only|work\s+authori[sz]ation\s+(in\s+the\s+)?(us|usa)\s+(required|is\s+required)|must\s+be\s+authori[sz]ed\s+to\s+work\s+in\s+the\s+(us|united\s+states)|(us|u\.s\.)\s+citizens?\s+(only|or\s+green\s+card))\b/i
};
function snippet(text, rx) { var m = text.match(rx); return m ? m[0].replace(/\s+/g, ' ').slice(0, 60) : ''; }
function classifyEngagement(job) {
  job = job || {};
  var text = [job.title, job.description, job.jobType, job.salary, job.eligibility, job.contractDuration].filter(Boolean).join(' \n ');
  var src = String(job.source || '').toLowerCase();
  var ctype = String(job.companyType || '');
  var model = 'Unknown', evidence = '', s;
  if ((s = snippet(text, RX.c2cExcluded))) { model = RX.directHire.test(text) && !/contract/i.test(job.jobType || '') ? 'Direct-hire' : 'W2-contract'; evidence = 'excludes vendors: "' + s + '"'; }
  else if ((s = snippet(text, RX.c2cExplicit))) { model = 'C2C'; evidence = '"' + s + '"'; }
  else if ((s = snippet(text, RX.w2Contract))) { model = 'W2-contract'; evidence = '"' + s + '"'; }
  else if ((s = snippet(text, RX.c2cLikely))) { model = 'C2C-likely'; evidence = '"' + s + '"'; }
  else if (/techfetch|dice|c2c|hotlist/.test(src)) { model = 'C2C-likely'; evidence = 'source: ' + (job.source || ''); }
  else if (/Staffing|Recruiting|IT Consulting/.test(ctype) && /contract/i.test(job.jobType || '')) { model = 'C2C-likely'; evidence = 'contract role posted by ' + ctype + ' firm'; }
  else if ((s = snippet(text, RX.directHire)) && !/contract/i.test(job.jobType || '')) { model = 'Direct-hire'; evidence = '"' + s + '"'; }
  var offshoreOk = 'unknown', oe = '';
  if ((s = snippet(text, RX.offshoreNo))) { offshoreOk = 'no'; oe = '"' + s + '"'; }
  else if ((s = snippet(text, RX.offshoreYes))) { offshoreOk = 'yes'; oe = '"' + s + '"'; }
  else if (/india/i.test(job.detectedCountry || '') || /india/i.test(job.location || '')) { offshoreOk = 'yes'; oe = 'India-located posting'; }
  return { model: model, offshoreOk: offshoreOk, evidence: evidence + (oe ? (evidence ? ' · ' : '') + 'offshore ' + offshoreOk + ': ' + oe : '') };
}
module.exports = { classifyEngagement: classifyEngagement };
