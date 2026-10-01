// #592: Engagement-model classifier — is this posting open to Corp-to-Corp (C2C) vendors?
// Pure regex, no LLM: runs at harvest (job-search.js / apify.js), on backfill (job-db.js) and is cheap
// enough to run on every save. Returns the verdict PLUS the phrase that decided it so the UI can show why.
//   model:      'C2C' | 'C2C-likely' | 'W2-contract' | 'Direct-hire' | 'Unknown'
//   offshoreOk: 'yes' | 'no' | 'unknown'
//   evidence:   short human-readable reason
var RX = {
  c2cExplicit: /\b(c2c|corp[\s-]*to[\s-]*corp|corp[\s-]*2[\s-]*corp|c2c\s*\/\s*w2|w2\s*\/\s*c2c|c2c\s*or\s*1099|1099\s*or\s*c2c|vendors?\s+(are\s+)?welcome|third[\s-]*party\s+vendors?\s+(are\s+)?(accepted|welcome|ok)|sub[\s-]*contract(or|ing)?s?\s+(are\s+)?(welcome|accepted|ok|allowed)|implementation\s+partner|prime\s+vendor|open\s+to\s+(all\s+)?vendors)\b/i,
  // #596: negations in any phrasing — "cannot subcontract or C2C", "not open to C2C", "C2C not accepted", "W2 only"
  c2cExcluded: /\b(w[\s-]?2\s*only|(no|not|non|cannot|can't|can\s+not|unable\s+to|not\s+able\s+to|without|excluding|excludes?|isn't|is\s+not|are\s+not|aren't|won't|will\s+not|do\s+not|don't|does\s+not|doesn't)\s+(\w+\s+){0,4}(c2c|corp[\s-]*to[\s-]*corp|corp[\s-]*2[\s-]*corp|sub[\s-]*contract\w*|third[\s-]*part(y|ies)|3rd[\s-]*part(y|ies)|vendors?|agencies|recruiters|1099)|(c2c|corp[\s-]*to[\s-]*corp|sub[\s-]*contract\w*|third[\s-]*party|vendors?)\s+(is|are|will\s+be|were)?\s*(not|never)\s+(accepted|allowed|permitted|considered|entertained|possible|available|an\s+option)|direct\s+(hire|employment)\s+only|must\s+be\s+(a\s+)?(us|u\.s\.)\s+citizen|(active\s+)?(secret|top\s+secret|ts\/sci|dod)\s+clearance\s+(required|is\s+required))\b/i,
  c2cLikely: /\b(staff\s+augmentation|staff\s+aug|t\s*&\s*m|time\s+and\s+materials|all\s+visas?\s+(accepted|ok|welcome)|h[\s-]?1b|ead|gc\s*\/\s*usc|usc\s*\/\s*gc|opt\s*\/\s*cpt|hourly\s+rate|rate\s*[:\-]\s*\$?\d|\$\s?\d{2,3}\s*\/\s*(hr|hour)|duration\s*[:\-]|\d+\s*(\+)?\s*months?\s+(contract|extension)|extension\s+possible|contract\s+to\s+hire|c2h)\b/i,
  w2Contract: /\b(contract[\s-]*to[\s-]*hire|c2h|cth\b|temp[\s-]*to[\s-]*(perm|hire)|w[\s-]?2\b(?![\s\/]*(\/|or|and)\s*(c2c|1099))|w2\s+contract|w-2\s+contract|contract\s+w2|on\s+our\s+w2|w2\s+hourly|benefits\s+eligible\s+contract)\b/i,
  directHire: /\b(direct\s+hire|permanent\s+(position|role|employee)|full[\s-]*time\s+employee|fte\b|salary\s*[:\-]|annual\s+salary|401\s*\(?k\)?|paid\s+time\s+off|\bpto\b|health\s+insurance|equity|stock\s+options|bonus\s+eligible)\b/i,
  offshoreYes: /\b(offshore|off-shore|nearshore|remote\s*[\-–:]\s*india|from\s+india|india[\s-]*based|work\s+from\s+india|global\s+remote|remote\s*[\-–:]\s*(anywhere|worldwide|global)|any\s+location|ist\s+(overlap|hours|shift)|overlap\s+with\s+(us|est|pst|edt|pdt)|us\s+hours\s+overlap|night\s+shift\s+ist)\b/i,
  // #622/#623: US clearance / federal- or state-program signals (CJIS, background checks, nationwide) ⇒ US-person work, never offshoreable
  clearance: /\b(public\s+trust|(secret|top\s+secret|ts\/sci|dod|dhs|doe|government|security|federal)\s+clearance|clearance\s*[:\-]\s*[a-z]|(active|current|interim)\s+clearance|(obtain|hold|maintain)\s+(and\s+maintain\s+)?(a\s+|an\s+)?(\w+\s+){0,2}clearance|clearance\s+(is\s+)?required|federal\s+(program|contract|client|agency|cybersecurity|government)|fedramp|fisma|nist\s+800-53|u\.?s\.?\s+person(s)?\s+only|must\s+be\s+(a\s+)?u\.?s\.?\s+person|cjis|open\s+to\s+candidates\s+nationwide|nationwide\s+(candidates|remote)|state\s+of\s+[A-Z][a-z]+(\s+[A-Z][a-z]+)?\b|state\s+(agency|agencies|government)|(criminal|credit)\s+(and\s+(criminal|credit)\s+)?background\s+checks?|fingerprint)\b/i,
  // #622: an annual salary band ($70,000 - $90,000 / $70K-$90K / 70k-90k per year) with no hourly rate ⇒ salaried hire
  annualSalary: /(\$\s?\d{2,3},\d{3}(\.\d\d)?\s*(-|–|to)\s*\$?\s?\d{2,3},\d{3}(\.\d\d)?|\$\s?\d{2,3}\s?k\s*(-|–|to)\s*\$?\s?\d{2,3}\s?k\b|\d{2,3}k\s*(-|–|to)\s*\d{2,3}k\s*(per\s+)?(year|annum|yr|annually)|(per\s+year|per\s+annum|\/\s?(year|yr|annum)|annually))/i,
  hourly: /(\$\s?\d{2,3}(\.\d\d)?\s*(-|–|to)?\s*\$?\s?\d{0,3}\s*\/\s*(hr|hour)|per\s+hour|hourly)/i,
  // #635: presence requirements — local-only, hybrid, N days on-site — are never offshoreable
  presence: /\b(must\s+be\s+(a\s+)?local|local\s+(candidates?|resources?|consultants?)\s+only|locals?\s+only|candidates?\s+must\s+be\s+local|hybrid|\d+\s*(-|to)?\s*\d*\s*days?\s+(a|per)\s+(week|month)\s+(on-?site|in\s+(the\s+)?office)|on-?site\s+(\d+|one|two|three|four)\s+days?|(fully|100%)\s+on-?site|on-?site\s+only|in[\s-]office\s+(role|position|required))\b/i,
  // #635: company boilerplate that mentions offshore as a SERVICE LINE, not as a term of this job — stripped before offshoreYes runs
  offshoreBoilerplate: /\b(provider|providers|leader|leaders|specialist|specialists|company|firm)\s+(of|in)\s+[^.\n]{0,80}\b(offshore|nearshore|near\s*shore)\b[^.\n]*|\b(offshore|off-shore)(\s*,\s*|\s+and\s+|\s*\/\s*|\s+or\s+)(onshore|on-shore|nearshore|near\s*shore)\b[^.\n]*|\b(onshore|nearshore|near\s*shore)(\s*,\s*|\s+and\s+|\s*\/\s*|\s+or\s+)(offshore|off-shore)\b[^.\n]*|\b(offshore|nearshore)\s+(outsourcing|services|delivery|development\s+cent(er|re)s?|teams?|model|capabilit(y|ies))\b/gi,
  offshoreNo: /\b(visa[\s-]*independent|(usc|us\s+citizens?|green\s+card|gc)\s*(\/|or|and)?\s*(gc|green\s+card|usc|us\s+citizens?)?\s+only|no\s+(visa\s+)?sponsorship|(cannot|can't|unable\s+to|will\s+not|won't|do\s+not|does\s+not)\s+(provide\s+|offer\s+)?sponsor(ship)?|must\s+(be\s+)?(located|reside|residing|based)\s+in\s+(the\s+)?(us|u\.s\.|usa|united\s+states)|us[\s-]*based\s+only|remote\s*[\-–:(]\s*(us|usa|u\.s\.)\s*(only)?|anywhere\s+in\s+the\s+(us|usa|united\s+states)|no\s+offshore|onshore\s+only|work\s+authori[sz]ation\s+(in\s+the\s+)?(us|usa)\s+(required|is\s+required)|must\s+be\s+authori[sz]ed\s+to\s+work\s+in\s+the\s+(us|united\s+states)|(us|u\.s\.)\s+citizens?\s+(only|or\s+green\s+card))\b/i
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
  else if ((s = snippet(text, RX.annualSalary)) && !RX.hourly.test(text)) { model = 'Direct-hire'; evidence = 'annual salary: "' + s + '"'; }
  else if (/techfetch|dice|c2c|hotlist/.test(src)) { model = 'C2C-likely'; evidence = 'source: ' + (job.source || ''); }
  else if (/Staffing|Recruiting|Consulting/i.test(ctype) && /contract/i.test(job.jobType || '')) { model = 'C2C-likely'; evidence = 'contract role posted by ' + ctype + ' firm'; }
  else if ((s = snippet(text, RX.directHire)) && !/contract/i.test(job.jobType || '')) { model = 'Direct-hire'; evidence = '"' + s + '"'; }
  var offshoreOk = 'unknown', oe = '';
  var inIndia = /india/i.test(job.detectedCountry || '') || /india/i.test(job.location || '');
  if (!inIndia && (s = snippet(text, RX.clearance))) { offshoreOk = 'no'; oe = 'clearance/govt: "' + s + '"'; }
  else if (!inIndia && (s = snippet(text, RX.presence))) { offshoreOk = 'no'; oe = 'presence required: "' + s + '"'; }
  else if ((s = snippet(text, RX.offshoreNo))) { offshoreOk = 'no'; oe = '"' + s + '"'; }
  else if ((s = snippet(text.replace(RX.offshoreBoilerplate, ' '), RX.offshoreYes))) { offshoreOk = 'yes'; oe = '"' + s + '"'; }
  else if (/india/i.test(job.detectedCountry || '') || /india/i.test(job.location || '')) { offshoreOk = 'yes'; oe = 'India-located posting'; }
  return { model: model, offshoreOk: offshoreOk, evidence: evidence + (oe ? (evidence ? ' · ' : '') + 'offshore ' + offshoreOk + ': ' + oe : '') };
}
// #616: many JDs carry the real city in the body ("Locations: Louisville", "Location: Plano, TX") while the
// job-board location field only says the country. Returns the city string or ''.
function extractJdLocation(desc) {
  var t = String(desc || '').slice(0, 4000);
  var lines = t.split(/\r?\n|\s*\|\s*|\s·\s/);
  for (var i = 0; i < lines.length; i++) {
    var m = lines[i].match(/^\s*(?:job\s+|work\s+)?locations?\s*[:\-–]\s*(.+)$/i);
    if (!m) continue;
    var loc = m[1].replace(/\(.*?\)/g, ' ').replace(/\b(hybrid|onsite|on-site|remote|100%|only|preferred)\b/gi, ' ').replace(/\s+/g, ' ').trim().replace(/[.,;\s]+$/, '');
    if (!loc || /^(anywhere|usa|us|u\.s\.|united states|india|multiple|various|tbd|n\/a)$/i.test(loc)) continue;
    if (loc.length > 60) loc = loc.slice(0, 60);
    return loc;
  }
  return '';
}
function isBareLocation(loc) { return !String(loc || '').trim() || /^(remote|hybrid|anywhere|usa|us|u\.s\.|united states|united states of america|india|uk|united kingdom|canada|worldwide|global|n\/a)$/i.test(String(loc).trim()); }
module.exports = { classifyEngagement: classifyEngagement, extractJdLocation: extractJdLocation, isBareLocation: isBareLocation };
