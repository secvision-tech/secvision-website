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

// ---------------------------------------------------------------------------
// #636: AI classification — one Haiku call per job, strict JSON out. The regex classifier above stays as the
// instant placeholder at harvest and as the fallback when the API is unavailable; this is the authority.
// Requirement paragraphs outrank company boilerplate ("global provider of offshore outsourcing" is not a
// term of the job). offshoreOk is DERIVED here from workMode/locality/workAuth/clearance so fields never
// contradict each other.
// ---------------------------------------------------------------------------
var AI_MODEL = 'claude-haiku-4-5-20251001';
var AI_PROMPT = [
  'You classify a job posting for a staffing agency that supplies India-based remote cybersecurity consultants to US/EU clients.',
  'Read the posting and return ONLY a JSON object (no prose, no code fence) with exactly these keys:',
  '{',
  '  "engagementModel": "C2C" | "C2C-likely" | "W2-contract" | "Direct-hire" | "Expert-gig" | "Unknown",',
  '  "workMode": "remote" | "hybrid" | "onsite" | "unknown",',
  '  "locality": "none" | "must-be-local" | "state-residents" | "nationwide-US" | "country-only",',
  '  "workAuth": "none" | "usc-only" | "usc-gc" | "no-sponsorship" | "visa-independent" | "any-visa",',
  '  "clearance": "none" | "public-trust" | "secret" | "ts-sci" | "cjis" | "other",',
  '  "payType": "hourly" | "annual" | "per-task" | "none",',
  '  "offshoreStated": "yes" | "no" | "unstated",',
  '  "jdCity": "<city, state/country named as the work location in the body, or empty>",',
  '  "confidence": <0.0-1.0>,',
  '  "evidence": ["<verbatim quote>", "<verbatim quote>", "<verbatim quote>"]',
  '}',
  'Rules:',
  '- Only the REQUIREMENTS of this job count. Ignore "About the company" boilerplate: a firm that "provides offshore/nearshore outsourcing" says nothing about whether THIS seat can be offshore.',
  '- engagementModel: "C2C" when corp-to-corp / vendors / subcontractors / all visas are explicitly welcome; "W2-contract" ONLY when the text itself says W2 / W-2 only, contract-to-hire, CTH, temp-to-perm, or explicitly refuses subcontracting or C2C; "Direct-hire" for permanent or salaried employment (annual salary band, benefits, 401k, PTO) even if the board tags it "Contract"; "Expert-gig" for AI-training / data-labelling / expert-grading platforms paid per task or hour to individuals; "C2C-likely" for a contract role from a staffing or consulting firm with hourly rate or duration but no explicit vendor language; otherwise "Unknown".',
  '- Never infer engagement terms from the company name or its reputation (e.g. "large staffing firms usually use W2"). If no sentence states the terms, answer "Unknown". "Unknown" is a correct and expected answer.',
  '- workMode: "hybrid" if any days on-site are required; "onsite" ONLY if the text says on-site / in-office / in-person / at the client location is required; "remote" only if the role is fully remote. A city or address alone, with no statement about remote or on-site, is "unknown".',
  '- locality: "must-be-local" for "candidate must be local" / "locals only"; "state-residents" for residency in a named state; "nationwide-US" for "anywhere in the US" / "open to candidates nationwide" / "remote - US"; "country-only" when the posting restricts to a named country other than the US; else "none".',
  '- clearance: any government clearance, Public Trust, CJIS, or "must be able to obtain a clearance" counts. State or federal program work with background checks beyond a routine check -> "other".',
  '- payType: "annual" when a yearly salary figure is given (e.g. $90,000 - $120,000, $85K/yr, per annum); "hourly" for $/hr; "per-task" for per-task/per-item payment.',
  '- offshoreStated: "yes" only if the REQUIREMENT says offshore / nearshore / India-based / global remote / any location is acceptable; "no" if it says US-based only, must reside in the US, no offshore, onshore only; else "unstated".',
  '- evidence: up to 3 short verbatim quotes (under 100 characters each), one for each decisive field. Prefer the sentence that decided workMode/locality/clearance. Inside a quote, replace any double-quote character with a single quote so the JSON stays valid.',
  '- If the posting is in India (location in India), answer the same fields literally; do not reason about offshoring.',
  'Posting follows.'
].join('\n');

function deriveOffshore(c, job) {
  var inIndia = /india/i.test(String((job && job.detectedCountry) || '') + ' ' + String((job && job.location) || ''));
  if (inIndia) return { offshoreOk: 'yes', why: 'India-located posting' };
  if (c.clearance && c.clearance !== 'none') return { offshoreOk: 'no', why: 'clearance: ' + c.clearance };
  if (c.workMode === 'onsite' || c.workMode === 'hybrid') return { offshoreOk: 'no', why: 'work mode: ' + c.workMode };
  if (c.locality === 'must-be-local' || c.locality === 'state-residents' || c.locality === 'nationwide-US' || c.locality === 'country-only') return { offshoreOk: 'no', why: 'locality: ' + c.locality };
  if (c.workAuth === 'usc-only' || c.workAuth === 'usc-gc' || c.workAuth === 'visa-independent') return { offshoreOk: 'no', why: 'work authorization: ' + c.workAuth };
  if (c.offshoreStated === 'no') return { offshoreOk: 'no', why: 'posting says US/onshore only' };
  if (c.payType === 'annual' && c.engagementModel === 'Direct-hire') return { offshoreOk: 'no', why: 'salaried employee hire' };
  if (c.offshoreStated === 'yes') return { offshoreOk: 'yes', why: 'posting accepts offshore' };
  if (c.workAuth === 'any-visa') return { offshoreOk: 'yes', why: 'all visas accepted' };
  return { offshoreOk: 'unknown', why: '' };
}

// #636c: JSON.parse first; if the model's verbatim quotes broke the JSON (unescaped double quotes are the usual
// culprit), recover the scalar fields one by one and the evidence strings loosely instead of failing the job.
function parseLoose(src) {
  try { return JSON.parse(src); } catch (e) {}
  var c = {};
  ['engagementModel', 'workMode', 'locality', 'workAuth', 'clearance', 'payType', 'offshoreStated', 'jdCity'].forEach(function (k) {
    var mm = src.match(new RegExp('"' + k + '"\\s*:\\s*"([^"\\n]*)"')); if (mm) c[k] = mm[1];
  });
  var cf = src.match(/"confidence"\s*:\s*([0-9.]+)/); if (cf) c.confidence = parseFloat(cf[1]);
  var ev = src.match(/"evidence"\s*:\s*\[([\s\S]*?)\]\s*\}?\s*$/);
  if (ev) {
    // split on `", "` boundaries rather than every quote, so an inner quote doesn't fragment a sentence
    c.evidence = ev[1].split(/"\s*,\s*"/).map(function (q) { return q.replace(/^\s*"/, '').replace(/"\s*$/, '').trim(); }).filter(Boolean).slice(0, 3);
  }
  if (!c.engagementModel) throw new Error('unrecoverable JSON');
  return c;
}
// Returns {model, offshoreOk, evidence, ai:{...}} or null when the API is not configured / fails.
async function classifyEngagementAI(job, opts) {
  opts = opts || {};
  var key = opts.apiKey || process.env.ANTHROPIC_API_KEY;
  if (!key) return null;
  var desc = String(job.description || '').replace(/<[^>]+>/g, ' ').replace(/\s{2,}/g, ' ').trim().slice(0, 9000);
  if (!desc && !job.title) return null;
  var header = [
    'Title: ' + (job.title || ''), 'Company: ' + (job.company || ''), 'Company type: ' + (job.companyType || ''),
    'Board location: ' + (job.location || ''), 'Country: ' + (job.detectedCountry || ''), 'Board job type: ' + (job.jobType || ''),
    'Board remote flag: ' + (job.remote || job.workType || ''), 'Salary/rate field: ' + (job.salary || ''), 'Duration field: ' + (job.contractDuration || ''),
    'Source: ' + (job.source || '')
  ].join('\n');
  var body = JSON.stringify({ model: AI_MODEL, max_tokens: 700, temperature: 0, system: AI_PROMPT,
    messages: [{ role: 'user', content: header + '\n\n---\n' + desc }] });
  // #636b: retry on rate-limit / overload / timeout with backoff (429, 529, 5xx, abort)
  var attempts = opts.attempts || 3, lastErr = null, data = null;
  for (var at = 0; at < attempts && !data; at++) {
    var ctrl = new AbortController();
    var tmo = setTimeout(function () { ctrl.abort(); }, opts.timeoutMs || 15000);
    try {
      var resp = await fetch('https://api.anthropic.com/v1/messages', {
        method: 'POST', signal: ctrl.signal,
        headers: { 'Content-Type': 'application/json', 'x-api-key': key, 'anthropic-version': '2023-06-01' },
        body: body
      });
      if (!resp.ok) {
        var et = ''; try { et = (await resp.text()).slice(0, 160); } catch (e) {}
        lastErr = 'HTTP ' + resp.status + (et ? ' ' + et : '');
        if (resp.status === 429 || resp.status === 529 || resp.status >= 500) { await new Promise(function (r) { setTimeout(r, 1200 * (at + 1) + Math.random() * 600); }); continue; }
        break;   // 400/401/403: retrying won't help
      }
      data = await resp.json();
    } catch (e) {
      lastErr = (e && e.name === 'AbortError') ? 'timeout' : String(e && e.message || e);
      await new Promise(function (r) { setTimeout(r, 800 * (at + 1)); });
    } finally { clearTimeout(tmo); }
  }
  if (!data) { if (opts.errors) opts.errors.push(lastErr || 'unknown'); return null; }
  try {
    var txt = (data.content || []).filter(function (b) { return b.type === 'text'; }).map(function (b) { return b.text; }).join('').trim();
    txt = txt.replace(/^```(?:json)?\s*/i, '').replace(/```\s*$/, '').trim();
    var m = txt.match(/\{[\s\S]*\}/); if (!m) throw new Error('no JSON');
    var c = parseLoose(m[0]);
    var MODELS = ['C2C', 'C2C-likely', 'W2-contract', 'Direct-hire', 'Expert-gig', 'Unknown'];
    if (MODELS.indexOf(c.engagementModel) < 0) c.engagementModel = 'Unknown';
    var d = deriveOffshore(c, job);
    var ev = (Array.isArray(c.evidence) ? c.evidence : []).filter(Boolean).map(function (q) { return '"' + String(q).replace(/\s+/g, ' ').slice(0, 90) + '"'; }).join(' · ');
    var tags = [c.workMode && c.workMode !== 'unknown' ? c.workMode : '', c.locality && c.locality !== 'none' ? c.locality : '', c.clearance && c.clearance !== 'none' ? 'clearance:' + c.clearance : '', c.workAuth && c.workAuth !== 'none' ? c.workAuth : '', c.payType && c.payType !== 'none' ? c.payType : ''].filter(Boolean).join(', ');
    return {
      model: c.engagementModel, offshoreOk: d.offshoreOk,
      evidence: 'AI: ' + (tags || 'no restrictions found') + (d.why ? ' · offshore ' + d.offshoreOk + ' (' + d.why + ')' : '') + (ev ? ' · ' + ev : ''),
      ai: { workMode: c.workMode || 'unknown', locality: c.locality || 'none', workAuth: c.workAuth || 'none', clearance: c.clearance || 'none', payType: c.payType || 'none', offshoreStated: c.offshoreStated || 'unstated', jdCity: String(c.jdCity || '').slice(0, 60), confidence: typeof c.confidence === 'number' ? c.confidence : null, model: AI_MODEL, at: new Date() }
    };
  } catch (e) {
    if (opts.errors) opts.errors.push('parse: ' + String(e && e.message || e));
    return null;
  }
}
// Fields to $set on a job doc from an AI result
function aiSetFields(r) {
  return { engagementModel: r.model, offshoreOk: r.offshoreOk, engagementEvidence: r.evidence, engagementAI: true, workMode: r.ai.workMode, engagementDetail: r.ai };
}

module.exports = { classifyEngagement: classifyEngagement, classifyEngagementAI: classifyEngagementAI, aiSetFields: aiSetFields, extractJdLocation: extractJdLocation, isBareLocation: isBareLocation };
