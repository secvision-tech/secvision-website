// ============================================================================
// SecVision Match Engine — consultant profile matching for job requirements
//
// Flow:
//   1. matchProfiles (job) → score CACHED profiles first (free), return >=60%
//   2. If not enough matches → topUpProfiles fetches fresh via Apify, caches,
//      scores, merges.
//
// Architecture: source-agnostic. Apify is the current TEST source. Each profile
// is tagged with `source` + `fetchedAt` so production can swap to Dice / own
// funnel and apply per-source retention. Matching engine never cares about source.
//
// Scoring = deterministic HARD GATES (free) + LLM WEIGHTED SCORE (claude-sonnet-4-6).
// ============================================================================

const { getDb } = require('./db');

const APIFY_TOKEN = process.env.APIFY_API_TOKEN;
const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY;
const PROFILE_ACTOR_ID = 'bebity~linkedin-premium-actor';
const SCORING_MODEL = 'claude-sonnet-4-6';
// Bump when the scoring formula changes so cached scores are recomputed rather than
// silently kept. v2 = added the remote-aware location penalty.
const SCORING_VERSION = 2;

const TENANT_ID = process.env.ENTRA_TENANT_ID || '';
const CLIENT_ID = process.env.ENTRA_CLIENT_ID || '';

const hdrs = {
  'Content-Type': 'application/json',
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'POST,OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization'
};

const MATCH_THRESHOLD = 60;           // >=60% to be a proposable match
const PAGE_SIZE = 10;                  // profiles shown per page
const FETCH_BATCH = 50;               // profiles pulled from Apify per top-up
const CACHE_COLLECTION = 'consultant_profiles';

// Default scoring weights (tunable later via settings). Must sum to 100.
const DEFAULT_WEIGHTS = {
  skills: 35,
  certifications: 20,
  compliance: 15,
  role: 15,
  experience: 10,
  rate: 5
};

// ---------------------------------------------------------------------------
// JWT auth (mirrors job-db.js)
// ---------------------------------------------------------------------------
function decodeJwt(token) {
  try {
    var parts = token.split('.');
    if (parts.length !== 3) return null;
    var payload = parts[1].replace(/-/g, '+').replace(/_/g, '/');
    while (payload.length % 4) payload += '=';
    return JSON.parse(Buffer.from(payload, 'base64').toString('utf8'));
  } catch (e) { return null; }
}
function validateToken(event) {
  var authHeader = (event.headers || {}).authorization || (event.headers || {}).Authorization || '';
  if (!authHeader.startsWith('Bearer ')) return null;
  var claims = decodeJwt(authHeader.slice(7));
  if (!claims) return null;
  if (claims.iss && TENANT_ID && !claims.iss.includes(TENANT_ID)) return null;
  if (claims.aud && CLIENT_ID && claims.aud !== CLIENT_ID) return null;
  if (claims.exp && claims.exp < Math.floor(Date.now() / 1000)) return null;
  return {
    email: (claims.preferred_username || claims.email || claims.upn || '').toLowerCase(),
    name: claims.name || ''
  };
}

// ---------------------------------------------------------------------------
// ADAPTER: Apify bebity profile → normalized ConsultantProfile
// ---------------------------------------------------------------------------
function normalizeApifyProfile(p) {
  var exp = Array.isArray(p.experience) ? p.experience : [];
  // total years from experience durations (rough)
  var totalYears = 0;
  exp.forEach(function (e) {
    var m = (e.duration || '').match(/(\d+)\s*yr/);
    if (m) totalYears += parseInt(m[1]);
  });
  var certs = (Array.isArray(p.certifications) ? p.certifications : [])
    .map(function (c) { return (typeof c === 'string') ? c : (c.name || ''); }).filter(Boolean);
  // Fallback: if actor didn't return a certifications field, scan about/headline/experience text
  // for common cybersecurity cert names so cert-matching still works.
  if (!certs.length) {
    var scanText = ((p.summary || '') + ' ' + (p.headline || '') + ' ' +
      (Array.isArray(p.experience) ? p.experience.map(function (e) { return (e.title || '') + ' ' + (e.description || ''); }).join(' ') : ''));
    var CERT_PATTERNS = ['CISSP', 'CISM', 'CISA', 'CEH', 'OSCP', 'OSCE', 'GCIH', 'GCIA', 'GSEC', 'GPEN', 'GCFA', 'GWAPT',
      'CCSP', 'CCSK', 'Security\\+', 'CompTIA Security', 'CySA\\+', 'PenTest\\+', 'CASP',
      'SC-100', 'SC-200', 'SC-300', 'AZ-500', 'AZ-104', 'AWS Security', 'CCNA', 'CCNP', 'CISSP-ISSAP',
      'CRISC', 'CGEIT', 'CIPP', 'ITIL', 'PMP'];
    CERT_PATTERNS.forEach(function (c) {
      var re = new RegExp('\\b' + c + '\\b', 'i');
      if (re.test(scanText)) certs.push(c.replace('\\+', '+'));
    });
  }
  var currentRole = exp[0] ? (exp[0].title || '') : (p.headline || '');
  var currentCompany = exp[0] ? (exp[0].companyName || '') : '';

  return {
    // identity
    source: 'apify-linkedin',
    sourceId: p.vanityName || p.urn || p.linkedinUrl || '',
    linkedinUrl: p.linkedinUrl || '',
    name: ((p.firstName || '') + ' ' + (p.lastName || '')).trim() || p.vanityName || 'Unknown',
    headline: p.headline || '',
    location: p.location || '',
    industry: p.industry || '',
    profilePicture: p.profilePictureUrl || '',
    // scored attributes
    skills: Array.isArray(p.skills) ? p.skills : [],
    certifications: certs,
    currentRole: currentRole,
    currentCompany: currentCompany,
    yearsExperience: totalYears,
    experience: exp.map(function (e) {
      return {
        title: e.title || '', company: e.companyName || '',
        duration: e.duration || '', description: e.description || '',
        location: e.location || ''
      };
    }),
    summary: p.summary || '',
    education: Array.isArray(p.education) ? p.education.map(function (ed) {
      return { school: ed.schoolName || '', degree: ed.degreeName || '', field: ed.fieldOfStudy || '' };
    }) : [],
    languages: Array.isArray(p.languages) ? p.languages.map(function (l) { return l.name; }) : [],
    // Contractor detection: employmentType in experience, or freelance/consultant/contractor signals
    contractorSignal: (function () {
      var txt = ((p.headline || '') + ' ' + (p.summary || '') + ' ' +
        exp.map(function (e) { return (e.title || '') + ' ' + (e.employmentType || '') + ' ' + (e.companyName || ''); }).join(' ')).toLowerCase();
      var isContractor = /\b(freelanc|contract|consultant|self-employed|independent|c2c|corp-to-corp|1099|sole proprietor|contractor)\b/.test(txt);
      var hasContractEmployment = exp.some(function (e) { return /freelance|contract|self-employed/i.test(e.employmentType || ''); });
      return { likely: isContractor || hasContractEmployment, employmentTypes: exp.map(function (e) { return e.employmentType || ''; }).filter(Boolean) };
    })(),
    // hard-gate attributes — LinkedIn rarely exposes these, so default unknown
    workAuthorization: 'unknown',
    securityClearance: 'unknown',
    availability: 'unknown',
    rateExpectation: null,
    fetchedAt: new Date()
  };
}

// ---------------------------------------------------------------------------
// Extract structured REQUIREMENTS from a job record
// ---------------------------------------------------------------------------
function extractJobRequirements(job) {
  function toArr(v) {
    if (!v) return [];
    if (Array.isArray(v)) return v.filter(Boolean);
    return String(v).split(/[,;|]/).map(function (s) { return s.trim(); }).filter(Boolean);
  }
  return {
    jobId: job._id ? String(job._id) : (job.jobId || ''),
    title: job.title || job.titleClean || '',
    role: job.titleClean || job.title || '',
    tools: toArr(job.tools),
    certifications: toArr(job.certifications),
    compliance: toArr(job.compliance),
    experienceRequired: job.experience || '',
    country: job.detectedCountry || job.searchCountry || '',
    location: job.location || '',
    isContractRole: (job.jobType === 'Contract') || /\bcontract\b|c2c|corp-to-corp|contractor|freelance/i.test(job.jobType || ''),
    remote: job.remote || '',
    jobType: job.jobType || '',
    salary: job.salary || '',
    // hard-gate requirements (parsed from description where possible)
    requiresClearance: /clearance|cleared|ts\/sci|secret|public trust/i.test(job.description || job.eligibility || ''),
    requiresCitizen: /u\.?s\.?\s*citizen|must be a citizen|citizenship required/i.test(job.description || job.eligibility || ''),
    onsite: /on-?site|in-?person|hybrid/i.test((job.remote || '') + ' ' + (job.location || '')),
    // Education requirement — only score education when the JD actually mentions a degree requirement
    educationRequired: (function () {
      var d = (job.description || '') + ' ' + (job.eligibility || '');
      var m = d.match(/\b(bachelor'?s?|master'?s?|ph\.?d|doctorate|b\.?s\.?|m\.?s\.?|b\.?tech|m\.?tech|degree)\b[^.]{0,60}/i);
      return m ? m[0].trim().slice(0, 80) : '';
    })(),
    description: (job.description || '').slice(0, 1500)
  };
}

// ---------------------------------------------------------------------------
// HARD GATES (deterministic, no LLM). Returns {passed, reasons[], flags[]}
// "unknown" → flagged caution, not auto-fail (recruiter verifies).
// ---------------------------------------------------------------------------
function applyHardGates(req, profile) {
  var reasons = [];   // hard failures
  var flags = [];     // unknowns to verify manually

  // Clearance
  if (req.requiresClearance) {
    if (profile.securityClearance === 'unknown') flags.push('Clearance required — not stated on profile, verify');
    else if (!/secret|ts|clearance|public trust/i.test(profile.securityClearance)) reasons.push('Lacks required security clearance');
  }
  // Citizenship / work authorization
  if (req.requiresCitizen) {
    if (profile.workAuthorization === 'unknown') flags.push('US citizenship required — not stated, verify');
    else if (!/citizen|gc|green card/i.test(profile.workAuthorization)) reasons.push('Does not meet citizenship requirement');
  }
  // Availability (only a flag, never a hard fail for now)
  if (profile.availability === 'unknown') flags.push('Availability not stated, confirm');

  return { passed: reasons.length === 0, reasons: reasons, flags: flags };
}

// ---------------------------------------------------------------------------
// LLM BATCH SCORING — score N profiles against one job in a single call
// ---------------------------------------------------------------------------
async function scoreProfilesBatch(req, profiles, weights) {
  if (!profiles.length) return [];
  if (!ANTHROPIC_API_KEY) throw new Error('ANTHROPIC_API_KEY not configured');

  // Compact each profile so the prompt stays lean
  var compact = profiles.map(function (p, i) {
    return {
      i: i,
      role: p.currentRole || p.headline,
      years: p.yearsExperience,
      contractor: p.contractorSignal ? p.contractorSignal.likely : false,
      skills: (p.skills || []).slice(0, 25),
      certs: (p.certifications || []).slice(0, 12),
      summary: (p.summary || '').slice(0, 200),
      exp: (p.experience || []).slice(0, 3).map(function (e) {
        return (e.title || '') + ' @ ' + (e.company || '') + (e.description ? ': ' + e.description.slice(0, 80) : '');
      })
    };
  });

  var sys = 'You are an expert cybersecurity staffing matcher. Score each candidate against the job on a 0-100 scale for each dimension. ' +
    'Use semantic understanding: e.g. "Splunk ES + QRadar" satisfies a "SIEM engineering" requirement even without exact keywords. ' +
    'Be strict and realistic. Return ONLY valid JSON, no prose, no markdown fences.';

  // Education is scored ONLY when the JD requires it; otherwise it's ignored (no penalty).
  var scoreEducation = !!req.educationRequired;
  var w = Object.assign({}, weights);
  if (scoreEducation) {
    // carve out 10 points for education, proportionally from the others
    var edW = 10;
    var factor = (100 - edW) / 100;
    w = { skills: Math.round(weights.skills * factor), certifications: Math.round(weights.certifications * factor),
      compliance: Math.round(weights.compliance * factor), role: Math.round(weights.role * factor),
      experience: Math.round(weights.experience * factor), rate: Math.round(weights.rate * factor), education: edW };
  }

  var prompt =
    'JOB REQUIREMENTS:\n' +
    'Role: ' + req.role + '\n' +
    'Tools/Technologies required: ' + (req.tools.join(', ') || 'not specified') + '\n' +
    'Certifications preferred: ' + (req.certifications.join(', ') || 'none') + '\n' +
    'Compliance experience: ' + (req.compliance.join(', ') || 'none') + '\n' +
    'Experience required: ' + (req.experienceRequired || 'not specified') + '\n' +
    (scoreEducation ? 'Education required: ' + req.educationRequired + '\n' : '') +
    'Location/Country: ' + (req.country || req.location || 'any') + '\n' +
    'Engagement type: ' + (req.isContractRole ? 'CONTRACT — prefer candidates who are contractors/consultants/freelancers open to contract work (see contractorLikely flag). Penalize role score for candidates who appear to be settled full-time employees not open to contract.' : 'Full-time or either') + '\n\n' +
    'CANDIDATES (JSON array):\n' + JSON.stringify(compact) + '\n\n' +
    'For EACH candidate return an object with these 0-100 scores:\n' +
    '  skills, certifications, compliance, role, experience, rate' + (scoreEducation ? ', education' : '') + '\n' +
    '(rate: 50 if unknown. For CONTRACT roles, factor contractor-availability into "role".' +
    (scoreEducation ? ' Score "education" 0-100 vs required education.' : '') + ') Add a SHORT "reason" (max 12 words).\n' +
    'Respond with ONLY a JSON array, no other text:\n' +
    '[{"i":0,"skills":85,"certifications":70,"compliance":60,"role":90,"experience":80,"rate":50' + (scoreEducation ? ',"education":75' : '') + ',"reason":"..."}]';

  var ctrl = new AbortController();
  var tmo = setTimeout(function () { ctrl.abort(); }, 22000);  // hard cap just under Netlify's 26s
  var resp, data;
  try {
    resp = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01'
      },
      body: JSON.stringify({
        model: SCORING_MODEL,
        max_tokens: 1200,
        system: sys,
        messages: [{ role: 'user', content: prompt }]
      }),
      signal: ctrl.signal
    });
    data = await resp.json();
  } catch (e) {
    clearTimeout(tmo);
    throw new Error(e.name === 'AbortError' ? 'Scoring timed out — try again (fewer profiles will score per pass)' : 'Scoring request failed: ' + e.message);
  }
  clearTimeout(tmo);
  if (data.error) throw new Error('Anthropic: ' + (data.error.message || JSON.stringify(data.error)));

  var text = (data.content || []).filter(function (c) { return c.type === 'text'; }).map(function (c) { return c.text; }).join('');
  text = text.replace(/```json|```/g, '').trim();
  var scores;
  try { scores = JSON.parse(text); } catch (e) { throw new Error('LLM returned unparseable JSON'); }

  // Merge scores back onto profiles + compute weighted overall
  return profiles.map(function (p, idx) {
    var s = scores.find(function (x) { return x.i === idx; }) || {};
    var dims = {
      skills: clamp(s.skills), certifications: clamp(s.certifications), compliance: clamp(s.compliance),
      role: clamp(s.role), experience: clamp(s.experience), rate: clamp(s.rate === undefined ? 50 : s.rate)
    };
    if (scoreEducation) dims.education = clamp(s.education === undefined ? 50 : s.education);
    var base = Math.round(
      (dims.skills * w.skills + dims.certifications * w.certifications +
        dims.compliance * w.compliance + dims.role * w.role +
        dims.experience * w.experience + dims.rate * w.rate +
        (scoreEducation ? dims.education * w.education : 0)) / 100
    );
    // Soft location penalty — severity depends on whether the role is remote.
    var lf = locationFit(req, p);
    var overall = Math.round(base * lf.factor);
    dims.location = lf.sameCountry === null ? 50 : (lf.sameCountry ? 100 : Math.round(lf.factor * 100));
    var reason = s.reason || '';
    if (lf.note) reason = reason ? (reason + ' · ' + lf.note) : lf.note;
    return {
      profile: p, overall: overall, dimensions: dims, reason: reason,
      locationFit: { sameCountry: lf.sameCountry, factor: lf.factor, profileCountry: lf.profCountry, baseScore: base }
    };
  });
}
function clamp(n) { n = parseInt(n); if (isNaN(n)) return 0; return Math.max(0, Math.min(100, n)); }

// ---------------------------------------------------------------------------
// Location fit — deterministic, applied AFTER the LLM's weighted score.
// ---------------------------------------------------------------------------
// Geography is a factual comparison, so we don't ask the LLM to judge it (it would
// cost tokens and be less reliable). Instead the LLM scores skills/certs/etc., and
// we multiply that by a location factor.
//
// Severity depends on the job's work arrangement:
//   * ON-SITE / HYBRID  -> an out-of-country consultant realistically can't be placed
//                          (work auth, payroll, on-site expectation) => heavy penalty.
//   * REMOTE            -> out-of-country is workable => light penalty, so in-country
//                          still ranks first but others remain visible.
const LOC_PENALTY = {
  onsite:  { sameCountry: 1.00, otherCountry: 0.55 },  // heavy: ~45% cut
  remote:  { sameCountry: 1.00, otherCountry: 0.90 },  // light: ~10% cut
  unknown: { sameCountry: 1.00, otherCountry: 0.75 }   // middle ground
};

function jobIsRemote(req) {
  var hay = ((req.remote || '') + ' ' + (req.jobType || '') + ' ' + (req.title || '') + ' ' + (req.location || '')).toLowerCase();
  if (/\b(remote|work from home|wfh|telecommute|anywhere|distributed)\b/.test(hay)) return true;
  if (/\b(on-?site|onsite|in-?office|hybrid)\b/.test(hay)) return false;
  return null; // unknown
}

// Normalize a country string for comparison ("USA"/"United States"/"US" -> "united states")
function canonCountry(c) {
  var s = String(c || '').trim().toLowerCase();
  if (!s) return '';
  if (/^(us|usa|u\.s\.a?\.?|united states( of america)?)$/.test(s)) return 'united states';
  if (/^(uk|u\.k\.|united kingdom|great britain|england|scotland|wales)$/.test(s)) return 'united kingdom';
  if (/^(uae|united arab emirates)$/.test(s)) return 'united arab emirates';
  if (/^ca$|^canada$/.test(s)) return 'canada';
  return s;
}

// Derive a profile's country from its explicit country field, else the tail of its location
function profileCountry(p) {
  if (p.country) return canonCountry(p.country);
  var loc = String(p.location || '').trim();
  if (!loc) return '';
  var tail = loc.split(',').pop().trim();
  return canonCountry(tail);
}

// Returns { factor, sameCountry, profCountry, note }
function locationFit(req, profile) {
  var jobCountry = canonCountry(req.country || '');
  var profCountry = profileCountry(profile);
  var remote = jobIsRemote(req);
  var band = remote === true ? LOC_PENALTY.remote : (remote === false ? LOC_PENALTY.onsite : LOC_PENALTY.unknown);

  // If we can't tell either side's country, don't penalize — we have no evidence.
  if (!jobCountry || !profCountry) {
    return { factor: 1, sameCountry: null, profCountry: profCountry, note: '' };
  }
  if (jobCountry === profCountry) {
    return { factor: band.sameCountry, sameCountry: true, profCountry: profCountry, note: '' };
  }
  var pretty = profCountry.replace(/\b\w/g, function (m) { return m.toUpperCase(); });
  var jobPretty = jobCountry.replace(/\b\w/g, function (m) { return m.toUpperCase(); });
  var note = remote === true
    ? 'Different country (' + pretty + ' vs ' + jobPretty + ') — role is remote, so workable'
    : 'Different country (' + pretty + ' vs ' + jobPretty + ') — on-site/hybrid role, placement unlikely';
  return { factor: band.otherCountry, sameCountry: false, profCountry: profCountry, note: note };
}

// ---------------------------------------------------------------------------
// Build Apify search keywords from job requirements
// ---------------------------------------------------------------------------
// Default sourcing config — how many profiles to fetch per keyword variant.
// LinkedIn headlines say "Consultant" far more often than "Contractor" (~70/30),
// so we weight the fetch accordingly. Tunable via the settings collection.
const DEFAULT_SOURCING = {
  variants: [
    { suffix: 'Consultant', limit: 35 },
    { suffix: 'Contractor', limit: 15 }
  ]
};

async function getSourcingConfig(db) {
  try {
    var s = await db.collection('settings').findOne({ _id: 'match_sourcing' });
    if (s && Array.isArray(s.variants) && s.variants.length) return { variants: s.variants };
  } catch (e) {}
  return DEFAULT_SOURCING;
}

// US state abbreviations + names, used to sanity-check a job's detectedCountry.
const US_STATE_CODES = /\b(AL|AK|AZ|AR|CA|CO|CT|DE|FL|GA|HI|ID|IL|IN|IA|KS|KY|LA|ME|MD|MA|MI|MN|MS|MO|MT|NE|NV|NH|NJ|NM|NY|NC|ND|OH|OK|OR|PA|RI|SC|SD|TN|TX|UT|VT|VA|WA|WV|WI|WY|DC)\b/;
const US_STATE_NAMES = /\b(California|Texas|New York|Florida|Illinois|Virginia|Washington|Georgia|Massachusetts|Colorado|Arizona|Ohio|Michigan|Pennsylvania|Maryland|Minnesota|Oregon|Nevada|Utah|Missouri|Indiana|Wisconsin|Tennessee|Alabama|Connecticut|New Jersey|North Carolina|South Carolina)\b/i;

// A "CA" in "Santa Ana, CA" means California, not Canada. When the job's own location text
// clearly names a US state, prefer United States over a contradicting detectedCountry.
function resolveSearchCountry(req) {
  var detected = (req.country || '').trim();
  var loc = (req.location || '').trim();
  if (!loc) return detected;
  var looksUS = US_STATE_NAMES.test(loc) || US_STATE_CODES.test(loc.toUpperCase()) || /\b(USA|U\.S\.A?\.?|United States)\b/i.test(loc);
  if (looksUS && /^canada$/i.test(detected)) return 'United States';
  return detected || (looksUS ? 'United States' : '');
}

// #406: Firms that bill their employees out to clients. Someone permanently employed here is
// not "unavailable" — they're reachable via a SUB-CONTRACT with their employer.
const CONSULTING_FIRM_HINTS = /\b(consult|consulting|consultancy|advisory|staffing|recruit|resourcing|talent|solutions|services|technologies|technology|systems|infotech|softech|labs|partners|associates|group|global|outsourc|managed services|msp|mssp|systems integrator|si\b)\b/i;
const KNOWN_CONSULTANCIES = /\b(accenture|deloitte|kpmg|pwc|pricewaterhouse|ey\b|ernst\s*&?\s*young|mckinsey|bain|bcg|capgemini|cognizant|infosys|wipro|tcs|tata consultancy|hcl|tech mahindra|ltimindtree|mindtree|mphasis|persistent|zensar|birlasoft|coforge|hexaware|virtusa|ust global|globant|epam|luxoft|thoughtworks|slalom|booz allen|leidos|caci|saic|mantech|peraton|optiv|kudelski|nccgroup|ncc group|trustwave|secureworks|kroll|stroz|mandiant|crowdstrike services|ibm|dxc|atos|ntt data|fujitsu|unisys|cgi\b|sopra|inetum)\b/i;

function detectEngagementType(profile) {
  var sig = profile.contractorSignal || {};
  if (sig.likely) return 'Contractor';                       // self-declared independent

  var co = (profile.currentCompany || '').trim();
  var headline = (profile.headline || '') + ' ' + (profile.currentRole || '');
  if (co) {
    // Employed at a consultancy/services firm → sub-contractable through that firm
    if (KNOWN_CONSULTANCIES.test(co) || CONSULTING_FIRM_HINTS.test(co)) return 'Sub-Contractor';
  }
  // Headline says "Consultant at X" but X isn't obviously a firm — still likely billable
  if (/\bconsultant\b/i.test(headline) && co) return 'Sub-Contractor';
  if (co) return 'Permanent';
  return 'Unknown';
}
// Analyst" wins over "Security Analyst", and "Cloud Security Architect" over "Security Architect".
// Canonical cybersecurity roles we source for. Longest first so "Security Operations Center
// Analyst" wins over "Security Analyst", and "Cloud Security Architect" over "Security Architect".
const CANONICAL_ROLES = [
  'Security Operations Center Analyst', 'Security Operations Engineer', 'Security Operations Analyst',
  'Cloud Security Architect', 'Cloud Security Engineer', 'Application Security Engineer',
  'Information Security Analyst', 'Information Security Engineer', 'Information Security Manager',
  'Cyber Security Architect', 'Cyber Security Engineer', 'Cyber Security Analyst', 'Cyber Security Consultant',
  'Cybersecurity Architect', 'Cybersecurity Engineer', 'Cybersecurity Analyst', 'Cybersecurity Consultant',
  'Incident Response Analyst', 'Incident Response Engineer', 'Threat Intelligence Analyst',
  'Threat Detection Engineer', 'Detection Engineer', 'Vulnerability Management Analyst',
  'Penetration Tester', 'Security Architect', 'Security Engineer', 'Security Analyst',
  'Security Consultant', 'Security Administrator', 'SOC Analyst', 'SOC Engineer',
  'Network Security Engineer', 'Identity and Access Management Engineer', 'IAM Engineer',
  'GRC Analyst', 'Compliance Analyst', 'Risk Analyst', 'Security Manager', 'Security Specialist',
  'DevSecOps Engineer', 'Malware Analyst', 'Forensics Analyst', 'Digital Forensics Analyst',
  'Security Researcher', 'Red Team Operator', 'Blue Team Analyst', 'Purple Team Engineer'
].sort(function (a, b) { return b.length - a.length; });

// Job-board titles are noisy: ". Security Architect- On Site- Santa Ana, CA", "Sr. SOC Analyst (Remote) - W2".
// Pull the canonical role out rather than trying to scrub arbitrary junk.
function buildSearchRole(req) {
  var raw = (req.role || '').trim();
  if (!raw) return 'Cybersecurity Engineer';

  // Normalize separators/punctuation so "Architect-" and "Architect," both tokenize cleanly
  var norm = raw
    .replace(/[\u2010-\u2015]/g, '-')            // unicode dashes → hyphen
    .replace(/[(){}\[\]]/g, ' ')                  // brackets → space
    .replace(/[-–—/|,;:]+/g, ' ')                 // separators → space
    .replace(/[^\w\s.+#]/g, ' ')                  // strip other punctuation
    .replace(/\s+/g, ' ')
    .trim();

  // 1) Exact canonical role match (case-insensitive, whole-phrase)
  for (var i = 0; i < CANONICAL_ROLES.length; i++) {
    var cr = CANONICAL_ROLES[i];
    var re = new RegExp('(^|\\s)' + cr.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '($|\\s)', 'i');
    if (re.test(norm)) return cr;
  }

  // 2) Fallback: strip common noise, then keep the first 2-4 meaningful words
  var NOISE = /\b(on\s?site|onsite|remote|hybrid|contract|contractor|consultant|freelance|full\s?time|part\s?time|w2|c2c|1099|corp\s?to\s?corp|urgent|hiring|immediate|opening|position|role|job|opportunity|needed|required|us|usa|united states|canada|uk|senior|junior|lead|principal|staff|sr|jr|i{1,3}|iv|v|l[1-4]|level\s*[1-4]|ii|iii)\b/gi;
  var STATE = /\b(a[klrz]|c[aot]|d[ce]|fl|ga|hi|i[adln]|k[sy]|la|m[adeinost]|n[cdehjmvy]|o[hkr]|pa|ri|s[cd]|t[nx]|ut|v[at]|w[aivy])\b/gi;
  var cleaned = norm
    .replace(NOISE, ' ')
    .replace(STATE, ' ')                          // drop trailing state codes like "CA"
    .replace(/\b\d+\b/g, ' ')                     // drop bare numbers
    .replace(/\s+/g, ' ')
    .trim();

  if (!cleaned) return 'Cybersecurity Engineer';
  var words = cleaned.split(' ').filter(function (w) { return w.length > 1; });
  if (!words.length) return 'Cybersecurity Engineer';
  return words.slice(0, 4).join(' ');
}

// Build the per-variant search targets, e.g.
//   [{ keyword: 'Security Architect Consultant', limit: 35 }, { keyword: '... Contractor', limit: 15 }]
// NOTE: the Apify actor applies `limit` PER KEYWORD, so each variant is fetched separately.
function buildSearchTargets(req, sourcing) {
  var role = buildSearchRole(req);
  return (sourcing.variants || DEFAULT_SOURCING.variants).map(function (v) {
    return { keyword: (role + ' ' + v.suffix).trim(), limit: v.limit };
  });
}

// ---------------------------------------------------------------------------
// MAIN HANDLER
// ---------------------------------------------------------------------------
exports.handler = async function (event) {
  if (event.httpMethod === 'OPTIONS') return { statusCode: 200, headers: hdrs, body: '' };
  if (event.httpMethod !== 'POST') return { statusCode: 405, headers: hdrs, body: JSON.stringify({ error: 'POST only' }) };

  var authUser = validateToken(event);
  if (!authUser || !authUser.email) return { statusCode: 401, headers: hdrs, body: JSON.stringify({ error: 'Invalid token' }) };

  var body;
  try { body = JSON.parse(event.body || '{}'); } catch (e) { return { statusCode: 400, headers: hdrs, body: JSON.stringify({ error: 'Bad JSON' }) }; }
  var action = body.action;

  try {
    var db = await getDb();
    var jobsCol = db.collection('jobs');
    var cacheCol = db.collection(CACHE_COLLECTION);
    var weights = DEFAULT_WEIGHTS;

    // Resolve the job requirements from jobId
    async function getReq(jobId) {
      var ObjectId = require('mongodb').ObjectId;
      var job = null;
      try { job = await jobsCol.findOne({ _id: new ObjectId(jobId) }); } catch (e) {}
      if (!job) job = await jobsCol.findOne({ jobId: jobId });
      if (!job) return null;
      return extractJobRequirements(job);
    }

    // ---- ACTION: matchCached — score already-cached profiles for this job ----
    if (action === 'matchCached') {
      var req = await getReq(body.jobId);
      if (!req) return { statusCode: 404, headers: hdrs, body: JSON.stringify({ error: 'Job not found' }) };

      var page = body.page || 0;
      // Pull cached profiles that haven't been scored for this job yet, plus already-scored ones
      var cached = await cacheCol.find({}).limit(400).toArray();
      if (!cached.length) {
        return { statusCode: 200, headers: hdrs, body: JSON.stringify({ matches: [], page: page, hasMore: false, cachedCount: 0, needsTopUp: true }) };
      }

      // Separate profiles already scored for this job (stored in matchCache) vs not
      var toScore = [];
      var preScored = [];
      cached.forEach(function (p) {
        var mc = (p.matchCache || {})[req.jobId];
        // Re-score anything cached before the current scoring version (e.g. entries saved
        // before the location penalty existed), otherwise stale scores would persist forever.
        if (mc && mc.v === SCORING_VERSION) {
          // locationFit isn't stored in the cache entry — recompute it (cheap, deterministic)
          // so the in-country count and the UI badge work for cached results too.
          var lfC = locationFit(req, p);
          preScored.push({
            profile: p, overall: mc.overall, dimensions: mc.dimensions, reason: mc.reason,
            locationFit: { sameCountry: lfC.sameCountry, factor: lfC.factor, profileCountry: lfC.profCountry,
                           baseScore: lfC.factor ? Math.round(mc.overall / lfC.factor) : mc.overall }
          });
        } else {
          toScore.push(p);
        }
      });

      // Score the unscored ones — but CAP per request to stay under Netlify's 26s limit.
      // Score in small sub-batches, persisting each, so a timeout doesn't lose all progress.
      var SCORE_CAP = 8;
      var newlyScored = [];
      var moreToScore = false;
      var scoreError = null;
      if (toScore.length) {
        if (toScore.length > SCORE_CAP) { moreToScore = true; toScore = toScore.slice(0, SCORE_CAP); }
        var gated = toScore.map(function (p) { return { p: p, gate: applyHardGates(req, p) }; });
        var passing = gated.filter(function (g) { return g.gate.passed; }).map(function (g) { return g.p; });
        try {
          var SUB = 4;
          for (var b = 0; b < passing.length; b += SUB) {
            var chunk = passing.slice(b, b + SUB);
            var llmScored = await scoreProfilesBatch(req, chunk, weights);
            for (var i = 0; i < llmScored.length; i++) {
              var r = llmScored[i];
              var gate = gated.find(function (g) { return g.p.sourceId === r.profile.sourceId; });
              var entry = { overall: r.overall, dimensions: r.dimensions, reason: r.reason, flags: gate ? gate.gate.flags : [], scoredAt: new Date(), v: SCORING_VERSION };
              newlyScored.push({ profile: r.profile, overall: r.overall, dimensions: r.dimensions, reason: r.reason, flags: entry.flags });
              try { await cacheCol.updateOne({ _id: r.profile._id }, { $set: { ['matchCache.' + req.jobId]: entry } }); } catch (e) {}
            }
          }
          gated.filter(function (g) { return !g.gate.passed; }).forEach(function (g) {
            newlyScored.push({ profile: g.p, overall: 0, dimensions: {}, reason: 'Disqualified: ' + g.gate.reasons.join('; '), flags: g.gate.flags, gatedOut: true });
          });
        } catch (scErr) {
          // A sub-batch failed (e.g. timeout). Earlier sub-batches are saved; signal retry.
          scoreError = scErr.message;
          moreToScore = true;
        }
      }

      var all = preScored.concat(newlyScored)
        .filter(function (m) { return m.overall >= MATCH_THRESHOLD; })
        .sort(function (a, b) { return b.overall - a.overall; });

      var start = page * PAGE_SIZE;
      var pageItems = all.slice(start, start + PAGE_SIZE);
      return {
        statusCode: 200, headers: hdrs, body: JSON.stringify({
          matches: pageItems.map(formatMatch),
          // #402: the full ranked set (id + score only) so the client can ask the server to
          // add the next batch of 10 unsaved candidates without re-scoring.
          allMatchRefs: all.map(function (m) { return { sourceId: m.profile.sourceId, overall: m.overall }; }),
          page: page, hasMore: all.length > start + PAGE_SIZE,
          totalMatches: all.length, cachedCount: cached.length,
          // How many of the matches are actually in the job's own country? If zero, the UI
          // tells the user to source locally rather than silently showing foreign consultants.
          inCountryMatches: all.filter(function (m) { return m.locationFit && m.locationFit.sameCountry === true; }).length,
          jobCountry: req.country || '',
          moreToScore: moreToScore,
          needsTopUp: all.length < PAGE_SIZE && !moreToScore
        })
      };
    }

    // ---- ACTION: startTopUp — kick off one Apify run PER keyword variant ----
    if (action === 'startTopUp') {
      var req2 = await getReq(body.jobId);
      if (!req2) return { statusCode: 404, headers: hdrs, body: JSON.stringify({ error: 'Job not found' }) };
      if (!APIFY_TOKEN) return { statusCode: 200, headers: hdrs, body: JSON.stringify({ error: 'APIFY_API_TOKEN not configured' }) };

      var sourcing = await getSourcingConfig(db);
      var targets = buildSearchTargets(req2, sourcing);
      // The job's detectedCountry is occasionally wrong (e.g. "Santa Ana, CA" read as Canada).
      // If the job's own location text names a US state or "United States", trust that instead.
      var searchCountry = resolveSearchCountry(req2);
      var locations = searchCountry ? [searchCountry] : [];
      var runs = [];
      try {
        for (var t = 0; t < targets.length; t++) {
          var tgt = targets[t];
          var resp = await fetch('https://api.apify.com/v2/acts/' + PROFILE_ACTOR_ID + '/runs?token=' + APIFY_TOKEN, {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              action: 'get-profiles',
              keywords: [tgt.keyword],       // one keyword per run — actor applies limit PER keyword
              limit: tgt.limit,
              location: locations,
              profileFields: ['about', 'experience', 'skills', 'languages', 'organizations']
            })
          });
          var run = await resp.json();
          if (run.data && run.data.id) {
            runs.push({ runId: run.data.id, datasetId: run.data.defaultDatasetId, keyword: tgt.keyword, limit: tgt.limit });
          } else if (!runs.length && t === targets.length - 1) {
            return { statusCode: 200, headers: hdrs, body: JSON.stringify({
              error: 'Failed to start profile fetch',
              apifyStatus: resp.status,
              detail: run && run.error ? (run.error.message || run.error.type || JSON.stringify(run.error)) : JSON.stringify(run).slice(0, 400),
              sentTargets: targets, sentLocation: locations
            }) };
          }
        }
        if (!runs.length) return { statusCode: 200, headers: hdrs, body: JSON.stringify({ error: 'No Apify runs could be started' }) };
        return { statusCode: 200, headers: hdrs, body: JSON.stringify({ runs: runs, targets: targets, searchCountry: searchCountry }) };
      } catch (e) {
        return { statusCode: 200, headers: hdrs, body: JSON.stringify({ error: 'Start error: ' + e.message }) };
      }
    }

    // ---- ACTION: checkTopUp — poll ALL runs; when all done, cache their profiles ----
    if (action === 'checkTopUp') {
      var req3 = await getReq(body.jobId);
      if (!req3) return { statusCode: 404, headers: hdrs, body: JSON.stringify({ error: 'Job not found' }) };
      var runs = body.runs || (body.runId ? [{ runId: body.runId, datasetId: body.datasetId }] : []);
      if (!runs.length) return { statusCode: 200, headers: hdrs, body: JSON.stringify({ error: 'No runs to check' }) };

      async function fetchWithTimeout(url, opts, ms) {
        var ctrl = new AbortController();
        var t = setTimeout(function () { ctrl.abort(); }, ms || 12000);
        try { var res = await fetch(url, Object.assign({}, opts, { signal: ctrl.signal })); return res; }
        finally { clearTimeout(t); }
      }

      // Pull a set of finished runs' datasets into the cache. Idempotent: profiles are
      // upserted by {source,sourceId}, so harvesting the same run twice is harmless.
      async function harvestRuns(runList) {
        var allNormalized = [];
        for (var rj = 0; rj < runList.length; rj++) {
          if (!runList[rj].datasetId) continue;
          try {
            var rResp = await fetchWithTimeout('https://api.apify.com/v2/datasets/' + runList[rj].datasetId + '/items?token=' + APIFY_TOKEN + '&format=json', {}, 12000);
            var raw = await rResp.json();
            var norm = (raw || []).map(normalizeApifyProfile).filter(function (p) { return p.sourceId; });
            allNormalized = allNormalized.concat(norm);
          } catch (e) { /* skip this dataset; others may still yield */ }
        }
        var seen = {}, deduped = [];
        allNormalized.forEach(function (p) { if (!seen[p.sourceId]) { seen[p.sourceId] = 1; deduped.push(p); } });
        if (!deduped.length) return 0;
        var ops = deduped.map(function (np) {
          return {
            updateOne: {
              filter: { source: np.source, sourceId: np.sourceId },
              update: {
                $set: {
                  name: np.name, headline: np.headline, location: np.location, industry: np.industry,
                  linkedinUrl: np.linkedinUrl, profilePicture: np.profilePicture,
                  skills: np.skills, certifications: np.certifications, currentRole: np.currentRole,
                  currentCompany: np.currentCompany, yearsExperience: np.yearsExperience,
                  experience: np.experience, summary: np.summary, education: np.education, languages: np.languages,
                  contractorSignal: np.contractorSignal,
                  workAuthorization: np.workAuthorization, securityClearance: np.securityClearance,
                  availability: np.availability, rateExpectation: np.rateExpectation,
                  source: np.source, sourceId: np.sourceId, fetchedAt: np.fetchedAt
                },
                $setOnInsert: { createdAt: new Date(), matchCache: {} }
              },
              upsert: true
            }
          };
        });
        try { await cacheCol.bulkWrite(ops, { ordered: false }); } catch (e) {}
        return deduped.length;
      }

      // Poll every run's status
      var allDone = true, anyFailed = [], statuses = [], doneRuns = [];
      for (var ri = 0; ri < runs.length; ri++) {
        try {
          var sResp = await fetchWithTimeout('https://api.apify.com/v2/actor-runs/' + runs[ri].runId + '?token=' + APIFY_TOKEN, {}, 8000);
          var sData = await sResp.json();
          var st = sData.data ? sData.data.status : 'UNKNOWN';
          statuses.push({ keyword: runs[ri].keyword || '', status: st });
          if (st === 'RUNNING' || st === 'READY') allDone = false;
          else if (st !== 'SUCCEEDED') anyFailed.push({ keyword: runs[ri].keyword, status: st });
          else doneRuns.push(runs[ri]);   // SUCCEEDED — safe to harvest now
        } catch (e) {
          allDone = false; // status check slow — keep polling
          statuses.push({ keyword: runs[ri].keyword || '', status: 'CHECKING' });
        }
      }

      // If some runs are still going, harvest whatever HAS finished so their profiles land
      // in the cache now. One slow run shouldn't block the other's results.
      if (!allDone) {
        var partial = 0;
        if (doneRuns.length) partial = await harvestRuns(doneRuns);
        return { statusCode: 200, headers: hdrs, body: JSON.stringify({
          done: false, statuses: statuses, partialFetched: partial
        }) };
      }

      // All runs finished — harvest every successful dataset (shared, idempotent helper)
      var fetchedCount = await harvestRuns(runs);

      return { statusCode: 200, headers: hdrs, body: JSON.stringify({
        done: true, fetched: fetchedCount, failedRuns: anyFailed,
        message: 'Fetched and cached ' + fetchedCount + ' profiles across ' + runs.length + ' searches.'
      }) };
    }

    // ---- #381: JOB CANDIDATES — matched profiles saved against a job ----
    // Stored on the job record as candidateProfiles: [{ sourceId, overall, addedAt }]
    // NOTE: jobId may be a Mongo _id OR the external jobId string — resolve both (like getReq).
    async function findJobDoc(jobId) {
      var ObjectId = require('mongodb').ObjectId;
      var jobsColL = db.collection('jobs');
      var j = null;
      try { j = await jobsColL.findOne({ _id: new ObjectId(jobId) }); } catch (e) {}
      if (!j) j = await jobsColL.findOne({ jobId: jobId });
      return j;
    }

    if (action === 'addCandidates') {
      var jobsCol = db.collection('jobs');
      var cands = body.candidates || [];
      if (!cands.length) return { statusCode: 200, headers: hdrs, body: JSON.stringify({ added: 0 }) };
      var jobDoc = await findJobDoc(body.jobId);
      if (!jobDoc) return { statusCode: 404, headers: hdrs, body: JSON.stringify({ error: 'Job not found' }) };

      // Attach to the job (dedupe by sourceId)
      var existing = jobDoc.candidateProfiles || [];
      var have = {}; existing.forEach(function (e) { have[e.sourceId] = 1; });
      var fresh = cands.filter(function (c) { return c.sourceId && !have[c.sourceId]; })
        .sort(function (a, b) { return (b.overall || 0) - (a.overall || 0); });

      // #402: add at most ADD_BATCH new candidates per Match run — repeated runs accumulate
      // (10, then 20, then 30 ...). Only ever the best-scoring unsaved ones.
      var ADD_BATCH = body.addBatch || PAGE_SIZE;
      var remaining = fresh.length - ADD_BATCH;
      fresh = fresh.slice(0, ADD_BATCH);
      if (!fresh.length) {
        return { statusCode: 200, headers: hdrs, body: JSON.stringify({ added: 0, total: existing.length, moreAvailable: 0 }) };
      }

      // Adopt the selected profiles into the managed consultant DB (so they can enter the pipeline)
      var pickedIds = fresh.map(function (c) { return c.sourceId; });
      var adoptOps = pickedIds.map(function (sid) {
        return {
          updateOne: {
            filter: { sourceId: sid },
            update: {
              $set: { managed: true, updatedAt: new Date() },
              $setOnInsert: { availability: 'available', pipelineStatus: 'none', createdAt: new Date() }
            }
          }
        };
      });
      try { await cacheCol.bulkWrite(adoptOps, { ordered: false }); } catch (e) {}
      // #406: classify engagement type (Contractor / Sub-Contractor / Permanent) where unset.
      // Sub-Contractor = employed by a consultancy or staffing firm, so reachable via their employer.
      try {
        var unset = await cacheCol.find({ sourceId: { $in: pickedIds }, engagementType: { $exists: false } }).toArray();
        if (unset.length) {
          var typeOps = unset.map(function (p) {
            return { updateOne: { filter: { _id: p._id }, update: { $set: { engagementType: detectEngagementType(p) } } } };
          });
          await cacheCol.bulkWrite(typeOps, { ordered: false });
        }
      } catch (e) {}

      var toAdd = fresh.map(function (c) { return { sourceId: c.sourceId, overall: c.overall || 0, addedAt: new Date(), addedBy: authUser ? authUser.email : '' }; });
      await jobsCol.updateOne({ _id: jobDoc._id }, { $push: { candidateProfiles: { $each: toAdd } } });
      return { statusCode: 200, headers: hdrs, body: JSON.stringify({
        added: toAdd.length,
        total: existing.length + toAdd.length,
        moreAvailable: remaining > 0 ? remaining : 0
      }) };
    }

    if (action === 'listCandidates') {
      var jd = await findJobDoc(body.jobId);
      if (!jd) return { statusCode: 200, headers: hdrs, body: JSON.stringify({ candidates: [] }) };
      var cps = jd.candidateProfiles || [];
      if (!cps.length) return { statusCode: 200, headers: hdrs, body: JSON.stringify({ candidates: [] }) };
      var ids = cps.map(function (c) { return c.sourceId; });
      var profs = await cacheCol.find({ sourceId: { $in: ids } }).toArray();
      var byId = {}; profs.forEach(function (p) { byId[p.sourceId] = p; });
      var out = cps.map(function (c) {
        var p = byId[c.sourceId] || {};
        return {
          _id: p._id ? p._id.toString() : '', sourceId: c.sourceId, overall: c.overall, addedAt: c.addedAt,
          name: p.name || '(profile removed)', currentRole: p.currentRole || p.headline || '',
          currentCompany: p.currentCompany || '', location: p.location || '', country: p.country || '',
          engagementType: p.engagementType || (p.contractorSignal && p.contractorSignal.likely ? 'Contractor' : 'Unknown'),
          availability: p.availability || 'available', pipelineStatus: p.pipelineStatus || 'none',
          certifications: p.certifications || [], linkedinUrl: p.linkedinUrl || ''
        };
      }).sort(function (a, b) { return (b.overall || 0) - (a.overall || 0); });
      return { statusCode: 200, headers: hdrs, body: JSON.stringify({ candidates: out }) };
    }

    if (action === 'removeCandidate') {
      var jr = await findJobDoc(body.jobId);
      if (!jr) return { statusCode: 404, headers: hdrs, body: JSON.stringify({ error: 'Job not found' }) };
      await db.collection('jobs').updateOne({ _id: jr._id }, { $pull: { candidateProfiles: { sourceId: body.sourceId } } });
      return { statusCode: 200, headers: hdrs, body: JSON.stringify({ removed: true }) };
    }

    // ---- ACTION: getSourcing / setSourcing (keyword variants + per-variant fetch limits) ----
    if (action === 'getSourcing') {
      var sc = await getSourcingConfig(db);
      return { statusCode: 200, headers: hdrs, body: JSON.stringify({ variants: sc.variants, defaults: DEFAULT_SOURCING.variants }) };
    }
    if (action === 'setSourcing') {
      if (!Array.isArray(body.variants) || !body.variants.length) return { statusCode: 400, headers: hdrs, body: JSON.stringify({ error: 'variants array required' }) };
      var clean = body.variants
        .filter(function (v) { return v && v.suffix; })
        .map(function (v) { return { suffix: String(v.suffix).trim(), limit: Math.max(1, parseInt(v.limit) || 10) }; });
      if (!clean.length) return { statusCode: 400, headers: hdrs, body: JSON.stringify({ error: 'No valid variants' }) };
      await db.collection('settings').updateOne({ _id: 'match_sourcing' }, { $set: { variants: clean, updatedAt: new Date() } }, { upsert: true });
      return { statusCode: 200, headers: hdrs, body: JSON.stringify({ saved: true, variants: clean }) };
    }

    // ---- ACTION: getWeights / setWeights (super admin later) ----
    if (action === 'getWeights') {
      return { statusCode: 200, headers: hdrs, body: JSON.stringify({ weights: DEFAULT_WEIGHTS }) };
    }

    return { statusCode: 400, headers: hdrs, body: JSON.stringify({ error: 'Unknown action: ' + action }) };
  } catch (e) {
    return { statusCode: 500, headers: hdrs, body: JSON.stringify({ error: e.message }) };
  }
};

function formatMatch(m) {
  return {
    sourceId: m.profile.sourceId,
    name: m.profile.name,
    headline: m.profile.headline,
    location: m.profile.location,
    linkedinUrl: m.profile.linkedinUrl,
    currentRole: m.profile.currentRole,
    currentCompany: m.profile.currentCompany,
    yearsExperience: m.profile.yearsExperience,
    skills: (m.profile.skills || []).slice(0, 15),
    certifications: m.profile.certifications || [],
    overall: m.overall,
    locationFit: m.locationFit || null,
    dimensions: m.dimensions,
    reason: m.reason,
    flags: m.flags || [],
    contractorLikely: m.profile.contractorSignal ? m.profile.contractorSignal.likely : false,
    source: m.profile.source
  };
}
