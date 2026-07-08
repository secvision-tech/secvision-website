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
    var overall = Math.round(
      (dims.skills * w.skills + dims.certifications * w.certifications +
        dims.compliance * w.compliance + dims.role * w.role +
        dims.experience * w.experience + dims.rate * w.rate +
        (scoreEducation ? dims.education * w.education : 0)) / 100
    );
    return { profile: p, overall: overall, dimensions: dims, reason: s.reason || '' };
  });
}
function clamp(n) { n = parseInt(n); if (isNaN(n)) return 0; return Math.max(0, Math.min(100, n)); }

// ---------------------------------------------------------------------------
// Build Apify search keywords from job requirements
// ---------------------------------------------------------------------------
function buildSearchKeywords(req) {
  // #354: use the ROLE only — adding tools/contract words returned too many out-of-context
  // results. A clean role keyword ("Security Architect") yields far more relevant profiles.
  var role = (req.role || '').trim();
  // strip seniority/level noise that hurts search recall
  role = role.replace(/\b(senior|junior|lead|principal|staff|sr\.?|jr\.?|l[1-4]|level\s*[1-4])\b/gi, '').replace(/\s+/g, ' ').trim();
  return role || 'cybersecurity engineer';
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
        if (mc) preScored.push({ profile: p, overall: mc.overall, dimensions: mc.dimensions, reason: mc.reason });
        else toScore.push(p);
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
              var entry = { overall: r.overall, dimensions: r.dimensions, reason: r.reason, flags: gate ? gate.gate.flags : [], scoredAt: new Date() };
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
          page: page, hasMore: all.length > start + PAGE_SIZE,
          totalMatches: all.length, cachedCount: cached.length,
          moreToScore: moreToScore,
          needsTopUp: all.length < PAGE_SIZE && !moreToScore
        })
      };
    }

    // ---- ACTION: startTopUp — kick off Apify fetch of fresh profiles ----
    if (action === 'startTopUp') {
      var req2 = await getReq(body.jobId);
      if (!req2) return { statusCode: 404, headers: hdrs, body: JSON.stringify({ error: 'Job not found' }) };
      if (!APIFY_TOKEN) return { statusCode: 200, headers: hdrs, body: JSON.stringify({ error: 'APIFY_API_TOKEN not configured' }) };

      var keywords = buildSearchKeywords(req2);
      var locations = req2.country ? [req2.country] : [];
      try {
        var resp = await fetch('https://api.apify.com/v2/acts/' + PROFILE_ACTOR_ID + '/runs?token=' + APIFY_TOKEN, {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            action: 'get-profiles',
            keywords: [keywords],
            limit: FETCH_BATCH,
            location: locations,
            profileFields: ['about', 'experience', 'skills', 'languages', 'organizations']
          })
        });
        var run = await resp.json();
        if (!run.data || !run.data.id) {
          return { statusCode: 200, headers: hdrs, body: JSON.stringify({
            error: 'Failed to start profile fetch',
            apifyStatus: resp.status,
            detail: run && run.error ? (run.error.message || run.error.type || JSON.stringify(run.error)) : JSON.stringify(run).slice(0, 400),
            sentKeywords: keywords, sentLocation: locations
          }) };
        }
        return { statusCode: 200, headers: hdrs, body: JSON.stringify({ runId: run.data.id, datasetId: run.data.defaultDatasetId, keywords: keywords }) };
      } catch (e) {
        return { statusCode: 200, headers: hdrs, body: JSON.stringify({ error: 'Start error: ' + e.message }) };
      }
    }

    // ---- ACTION: checkTopUp — poll Apify; when done, cache + score + return ----
    if (action === 'checkTopUp') {
      var req3 = await getReq(body.jobId);
      if (!req3) return { statusCode: 404, headers: hdrs, body: JSON.stringify({ error: 'Job not found' }) };
      var runId = body.runId, datasetId = body.datasetId;
      if (!runId) return { statusCode: 200, headers: hdrs, body: JSON.stringify({ error: 'No runId' }) };

      // helper: fetch with a hard timeout so a hung Apify call can't stall the whole function
      async function fetchWithTimeout(url, opts, ms) {
        var ctrl = new AbortController();
        var t = setTimeout(function () { ctrl.abort(); }, ms || 12000);
        try { var res = await fetch(url, Object.assign({}, opts, { signal: ctrl.signal })); return res; }
        finally { clearTimeout(t); }
      }

      var statusData;
      try {
        var statusResp = await fetchWithTimeout('https://api.apify.com/v2/actor-runs/' + runId + '?token=' + APIFY_TOKEN, {}, 10000);
        statusData = await statusResp.json();
      } catch (e) {
        return { statusCode: 200, headers: hdrs, body: JSON.stringify({ done: false, status: 'CHECKING', note: 'status check slow, will retry' }) };
      }
      var status = statusData.data ? statusData.data.status : 'UNKNOWN';
      if (status === 'RUNNING' || status === 'READY') {
        return { statusCode: 200, headers: hdrs, body: JSON.stringify({ done: false, status: status }) };
      }
      if (status !== 'SUCCEEDED') {
        return { statusCode: 200, headers: hdrs, body: JSON.stringify({ done: true, status: status, error: 'Fetch ' + status }) };
      }

      // Fetch raw profiles (with timeout), normalize
      var raw;
      try {
        var resultsResp = await fetchWithTimeout('https://api.apify.com/v2/datasets/' + datasetId + '/items?token=' + APIFY_TOKEN + '&format=json&limit=' + FETCH_BATCH, {}, 15000);
        raw = await resultsResp.json();
      } catch (e) {
        return { statusCode: 200, headers: hdrs, body: JSON.stringify({ done: false, status: 'FETCHING', note: 'results fetch slow, will retry' }) };
      }
      var normalized = (raw || []).map(normalizeApifyProfile).filter(function (p) { return p.sourceId; });

      // Upsert into cache in a SINGLE bulkWrite (fast) instead of 50 sequential writes
      if (normalized.length) {
        var ops = normalized.map(function (np) {
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
      }

      return { statusCode: 200, headers: hdrs, body: JSON.stringify({ done: true, status: status, fetched: normalized.length, message: 'Fetched and cached ' + normalized.length + ' profiles. Re-run match.' }) };
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
    dimensions: m.dimensions,
    reason: m.reason,
    flags: m.flags || [],
    contractorLikely: m.profile.contractorSignal ? m.profile.contractorSignal.likely : false,
    source: m.profile.source
  };
}
