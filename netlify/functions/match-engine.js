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
// ---------------------------------------------------------------------------
// #410: Location language normalization
// ---------------------------------------------------------------------------
// LinkedIn returns each profile's location in that profile's own locale, e.g.
//   "Nowy Jork, Stany Zjednoczone"                  (Polish)
//   "Sint-Eloois-Vijve, Région flamande, Belgique"  (French)
//   "Chicago, Illinois, Verenigde Staten"           (Dutch)
//   "Lanham, Maryland, Vereinigte Staaten von Amerika" (German)
//   "Stati Uniti d'America"                          (Italian)
//   "Spojené státy"                                  (Czech)
// We normalize the COUNTRY and common REGION words to English. City names are
// proper nouns and are left alone.
//
// Keys must be lowercase. Longest keys are matched first so "vereinigte staaten von
// amerika" wins over "vereinigte staaten".
const LOCATION_TERM_MAP = {
  // ---- United States (incl. long "of America" forms) ----
  'stany zjednoczone': 'United States',
  'stany zjednoczone ameryki': 'United States',
  'etats-unis': 'United States',
  'états-unis': 'United States',
  "etats-unis d'amerique": 'United States',
  "états-unis d'amérique": 'United States',
  'vereinigte staaten': 'United States',
  'vereinigte staaten von amerika': 'United States',
  'estados unidos': 'United States',
  'estados unidos de américa': 'United States',
  'estados unidos da américa': 'United States',
  'verenigde staten': 'United States',
  'verenigde staten van amerika': 'United States',
  'stati uniti': 'United States',
  "stati uniti d'america": 'United States',
  'spojené státy': 'United States',
  'spojené státy americké': 'United States',
  'spojené štáty': 'United States',
  'amerikas förenta stater': 'United States',
  'amerikai egyesült államok': 'United States',
  'statele unite': 'United States',
  'statele unite ale americii': 'United States',
  'yhdysvallat': 'United States',
  'amerika birleşik devletleri': 'United States',
  'соединённые штаты': 'United States',
  'сполучені штати': 'United States',

  // ---- United Kingdom ----
  'royaume-uni': 'United Kingdom', 'vereinigtes königreich': 'United Kingdom',
  'reino unido': 'United Kingdom', 'regno unito': 'United Kingdom',
  'verenigd koninkrijk': 'United Kingdom', 'wielka brytania': 'United Kingdom',
  'zjednoczone królestwo': 'United Kingdom', 'spojené království': 'United Kingdom',
  'storbritannien': 'United Kingdom', 'birleşik krallık': 'United Kingdom',

  // ---- Other common countries ----
  'belgique': 'Belgium', 'belgië': 'Belgium', 'belgien': 'Belgium', 'belgio': 'Belgium', 'bélgica': 'Belgium',
  'allemagne': 'Germany', 'deutschland': 'Germany', 'duitsland': 'Germany', 'germania': 'Germany',
  'alemania': 'Germany', 'alemanha': 'Germany', 'niemcy': 'Germany', 'německo': 'Germany',
  'frankrijk': 'France', 'frankreich': 'France', 'francia': 'France', 'frança': 'France',
  'francja': 'France', 'francie': 'France',
  'pays-bas': 'Netherlands', 'niederlande': 'Netherlands', 'nederland': 'Netherlands',
  'paesi bassi': 'Netherlands', 'países bajos': 'Netherlands', 'holandia': 'Netherlands',
  'espagne': 'Spain', 'spanien': 'Spain', 'españa': 'Spain', 'spagna': 'Spain',
  'spanje': 'Spain', 'hiszpania': 'Spain', 'espanha': 'Spain',
  'italie': 'Italy', 'italien': 'Italy', 'italia': 'Italy', 'italië': 'Italy', 'włochy': 'Italy',
  'suisse': 'Switzerland', 'schweiz': 'Switzerland', 'svizzera': 'Switzerland',
  'zwitserland': 'Switzerland', 'suiza': 'Switzerland', 'szwajcaria': 'Switzerland',
  'autriche': 'Austria', 'österreich': 'Austria', 'oostenrijk': 'Austria', 'austria': 'Austria',
  'inde': 'India', 'indien': 'India', 'india': 'India', 'indie': 'India',
  'canadá': 'Canada', 'kanada': 'Canada', 'kanadassa': 'Canada',
  'brasil': 'Brazil', 'brésil': 'Brazil', 'brasilien': 'Brazil', 'brasile': 'Brazil',
  'polska': 'Poland', 'pologne': 'Poland', 'polen': 'Poland', 'polonia': 'Poland',
  'irlande': 'Ireland', 'irland': 'Ireland', 'irlanda': 'Ireland', 'ierland': 'Ireland',
  'suède': 'Sweden', 'schweden': 'Sweden', 'sverige': 'Sweden', 'zweden': 'Sweden',
  'danemark': 'Denmark', 'dänemark': 'Denmark', 'danmark': 'Denmark', 'denemarken': 'Denmark',
  'norvège': 'Norway', 'norwegen': 'Norway', 'norge': 'Norway', 'noorwegen': 'Norway',
  'finlande': 'Finland', 'finnland': 'Finland', 'suomi': 'Finland',
  'portugal': 'Portugal', 'portogallo': 'Portugal',
  'tchéquie': 'Czech Republic', 'tschechien': 'Czech Republic', 'česko': 'Czech Republic',
  'česká republika': 'Czech Republic', 'czechy': 'Czech Republic',
  'australie': 'Australia', 'australien': 'Australia', 'australië': 'Australia',
  'singapour': 'Singapore', 'singapur': 'Singapore',
  'émirats arabes unis': 'United Arab Emirates', 'vereinigte arabische emirate': 'United Arab Emirates',
  'emiratos árabes unidos': 'United Arab Emirates',

  // ---- Regions / administrative words ----
  'région flamande': 'Flanders', 'vlaams gewest': 'Flanders', 'flemish region': 'Flanders',
  'région wallonne': 'Wallonia', 'waals gewest': 'Wallonia',
  'région de bruxelles-capitale': 'Brussels', 'brussels hoofdstedelijk gewest': 'Brussels',
  'catalogne': 'Catalonia', 'cataluña': 'Catalonia', 'catalunya': 'Catalonia',
  'baviera': 'Bavaria', 'bayern': 'Bavaria', 'bavière': 'Bavaria',
  'lombardia': 'Lombardy', 'lombardie': 'Lombardy',
  'andalucía': 'Andalusia', 'andalousie': 'Andalusia',

  // ---- Cities that get localized (most city names don't, but a few big ones do) ----
  'nowy jork': 'New York', 'nueva york': 'New York', 'new york city': 'New York',
  'londyn': 'London', 'londres': 'London', 'londra': 'London', 'londen': 'London',
  'parigi': 'Paris', 'parís': 'Paris', 'paryż': 'Paris',
  'rzym': 'Rome', 'roma': 'Rome', 'rom': 'Rome',
  'wiedeń': 'Vienna', 'wien': 'Vienna', 'vienne': 'Vienna', 'vienna': 'Vienna',
  'monachium': 'Munich', 'münchen': 'Munich', 'munich': 'Munich',
  'kolonia': 'Cologne', 'köln': 'Cologne',
  'praga': 'Prague', 'praha': 'Prague', 'prag': 'Prague',
  'warszawa': 'Warsaw', 'warschau': 'Warsaw', 'varsovie': 'Warsaw',
  'bruksela': 'Brussels', 'bruxelles': 'Brussels', 'brussel': 'Brussels', 'brüssel': 'Brussels',
  'genève': 'Geneva', 'genf': 'Geneva', 'ginevra': 'Geneva',
  'zurych': 'Zurich', 'zürich': 'Zurich', 'zurigo': 'Zurich',
  'kopenhaga': 'Copenhagen', 'københavn': 'Copenhagen', 'kopenhagen': 'Copenhagen',
  'lizbona': 'Lisbon', 'lisboa': 'Lisbon', 'lissabon': 'Lisbon', 'lisbonne': 'Lisbon',
  'mediolan': 'Milan', 'milano': 'Milan', 'milan': 'Milan', 'mailand': 'Milan',
  'florencja': 'Florence', 'firenze': 'Florence', 'florenz': 'Florence',
  'wenecja': 'Venice', 'venezia': 'Venice', 'venedig': 'Venice',
  'neapol': 'Naples', 'napoli': 'Naples', 'neapel': 'Naples',
  'turyn': 'Turin', 'torino': 'Turin',
  'sewilla': 'Seville', 'sevilla': 'Seville', 'séville': 'Seville',
  'moskwa': 'Moscow', 'moskau': 'Moscow', 'moscou': 'Moscow', 'mosca': 'Moscow',

  // ---- Cyrillic country names ----
  'канада': 'Canada', 'соединённые штаты': 'United States', 'сполучені штати': 'United States',
  'германия': 'Germany', 'франция': 'France', 'испания': 'Spain', 'австрия': 'Austria',
  'индия': 'India', 'великобритания': 'United Kingdom',
  // ---- Swedish / Nordic country names not already covered ----
  'österrike': 'Austria', 'tyskland': 'Germany', 'frankrike': 'France', 'storbritannien': 'United Kingdom',

  // ---- Administrative prefixes to strip (empty value = drop the prefix, keep the place) ----
  'großraum': '', 'grossraum': '',                       // German "Greater ... area"
  'región metropolitana de': '', 'region metropolitana de': '',
  'área metropolitana de': '', 'area metropolitana di': '',
  'grand': '', 'greater': '',
  'provincia di': '', 'province de': '', 'provincie': '',
  'región de': '', 'region de': '', 'comunidad de': '',
  'comunidad autónoma de': '', 'bundesland': '', 'regione': '',
  'województwo': '', 'kraj': ''
};

// Longest keys first so multi-word terms win over their prefixes.
const LOCATION_TERM_KEYS = Object.keys(LOCATION_TERM_MAP).sort(function (a, b) { return b.length - a.length; });

function normalizeLocationToEnglish(loc) {
  if (!loc) return loc;
  var parts = String(loc).split(',').map(function (s) { return s.trim(); }).filter(Boolean);
  var out = parts.map(function (part) {
    var lower = part.toLowerCase();
    // exact match on the whole comma-part
    if (Object.prototype.hasOwnProperty.call(LOCATION_TERM_MAP, lower)) return LOCATION_TERM_MAP[lower];
    // administrative prefix ("Provincia di Milano" -> "Milano" -> "Milan")
    for (var i = 0; i < LOCATION_TERM_KEYS.length; i++) {
      var k = LOCATION_TERM_KEYS[i];
      if (LOCATION_TERM_MAP[k] === '' && lower.indexOf(k + ' ') === 0) {
        var rest = part.slice(k.length).trim();
        var restLower = rest.toLowerCase();
        // the remainder may itself be a translatable place name
        if (Object.prototype.hasOwnProperty.call(LOCATION_TERM_MAP, restLower) && LOCATION_TERM_MAP[restLower]) {
          return LOCATION_TERM_MAP[restLower];
        }
        return rest;
      }
    }
    return part;
  }).filter(function (s) { return s && s.length; });
  // drop consecutive duplicates (e.g. "United States, United States")
  var dedup = out.filter(function (v, i) { return i === 0 || v.toLowerCase() !== out[i - 1].toLowerCase(); });
  return dedup.join(', ');
}

// #459: total experience from a position list. Parses each position's date range,
// merges overlapping intervals (concurrent roles don't double-count), sums the merged
// span with months included; falls back to "N yrs M mos" sums when no dates parse.
// Handles "Jan 2019 - Present", "Jan 2015 - Mar 2020", bare "2015 - 2020", and
// structured {startDate:{year,month},endDate:{...}} entries.
function computeYearsFromExperience(exp) {
  var MONTHS = { jan:0, feb:1, mar:2, apr:3, may:4, jun:5, jul:6, aug:7, sep:8, oct:9, nov:10, dec:11 };
  var intervals = [], fallbackMonths = 0;
  (Array.isArray(exp) ? exp : []).forEach(function (e) {
    // structured dates from some actors: {year,month} objects, ISO strings, or bare numbers
    var sd = e.startDate || e.starts_at || e.start, ed = e.endDate || e.ends_at || e.end;
    function toDate(v, isEnd) {
      if (!v) return isEnd ? new Date() : null;
      if (v.year) return new Date(parseInt(v.year), (v.month ? v.month - 1 : (isEnd ? 11 : 0)), 1);
      if (typeof v === 'number') return new Date(v, isEnd ? 11 : 0, 1);
      if (typeof v === 'string') { var d0 = new Date(v); if (!isNaN(d0.getTime())) return d0; }
      return null;
    }
    if (sd) {
      var start0 = toDate(sd, false), end0 = toDate(ed, true);
      if (start0 && end0 && end0 > start0) { intervals.push([start0.getTime(), end0.getTime()]); return; }
    }
    var txt = (e.duration || '') + ' ' + (e.dateRange || e.dates || '');
    var r = txt.match(/([A-Za-z]{3})[a-z]*\.?\s+(\d{4})\s*[-\u2013\u2014]\s*(?:(Present|Current|Now)|([A-Za-z]{3})[a-z]*\.?\s+(\d{4}))/i);
    if (r && MONTHS[r[1].toLowerCase()] !== undefined) {
      var start = new Date(parseInt(r[2]), MONTHS[r[1].toLowerCase()], 1);
      // LinkedIn counts months INCLUSIVELY (Jan-Mar = 3 mos), so the end month itself counts:
      // use the first day of the FOLLOWING month as the interval end.
      var end = r[3] ? new Date() : (r[4] && MONTHS[r[4].toLowerCase()] !== undefined ? new Date(parseInt(r[5]), MONTHS[r[4].toLowerCase()] + 1, 1) : null);
      if (end && end > start) { intervals.push([start.getTime(), end.getTime()]); return; }
    }
    // numeric ranges: 06/2019 - 03/2021, 06-2019 to 03-2021, 2019/06 variants
    var rn = txt.match(/\b(\d{1,2})[\/\-](\d{4})\s*(?:[-\u2013\u2014]|to)\s*(?:(Present|Current|Now)|(\d{1,2})[\/\-](\d{4}))/i);
    if (rn) {
      var sN = new Date(parseInt(rn[2]), parseInt(rn[1]) - 1, 1);
      var eN = rn[3] ? new Date() : new Date(parseInt(rn[5]), parseInt(rn[4]), 1);
      if (eN > sN) { intervals.push([sN.getTime(), eN.getTime()]); return; }
    }
    // bare year range: "2015 - 2020" / "2019 - Present"
    var ry = txt.match(/\b(19|20)(\d{2})\s*[-\u2013\u2014]\s*(?:(Present|Current|Now)|(19|20)(\d{2}))\b/i);
    if (ry) {
      var ys = parseInt(ry[1] + ry[2], 10);
      var ye = ry[3] ? new Date().getFullYear() : parseInt(ry[4] + ry[5], 10);
      if (ye >= ys) { intervals.push([new Date(ys, 0, 1).getTime(), new Date(ye, 11, 1).getTime()]); return; }
    }
    var ym = txt.match(/(\d+)\s*yrs?/i), mm = txt.match(/(\d+)\s*mos?/i);
    fallbackMonths += (ym ? parseInt(ym[1]) * 12 : 0) + (mm ? parseInt(mm[1]) : 0);
  });
  var totalYears = 0;
  if (intervals.length) {
    intervals.sort(function (a, b) { return a[0] - b[0]; });
    var mergedMs = 0, curS = intervals[0][0], curE = intervals[0][1];
    for (var ii = 1; ii < intervals.length; ii++) {
      if (intervals[ii][0] <= curE) { curE = Math.max(curE, intervals[ii][1]); }
      else { mergedMs += curE - curS; curS = intervals[ii][0]; curE = intervals[ii][1]; }
    }
    mergedMs += curE - curS;
    totalYears = mergedMs / (365.25 * 24 * 3600 * 1000) + fallbackMonths / 12;
  } else {
    totalYears = fallbackMonths / 12;
  }
  return Math.round(totalYears * 10) / 10;   // one decimal keeps the months
}

// Profiles state their own experience ("5+ years of hands-on experience"). When the
// position history is mangled by the scraper (real roles shredded, durations lost),
// the person's stated claim is a better floor than the broken math.
function statedYears(textBlob) {
  var m = (textBlob || '').match(/(\d{1,2})\s*\+?\s*years?(?:\s+of)?\s+(?:hands[- ]on\s+|professional\s+|industry\s+|work(?:ing)?\s+)?experience/i);
  return m ? parseInt(m[1], 10) : 0;
}

function normalizeApifyProfile(p) {
  var exp = Array.isArray(p.experience) ? p.experience : [];
  var totalYears = Math.max(computeYearsFromExperience(exp),
    statedYears((p.summary || '') + ' ' + (p.headline || '')));
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
    location: normalizeLocationToEnglish(p.location || ''),
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
// Stage 3: reverse matching — score a batch of JOBS against one CONSULTANT.
// ---------------------------------------------------------------------------
// Forward matching scores many candidates against one job. This is the inverse:
// given one consultant, score how well each job fits them. Reuses the same weighted
// dimensions and the same deterministic location penalty for consistency.
async function scoreJobsForConsultant(consultant, jobs, weights) {
  if (!jobs.length) return [];
  if (!ANTHROPIC_API_KEY) throw new Error('ANTHROPIC_API_KEY not configured');

  var w = weights || DEFAULT_WEIGHTS;
  var compact = jobs.map(function (j, i) {
    return {
      i: i,
      title: j.title || j.titleClean || '',
      company: j.company || '',
      skills: (j.skills && j.skills !== 'See details') ? String(j.skills).slice(0, 400) : '',
      certifications: (j.certifications && j.certifications !== 'See details') ? String(j.certifications).slice(0, 200) : '',
      compliance: (j.compliance && j.compliance !== 'See details') ? String(j.compliance).slice(0, 200) : '',
      tools: (j.tools && j.tools !== 'See details') ? String(j.tools).slice(0, 200) : '',
      experience: j.experience || j.experienceLevel || ''
    };
  });

  var cSkills = (consultant.skills || []).join(', ');
  var cCerts = (consultant.certifications || []).join(', ');
  var prompt =
    'You are matching ONE cybersecurity consultant against several job openings. '
    + 'Score how well the CONSULTANT fits EACH job.\n\n'
    + 'CONSULTANT:\n'
    + '  Role: ' + (consultant.currentRole || consultant.headline || '') + '\n'
    + '  Experience: ' + (consultant.yearsExperience || 'unknown') + ' years\n'
    + '  Skills: ' + (cSkills || 'not listed') + '\n'
    + '  Certifications: ' + (cCerts || 'none listed') + '\n'
    + '  Summary: ' + String(consultant.summary || '').slice(0, 500) + '\n\n'
    + 'JOBS (JSON array):\n' + JSON.stringify(compact) + '\n\n'
    + 'For EACH job return 0-100 scores for how well THIS consultant fits THAT job: '
    + 'skills, certifications, compliance, role, experience, rate (50 if unknown). '
    + 'Also a one-sentence "reason".\n'
    + 'Respond with ONLY a JSON array: [{"i":0,"skills":..,"certifications":..,"compliance":..,'
    + '"role":..,"experience":..,"rate":..,"reason":".."}, ...]. No prose, no code fences.';

  var ctrl = new AbortController();
  var tmo = setTimeout(function () { ctrl.abort(); }, 22000);
  var scores;
  try {
    var resp = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST', signal: ctrl.signal,
      headers: { 'Content-Type': 'application/json', 'x-api-key': ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01' },
      body: JSON.stringify({ model: SCORING_MODEL, max_tokens: 2000, messages: [{ role: 'user', content: prompt }] })
    });
    if (!resp.ok) throw new Error('Anthropic ' + resp.status);
    var data = await resp.json();
    var txt = (data.content || []).filter(function (b) { return b.type === 'text'; }).map(function (b) { return b.text; }).join('').trim();
    txt = txt.replace(/^```(?:json)?\s*/i, '').replace(/```\s*$/, '').trim();
    scores = JSON.parse(txt);
  } finally { clearTimeout(tmo); }

  return jobs.map(function (j, i) {
    var s = (scores || []).find(function (x) { return x.i === i; }) || {};
    var dims = {
      skills: clamp(s.skills), certifications: clamp(s.certifications),
      compliance: clamp(s.compliance), role: clamp(s.role),
      experience: clamp(s.experience), rate: clamp(s.rate === undefined ? 50 : s.rate)
    };
    var base = Math.round(
      (dims.skills * w.skills + dims.certifications * w.certifications +
        dims.compliance * w.compliance + dims.role * w.role +
        dims.experience * w.experience + dims.rate * w.rate) / 100
    );
    var req = { country: j.detectedCountry || '', location: j.location || '', jobType: j.jobType || '', title: j.title || '', remote: j.remote || '' };
    var lf = locationFit(req, consultant);
    var overall = Math.round(base * lf.factor);
    return {
      job: j, overall: overall, dimensions: dims, reason: s.reason || '',
      locationFit: { sameCountry: lf.sameCountry, factor: lf.factor, jobCountry: canonCountry(j.detectedCountry || ''), baseScore: base }
    };
  });
}


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
// #428: LinkedIn returns countries in many languages/scripts. For matching to work, a
// consultant in "Kanada"/"Канада" and a job in "Canada" must resolve to the SAME country.
// This maps localized/native country names (lowercased) to canonical English.
const COUNTRY_ALIASES = {
  'canada': 'canada', 'kanada': 'canada', 'канада': 'canada', 'canadá': 'canada', 'ca': 'canada',
  'united states': 'united states', 'usa': 'united states', 'us': 'united states',
  'vereinigte staaten': 'united states', 'estados unidos': 'united states', 'états-unis': 'united states',
  'stany zjednoczone': 'united states', 'verenigde staten': 'united states', 'stati uniti': 'united states',
  'соединённые штаты': 'united states', 'сполучені штати': 'united states',
  'united kingdom': 'united kingdom', 'uk': 'united kingdom', 'großbritannien': 'united kingdom',
  'grossbritannien': 'united kingdom', 'royaume-uni': 'united kingdom', 'reino unido': 'united kingdom',
  'vereinigtes königreich': 'united kingdom', 'storbritannien': 'united kingdom',
  'germany': 'germany', 'deutschland': 'germany', 'allemagne': 'germany', 'alemania': 'germany',
  'tyskland': 'germany', 'niemcy': 'germany', 'германия': 'germany',
  'austria': 'austria', 'österreich': 'austria', 'osterreich': 'austria', 'österrike': 'austria',
  'autriche': 'austria', 'австрия': 'austria',
  'switzerland': 'switzerland', 'schweiz': 'switzerland', 'suisse': 'switzerland', 'svizzera': 'switzerland',
  'france': 'france', 'frankreich': 'france', 'frankrike': 'france', 'франция': 'france',
  'netherlands': 'netherlands', 'niederlande': 'netherlands', 'nederland': 'netherlands', 'pays-bas': 'netherlands',
  'belgium': 'belgium', 'belgique': 'belgium', 'belgië': 'belgium', 'belgien': 'belgium',
  'spain': 'spain', 'españa': 'spain', 'espagne': 'spain', 'spanien': 'spain', 'испания': 'spain',
  'italy': 'italy', 'italia': 'italy', 'italien': 'italy', 'italie': 'italy',
  'ireland': 'ireland', 'irland': 'ireland', 'irlande': 'ireland',
  'india': 'india', 'indien': 'india', 'inde': 'india', 'индия': 'india',
  'australia': 'australia', 'australien': 'australia', 'australie': 'australia',
  'sweden': 'sweden', 'sverige': 'sweden', 'schweden': 'sweden',
  'poland': 'poland', 'polska': 'poland', 'polen': 'poland', 'pologne': 'poland',
  'brazil': 'brazil', 'brasil': 'brazil', 'brasilien': 'brazil',
  'singapore': 'singapore', 'singapur': 'singapore',
  'united arab emirates': 'united arab emirates', 'uae': 'united arab emirates',
  'vereinigte arabische emirate': 'united arab emirates'
};
// Profiles often carry a bare city ("Greater Bengaluru Area") with no country. The harvest
// country-gate uses these hints as a fallback so such profiles aren't wrongly rejected.
// LinkedIn geoUrn IDs: the bebity actor's location autocomplete fails on plain country names
// ("Couldn't look up location \"India\""), but its docs accept raw geo IDs, which skip the
// broken lookup entirely. These are LinkedIn's stable country geoUrn values.
const COUNTRY_GEO_IDS = {
  'india': '102713980',
  'united states': '103644278',
  'united kingdom': '101165590',
  'canada': '101174742'
};
const COUNTRY_CITY_HINTS = {
  'india': /\b(bengaluru|bangalore|mumbai|pune|hyderabad|chennai|new delhi|delhi|noida|gurgaon|gurugram|kolkata|ahmedabad|kochi|coimbatore|thiruvananthapuram|jaipur|chandigarh|indore|nagpur)\b/i,
  'united states': /\b(new york|san francisco|seattle|austin|dallas|chicago|boston|atlanta|denver|los angeles|washington dc)\b/i,
  'united kingdom': /\b(london|manchester|edinburgh|birmingham|leeds|glasgow)\b/i
};
function canonCountry(c) {
  var s = String(c || '').trim().toLowerCase();
  if (!s) return '';
  if (COUNTRY_ALIASES[s]) return COUNTRY_ALIASES[s];
  // regex fallbacks for punctuated forms
  if (/^(us|usa|u\.s\.a?\.?|united states( of america)?)$/.test(s)) return 'united states';
  if (/^(uk|u\.k\.|united kingdom|great britain|england|scotland|wales)$/.test(s)) return 'united kingdom';
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
    { suffix: 'Contractor', limit: 15 },
    // Contract-intent variants: surface people already signalling independent/contract
    // work — the population the bench converts fastest. Modest limits control cost.
    { suffix: 'Freelance', limit: 10 },
    { suffix: 'Independent Consultant', limit: 10 }
  ]
};

// Signals that a profile is contract-oriented (headline/summary/about text).
const CONTRACT_INTENT_RE = /freelanc|independent\s+consultant|contract(?:or|ing)?|open\s+to\s+(?:contract|work)|c2c|corp[\s-]*to[\s-]*corp|immediate\s+joiner|available\s+for\s+(?:projects|consulting)|hire\s+me/i;

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
    if (action === 'recalcExperience') {
      // #459 backfill: recompute yearsExperience for every stored consultant from their
      // saved position history — no re-fetch needed. Pure CPU + one bulk write.
      var reDocs = await cacheCol.find({ experience: { $exists: true, $type: 'array', $ne: [] } })
        .project({ experience: 1, yearsExperience: 1, summary: 1, headline: 1, yearsManual: 1 }).toArray();
      var reOps = [], unchanged = 0;
      reDocs.forEach(function (dc) {
        if (dc.yearsManual) { unchanged++; return; }   // user-set values always win
        var ny = Math.max(computeYearsFromExperience(dc.experience),
          statedYears((dc.summary || '') + ' ' + (dc.headline || '')));
        if (ny > 0 && ny !== dc.yearsExperience) {
          reOps.push({ updateOne: { filter: { _id: dc._id }, update: { $set: { yearsExperience: ny } } } });
        } else { unchanged++; }
      });
      if (reOps.length) await cacheCol.bulkWrite(reOps, { ordered: false });
      var totalDocs = await cacheCol.countDocuments({});
      return { statusCode: 200, headers: hdrs, body: JSON.stringify({
        checked: reDocs.length, updated: reOps.length, unchanged: unchanged,
        noData: totalDocs - reDocs.length
      }) };
    }

    if (action === 'matchCached') {
      var req = await getReq(body.jobId);
      if (!req) return { statusCode: 404, headers: hdrs, body: JSON.stringify({ error: 'Job not found' }) };

      var page = body.page || 0;
      // Pull cached profiles that haven't been scored for this job yet, plus already-scored ones
      // Three targeted fetches, merged and deduped — a single blind window misses exactly
      // the profiles that matter once the collection outgrows it:
      //   (1) managed consultants (your bench) ALWAYS load — they are the proposable people;
      //   (2) same-country profiles ALWAYS load — the only ones an onsite job can use;
      //   (3) the general window fills the rest.
      var mcFetches = [ cacheCol.find({ managed: true }).limit(200).toArray() ];
      try {
        if (req.country) {
          var cRe = new RegExp(req.country.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i');
          mcFetches.push(cacheCol.find({ $or: [ { country: cRe }, { location: cRe } ] }).limit(200).toArray());
        }
      } catch (e) {}
      mcFetches.push(cacheCol.find({}).limit(600).toArray());
      var mcParts = await Promise.all(mcFetches);
      var mcSeen = {}, cached = [];
      mcParts.forEach(function (part) {
        part.forEach(function (p) {
          var k = String(p._id);
          if (mcSeen[k]) return;
          mcSeen[k] = 1; cached.push(p);
        });
      });
      // Scoring order: same-country first, and within each country group the bench
      // (managed) before scraped prospects.
      try {
        var mcJobCountry = canonCountry(req.country || '');
        cached.sort(function (a, b) {
          var ac = (mcJobCountry && profileCountry(a) === mcJobCountry) ? 0 : 1;
          var bc = (mcJobCountry && profileCountry(b) === mcJobCountry) ? 0 : 1;
          if (ac !== bc) return ac - bc;
          return (a.managed ? 0 : 1) - (b.managed ? 0 : 1);
        });
      } catch (e) { /* ordering is an optimization; never fail the match */ }
      if (!cached.length) {
        return { statusCode: 200, headers: hdrs, body: JSON.stringify({ matches: [], page: page, hasMore: false, cachedCount: 0, needsTopUp: true }) };
      }

      // Separate profiles already scored for this job (stored in matchCache) vs not
      var toScore = [];
      var preScored = [];
      cached.forEach(function (p) {
        var mc = (p.matchCache || {})[req.jobId] || (p.jobMatchCache || {})[req.jobId];   // #491: union
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

      // #456: pure page navigation — return existing scores, never start scoring.
      if (body.noScore) { toScore = []; }
      // Score the unscored ones — but CAP per request to stay under Netlify's 26s limit.
      // Score in small sub-batches, persisting each, so a timeout doesn't lose all progress.
      // #416: Don't grind through the entire cache. Two stopping rules:
      //   1. EVAL_CAP — never evaluate more than N profiles in one Match run.
      //   2. Enough matches — once we have (page+1)*PAGE_SIZE matches, the current page is
      //      full, so stop. Further scoring happens only when the user asks (Next / Fetch More).
      // Both are overridable per-request so "Next" can push further into the cache.
      var EVAL_CAP = Math.min(parseInt(body.evalCap) || 50, 600);  // ceiling matches cache/job window; was 200 — spent caps permanently blocked in-country scoring
      var NEED_MATCHES = (page + 1) * PAGE_SIZE;

      var SCORE_CAP = 8;
      var newlyScored = [];
      var moreToScore = false;
      var scoreError = null;
      var evaluated = preScored.length;   // cached scores already count toward the cap

      // Already have a full page from cache alone? Don't score anything new.
      var haveNow = preScored.filter(function (m) { return m.overall >= MATCH_THRESHOLD; }).length;
      if (haveNow >= NEED_MATCHES) {
        toScore = [];
        moreToScore = false;
      } else if (evaluated >= EVAL_CAP) {
        // Cap already consumed by cached entries — offer to continue, but don't spend now.
        moreToScore = toScore.length > 0;
        toScore = [];
      } else if (toScore.length) {
        // Only score up to what the cap allows, and never more than SCORE_CAP per request.
        var roomLeft = EVAL_CAP - evaluated;
        var budget = Math.min(SCORE_CAP, roomLeft);
        if (toScore.length > budget) { moreToScore = true; toScore = toScore.slice(0, budget); }
      }

      if (toScore.length) {
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

      // #416: separate "the client must keep polling to finish this page" from "there are
      // more cached profiles we COULD score if the user asks".
      //   keepScoring  -> auto-continue (we don't yet have a full page and budget remains)
      //   canScoreMore -> show a "Score more" affordance; do NOT auto-continue
      var pageIsFull = all.length >= (page + 1) * PAGE_SIZE;
      var unscoredLeft = cached.length - (preScored.length + newlyScored.length);
      var budgetUsed = (preScored.length + newlyScored.length) >= EVAL_CAP;
      var keepScoring = moreToScore && !pageIsFull && !budgetUsed && !scoreError;
      var canScoreMore = (unscoredLeft > 0) && !keepScoring;

      return {
        statusCode: 200, headers: hdrs, body: JSON.stringify({
          matches: pageItems.map(formatMatch),
          // #432: compact list of the profiles scored in THIS batch (all of them, incl.
          // sub-threshold) so the UI can show each consultant ticking past with their score.
          justScored: newlyScored.map(function (m) {
            return {
              name: m.profile.name || '',
              role: m.profile.currentRole || m.profile.headline || '',
              country: (m.locationFit && m.locationFit.profileCountry) ? m.locationFit.profileCountry : (profileCountry(m.profile) || ''),
              overall: m.overall
            };
          }),
          // #402: the full ranked set (id + score only) so the client can ask the server to
          // add the next batch of 10 unsaved candidates without re-scoring.
          allMatchRefs: all.map(function (m) { return { sourceId: m.profile.sourceId, overall: m.overall }; }),
          page: page, hasMore: all.length > start + PAGE_SIZE,
          totalMatches: all.length, cachedCount: cached.length,
          // How many of the matches are actually in the job's own country? If zero, the UI
          // tells the user to source locally rather than silently showing foreign consultants.
          inCountryMatches: all.filter(function (m) { return m.locationFit && m.locationFit.sameCountry === true; }).length,
          jobCountry: req.country || '',
          evaluated: preScored.length + newlyScored.length,
          unscoredLeft: unscoredLeft > 0 ? unscoredLeft : 0,
          moreToScore: keepScoring,          // frontend auto-continues ONLY on this
          canScoreMore: canScoreMore,        // offer a manual "score more" instead
          needsTopUp: all.length < PAGE_SIZE && !keepScoring && !canScoreMore
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
      // Country override (e.g. build an India bench against a US job's keywords). Falls back
      // to the job's own country when not provided.
      var searchCountry = (body.countryOverride && String(body.countryOverride).trim()) || resolveSearchCountry(req2);
      // Prefer LinkedIn geo IDs — the actor's place-name autocomplete is broken for country
      // names ("Couldn't look up location"), but raw geo IDs skip that lookup.
      var geoId = COUNTRY_GEO_IDS[canonCountry(searchCountry)] || '';
      var locations = geoId ? [geoId] : (searchCountry ? [searchCountry] : []);
      var runs = [];
      try {
        for (var t = 0; t < targets.length; t++) {
          var tgt = targets[t];
          // With a geo ID the actor's own filter works — keep the keyword clean. Only when we
          // lack a geo ID do we bake the country into the keyword as a soft filter. The
          // harvest-side country gate applies in both cases.
          var kw = tgt.keyword + (!geoId && searchCountry ? ' ' + searchCountry : '');
          var resp = await fetch('https://api.apify.com/v2/acts/' + PROFILE_ACTOR_ID + '/runs?token=' + APIFY_TOKEN, {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              action: 'get-profiles',
              keywords: [kw],                // one keyword per run — actor applies limit PER keyword
              limit: tgt.limit,
              location: locations,           // kept: harmless if ignored, useful if vendor fixes it
              profileFields: ['about', 'experience', 'skills', 'languages', 'organizations']
            })
          });
          var run = await resp.json();
          if (run.data && run.data.id) {
            runs.push({ runId: run.data.id, datasetId: run.data.defaultDatasetId, keyword: tgt.keyword, limit: tgt.limit, country: searchCountry || '' });
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
      var rejectedOffCountry = 0, rejectedJunk = 0;
      async function harvestRuns(runList) {
        var allNormalized = [];
        for (var rj = 0; rj < runList.length; rj++) {
          if (!runList[rj].datasetId) continue;
          try {
            var rResp = await fetchWithTimeout('https://api.apify.com/v2/datasets/' + runList[rj].datasetId + '/items?token=' + APIFY_TOKEN + '&format=json', {}, 12000);
            var raw = await rResp.json();
            var norm = (raw || []).map(normalizeApifyProfile).filter(function (p) { return p.sourceId; });
            // Junk guard: the actor sometimes returns UI artifacts as "profiles"
            // (e.g. name "Add cover image", headline "Create a slideshow with").
            norm = norm.filter(function (p) {
              var blob = ((p.name || '') + ' ' + (p.headline || '')).toLowerCase();
              if (/add cover image|create a slideshow|see who you know/.test(blob)) { rejectedJunk++; return false; }
              if (!p.name && !p.headline) { rejectedJunk++; return false; }
              return true;
            });
            // Contract-intent tagging: mark profiles whose headline/summary signal
            // contract readiness, and hint engagementType so the existing Contractor
            // filter in the Consultants tab surfaces them. Never overrides a value a
            // user has already set.
            norm.forEach(function (p) {
              var blob = ((p.headline || '') + ' ' + (p.summary || '') + ' ' + (p.about || ''));
              if (CONTRACT_INTENT_RE.test(blob)) {
                p.contractSignal = true;
                if (!p.engagementType || p.engagementType === 'Unknown') p.engagementType = 'Contractor';
              }
            });
            // Country gate: the actor's location filter is unreliable, so enforce it here.
            // A run tagged with an expected country only admits profiles that resolve to it.
            var wantCountry = canonCountry(runList[rj].country || '');
            if (wantCountry) {
              norm = norm.filter(function (p) {
                var normLoc = normalizeLocationToEnglish(p.location || '');
                var pc = canonCountry(profileCountry({ location: normLoc }));
                if (pc === wantCountry) return true;
                // Bare-city locations ("Greater Bengaluru Area") carry no country — use hints.
                var hint = COUNTRY_CITY_HINTS[wantCountry];
                if (hint && hint.test(normLoc)) return true;
                rejectedOffCountry++; return false;
              });
            }
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
                  contractSignal: np.contractSignal || false,
                  linkedinUrl: np.linkedinUrl, profilePicture: np.profilePicture,
                  skills: np.skills, certifications: np.certifications, currentRole: np.currentRole,
                  currentCompany: np.currentCompany, yearsExperience: np.yearsExperience,
                  experience: np.experience, summary: np.summary, education: np.education, languages: np.languages,
                  contractorSignal: np.contractorSignal,
                  workAuthorization: np.workAuthorization, securityClearance: np.securityClearance,
                  availability: np.availability, rateExpectation: np.rateExpectation,
                  source: np.source, sourceId: np.sourceId, fetchedAt: np.fetchedAt
                },
                $setOnInsert: { createdAt: new Date(), matchCache: {}, engagementType: np.engagementType || 'Unknown' }
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
        rejectedOffCountry: rejectedOffCountry, rejectedJunk: rejectedJunk,
        message: 'Fetched and cached ' + fetchedCount + ' profiles across ' + runs.length + ' searches.'
          + (rejectedOffCountry ? ' Rejected ' + rejectedOffCountry + ' off-country result' + (rejectedOffCountry > 1 ? 's' : '') + ' (actor location filter is unreliable — filtered server-side).' : '')
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
          yearsExperience: (p.yearsExperience === undefined || p.yearsExperience === null) ? null : p.yearsExperience,
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
      // #447: also remember the removal so reverse matching (matchJobs) won't re-add
      // this consultant to this job. Manual addCandidates deliberately ignores this list.
      await db.collection('jobs').updateOne({ _id: jr._id }, {
        $pull: { candidateProfiles: { sourceId: body.sourceId } },
        $addToSet: { candidatesRemoved: body.sourceId }
      });
      return { statusCode: 200, headers: hdrs, body: JSON.stringify({ removed: true }) };
    }

    // ---- Stage 3: matchJobs — reverse matching, one consultant -> jobs in a time window ----
    if (action === 'matchJobs') {
      var consId = body.consultantId || '';
      if (!consId) return { statusCode: 400, headers: hdrs, body: JSON.stringify({ error: 'consultantId required' }) };
      var cacheCol = db.collection(CACHE_COLLECTION);

      var consultant = null;
      try { consultant = await cacheCol.findOne({ _id: new (require('mongodb').ObjectId)(consId) }); } catch (e) {}
      if (!consultant) consultant = await cacheCol.findOne({ sourceId: consId });
      if (!consultant) return { statusCode: 404, headers: hdrs, body: JSON.stringify({ error: 'Consultant not found' }) };

      // Time window (default 7 days per Sunil). Maps period -> days.
      var PERIOD_DAYS = { '1d': 1, '3d': 3, '1w': 7, '2w': 14, '1m': 30 };
      var days = PERIOD_DAYS[body.period] || 7;
      var since = new Date(Date.now() - days * 24 * 60 * 60 * 1000);

      var page = parseInt(body.page) || 0;
      var PAGE = 10;
      var EVAL_CAP = Math.min(parseInt(body.evalCap) || 50, 600);  // ceiling matches cache/job window; was 200 — spent caps permanently blocked in-country scoring
      var NEED = (page + 1) * PAGE;
      var SCORE_CAP = 8;

      var jobsCol = db.collection('jobs');
      // Candidate jobs: in the window, with something to score against. Newest first.
      // #434: currently limited to CONTRACT roles only — that's the staffing business today.
      // Remove the contract clause below to reopen to all job types.
      var jobQuery = {
        $and: [
          { $or: [{ datePosted: { $gte: since } }, { dateScanned: { $gte: since } }] },
          { $or: [{ skills: { $exists: true, $ne: '' } }, { tools: { $exists: true, $ne: '' } }] },
          { $or: [{ jobType: { $regex: 'contract', $options: 'i' } }, { contractDuration: { $exists: true, $nin: [null, ''] } }] }
        ]
      };
      var candidateJobs = await jobsCol.find(jobQuery)
        .project({ title: 1, titleClean: 1, company: 1, location: 1, detectedCountry: 1, salary: 1,
          datePosted: 1, dateScanned: 1, skills: 1, certifications: 1, compliance: 1, tools: 1,
          experience: 1, experienceLevel: 1, jobType: 1, remote: 1, contractDuration: 1, applyLink: 1,
          jobUrl: 1, source: 1, matchCacheRev: 1 })
        .sort({ datePosted: -1, dateScanned: -1 }).limit(500).toArray();

      // Split into already-scored (cached on the consultant) vs to-score.
      // #491: union both caches — job-side scoring writes matchCache[jobId] on this
      // consultant; without this merge those pairs never appear in Match Jobs and the
      // pair gets re-scored with drift. jobMatchCache wins on conflict (same shape).
      var revCache = Object.assign({}, consultant.matchCache || {}, consultant.jobMatchCache || {});
      var preScored = [], toScore = [];
      candidateJobs.forEach(function (j) {
        var key = String(j._id);
        var mc = revCache[key];
        if (mc && mc.v === SCORING_VERSION) {
          preScored.push({ job: j, overall: mc.overall, dimensions: mc.dimensions, reason: mc.reason,
            locationFit: mc.locationFit || null });
        } else {
          toScore.push(j);
        }
      });

      var evaluated = preScored.length;
      var haveNow = preScored.filter(function (m) { return m.overall >= MATCH_THRESHOLD; }).length;
      var moreToScore = false, scoreError = null, newlyScored = [];

      if (haveNow >= NEED) {
        toScore = [];
      } else if (evaluated >= EVAL_CAP) {
        moreToScore = toScore.length > 0; toScore = [];
      } else if (toScore.length) {
        var budget = Math.min(SCORE_CAP, EVAL_CAP - evaluated);
        if (toScore.length > budget) { moreToScore = true; toScore = toScore.slice(0, budget); }
      }

      if (toScore.length) {
        try {
          var weights = DEFAULT_WEIGHTS;
          newlyScored = await scoreJobsForConsultant(consultant, toScore, weights);
          // cache each result on the consultant
          var setOps = {};
          newlyScored.forEach(function (r) {
            setOps['jobMatchCache.' + String(r.job._id)] = {
              overall: r.overall, dimensions: r.dimensions, reason: r.reason,
              locationFit: r.locationFit, v: SCORING_VERSION, scoredAt: new Date()
            };
          });
          if (Object.keys(setOps).length) {
            try { await cacheCol.updateOne({ _id: consultant._id }, { $set: setOps }); } catch (e) {}
          }
        } catch (e) { scoreError = e.message; }
      }

      var all = preScored.concat(newlyScored)
        .filter(function (m) { return m.overall >= MATCH_THRESHOLD; })
        .sort(function (a, b) { return b.overall - a.overall; });

      var start = page * PAGE;
      var pageItems = all.slice(start, start + PAGE);
      var pageIsFull = all.length >= (page + 1) * PAGE;
      var evaluatedTotal = preScored.length + newlyScored.length;
      var unscoredLeft = candidateJobs.length - evaluatedTotal;
      var keepScoring = moreToScore && !pageIsFull && evaluatedTotal < EVAL_CAP && !scoreError;

      // #419: Persist the matches so the list survives closing the popup. We merge into a
      // `matchedJobs` array on the consultant (dedup by jobId, keep the latest score).
      // User deletions are respected via a `matchedJobsRemoved` set — we never re-add a
      // job the user explicitly deleted.
      var removedSet = {};
      (consultant.matchedJobsRemoved || []).forEach(function (id) { removedSet[id] = 1; });
      var existing = {};
      (consultant.matchedJobs || []).forEach(function (mj) { existing[mj.jobId] = mj; });
      all.forEach(function (m) {
        var jid = String(m.job._id);
        if (removedSet[jid]) return;                 // user deleted this — don't resurrect it
        existing[jid] = {
          jobId: jid,
          title: m.job.title || m.job.titleClean || '',
          company: m.job.company || '',
          location: m.job.location || '',
          country: m.job.detectedCountry || '',
          salary: m.job.salary || '',
          datePosted: m.job.datePosted || m.job.dateScanned || null,
          jobType: m.job.jobType || '',
          contractDuration: m.job.contractDuration || '',
          applyLink: m.job.applyLink || m.job.jobUrl || '',
          source: m.job.source || '',
          overall: m.overall, reason: m.reason,
          locationFit: m.locationFit,
          matchedAt: new Date()
        };
      });
      var mergedList = Object.keys(existing).map(function (k) { return existing[k]; })
        .sort(function (a, b) { return b.overall - a.overall; });
      try { await cacheCol.updateOne({ _id: consultant._id }, { $set: { matchedJobs: mergedList } }); } catch (e) {}

      // #447: two-sided persistence — a consultant matched to a job should also appear in
      // that JOB's Matched Candidates. Same lean entry shape as addCandidates; guarded so
      // we never duplicate and never resurrect a candidate the user removed from the job.
      try {
        var wbSid = consultant.sourceId;
        if (!wbSid) {
          // manual consultants have no sourceId — assign one so candidate hydration works
          wbSid = String(consultant._id);
          await cacheCol.updateOne({ _id: consultant._id }, { $set: { sourceId: wbSid } });
          consultant.sourceId = wbSid;
        }
        var wbOps = all.map(function (m) {
          return { updateOne: {
            filter: { _id: m.job._id,
              candidatesRemoved: { $ne: wbSid },
              'candidateProfiles.sourceId': { $ne: wbSid } },
            update: { $push: { candidateProfiles: {
              sourceId: wbSid, overall: m.overall, addedAt: new Date(),
              addedBy: authUser ? authUser.email : '', via: 'matchJobs'
            } } }
          } };
        });
        if (wbOps.length) await jobsCol.bulkWrite(wbOps, { ordered: false });
      } catch (e) { /* write-back is best-effort; the consultant-side list is authoritative */ }

      return { statusCode: 200, headers: hdrs, body: JSON.stringify({
        matches: pageItems.map(function (m) {
          return {
            jobId: String(m.job._id),
            title: m.job.title || m.job.titleClean || '',
            company: m.job.company || '',
            location: m.job.location || '',
            country: m.job.detectedCountry || '',
            salary: m.job.salary || '',
            datePosted: m.job.datePosted || m.job.dateScanned || null,
            jobType: m.job.jobType || '',
            contractDuration: m.job.contractDuration || '',
            applyLink: m.job.applyLink || m.job.jobUrl || '',
            source: m.job.source || '',
            overall: m.overall, dimensions: m.dimensions, reason: m.reason,
            locationFit: m.locationFit
          };
        }),
        page: page, hasMore: all.length > start + PAGE,
        totalMatches: all.length, evaluated: evaluatedTotal,
        jobsInWindow: candidateJobs.length, unscoredLeft: unscoredLeft > 0 ? unscoredLeft : 0,
        period: body.period || '1w', days: days,
        moreToScore: keepScoring,
        canScoreMore: (unscoredLeft > 0) && !keepScoring,
        scoreError: scoreError,
        consultantCountry: profileCountry(consultant)
      }) };
    }

    // ---- #419: listMatchedJobs — return the saved matched-jobs list (NO scoring, free) ----
    if (action === 'listMatchedJobs') {
      var lcId = body.consultantId || '';
      if (!lcId) return { statusCode: 400, headers: hdrs, body: JSON.stringify({ error: 'consultantId required' }) };
      var lcCol = db.collection(CACHE_COLLECTION);
      var lcCons = null;
      try { lcCons = await lcCol.findOne({ _id: new (require('mongodb').ObjectId)(lcId) }); } catch (e) {}
      if (!lcCons) lcCons = await lcCol.findOne({ sourceId: lcId });
      if (!lcCons) return { statusCode: 404, headers: hdrs, body: JSON.stringify({ error: 'Consultant not found' }) };
      var saved = (lcCons.matchedJobs || []).sort(function (a, b) { return b.overall - a.overall; });
      return { statusCode: 200, headers: hdrs, body: JSON.stringify({
        matches: saved, totalMatches: saved.length, consultantCountry: profileCountry(lcCons), saved: true
      }) };
    }

    // ---- #419: deleteMatchedJob — remove one saved match and remember not to re-add it ----
    if (action === 'deleteMatchedJob') {
      var dcId = body.consultantId || '';
      var dJobId = body.jobId || '';
      if (!dcId || !dJobId) return { statusCode: 400, headers: hdrs, body: JSON.stringify({ error: 'consultantId and jobId required' }) };
      var dcCol = db.collection(CACHE_COLLECTION);
      var dFilter = null;
      try { dFilter = { _id: new (require('mongodb').ObjectId)(dcId) }; } catch (e) { dFilter = { sourceId: dcId }; }
      // pull from matchedJobs, add to the removed set so future scoring won't resurrect it
      await dcCol.updateOne(dFilter, {
        $pull: { matchedJobs: { jobId: dJobId } },
        $addToSet: { matchedJobsRemoved: dJobId }
      });
      // #447: mirror the deletion on the job side — but ONLY entries added via matchJobs;
      // candidates added manually through Match Profiles are left untouched.
      try {
        var dCons = await dcCol.findOne(dFilter);
        var dSid = dCons && dCons.sourceId;
        if (dSid) {
          var dOID = require('mongodb').ObjectId;
          var dJFilter; try { dJFilter = { _id: new dOID(dJobId) }; } catch (e) { dJFilter = { jobId: dJobId }; }
          await db.collection('jobs').updateOne(dJFilter,
            { $pull: { candidateProfiles: { sourceId: dSid, via: 'matchJobs' } } });
        }
      } catch (e) { /* best-effort sync */ }
      var dcCons = await dcCol.findOne(dFilter);
      return { statusCode: 200, headers: hdrs, body: JSON.stringify({
        removed: true, remaining: (dcCons && dcCons.matchedJobs ? dcCons.matchedJobs.length : 0)
      }) };
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
    managed: !!m.profile.managed,
    // #461: availability signals — the UI flags people you cannot place right now
    availability: m.profile.availability || '',
    pipelineStatus: m.profile.pipelineStatus || '',
    engagementType: m.profile.engagementType || '',
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
