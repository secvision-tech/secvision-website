const CERT_RE = /CISSP|CISM|CISA|CEH|OSCP|OSCE|GPEN|GCIH|GCIA|GSEC|GREM|CompTIA\s*Security\+|CompTIA\s*CySA\+|CompTIA\s*CASP\+|CompTIA\s*Network\+|SC-100|SC-200|SC-300|SC-400|AZ-500|AZ-900|MS-500|CCSP|CCNA|CCNP|CRISC|CGEIT|SSCP|CPTS|eJPT|eCPPT|PNPT|SANS|GIAC|ITIL|TOGAF/gi;
const COMP_RE = /SOC\s*2|SOC2|ISO\s*27001|ISO\s*27002|NIST\s*(?:SP\s*)?800-53|NIST\s*(?:SP\s*)?800-61|NIST\s*(?:SP\s*)?800-171|NIST\s*(?:SP\s*)?800-37|NIST\s*CSF|PCI[\s-]*DSS|HIPAA|GDPR|FedRAMP|HITRUST|CMMC|CCPA|FISMA|SOX|COBIT|CIS\s*Controls|CIS\s*Benchmarks|MITRE\s*ATT&CK|Zero\s*Trust|TIC\s*3\.0|COSO|ITAR|NERC\s*CIP|FERPA|GLBA|DFARS|ISMS|ISO\s*22301|CSA\s*STAR|cyber\s*kill\s*chain|kill\s*chain\s*framework|Lockheed\s*Martin\s*kill\s*chain|Diamond\s*Model|OWASP\s*Top\s*10|STRIDE|DREAD|FAIR|OCTAVE|ISO\s*31000|NIST\s*RMF|STIX[\s/]*TAXII/gi;
const TOOL_RE = /Microsoft\s*Defender(?:\s*(?:for\s*)?(?:Endpoint|Cloud|Identity|Office|365))?|Microsoft\s*Sentinel|Azure\s*Sentinel|Splunk|QRadar|CrowdStrike|SentinelOne|Palo\s*Alto|Cortex\s*XDR|Cortex\s*XSOAR|LogRhythm|Elastic\s*(?:Security|SIEM|Stack)|Chronicle|Tenable|Qualys|Nessus|Rapid7|InsightVM|Carbon\s*Black|VMware\s*Carbon\s*Black|Fortinet|FortiSIEM|FortiGate|Check\s*Point|Cisco\s*(?:ASA|Firepower|SecureX|Umbrella)|Snort|Suricata|Wireshark|Burp\s*Suite|Metasploit|XSOAR|Phantom|Swimlane|Demisto|KQL|SPL|YARA|Sigma|ServiceNow\s*(?:SecOps|ITSM)?|Jira|Proofpoint|Mimecast|Zscaler|Okta|CyberArk|BeyondTrust|Varonis|DarkTrace|Vectra|Tanium|Exabeam|Securonix|NetWitness|ArcSight|SIEM|SOAR|EDR|XDR|NDR|IDS[\s/]*IPS|DLP|WAF|CASB|CSPM|CWPP|CNAPP|IAM|PAM|MFA|SSO|UEBA|threat\s*intelligence\s*platform|cloud\s*security\s*(?:tools|platforms)/gi;
const SKILL_RE = /incident\s*response|threat\s*(?:hunting|analysis|detection|modeling|reporting|intelligence)|forensic\s*(?:analysis|investigation)|digital\s*forensics|malware\s*(?:analysis|reverse\s*engineering)|reverse\s*engineering|vulnerability\s*(?:management|assessment|scanning)|penetration\s*testing|pen\s*testing|red\s*team(?:ing)?|blue\s*team(?:ing)?|purple\s*team(?:ing)?|security\s*(?:monitoring|operations|engineering|architecture|assessment|automation|orchestration)|SOC\s*(?:operations|monitoring|analysis)|log\s*(?:analysis|management|correlation)|network\s*(?:security|forensics|analysis|monitoring)|cloud\s*security|endpoint\s*(?:security|protection)|identity\s*(?:management|governance)|access\s*(?:management|control)|data\s*(?:loss\s*prevention|protection|classification)|risk\s*(?:assessment|management|analysis)|compliance\s*(?:monitoring|management|auditing)|alert\s*triage|detection\s*engineering|rule\s*(?:writing|development|tuning)|playbook\s*(?:development|automation)|KQL|scripting|Python|PowerShell|Bash|JavaScript|SQL|RegEx|API\s*(?:security|integration)|SDLC|DevSecOps|CI[\s/]*CD|container\s*security|Kubernetes\s*security|RBAC|PKI|encryption|cryptography|PCAP\s*analysis|packet\s*analysis|memory\s*forensics|disk\s*forensics|evidence\s*(?:collection|preservation)|tabletop\s*exercises|disaster\s*recovery|business\s*continuity|patch\s*management|asset\s*management|phishing\s*(?:analysis|simulation)|email\s*security|DNS\s*security|web\s*application\s*security|mobile\s*security|IoT\s*security|OT\s*security|ICS\s*security|SCADA\s*security/gi;

function unique(text, re) {
  if (!text) return [];
  var m = text.match(re) || [], seen = {};
  return m.filter(function(v) { var k = v.toLowerCase().replace(/\s+/g,' ').trim(); if (seen[k]) return false; seen[k] = true; return true; }).slice(0, 12);
}

function extractExp(job) {
  var d = job.job_description || '', parts = [], seen = {};
  // P1: "X+ years of [adj] experience in/with..." #70: added work|practical|industry|related|combined|prior|recent
  var p1 = /(\d+)\+?\s*years?\s*(?:of\s*)?(?:demonstrated\s*|proven\s*|hands[\s\-\u2010\u2011]*on\s*|relevant\s*|professional\s*|progressive\s*|direct\s*|solid\s*|extensive\s*|total\s*|work\s*|practical\s*|industry\s*|related\s*|combined\s*|cumulative\s*|prior\s*|recent\s*)?(?:experience|expertise|background)\s*(?:in|with|working\s*(?:in|with)|leading|managing|performing|supporting|conducting|across|within|using|on)?\s*([\w\s,\/&\-\u2010\u2013()]+?)(?:\.|;|\n|,\s*(?:with|including|and|or|in|plus|specific))/gi;
  var m; while ((m = p1.exec(d)) !== null && parts.length < 5) {
    var c = m[2].trim().slice(0, 40).replace(/^\s*(?:a|an|the)\s*/i, '');
    if (c.length < 3) continue; var k = m[1] + c.toLowerCase();
    if (!seen[k]) { seen[k] = true; parts.push(m[1] + '+ yr ' + c); }
  }
  // P2: "X-Y years [of experience]" - validate range 1-30
  var p2 = /(\d+)\s*[\-\u2013]+\s*(\d+)\s*(?:years?\s*)?(?:of\s*)?(?:[\w\s]*)?(?:experience|expertise)?/gi;
  while ((m = p2.exec(d)) !== null && parts.length < 5) {
    var y1 = parseInt(m[1]), y2 = parseInt(m[2]);
    if (y1 < 1 || y1 > 30 || y2 < 1 || y2 > 30 || y2 <= y1) continue;
    var k2 = m[1]+'-'+m[2]; if (!seen[k2]) { seen[k2] = true; parts.unshift(m[1]+'-'+m[2]+' years'); }
  }
  // P3: "minimum/at least/requires X years"
  var p3 = /(?:minimum|at\s*least|requires?)\s*(\d+)\+?\s*years?\s*(?:of\s*)?(?:[\w\-\u2010\u2011\s]*)?(?:experience|expertise)\s*(?:in|with|using)?\s*([\w\s,\/&\-]+?)(?:\.|;|,|\n|$)/gi;
  while ((m = p3.exec(d)) !== null && parts.length < 5) {
    var c3 = m[2].trim().slice(0, 35); if (c3.length < 3) continue;
    var k3 = 'min'+m[1]+c3.toLowerCase(); if (!seen[k3]) { seen[k3] = true; parts.push(m[1]+'+ yr '+c3); }
  }
  // P5: #71 "Experience Required: 8-10" or "Experience: 5+" or "Years of Experience: 7"
  var p5 = /(?:experience|expertise|years\s*of\s*experience)\s*(?:required|needed|level|range)?\s*:\s*(\d+)\s*[\-\u2013to]*\s*(\d+)?\s*\+?\s*(?:years?)?/gi;
  while ((m = p5.exec(d)) !== null && parts.length < 5) {
    var val = m[2] ? m[1]+'-'+m[2]+' years' : m[1]+'+ years';
    var k5 = 'p5'+m[1]+(m[2]||''); if (!seen[k5]) { seen[k5] = true; parts.push(val); }
  }
  // P6: Bullet point "* X+ years of work experience with..."
  var p6 = /[\u2022\-\*]\s*(\d+)\+?\s*years?\s*(?:of\s*)?(?:[\w\s]*?)(?:experience|expertise|background)\s*(?:in|with|on|across)?\s*([\w\s,\/&\-\u2010\u2013()]+?)(?:\.|;|\n|$)/gi;
  while ((m = p6.exec(d)) !== null && parts.length < 5) {
    var c6 = m[2].trim().slice(0, 35); if (c6.length < 3) continue;
    var k6 = 'p6'+m[1]+c6.toLowerCase(); if (!seen[k6]) { seen[k6] = true; parts.push(m[1]+'+ yr '+c6); }
  }
  // P4: Broad fallback
  if (parts.length === 0) {
    var p4 = /(\d+)\+?\s*years?\s*(?:of\s*)?(?:[\w\s,\-\u2010\u2011]*?)(?:experience|expertise)/gi;
    while ((m = p4.exec(d)) !== null && parts.length < 3) {
      var k4 = 'f'+m[1]; if (!seen[k4]) { seen[k4] = true; parts.push(m[1]+'+ years'); }
    }
  }
  if (parts.length === 0 && job.job_required_experience?.required_experience_in_months)
    parts.push(Math.round(job.job_required_experience.required_experience_in_months / 12) + '+ years');
  return parts.length ? parts.join(', ') : 'Not specified';
}

function extractElig(job) {
  var i = [], d = job.job_description || '', e = job.job_required_education;
  if (e) { if (e.postgraduate_degree) i.push('Postgraduate'); else if (e.bachelors_degree) i.push("Bachelor's"); else if (e.associates_degree) i.push("Associate's"); }
  if (/clearance|TS[\s/]*SCI|Secret\s*clearance/i.test(d)) i.push('Security Clearance');
  if (/U\.?S\.?\s*citizen/i.test(d)) i.push('US Citizen');
  if (/authorized\s*to\s*work/i.test(d)) i.push('Work Auth');
  return i.length ? i.join(', ') : 'See details';
}

// #46: Handle $XX.XX/hr, total compensation, salary range formats
function extractSalary(job) {
  if (job.job_min_salary && job.job_max_salary) {
    var s = job.job_salary_period === 'HOUR' ? '/hr' : '/yr';
    return '$'+Math.round(job.job_min_salary).toLocaleString()+'-$'+Math.round(job.job_max_salary).toLocaleString()+s;
  }
  var d = job.job_description || '';
  // Pattern: $XX.XX/hr - $YY.YY/hr or "set between $X and $Y"
  var m1 = d.match(/\$\s*([\d,.]+)\s*\/\s*(hr|hour)\s*(?:and|to|[\-\u2013])\s*\$?\s*([\d,.]+)\s*\/?\s*(?:hr|hour)?/i);
  if (m1) return '$'+m1[1]+'/hr - $'+m1[3]+'/hr';
  // Pattern: "between $X/hr and $Y/hr" or "set between $X and $Y"
  var m2 = d.match(/(?:between|from)\s*\$\s*([\d,.]+)\s*(?:\/\s*(?:hr|hour)\s*)?(?:and|to|[\-\u2013])\s*\$?\s*([\d,.]+)\s*(?:\/?\s*(?:hr|hour))?/i);
  if (m2) {
    var isHourly = /\/\s*(?:hr|hour)|per\s*hour|hourly/i.test(d.substring(Math.max(0,d.indexOf(m2[0])-30), d.indexOf(m2[0])+m2[0].length+30));
    return '$'+m2[1]+'-$'+m2[2]+(isHourly?'/hr':'/yr');
  }
  // Pattern: "$X,000 - $Y,000" with optional /yr /hr
  var m3 = d.match(/\$\s*([\d,]+(?:\.\d{1,2})?)\s*[\-\u2013to]+\s*\$?\s*([\d,]+(?:\.\d{1,2})?)\s*\+?\s*(?:\/?\s*)?(per\s*hour|per\s*year|hourly|annually|\/hr|\/yr|\/hour|\/year)?/i);
  if (m3) {
    var suffix = /hour|hr/i.test(m3[3]||'') ? '/hr' : '/yr';
    return '$'+m3[1]+'-$'+m3[2]+suffix;
  }
  // Pattern: "total compensation ... $X - $Y" or "compensation ... $X,000"
  var m4 = d.match(/(?:compensation|salary|pay)\s*(?:[\w\s]*?)\$\s*([\d,]+)\s*[\-\u2013to]+\s*\$?\s*([\d,]+)/i);
  if (m4) return '$'+m4[1]+'-$'+m4[2]+'/yr';
  return 'Not disclosed';
}

function extractContact(job) {
  var d = job.job_description || '';
  // Only extract real contact emails (not generic/company emails)
  var emailMatch = d.match(/(?:contact|email|reach|send|apply|submit|inquir)\w*\s*(?:at|to|:)\s*([\w.\-+]+@[\w.\-]+\.[\w]{2,})/i);
  if (!emailMatch) {
    // Try standalone email but validate it's a person email, not noreply/info/support
    var anyEmail = d.match(/([\w.\-+]+@[\w.\-]+\.[\w]{2,})/);
    if (anyEmail && !/noreply|no-reply|donotreply|notifications|info@|support@|careers@|jobs@|apply@|recruiting@|admin@/i.test(anyEmail[1])) {
      emailMatch = anyEmail;
    }
  }
  // Only match names that are explicitly labeled as recruiter/HR/contact
  var namePatterns = [
    /(?:recruiter|hiring\s*manager|talent\s*acquisition\s*(?:specialist|manager|lead)?|HR\s*(?:manager|director|contact))\s*:?\s*-?\s*([A-Z][a-z]{2,}\s+[A-Z][a-z]{2,})/,
    /(?:point\s*of\s*contact|POC)\s*:?\s*-?\s*([A-Z][a-z]{2,}\s+[A-Z][a-z]{2,})/,
    /([A-Z][a-z]{2,}\s+[A-Z][a-z]{2,})\s*,?\s*(?:Recruiter|Talent\s*Acquisition|HR\s*Manager|Hiring\s*Manager)/
  ];
  var name = '';
  for (var i = 0; i < namePatterns.length; i++) {
    var nm = d.match(namePatterns[i]);
    if (nm) { name = nm[1]; break; }
  }
  var email = emailMatch ? (emailMatch[1] || emailMatch[0]) : '';
  if (/noreply|no-reply|donotreply|notifications/i.test(email)) email = '';
  if (name && email) return name + ' (' + email + ')';
  if (email) return email;
  if (name) return name;
  return 'See details';
}

// #45, #49, #50: Smart job type detection from description
function detectJobType(job) {
  var apiType = job.job_employment_type || '';
  var d = job.job_description || '';
  var salary = extractSalary(job);

  // First check API structured type
  var typeMap = { 'FULLTIME':'Full-time','FULL_TIME':'Full-time','PARTTIME':'Part-time','PART_TIME':'Part-time',
    'CONTRACTOR':'Contract','CONTRACT':'Contract','INTERN':'Internship','INTERNSHIP':'Internship',
    'TEMPORARY':'Temporary','VOLUNTEER':'Volunteer','PER_DIEM':'Per Diem' };
  var mapped = typeMap[apiType.toUpperCase().trim()];

  // Now analyze description for contract signals
  var contractSignals = 0, fulltimeSignals = 0;

  // Strong contract indicators
  if (/\bcontract\s*(?:position|role|opportunity|assignment|engagement|basis|duration|length)\b/i.test(d)) contractSignals += 3;
  if (/\b(?:W-?2|1099|C2C|Corp[\s-]*to[\s-]*Corp)\b/i.test(d)) contractSignals += 3;
  if (/\b(?:contract[\s-]*to[\s-]*hire|temp[\s-]*to[\s-]*perm)\b/i.test(d)) contractSignals += 3;
  if (/\b\d+\+?\s*(?:month|months|mo)\s*(?:contract|engagement|assignment|duration)\b/i.test(d)) contractSignals += 3;
  if (/\bduration\s*:?\s*\d+\+?\s*(?:month|months|week|weeks)\b/i.test(d)) contractSignals += 3;
  if (/\b(?:contract|engagement)\s*(?:length|duration|period)\s*:?\s*\d+/i.test(d)) contractSignals += 3;
  if (/\b(?:with\s*(?:possible\s*)?extension)\b/i.test(d)) contractSignals += 2;
  if (/\/\s*(?:hr|hour)\b/i.test(salary)) contractSignals += 2;
  if (/\bcontract\s*(?:only|worker|staff|employee|personnel)\b/i.test(d)) contractSignals += 2;
  // Weak: just "contractor" mentioned in passing (like "manage contractor staff") - not counted

  // Strong full-time indicators
  if (/\bfull[\s-]*time\s*(?:position|role|opportunity|employee|employment)\b/i.test(d)) fulltimeSignals += 3;
  if (/\b(?:benefits|401k|401\(k\)|PTO|paid\s*time\s*off|medical|dental|vision)\b/i.test(d)) fulltimeSignals += 2;
  if (/\b(?:annual|yearly)\s*(?:salary|compensation|bonus)\b/i.test(d)) fulltimeSignals += 2;
  if (/\btotal\s*compensation\b/i.test(d)) fulltimeSignals += 2;
  if (/\/\s*(?:yr|year)\b/i.test(salary) && !salary.includes('Not disclosed')) fulltimeSignals += 1;
  if (/\bsalaried\b/i.test(d)) fulltimeSignals += 3;

  // Part-time indicators
  var partTimeSignals = /\bpart[\s-]*time\b/i.test(d) ? 3 : 0;

  // Internship indicators
  var internSignals = /\bintern(?:ship)?\b/i.test(d) ? 3 : 0;

  // Decision logic: description analysis overrides API type only if strong signals
  if (contractSignals >= 3 && contractSignals > fulltimeSignals) return 'Contract';
  if (fulltimeSignals >= 3 && fulltimeSignals > contractSignals) return 'Full-time';
  if (partTimeSignals >= 3) return 'Part-time';
  if (internSignals >= 3) return 'Internship';
  // Fall back to API type if available
  if (mapped) return mapped;
  // Final fallback: analyze salary hints
  if (salary.includes('/hr')) return 'Contract';
  if (salary.includes('/yr')) return 'Full-time';
  return 'Not specified';
}

// #60: Detect remote from both API field and description
function detectRemote(job) {
  if (job.job_is_remote) return 'Yes';
  var d = (job.job_description || '') + ' ' + (job.job_title || '');
  if (/\b(?:fully\s*remote|100%\s*remote|remote\s*(?:position|role|opportunity|work|only)|work\s*(?:from\s*home|remotely)|telecommute|telework)\b/i.test(d)) return 'Yes';
  if (/\bhybrid\b/i.test(d)) return 'Hybrid';
  return 'No';
}

// #68: Clean job title - strip clearance prefixes, location suffixes, keep core role
function cleanTitle(title) {
  if (!title) return 'N/A';
  var clean = title;
  // Remove clearance prefixes: "TS/SCI w/ CI Poly Cleared", "Secret Cleared", "Top Secret"
  clean = clean.replace(/^(?:TS[\s/]*SCI[\s/]*(?:w\/?\s*)?(?:CI\s*Poly\s*)?(?:Cleared\s*)?|Top[\s-]*Secret\s*(?:Cleared\s*)?|Secret\s*(?:Cleared\s*)?|Public\s*Trust\s*(?:Cleared\s*)?)/i, '').trim();
  // Remove trailing location/remote: "| Remote US", "- Remote", "(Hybrid)", "- Arlington, VA"
  clean = clean.replace(/\s*[\|–\-]\s*(?:Remote\s*(?:US|USA|UK|CA)?|Hybrid|On[\s-]*site|Onsite)\s*$/i, '').trim();
  clean = clean.replace(/\s*[\|–\-]\s*[A-Z][a-z]+(?:,\s*[A-Z]{2})?\s*$/i, '').trim();
  clean = clean.replace(/\s*\((?:Remote|Hybrid|On[\s-]*site|REMOTE|HYBRID)\)\s*$/i, '').trim();
  // Remove trailing clearance: "- TS/SCI Required", "(Secret Clearance)"
  clean = clean.replace(/\s*[\|–\-]\s*(?:TS[\s/]*SCI|Secret|Top\s*Secret|Clearance)[\w\s]*/i, '').trim();
  clean = clean.replace(/\s*\((?:TS[\s/]*SCI|Secret|Clearance)[^)]*\)\s*$/i, '').trim();
  // Remove leading/trailing dashes, pipes
  clean = clean.replace(/^[\s\-–|:]+|[\s\-–|:]+$/g, '').trim();
  return clean || title;
}

// #69: Detect actual country from job data and description
var COUNTRY_MAP = {
  'US':'United States','USA':'United States','United States':'United States',
  'CA':'Canada','Canada':'Canada',
  'GB':'United Kingdom','UK':'United Kingdom','United Kingdom':'United Kingdom',
  'DE':'Germany','Germany':'Germany',
  'FR':'France','France':'France',
  'AU':'Australia','Australia':'Australia',
  'IN':'India','India':'India',
  'SG':'Singapore','Singapore':'Singapore',
  'IE':'Ireland','Ireland':'Ireland',
  'NL':'Netherlands','Netherlands':'Netherlands',
  'CH':'Switzerland','Switzerland':'Switzerland',
  'SE':'Sweden','Sweden':'Sweden',
  'AE':'UAE','UAE':'United Arab Emirates','United Arab Emirates':'United Arab Emirates',
  'IL':'Israel','Israel':'Israel',
  'JP':'Japan','Japan':'Japan',
  'BR':'Brazil','Brazil':'Brazil',
  'MX':'Mexico','Mexico':'Mexico',
  'ZA':'South Africa','South Africa':'South Africa',
  'NZ':'New Zealand','New Zealand':'New Zealand'
};
var US_STATES = /\b(?:Alabama|Alaska|Arizona|Arkansas|California|Colorado|Connecticut|Delaware|Florida|Georgia|Hawaii|Idaho|Illinois|Indiana|Iowa|Kansas|Kentucky|Louisiana|Maine|Maryland|Massachusetts|Michigan|Minnesota|Mississippi|Missouri|Montana|Nebraska|Nevada|New\s*Hampshire|New\s*Jersey|New\s*Mexico|New\s*York|North\s*Carolina|North\s*Dakota|Ohio|Oklahoma|Oregon|Pennsylvania|Rhode\s*Island|South\s*Carolina|South\s*Dakota|Tennessee|Texas|Utah|Vermont|Virginia|Washington|West\s*Virginia|Wisconsin|Wyoming|D\.?C\.?)\b/i;
var US_STATE_CODES = /,\s*(?:AL|AK|AZ|AR|CA|CO|CT|DE|FL|GA|HI|ID|IL|IN|IA|KS|KY|LA|ME|MD|MA|MI|MN|MS|MO|MT|NE|NV|NH|NJ|NM|NY|NC|ND|OH|OK|OR|PA|RI|SC|SD|TN|TX|UT|VT|VA|WA|WV|WI|WY|DC)\b/;

function detectCountry(job) {
  // Priority 1: API structured country field
  var apiCountry = job.job_country || '';
  if (apiCountry && COUNTRY_MAP[apiCountry]) return COUNTRY_MAP[apiCountry];

  // Priority 2: Location fields
  var loc = [job.job_city, job.job_state, job.job_country].filter(Boolean).join(', ');
  for (var k in COUNTRY_MAP) {
    if (loc.indexOf(k) !== -1) return COUNTRY_MAP[k];
  }

  // Priority 3: Scan title and first 500 chars of description
  var text = (job.job_title || '') + ' ' + (job.job_description || '').slice(0, 500);
  if (US_STATES.test(text) || US_STATE_CODES.test(text) || /\bRemote\s*US\b|\bUSA\b|\bUnited\s*States\b/i.test(text)) return 'United States';
  if (/\bRemote\s*(?:UK|GB)\b|\bUnited\s*Kingdom\b|\bLondon\b|\bManchester\b/i.test(text)) return 'United Kingdom';
  if (/\bRemote\s*CA\b|\bCanada\b|\bToronto\b|\bVancouver\b|\bMontreal\b|\bOttawa\b/i.test(text)) return 'Canada';
  if (/\bRemote\s*(?:AU)\b|\bAustralia\b|\bSydney\b|\bMelbourne\b/i.test(text)) return 'Australia';
  if (/\bIndia\b|\bBangalore\b|\bMumbai\b|\bHyderabad\b|\bPune\b|\bDelhi\b/i.test(text)) return 'India';
  if (/\bGermany\b|\bBerlin\b|\bMunich\b|\bFrankfurt\b/i.test(text)) return 'Germany';

  return 'Unknown';
}

exports.handler = async (event) => {
  if (event.httpMethod === 'OPTIONS')
    return { statusCode: 204, headers: { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': 'Content-Type', 'Access-Control-Allow-Methods': 'POST, OPTIONS' }, body: '' };
  if (event.httpMethod !== 'POST')
    return { statusCode: 405, body: JSON.stringify({ error: 'Method not allowed' }) };
  var hdrs = { 'Access-Control-Allow-Origin': '*', 'Content-Type': 'application/json' };
  try {
    var body = JSON.parse(event.body);
    var apiKey = process.env.JSEARCH_API_KEY;
    if (!apiKey) return { statusCode: 500, headers: hdrs, body: JSON.stringify({ error: 'API key not configured' }) };
    var roles = body.roles || [body.query || 'cybersecurity'];
    var country = body.country || 'us';
    var isUSCA = !body.country || body.country === 'us' || body.country === 'ca';
    var countryName = body.countryName || '';
    var pagesPerRole = Math.min(Math.max(1, Math.ceil((body.pages||10) / roles.length)), 5);
    var allJobs = [], seenIds = {}, totalApiCalls = 0, startTime = Date.now();

    async function fetchPage(query, page, ctry, useEmpType) {
      if (Date.now() - startTime > 22000) return [];
      var params = new URLSearchParams({ query: query, page: String(page), num_pages: '1', country: ctry, date_posted: body.datePosted || 'all' });
      if (useEmpType && body.employmentTypes) params.set('employment_types', body.employmentTypes);
      try {
        var r = await fetch('https://jsearch.p.rapidapi.com/search?' + params, {
          headers: { 'x-rapidapi-host': 'jsearch.p.rapidapi.com', 'x-rapidapi-key': apiKey }
        });
        totalApiCalls++;
        if (!r.ok) return []; var d = await r.json(); return d.data || [];
      } catch (e) { return []; }
    }

    function addJobs(jobs) {
      jobs.forEach(function(job) {
        var jid = job.job_id || (job.employer_name + '|' + job.job_title);
        if (!seenIds[jid]) { seenIds[jid] = true; allJobs.push(job); }
      });
    }

    await Promise.all(roles.map(async function(role) {
      var pp = [], gotResults = false;
      if (isUSCA) {
        // US/CA: use country param with employment filter
        for (var p = 1; p <= pagesPerRole; p++) pp.push(fetchPage(role, p, country, true));
        var results = await Promise.all(pp);
        results.forEach(function(jobs) { if (jobs.length) gotResults = true; addJobs(jobs); });
      } else {
        // Non-US/CA: try local country code first (works for India, Japan, etc.)
        for (var p = 1; p <= pagesPerRole; p++) pp.push(fetchPage(role, p, country, false));
        var results = await Promise.all(pp);
        results.forEach(function(jobs) { if (jobs.length) gotResults = true; addJobs(jobs); });

        // Per-role fallback: if local country returned 0, search US index with country name
        if (!gotResults && countryName) {
          var fbQuery = role + ' ' + countryName;
          var fb = await fetchPage(fbQuery, 1, 'us', false);
          addJobs(fb);
        }
      }
    }));

    var jobs = allJobs.map(function(job, i) {
      var rawDesc = job.job_description || '';
      // #73: Strip HTML tags, style blocks, and CSS from descriptions
      var desc = rawDesc.replace(/<style[^>]*>[\s\S]*?<\/style>/gi, '')
        .replace(/<script[^>]*>[\s\S]*?<\/script>/gi, '')
        .replace(/<[^>]+>/g, ' ')
        .replace(/\s{2,}/g, ' ')
        .trim();
      var fullText = desc + ' ' + (job.job_highlights?.Qualifications || []).join(' ') + ' ' + (job.job_highlights?.Responsibilities || []).join(' ');
      var apiSkills = (job.job_required_skills || []).slice(0, 6);
      var exSkills = unique(fullText, SKILL_RE);
      var ss = {}, fs = [];
      apiSkills.concat(exSkills).forEach(function(s) { var k = s.toLowerCase().trim(); if (!ss[k] && fs.length < 10) { ss[k] = true; fs.push(s); } });
      // #62: Extract actual client company if staffing agency pattern found
      var actualCompany = job.employer_name || 'N/A';
      var clientPatterns = [
        /(?:our\s*client|the\s*client|client\s*company)\s*,?\s*(?:is\s*)?([\w\s&.,']+?)\s*,?\s*(?:is\s*(?:seeking|looking|hiring|searching)|seeks|needs|requires)/i,
        /(?:on\s*behalf\s*of|partnered\s*with|working\s*with|representing)\s*([\w\s&.,']+?)\s*(?:,|to\s*find|who\s*is|that\s*is)/i,
        /(?:hiring\s*for|staffing\s*for|recruiting\s*for)\s*([\w\s&.,']+?)(?:\.|,|\s*-|\s*who)/i
      ];
      // Words that cannot start a company name
      var badStarts = /^(?:over|under|about|with|the|a|an|and|or|for|in|at|to|from|by|on|is|are|was|were|has|have|had|will|would|can|could|may|might|shall|should|must|not|no|all|any|each|every|some|many|much|more|most|few|less|other|another|such|this|that|these|those|than|then|now|here|there|where|when|how|what|which|who|whom|whose|why|if|so|up|out|off|down|\d+)\b/i;
      for (var cp = 0; cp < clientPatterns.length; cp++) {
        var cm = desc.match(clientPatterns[cp]);
        if (cm) {
          var candidate = cm[1].trim().replace(/[,.']+$/, '');
          // Validate: length 3-60, starts with uppercase letter, not a common word
          if (candidate.length >= 3 && candidate.length <= 60 && /^[A-Z]/.test(candidate) && !badStarts.test(candidate)) {
            actualCompany = candidate;
            break;
          }
        }
      }
      // #63: Build company URL - use employer_website if available, else Google I'm Feeling Lucky
      var companyWebUrl = job.employer_website || '';
      if (!companyWebUrl) {
        companyWebUrl = 'https://www.google.com/search?btnI=1&q=' + encodeURIComponent(actualCompany + ' official website');
      }
      return {
        idx: i + 1, id: job.job_id,
        date: job.job_posted_at_datetime_utc ? new Date(job.job_posted_at_datetime_utc).toLocaleDateString('en-US') : 'N/A',
        dateRaw: job.job_posted_at_datetime_utc || '',
        title: job.job_title || 'N/A', titleClean: cleanTitle(job.job_title), company: actualCompany,
        companyUrl: companyWebUrl,
        location: [job.job_city, job.job_state, job.job_country].filter(Boolean).join(', ') || 'Remote',
        detectedCountry: detectCountry(job),
        experience: extractExp(job),
        skills: fs.length ? fs.join(', ') : 'See details',
        certifications: unique(fullText, CERT_RE).join(', ') || 'See details',
        compliance: unique(fullText, COMP_RE).join(', ') || 'See details',
        tools: unique(fullText, TOOL_RE).join(', ') || 'See details',
        eligibility: extractElig(job), salary: extractSalary(job),
        contact: extractContact(job),
        source: job.job_publisher || 'Unknown',
        jobType: detectJobType(job),
        remote: detectRemote(job),
        applyLink: job.job_apply_link || '', description: desc,
        qualifications: job.job_highlights?.Qualifications || [],
        responsibilities: job.job_highlights?.Responsibilities || [],
        benefits: job.job_highlights?.Benefits || []
      };
    });

    // Auto-save to MongoDB
    var savedCount = 0;
    try {
      var { getDb } = require('./db');
      var db = await getDb();
      var col = db.collection('jobs');
      var userEmail = body.userEmail || 'anonymous';
      var ops = jobs.map(function(j) {
        return {
          updateOne: {
            filter: { jobId: j.id },
            update: { $set: {
              jobId: j.id, datePosted: j.dateRaw ? new Date(j.dateRaw) : null, dateScanned: new Date(),
              title: j.title, titleClean: j.titleClean, company: j.company, companyUrl: j.companyUrl,
              location: j.location, detectedCountry: j.detectedCountry, experience: j.experience,
              skills: j.skills, certifications: j.certifications, compliance: j.compliance,
              tools: j.tools, eligibility: j.eligibility, salary: j.salary, contact: j.contact,
              source: j.source, jobType: j.jobType, remote: j.remote, applyLink: j.applyLink,
              description: j.description, qualifications: j.qualifications,
              responsibilities: j.responsibilities, benefits: j.benefits
            }, $setOnInsert: { status: 'new', companyType: '', notes: '', searchedBy: userEmail,
              searchRegion: body.searchRegion || '', searchCountry: body.country || 'us', createdAt: new Date() }
            },
            upsert: true
          }
        };
      });
      if (ops.length > 0) {
        var result = await col.bulkWrite(ops, { ordered: false });
        savedCount = (result.upsertedCount || 0) + (result.modifiedCount || 0);
      }
    } catch (dbErr) {
      console.error('MongoDB save error:', dbErr.message);
      // Don't fail the response if DB save fails
    }

    return { statusCode: 200, headers: hdrs, body: JSON.stringify({ jobs: jobs, totalResults: jobs.length, apiCalls: totalApiCalls, rolesSearched: roles, savedToDb: savedCount }) };
  } catch (err) {
    console.error('Error:', err);
    return { statusCode: 500, headers: hdrs, body: JSON.stringify({ error: 'Internal server error' }) };
  }
};
