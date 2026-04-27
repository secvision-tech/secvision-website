// Security Certifications only
const CERT_RE = /CISSP|CISM|CISA|CEH|OSCP|OSCE|GPEN|GCIH|GCIA|GSEC|GREM|CompTIA\s*Security\+|CompTIA\s*CySA\+|CompTIA\s*CASP\+|CompTIA\s*Network\+|SC-100|SC-200|SC-300|SC-400|AZ-500|AZ-900|MS-500|CCSP|CCNA|CCNP|CRISC|CGEIT|SSCP|CPTS|eJPT|eCPPT|PNPT|SANS|GIAC|ITIL|TOGAF/gi;

// Compliance frameworks only (separate from certs)
const COMP_RE = /SOC\s*2|SOC2|ISO\s*27001|ISO\s*27002|NIST\s*(?:SP\s*)?800-53|NIST\s*CSF|NIST\s*800-171|PCI[\s-]*DSS|HIPAA|GDPR|FedRAMP|HITRUST|CMMC|CCPA|FISMA|SOX|COBIT|CIS\s*Controls|CIS\s*Benchmarks|MITRE\s*ATT&CK|Zero\s*Trust|TIC\s*3\.0|COSO|ITAR|NERC\s*CIP|FERPA|GLBA|DFARS|ISMS|ISO\s*22301|CSA\s*STAR/gi;

// Tools - fixed TIP to require full phrase, not standalone word
const TOOL_RE = /Microsoft\s*Defender(?:\s*(?:for\s*)?(?:Endpoint|Cloud|Identity|Office|365))?|Microsoft\s*Sentinel|Azure\s*Sentinel|Splunk|QRadar|CrowdStrike|SentinelOne|Palo\s*Alto|Cortex\s*XDR|Cortex\s*XSOAR|LogRhythm|Elastic\s*(?:Security|SIEM|Stack)|Chronicle|Tenable|Qualys|Nessus|Rapid7|InsightVM|Carbon\s*Black|VMware\s*Carbon\s*Black|Fortinet|FortiSIEM|FortiGate|Check\s*Point|Cisco\s*(?:ASA|Firepower|SecureX|Umbrella)|Snort|Suricata|Wireshark|Burp\s*Suite|Metasploit|XSOAR|Phantom|Swimlane|Demisto|KQL|SPL|YARA|Sigma|ServiceNow\s*(?:SecOps|ITSM)?|Jira|Proofpoint|Mimecast|Zscaler|Okta|CyberArk|BeyondTrust|Varonis|DarkTrace|Vectra|Tanium|Exabeam|Securonix|NetWitness|ArcSight|SIEM|SOAR|EDR|XDR|NDR|IDS[\s/]*IPS|DLP|WAF|CASB|CSPM|CWPP|CNAPP|IAM|PAM|MFA|SSO|UEBA|threat\s*intelligence\s*platform|cloud\s*security\s*(?:tools|platforms)/gi;

// Technical skills
const SKILL_RE = /incident\s*response|threat\s*(?:hunting|analysis|detection|modeling|reporting|intelligence)|forensic\s*(?:analysis|investigation)|digital\s*forensics|malware\s*(?:analysis|reverse\s*engineering)|reverse\s*engineering|vulnerability\s*(?:management|assessment|scanning)|penetration\s*testing|pen\s*testing|red\s*team(?:ing)?|blue\s*team(?:ing)?|purple\s*team(?:ing)?|security\s*(?:monitoring|operations|engineering|architecture|assessment|automation|orchestration)|SOC\s*(?:operations|monitoring|analysis)|log\s*(?:analysis|management|correlation)|network\s*(?:security|forensics|analysis|monitoring)|cloud\s*security|endpoint\s*(?:security|protection)|identity\s*(?:management|governance)|access\s*(?:management|control)|data\s*(?:loss\s*prevention|protection|classification)|risk\s*(?:assessment|management|analysis)|compliance\s*(?:monitoring|management|auditing)|alert\s*triage|detection\s*engineering|rule\s*(?:writing|development|tuning)|playbook\s*(?:development|automation)|KQL|scripting|Python|PowerShell|Bash|JavaScript|SQL|RegEx|API\s*(?:security|integration)|SDLC|DevSecOps|CI[\s/]*CD|container\s*security|Kubernetes\s*security|RBAC|PKI|encryption|cryptography|PCAP\s*analysis|packet\s*analysis|memory\s*forensics|disk\s*forensics|evidence\s*(?:collection|preservation)|tabletop\s*exercises|disaster\s*recovery|business\s*continuity|patch\s*management|asset\s*management|phishing\s*(?:analysis|simulation)|email\s*security|DNS\s*security|web\s*application\s*security|mobile\s*security|IoT\s*security|OT\s*security|ICS\s*security|SCADA\s*security/gi;

function unique(text, re) {
  if (!text) return [];
  var m = text.match(re) || [], seen = {};
  return m.filter(function(v) {
    var k = v.toLowerCase().replace(/\s+/g, ' ').trim();
    if (seen[k]) return false; seen[k] = true; return true;
  }).slice(0, 12);
}

function extractExp(job) {
  var d = job.job_description || '', parts = [], seen = {};
  // P1: "X+ years of [adj] experience [working] in/with ..."
  var p1 = /(\d+)\+?\s*years?\s*(?:of\s*)?(?:demonstrated\s*|proven\s*|hands[\s\-\u2010\u2011]*on\s*|relevant\s*|professional\s*|progressive\s*|direct\s*|solid\s*|extensive\s*)?(?:experience|expertise)\s*(?:in|with|working\s*(?:in|with)|leading|managing|performing|supporting|conducting|across|within|using)?\s*([\w\s,/&\-\u2010\u2013()]+?)(?:\.|;|\n|,\s*(?:with|including|and|or|in|plus|specific))/gi;
  var m; while ((m = p1.exec(d)) !== null && parts.length < 5) {
    var c = m[2].trim().slice(0, 40).replace(/^\s*(?:a|an|the)\s*/i, '');
    if (c.length < 3) continue; var k = m[1] + c.toLowerCase();
    if (!seen[k]) { seen[k] = true; parts.push(m[1] + '+ yr ' + c); }
  }
  // P2: "X-Y years of experience"
  var p2 = /(\d+)\s*[\-\u2013]+\s*(\d+)\s*years?\s*(?:of\s*)?(?:experience|expertise)/gi;
  while ((m = p2.exec(d)) !== null && parts.length < 5) {
    var k2 = m[1]+'-'+m[2]; if (!seen[k2]) { seen[k2] = true; parts.unshift(m[1]+'-'+m[2]+' years'); }
  }
  // P3: "at least/minimum X years of [adj] experience in..."
  var p3 = /(?:minimum|at\s*least|requires?)\s*(\d+)\+?\s*years?\s*(?:of\s*)?(?:[\w\-\u2010\u2011\s]*)?(?:experience|expertise)\s*(?:in|with|using)?\s*([\w\s,/&\-]+?)(?:\.|;|,|\n|$)/gi;
  while ((m = p3.exec(d)) !== null && parts.length < 5) {
    var c3 = m[2].trim().slice(0, 35);
    if (c3.length < 3) continue; var k3 = 'min'+m[1]+c3.toLowerCase();
    if (!seen[k3]) { seen[k3] = true; parts.push(m[1]+'+ yr '+c3); }
  }
  // P4: Broad fallback "X+ years experience"
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

function extractSalary(job) {
  if (job.job_min_salary && job.job_max_salary) {
    var s = job.job_salary_period === 'HOUR' ? '/hr' : '/yr';
    return '$'+Math.round(job.job_min_salary).toLocaleString()+'-$'+Math.round(job.job_max_salary).toLocaleString()+s;
  }
  var m = (job.job_description||'').match(/\$\s*([\d,]+)\s*[\-\u2013to]+\s*\$?\s*([\d,]+)\s*(?:per\s*)?(hour|year|hr|yr|annually)?/i);
  if (m) return '$'+m[1]+'-$'+m[2]+(/hour|hr/i.test(m[3]||'')?'/hr':'/yr');
  return 'Not disclosed';
}

function extractContact(job) {
  var d = job.job_description || '';
  // Try to find email
  var emailMatch = d.match(/[\w.\-+]+@[\w.\-]+\.[\w]{2,}/);
  // Try to find contact name patterns
  var nameMatch = d.match(/(?:contact|reach out to|send.*to|apply.*to|email)\s*:?\s*([A-Z][a-z]+ [A-Z][a-z]+)/i);
  var name = nameMatch ? nameMatch[1] : '';
  var email = emailMatch ? emailMatch[0] : '';
  if (name && email) return name + ' (' + email + ')';
  if (email) return email;
  if (name) return name;
  return 'Apply online';
}

function mapType(t) {
  if (!t) return 'Not specified';
  var m = { 'FULLTIME':'Full-time','FULL_TIME':'Full-time','PARTTIME':'Part-time','PART_TIME':'Part-time',
    'CONTRACTOR':'Contract','CONTRACT':'Contract','INTERN':'Internship','INTERNSHIP':'Internship',
    'TEMPORARY':'Temporary','VOLUNTEER':'Volunteer','PER_DIEM':'Per Diem','OTHER':'Other' };
  return m[t.toUpperCase().trim()] || t;
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
    var totalPages = Math.min(body.pages || 10, 50);
    var pagesPerRole = Math.min(Math.max(1, Math.ceil(totalPages / roles.length)), 5);
    var allJobs = [], seenIds = {}, totalApiCalls = 0, startTime = Date.now();

    async function fetchPage(query, page) {
      if (Date.now() - startTime > 22000) return [];
      var params = new URLSearchParams({ query: query, page: String(page), num_pages: '1', country: 'us', date_posted: body.datePosted || 'all' });
      if (body.employmentTypes) params.set('employment_types', body.employmentTypes);
      try {
        var r = await fetch('https://jsearch.p.rapidapi.com/search?' + params, {
          headers: { 'x-rapidapi-host': 'jsearch.p.rapidapi.com', 'x-rapidapi-key': apiKey }
        });
        totalApiCalls++;
        if (!r.ok) return [];
        var d = await r.json();
        return d.data || [];
      } catch (e) { return []; }
    }

    await Promise.all(roles.map(async function(role) {
      var pp = [];
      for (var p = 1; p <= pagesPerRole; p++) pp.push(fetchPage(role, p));
      var results = await Promise.all(pp);
      results.forEach(function(jobs) {
        jobs.forEach(function(job) {
          var jid = job.job_id || (job.employer_name + '|' + job.job_title);
          if (!seenIds[jid]) { seenIds[jid] = true; allJobs.push(job); }
        });
      });
    }));

    var jobs = allJobs.map(function(job, i) {
      var desc = job.job_description || '';
      var fullText = desc + ' ' + (job.job_highlights?.Qualifications || []).join(' ') + ' ' + (job.job_highlights?.Responsibilities || []).join(' ');
      var apiSkills = (job.job_required_skills || []).slice(0, 6);
      var exSkills = unique(fullText, SKILL_RE);
      var ss = {}, fs = [];
      apiSkills.concat(exSkills).forEach(function(s) { var k = s.toLowerCase().trim(); if (!ss[k] && fs.length < 10) { ss[k] = true; fs.push(s); } });
      return {
        idx: i + 1, id: job.job_id,
        date: job.job_posted_at_datetime_utc ? new Date(job.job_posted_at_datetime_utc).toLocaleDateString('en-US') : 'N/A',
        title: job.job_title || 'N/A', company: job.employer_name || 'N/A',
        companyUrl: job.employer_website || '',
        location: [job.job_city, job.job_state, job.job_country].filter(Boolean).join(', ') || 'Remote',
        experience: extractExp(job),
        skills: fs.length ? fs.join(', ') : 'See details',
        certifications: unique(fullText, CERT_RE).join(', ') || 'See details',
        compliance: unique(fullText, COMP_RE).join(', ') || 'See details',
        tools: unique(fullText, TOOL_RE).join(', ') || 'See details',
        eligibility: extractElig(job), salary: extractSalary(job),
        contact: extractContact(job),
        source: job.job_publisher || 'Unknown', jobType: mapType(job.job_employment_type),
        remote: job.job_is_remote ? 'Yes' : 'No',
        applyLink: job.job_apply_link || '', description: desc,
        qualifications: job.job_highlights?.Qualifications || [],
        responsibilities: job.job_highlights?.Responsibilities || [],
        benefits: job.job_highlights?.Benefits || []
      };
    });
    return { statusCode: 200, headers: hdrs, body: JSON.stringify({ jobs: jobs, totalResults: jobs.length, apiCalls: totalApiCalls, rolesSearched: roles }) };
  } catch (err) {
    console.error('Error:', err);
    return { statusCode: 500, headers: hdrs, body: JSON.stringify({ error: 'Internal server error' }) };
  }
};
