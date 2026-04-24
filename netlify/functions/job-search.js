// Certifications + Compliance frameworks
const CERT_RE = /CISSP|CISM|CISA|CEH|OSCP|OSCE|GPEN|GCIH|GCIA|GSEC|GREM|CompTIA\s*Security\+|CompTIA\s*CySA\+|CompTIA\s*CASP\+|CompTIA\s*Network\+|SC-100|SC-200|SC-300|SC-400|AZ-500|AZ-900|MS-500|CCSP|CCNA|CCNP|CRISC|CGEIT|SSCP|CPTS|eJPT|eCPPT|PNPT|SANS|GIAC|SOC\s*2|SOC2|ISO\s*27001|ISO\s*27002|NIST\s*(?:SP\s*)?800-53|NIST\s*CSF|NIST\s*800-171|PCI[\s-]*DSS|HIPAA|GDPR|FedRAMP|HITRUST|CMMC|CCPA|FISMA|SOX|COBIT|CIS\s*Controls|CIS\s*Benchmarks|MITRE\s*ATT&CK|Zero\s*Trust|TIC\s*3\.0/gi;

// Tools + Platforms + Technology categories
const TOOL_RE = /Microsoft\s*Sentinel|Azure\s*Sentinel|Splunk|QRadar|CrowdStrike|SentinelOne|Palo\s*Alto|Cortex\s*XDR|Cortex\s*XSOAR|LogRhythm|Elastic\s*(?:Security|SIEM)|Chronicle|Defender\s*(?:for\s*)?(?:Endpoint|Cloud|Identity|Office)|Tenable|Qualys|Nessus|Rapid7|InsightVM|Carbon\s*Black|VMware\s*Carbon\s*Black|Fortinet|FortiSIEM|FortiGate|Check\s*Point|Cisco\s*ASA|Cisco\s*(?:Firepower|SecureX|Umbrella)|Snort|Suricata|Wireshark|Burp\s*Suite|Metasploit|XSOAR|Phantom|Swimlane|Demisto|KQL|SPL|YARA|Sigma|ServiceNow\s*(?:SecOps|ITSM)|Jira|Proofpoint|Mimecast|Zscaler|Okta|CyberArk|BeyondTrust|Varonis|DarkTrace|Vectra|SIEM|SOAR|EDR|XDR|NDR|IDS[\s/]*IPS|DLP|WAF|CASB|CSPM|CWPP|CNAPP|IAM|PAM|MFA|SSO|UEBA|TIP|threat\s*intelligence\s*platform|Zero\s*Trust\s*(?:tooling|architecture|framework)?/gi;

// Technical skills
const SKILL_RE = /incident\s*response|threat\s*(?:hunting|analysis|detection|modeling|reporting|intelligence)|forensic\s*(?:analysis|investigation)|digital\s*forensics|malware\s*analysis|reverse\s*engineering|vulnerability\s*(?:management|assessment|scanning)|penetration\s*testing|red\s*team(?:ing)?|blue\s*team(?:ing)?|purple\s*team(?:ing)?|security\s*(?:monitoring|operations|engineering|architecture|assessment|automation|orchestration)|SOC\s*(?:operations|monitoring|analysis)|log\s*(?:analysis|management|correlation)|network\s*(?:security|forensics|analysis|monitoring)|cloud\s*security|endpoint\s*(?:security|protection)|identity\s*(?:management|governance)|access\s*(?:management|control)|data\s*(?:loss\s*prevention|protection)|risk\s*(?:assessment|management|analysis)|compliance\s*(?:monitoring|management|auditing)|alert\s*triage|detection\s*engineering|rule\s*(?:writing|development|tuning)|playbook\s*(?:development|automation)|KQL\s*(?:queries|hunting)|scripting|Python|PowerShell|Bash|JavaScript|Go|Perl|SQL|RegEx|API\s*(?:security|integration)|SDLC|DevSecOps|CI[\s/]*CD\s*security|container\s*security|Kubernetes\s*security|IAM|RBAC|PKI|encryption|cryptography|PCAP\s*analysis|packet\s*analysis|memory\s*forensics|disk\s*forensics|chain\s*of\s*custody|evidence\s*(?:collection|preservation)|tabletop\s*exercises|BCP|DR|disaster\s*recovery|business\s*continuity/gi;

function unique(text, re) {
  if (!text) return [];
  var m = text.match(re) || [], seen = {};
  return m.filter(function(v) {
    var k = v.toLowerCase().replace(/\s+/g, ' ').trim();
    if (seen[k]) return false;
    seen[k] = true;
    return true;
  }).slice(0, 12);
}

function extractExp(job) {
  var d = job.job_description || '', parts = [];
  var range = d.match(/(\d+)\s*[\-\u2013to]+\s*(\d+)\s*years?/i);
  if (range) parts.push(range[1] + '-' + range[2] + ' years');
  else if (job.job_required_experience?.required_experience_in_months)
    parts.push(Math.round(job.job_required_experience.required_experience_in_months / 12) + '+ years');
  var techPat = /(\d+)\+?\s*years?\s*(?:of\s*)?(?:experience\s*(?:in|with)\s*)([\w\s,/&]+?)(?:\.|,|;|\n)/gi, tm;
  while ((tm = techPat.exec(d)) !== null && parts.length < 4)
    parts.push(tm[1] + 'yr ' + tm[2].trim().slice(0, 30));
  return parts.length ? parts.join(', ') : 'Not specified';
}

function extractElig(job) {
  var items = [], d = job.job_description || '', edu = job.job_required_education;
  if (edu) {
    if (edu.postgraduate_degree) items.push('Postgraduate');
    else if (edu.bachelors_degree) items.push("Bachelor's");
    else if (edu.associates_degree) items.push("Associate's");
  }
  if (/clearance|TS\/SCI|Secret/i.test(d)) items.push('Security Clearance');
  if (/U\.?S\.?\s*citizen/i.test(d)) items.push('US Citizen');
  if (/authorized\s*to\s*work/i.test(d)) items.push('Work Auth');
  return items.length ? items.join(', ') : 'See details';
}

function extractSalary(job) {
  if (job.job_min_salary && job.job_max_salary) {
    var s = job.job_salary_period === 'HOUR' ? '/hr' : '/yr';
    return '$' + Math.round(job.job_min_salary).toLocaleString() + '-$' + Math.round(job.job_max_salary).toLocaleString() + s;
  }
  var m = (job.job_description || '').match(/\$\s*([\d,]+)\s*[\-\u2013to]+\s*\$?\s*([\d,]+)\s*(?:per\s*)?(hour|year|hr|yr|annually)?/i);
  if (m) return '$' + m[1] + '-$' + m[2] + (/hour|hr/i.test(m[3] || '') ? '/hr' : '/yr');
  return 'Not disclosed';
}

function mapType(t) {
  if (!t) return 'Not specified';
  t = t.toUpperCase();
  if (t.includes('FULL')) return 'Full-time';
  if (t.includes('CONTRACT')) return 'Contract';
  if (t.includes('PART')) return 'Part-time';
  if (t.includes('INTERN')) return 'Internship';
  return t;
}

exports.handler = async (event) => {
  if (event.httpMethod === 'OPTIONS')
    return { statusCode: 204, headers: { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': 'Content-Type', 'Access-Control-Allow-Methods': 'POST, OPTIONS' }, body: '' };
  if (event.httpMethod !== 'POST')
    return { statusCode: 405, body: JSON.stringify({ error: 'Method not allowed' }) };
  var hdrs = { 'Access-Control-Allow-Origin': '*', 'Content-Type': 'application/json' };
  try {
    var body = JSON.parse(event.body);
    if (!body.query) return { statusCode: 400, headers: hdrs, body: JSON.stringify({ error: 'Query required' }) };
    var apiKey = process.env.JSEARCH_API_KEY;
    if (!apiKey) return { statusCode: 500, headers: hdrs, body: JSON.stringify({ error: 'API key not configured' }) };
    var numPages = Math.min(body.pages || 10, 10), allJobs = [], errs = 0, seenIds = {};

    // Always fetch from page 1 to ensure consistent, repeatable results
    for (var p = 1; p <= numPages; p++) {
      try {
        var params = new URLSearchParams({
          query: body.query,
          page: String(p),
          num_pages: '1',
          country: 'us',
          date_posted: body.datePosted || 'all'
        });
        if (body.employmentTypes) params.set('employment_types', body.employmentTypes);

        var r = await fetch('https://jsearch.p.rapidapi.com/search?' + params, {
          headers: { 'x-rapidapi-host': 'jsearch.p.rapidapi.com', 'x-rapidapi-key': apiKey }
        });
        if (!r.ok) { errs++; if (errs > 2) break; continue; }
        var d = await r.json();
        if (!d.data || d.data.length === 0) break;

        // Deduplicate by job_id to ensure no repeats within a single search
        d.data.forEach(function(job) {
          var jid = job.job_id || (job.employer_name + '|' + job.job_title);
          if (!seenIds[jid]) {
            seenIds[jid] = true;
            allJobs.push(job);
          }
        });
      } catch (e) { errs++; if (errs > 2) break; }
    }

    var jobs = allJobs.map(function(job, i) {
      var desc = job.job_description || '';
      var allQuals = (job.job_highlights?.Qualifications || []).join(' ');
      var allResp = (job.job_highlights?.Responsibilities || []).join(' ');
      var fullText = desc + ' ' + allQuals + ' ' + allResp;

      // Extract skills from description + qualifications + responsibilities
      var apiSkills = (job.job_required_skills || []).slice(0, 6);
      var extractedSkills = unique(fullText, SKILL_RE);
      // Merge API skills with extracted skills, deduplicated
      var skillSet = {}, finalSkills = [];
      apiSkills.concat(extractedSkills).forEach(function(s) {
        var k = s.toLowerCase().trim();
        if (!skillSet[k] && finalSkills.length < 10) { skillSet[k] = true; finalSkills.push(s); }
      });

      return {
        idx: i + 1, id: job.job_id,
        date: job.job_posted_at_datetime_utc ? new Date(job.job_posted_at_datetime_utc).toLocaleDateString('en-US') : 'N/A',
        title: job.job_title || 'N/A',
        company: job.employer_name || 'N/A',
        location: [job.job_city, job.job_state, job.job_country].filter(Boolean).join(', ') || 'Remote',
        experience: extractExp(job),
        skills: finalSkills.length ? finalSkills.join(', ') : 'See details',
        certifications: unique(fullText, CERT_RE).join(', ') || 'See details',
        tools: unique(fullText, TOOL_RE).join(', ') || 'See details',
        eligibility: extractElig(job),
        salary: extractSalary(job),
        source: job.job_publisher || 'Unknown',
        jobType: mapType(job.job_employment_type),
        remote: job.job_is_remote ? 'Yes' : 'No',
        applyLink: job.job_apply_link || '',
        description: desc,
        qualifications: job.job_highlights?.Qualifications || [],
        responsibilities: job.job_highlights?.Responsibilities || [],
        benefits: job.job_highlights?.Benefits || []
      };
    });

    return {
      statusCode: 200, headers: hdrs,
      body: JSON.stringify({
        jobs: jobs,
        totalResults: jobs.length,
        pagesSearched: numPages - errs,
        deduplicated: Object.keys(seenIds).length
      })
    };
  } catch (err) {
    console.error('Error:', err);
    return { statusCode: 500, headers: hdrs, body: JSON.stringify({ error: 'Internal server error' }) };
  }
};
