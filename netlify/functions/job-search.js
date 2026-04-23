const CERT_RE = /CISSP|CISM|CISA|CEH|OSCP|OSCE|GPEN|GCIH|GCIA|GSEC|GREM|CompTIA\s*Security\+|CompTIA\s*CySA\+|CompTIA\s*CASP\+|SC-100|SC-200|SC-300|SC-400|AZ-500|AZ-900|MS-500|CCSP|CCNA|CCNP|CRISC|CGEIT|SSCP|CPTS|eJPT|eCPPT|PNPT|SANS|GIAC/gi;
const TOOL_RE = /Microsoft\s*Sentinel|Azure\s*Sentinel|Splunk|QRadar|CrowdStrike|SentinelOne|Palo\s*Alto|Cortex\s*XDR|LogRhythm|Elastic\s*Security|Chronicle|Defender\s*(?:for\s*)?(?:Endpoint|Cloud|Identity|Office)|Tenable|Qualys|Nessus|Rapid7|Carbon\s*Black|Fortinet|FortiSIEM|Check\s*Point|Cisco\s*ASA|Snort|Suricata|Wireshark|Burp\s*Suite|Metasploit|XSOAR|Phantom|Swimlane|KQL|SPL|YARA|Sigma/gi;

function unique(text, re) {
  if (!text) return [];
  var m = text.match(re) || [], seen = {};
  return m.filter(function(v) { var k = v.toLowerCase().trim(); if (seen[k]) return false; seen[k] = true; return true; }).slice(0, 10);
}

function extractExp(job) {
  var d = job.job_description || '', parts = [];
  var range = d.match(/(\d+)\s*[\-\u2013to]+\s*(\d+)\s*years?/i);
  if (range) parts.push(range[1] + '-' + range[2] + ' years');
  else if (job.job_required_experience?.required_experience_in_months)
    parts.push(Math.round(job.job_required_experience.required_experience_in_months / 12) + '+ years');
  var techPat = /(\d+)\+?\s*years?\s*(?:of\s*)?(?:experience\s*(?:in|with)\s*)([\w\s,/&]+?)(?:\.|,|;|\n)/gi, tm;
  while ((tm = techPat.exec(d)) !== null && parts.length < 4)
    parts.push(tm[1] + 'yr ' + tm[2].trim().slice(0, 25));
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
  return items.length ? items.join(', ') : 'See details';
}

function extractSalary(job) {
  if (job.job_min_salary && job.job_max_salary) {
    var s = job.job_salary_period === 'HOUR' ? '/hr' : '/yr';
    return '$' + Math.round(job.job_min_salary).toLocaleString() + '-$' + Math.round(job.job_max_salary).toLocaleString() + s;
  }
  var m = (job.job_description || '').match(/\$\s*([\d,]+)\s*[\-\u2013to]+\s*\$?\s*([\d,]+)\s*(?:per\s*)?(hour|year|hr|yr)?/i);
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
    var numPages = Math.min(body.pages || 10, 10), allJobs = [], errs = 0;
    for (var p = 1; p <= numPages; p++) {
      try {
        var params = new URLSearchParams({ query: body.query, page: String(p), num_pages: '1', country: 'us', date_posted: body.datePosted || 'all' });
        if (body.employmentTypes) params.set('employment_types', body.employmentTypes);
        var r = await fetch('https://jsearch.p.rapidapi.com/search?' + params, {
          headers: { 'x-rapidapi-host': 'jsearch.p.rapidapi.com', 'x-rapidapi-key': apiKey }
        });
        if (!r.ok) { errs++; if (errs > 2) break; continue; }
        var d = await r.json();
        if (!d.data || d.data.length === 0) break;
        allJobs = allJobs.concat(d.data);
      } catch (e) { errs++; if (errs > 2) break; }
    }
    var jobs = allJobs.map(function(job, i) {
      var desc = job.job_description || '';
      return {
        idx: i + 1, id: job.job_id,
        date: job.job_posted_at_datetime_utc ? new Date(job.job_posted_at_datetime_utc).toLocaleDateString('en-US') : 'N/A',
        title: job.job_title || 'N/A', company: job.employer_name || 'N/A',
        location: [job.job_city, job.job_state, job.job_country].filter(Boolean).join(', ') || 'Remote',
        experience: extractExp(job),
        skills: (job.job_required_skills || []).slice(0, 8).join(', ') || 'See details',
        certifications: unique(desc, CERT_RE).join(', ') || 'See details',
        tools: unique(desc, TOOL_RE).join(', ') || 'See details',
        eligibility: extractElig(job), salary: extractSalary(job),
        source: job.job_publisher || 'Unknown', jobType: mapType(job.job_employment_type),
        remote: job.job_is_remote ? 'Yes' : 'No',
        applyLink: job.job_apply_link || '', description: desc,
        qualifications: job.job_highlights?.Qualifications || [],
        responsibilities: job.job_highlights?.Responsibilities || [],
        benefits: job.job_highlights?.Benefits || []
      };
    });
    return { statusCode: 200, headers: hdrs, body: JSON.stringify({ jobs: jobs, totalResults: jobs.length, pagesSearched: numPages - errs }) };
  } catch (err) {
    console.error('Error:', err);
    return { statusCode: 500, headers: hdrs, body: JSON.stringify({ error: 'Internal server error' }) };
  }
};
