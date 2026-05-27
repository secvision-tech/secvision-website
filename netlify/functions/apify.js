// Apify Bebity LinkedIn Jobs Scraper integration
const APIFY_TOKEN = process.env.APIFY_API_TOKEN;
const ACTOR_ID = 'bebity~linkedin-jobs-scraper';
const hdrs = { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Methods': 'POST,OPTIONS', 'Access-Control-Allow-Headers': 'Content-Type' };

exports.handler = async function(event) {
  if (event.httpMethod === 'OPTIONS') return { statusCode: 200, headers: hdrs, body: '' };
  if (event.httpMethod !== 'POST') return { statusCode: 405, headers: hdrs, body: 'Method not allowed' };

  try {
    var body = JSON.parse(event.body || '{}');
    var action = body.action;
    if (!APIFY_TOKEN) return { statusCode: 500, headers: hdrs, body: JSON.stringify({ error: 'APIFY_API_TOKEN not set' }) };

    // ACTION: startSearch - kick off Bebity scraper run
    if (action === 'startSearch') {
      var title = body.title || 'SOC Analyst';
      var location = body.location || 'United States';
      var rows = body.rows || 25;

      // Build LinkedIn search URL with exact phrase matching
      var searchUrl = 'https://www.linkedin.com/jobs/search/?keywords=' + encodeURIComponent('"' + title + '"') + '&location=' + encodeURIComponent(location);
      if (body.contractType) searchUrl += '&f_JT=' + (body.contractType === 'Contract' ? 'C' : body.contractType === 'Full-time' ? 'F' : '');
      if (body.datePosted === 'week') searchUrl += '&f_TPR=r604800';
      else if (body.datePosted === 'month') searchUrl += '&f_TPR=r2592000';
      else if (body.datePosted === 'day') searchUrl += '&f_TPR=r86400';

      var resp = await fetch('https://api.apify.com/v2/acts/' + ACTOR_ID + '/runs?token=' + APIFY_TOKEN, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ searchUrl: searchUrl, rows: rows })
      });

      if (!resp.ok) {
        var errText = await resp.text();
        return { statusCode: 500, headers: hdrs, body: JSON.stringify({ error: 'Apify start failed: ' + errText.slice(0, 300) }) };
      }

      var run = await resp.json();
      return { statusCode: 200, headers: hdrs, body: JSON.stringify({
        runId: run.data.id,
        datasetId: run.data.defaultDatasetId,
        status: run.data.status
      })};
    }

    // ACTION: checkRun - poll run status
    if (action === 'checkRun') {
      var runId = body.runId;
      if (!runId) return { statusCode: 400, headers: hdrs, body: JSON.stringify({ error: 'runId required' }) };

      var resp = await fetch('https://api.apify.com/v2/actor-runs/' + runId + '?token=' + APIFY_TOKEN);
      var run = await resp.json();
      return { statusCode: 200, headers: hdrs, body: JSON.stringify({
        status: run.data.status,
        datasetId: run.data.defaultDatasetId
      })};
    }

    // ACTION: getResults - fetch results from completed run and process
    if (action === 'getResults') {
      var datasetId = body.datasetId;
      if (!datasetId) return { statusCode: 400, headers: hdrs, body: JSON.stringify({ error: 'datasetId required' }) };

      var resp = await fetch('https://api.apify.com/v2/datasets/' + datasetId + '/items?token=' + APIFY_TOKEN + '&format=json');
      if (!resp.ok) return { statusCode: 500, headers: hdrs, body: JSON.stringify({ error: 'Failed to fetch results' }) };

      var rawJobs = await resp.json();

      // Map Bebity fields to our schema and filter for cybersecurity relevance
      var jobs = rawJobs.filter(function(j) {
        return isCyberRelevant(j.title, j.description);
      }).map(function(j) {
        var desc = (j.description || '').replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim();
        var descHtml = j.descriptionHtml || j.description || '';

        return {
          jobId: 'li_' + (j.id || ''),
          linkedinJobId: j.id || '',
          title: j.title || '',
          company: j.companyName || '',
          companyUrl: (j.companyUrl || '').replace(/\?trk=.*$/, ''),
          companyLogo: j.companyLogo || '',
          location: j.location || '',
          description: desc,
          descriptionHtml: descHtml,
          salary: j.salary || '',
          datePosted: j.publishedAt || null,
          contractType: j.contractType || '',
          experienceLevel: j.experienceLevel || '',
          sector: j.sector || '',
          workType: j.workType || '',
          benefits: j.benefits || '',
          applicationsCount: j.applicationsCount || '',
          applyLink: j.applyUrl || j.jobUrl || '',
          jobUrl: j.jobUrl || '',
          posterFullName: j.posterFullName || '',
          posterProfileUrl: j.posterProfileUrl || '',
          source: 'LinkedIn',
          sourceApi: 'apify-bebity'
        };
      });

      return { statusCode: 200, headers: hdrs, body: JSON.stringify({ jobs: jobs, total: jobs.length, rawTotal: rawJobs.length, filtered: rawJobs.length - jobs.length }) };
    }

    // ACTION: processAndSave - process Apify results through extraction pipeline and save to MongoDB
    if (action === 'processAndSave') {
      var jobs = body.jobs || [];
      // Filter for cybersecurity relevance
      jobs = jobs.filter(function(j) { return isCyberRelevant(j.title, j.description); });
      if (!jobs.length) return { statusCode: 200, headers: hdrs, body: JSON.stringify({ saved: 0, filtered: true }) };

      var { getDb } = require('./db');
      var db = await getDb();
      var col = db.collection('jobs');

      // Extraction patterns (same as job-search.js)
      var TOOL_RE = /Microsoft\s*Defender|Microsoft\s*Sentinel|Azure\s*Sentinel|Azure|Splunk|QRadar|CrowdStrike|SentinelOne|Palo\s*Alto|Cortex\s*XDR|Cortex\s*XSOAR|LogRhythm|Elastic\s*(?:Security|SIEM)|Chronicle|Tenable|Qualys|Nessus|Rapid7|Carbon\s*Black|Fortinet|FortiSIEM|FortiGate|Check\s*Point|Cisco\s*(?:ASA|Firepower|SecureX|Umbrella)|Snort|Suricata|Wireshark|Burp\s*Suite|Metasploit|Phantom|Swimlane|KQL|SPL|YARA|Sigma|ServiceNow|Jira|Proofpoint|Mimecast|Zscaler|Okta|CyberArk|BeyondTrust|Varonis|DarkTrace|Vectra|Tanium|Exabeam|Securonix|AWS|GCP|Google\s*Cloud|Prisma\s*Cloud|Wiz|Terraform|Ansible|Kubernetes|Docker|Jenkins|Python|Bash|PowerShell|SIEM|SOAR|EDR|XDR|NDR|IDS[\s\/]*IPS|DLP|WAF|CASB|CSPM|IAM|PAM|MFA|SSO|UEBA|Aqua|Twistlock|Trivy|Falco|Sysdig|Anchore|Checkov/gi;
      var CERT_RE = /CISSP|CISM|CISA|CEH|OSCP|GPEN|GCIH|GCIA|GSEC|GREM|CompTIA\s*Security\+|CompTIA\s*CySA\+|CompTIA\s*CASP\+|SC-100|SC-200|SC-300|SC-400|AZ-\d{3}|DP-\d{3}|AI-\d{3}|MS-\d{3}|PL-\d{3}|CCSP|CCNA|CCNP|CRISC|SSCP|SANS|GIAC|ITIL|CKA|CKAD|CKS|PCNSE|SABSA/gi;
      var COMP_RE = /SOC\s*2|ISO\s*27001|NIST\s*(?:SP\s*)?800-53|NIST\s*(?:SP\s*)?800-61|NIST\s*(?:SP\s*)?800-171|NIST\s*CSF|PCI[\s-]*DSS|HIPAA|GDPR|FedRAMP|HITRUST|CMMC|CCPA|FISMA|SOX|COBIT|CIS\s*Controls|MITRE\s*ATT&CK|Zero\s*Trust|NERC\s*CIP|OWASP\s*Top\s*10|NIST\s*RMF|STIX[\s\/]*TAXII|\bNIST\b/gi;

      function uniqueMatch(text, re) {
        if (!text) return [];
        var m = text.match(re) || [], seen = {};
        return m.filter(function(v) { var k = v.toLowerCase().trim(); if (seen[k]) return false; seen[k] = true; return true; }).slice(0, 12);
      }

      function detectJobType(contractType, desc) {
        if (/contract/i.test(contractType)) return 'Contract';
        if (/full.?time/i.test(contractType)) return 'Full-time';
        if (/part.?time/i.test(contractType)) return 'Part-time';
        if (/intern/i.test(contractType)) return 'Internship';
        if (/\bcontract\b/i.test(desc)) return 'Contract';
        return 'Full-time';
      }

      function detectRemote(desc, loc) {
        if (/\bremote\b/i.test(loc)) return 'Yes';
        if (/\b(?:fully\s*remote|100%\s*remote|remote\s*(?:position|role|work)|Location\s*:\s*Remote)\b/i.test(desc)) return 'Yes';
        if (/\bhybrid\b/i.test(desc) || /\bhybrid\b/i.test(loc)) return 'Hybrid';
        return 'No';
      }

      var ops = [];
      var processed = [];

      for (var i = 0; i < jobs.length; i++) {
        var j = jobs[i];
        var desc = j.description || '';
        var fullText = (j.title || '') + ' ' + desc;

        var tools = uniqueMatch(fullText, TOOL_RE).join(', ') || 'See details';
        var certs = uniqueMatch(fullText, CERT_RE).join(', ') || 'See details';
        var compliance = uniqueMatch(fullText, COMP_RE).join(', ') || 'See details';
        var jobType = detectJobType(j.contractType, desc);
        var remote = detectRemote(desc, j.location);

        // Build contact string from poster
        var contact = '';
        if (j.posterFullName) {
          contact = j.posterFullName;
          if (j.posterProfileUrl) contact += ' (' + j.posterProfileUrl + ')';
        }

        var jobDoc = {
          jobId: j.jobId,
          linkedinJobId: j.linkedinJobId,
          title: j.title,
          titleClean: j.title,
          company: j.company,
          companyUrl: j.companyUrl,
          companyLogo: j.companyLogo,
          location: j.location,
          description: desc,
          salary: j.salary || 'Not disclosed',
          datePosted: j.datePosted ? new Date(j.datePosted) : null,
          jobType: jobType,
          remote: remote,
          tools: tools,
          certifications: certs,
          compliance: compliance,
          contact: contact,
          posterFullName: j.posterFullName || '',
          posterProfileUrl: j.posterProfileUrl || '',
          source: 'LinkedIn',
          sourceApi: 'apify-bebity',
          applyLink: j.applyLink,
          jobUrl: j.jobUrl,
          experienceLevel: j.experienceLevel || '',
          sector: j.sector || '',
          benefits: j.benefits || '',
          applicationsCount: j.applicationsCount || '',
          eligibility: 'Open',
          detectedCountry: detectCountryFromLocation(j.location),
          dateScanned: new Date()
        };

        // Upsert: match by linkedinJobId or jobId
        ops.push({
          updateOne: {
            filter: { $or: [{ linkedinJobId: j.linkedinJobId }, { jobId: j.jobId }] },
            update: {
              $set: {
                title: jobDoc.title, titleClean: jobDoc.titleClean, company: jobDoc.company,
                companyUrl: jobDoc.companyUrl, companyLogo: jobDoc.companyLogo,
                location: jobDoc.location, description: jobDoc.description,
                salary: jobDoc.salary, datePosted: jobDoc.datePosted,
                tools: jobDoc.tools, certifications: jobDoc.certifications,
                compliance: jobDoc.compliance, contact: jobDoc.contact,
                posterFullName: jobDoc.posterFullName, posterProfileUrl: jobDoc.posterProfileUrl,
                source: jobDoc.source, sourceApi: jobDoc.sourceApi,
                applyLink: jobDoc.applyLink, jobUrl: jobDoc.jobUrl,
                experienceLevel: jobDoc.experienceLevel, sector: jobDoc.sector,
                benefits: jobDoc.benefits, applicationsCount: jobDoc.applicationsCount,
                detectedCountry: jobDoc.detectedCountry, dateScanned: jobDoc.dateScanned
              },
              $setOnInsert: {
                status: 'new', companyType: '', notes: '',
                jobType: jobDoc.jobType, remote: jobDoc.remote,
                eligibility: jobDoc.eligibility, linkedinJobId: jobDoc.linkedinJobId,
                jobId: jobDoc.jobId
              }
            },
            upsert: true
          }
        });

        processed.push(jobDoc);
      }

      var savedCount = 0;
      if (ops.length > 0) {
        var result = await col.bulkWrite(ops, { ordered: false });
        savedCount = (result.upsertedCount || 0) + (result.modifiedCount || 0);
      }

      // Save poster as contact if available
      var contactsCol = db.collection('contacts');
      for (var k = 0; k < jobs.length; k++) {
        if (jobs[k].posterFullName && jobs[k].posterProfileUrl) {
          try {
            await contactsCol.updateOne(
              { company: jobs[k].company, linkedin: jobs[k].posterProfileUrl },
              { $set: {
                company: jobs[k].company, name: jobs[k].posterFullName.replace(/[^\w\s]/g, ''),
                designation: 'Job Poster (LinkedIn)', email: 'N/A',
                linkedin: jobs[k].posterProfileUrl, source: 'LinkedIn Job Post',
                updatedAt: new Date()
              }, $setOnInsert: { createdAt: new Date() } },
              { upsert: true }
            );
          } catch(e) { /* ignore dups */ }
        }
      }

      return { statusCode: 200, headers: hdrs, body: JSON.stringify({
        saved: savedCount, total: processed.length, newJobs: ops.length
      })};
    }

    // ACTION: cleanupNonCyber - remove non-cybersecurity jobs previously saved by Apify
    if (action === 'cleanupNonCyber') {
      var { getDb } = require('./db');
      var db = await getDb();
      var col = db.collection('jobs');
      var apifyJobs = await col.find({ sourceApi: 'apify-bebity' }).project({ _id: 1, title: 1, description: 1 }).toArray();
      var toDelete = [];
      apifyJobs.forEach(function(j) {
        if (!isCyberRelevant(j.title, j.description)) toDelete.push(j._id);
      });
      var deleted = 0;
      if (toDelete.length > 0) {
        var result = await col.deleteMany({ _id: { $in: toDelete } });
        deleted = result.deletedCount || 0;
      }
      return { statusCode: 200, headers: hdrs, body: JSON.stringify({ checked: apifyJobs.length, deleted: deleted, kept: apifyJobs.length - deleted }) };
    }

    return { statusCode: 400, headers: hdrs, body: JSON.stringify({ error: 'Unknown action' }) };
  } catch(e) {
    console.error('Apify error:', e);
    return { statusCode: 500, headers: hdrs, body: JSON.stringify({ error: e.message }) };
  }
};

// Cybersecurity relevance filter — reject non-IT jobs
function isCyberRelevant(title, desc) {
  var t = (title || '').toLowerCase();
  var d = (desc || '').toLowerCase();

  // Reject known non-IT titles
  var NON_IT = /\b(humint|sigint|geoint|masint|maintenance\s*(?:tech|engineer|worker|manager)|customer\s*success|optimizer|program\s*analyst|budget\s*analyst|financial\s*analyst|hr\s*analyst|compensation\s*analyst|operations\s*analyst(?!\s*-?\s*(?:soc|cyber|security))|business\s*analyst|supply\s*chain|logistics|nurse|clinical|pharmacist|medical\s*coder|social\s*worker|case\s*manager|paralegal|loan\s*officer|mortgage|real\s*estate|truck\s*driver|warehouse|forklift|cashier|retail\s*associate|food\s*service|janitor|custodian|landscap|plumber|electrician(?!\s*(?:cyber|security)))\b/i;
  if (NON_IT.test(t)) return false;

  // Title contains cybersecurity keywords → pass immediately
  var CYBER_TITLE = /\b(soc\b|security|cyber|infosec|siem|threat|incident|malware|forensic|pentest|penetration|vulnerability|devsecops|secops|ciso|cloud\s*security|network\s*security|information\s*security|detection|response\s*analyst|blue\s*team|red\s*team|purple\s*team|ir\s*analyst|cert\s*analyst|csirt|dfir)\b/i;
  if (CYBER_TITLE.test(t)) return true;

  // Title is generic (e.g. "Analyst", "Engineer") — check description for cyber signals
  var cyberSignals = 0;
  var SIGNALS = [/\bsiem\b/i, /\bedr\b/i, /\bsoc\b/i, /\bsecurity\s*operations/i, /\bincident\s*response/i,
    /\bthreat\s*(?:hunt|detect|intel)/i, /\bfirewall/i, /\bids[\s\/]*ips\b/i, /\bmitre\s*att/i,
    /\bcrowdstrike|sentinel(?:one)?|splunk|qradar\b/i, /\bmalware\b/i, /\bphishing\b/i,
    /\bcybersecurity\b/i, /\bvulnerability/i, /\bpenetration\s*test/i, /\bnist\b/i,
    /\bcompti?a\s*security/i, /\bcissp\b/i, /\boscp\b/i, /\bgcih\b/i];
  SIGNALS.forEach(function(re) { if (re.test(d)) cyberSignals++; });

  // Need at least 3 cybersecurity signals in description for generic titles
  return cyberSignals >= 3;
}

function detectCountryFromLocation(loc) {
  if (!loc) return 'Unknown';
  var l = loc.toLowerCase();
  var US_STATES = /\b(AL|AK|AZ|AR|CA|CO|CT|DE|FL|GA|HI|ID|IL|IN|IA|KS|KY|LA|ME|MD|MA|MI|MN|MS|MO|MT|NE|NV|NH|NJ|NM|NY|NC|ND|OH|OK|OR|PA|RI|SC|SD|TN|TX|UT|VT|VA|WA|WV|WI|WY)\b/;
  if (US_STATES.test(loc) || /united states|usa/i.test(loc)) return 'United States';
  if (/united kingdom|england|scotland|wales/i.test(l)) return 'United Kingdom';
  if (/canada/i.test(l)) return 'Canada';
  if (/australia/i.test(l)) return 'Australia';
  if (/germany|deutschland/i.test(l)) return 'Germany';
  if (/france/i.test(l)) return 'France';
  if (/india/i.test(l)) return 'India';
  if (/switzerland/i.test(l)) return 'Switzerland';
  if (/netherlands/i.test(l)) return 'Netherlands';
  if (/singapore/i.test(l)) return 'Singapore';
  if (/ireland/i.test(l)) return 'Ireland';
  return 'Unknown';
}
