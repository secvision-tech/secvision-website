// Apify Bebity LinkedIn Jobs Scraper integration
const APIFY_TOKEN = process.env.APIFY_API_TOKEN;
const ACTOR_ID = 'bebity~linkedin-jobs-scraper';
const COMPANY_ACTOR_ID = 'bebity~linkedin-company-scraper';
const PROFILE_ACTOR_ID = 'bebity~linkedin-premium-actor';
const hdrs = { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Methods': 'POST,OPTIONS', 'Access-Control-Allow-Headers': 'Content-Type, Authorization' };

// Extract company from LinkedIn headline e.g. "Talent Acquisition at Peraton" -> "Peraton"
function extractCompanyFromHeadline(headline) {
  if (!headline) return '';
  var h = headline.trim();
  var atMatch = h.match(/\bat\s+([A-Z][\w&.,'\- ]+?)(?:\s*[|.\-]|$)/);
  if (atMatch) {
    var c = atMatch[1].trim().replace(/[,.|]+$/, '').trim();
    if (c.length >= 2 && c.length <= 60) return c;
  }
  if (h.indexOf('|') > -1) {
    var parts = h.split('|');
    var last = parts[parts.length - 1].trim();
    if (last.length >= 2 && last.length <= 40 && /^[A-Z]/.test(last) && !/recruiter|engineer|manager|analyst|developer|specialist|consultant|lead|director|officer/i.test(last)) {
      return last;
    }
  }
  return '';
}

// Lightweight JWT decode + validate (no MongoDB dependency)
function validateJwt(event) {
  var authHeader = (event.headers || {}).authorization || (event.headers || {}).Authorization || '';
  if (!authHeader.startsWith('Bearer ')) return null;
  try {
    var payload = JSON.parse(Buffer.from(authHeader.slice(7).split('.')[1].replace(/-/g,'+').replace(/_/g,'/'), 'base64').toString());
    var TENANT_ID = process.env.ENTRA_TENANT_ID || '';
    var CLIENT_ID = process.env.ENTRA_CLIENT_ID || '';
    if (payload.iss && TENANT_ID && !payload.iss.includes(TENANT_ID)) return { error: 'Invalid token issuer' };
    if (payload.aud && CLIENT_ID && payload.aud !== CLIENT_ID) return { error: 'Invalid token audience' };
    if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) return { error: 'Token expired' };
    return { email: (payload.preferred_username || payload.email || '').toLowerCase(), name: payload.name || '' };
  } catch (e) { return null; }
}

exports.handler = async function(event) {
  if (event.httpMethod === 'OPTIONS') return { statusCode: 200, headers: hdrs, body: '' };
  if (event.httpMethod !== 'POST') return { statusCode: 405, headers: hdrs, body: 'Method not allowed' };

  // Validate JWT (reject invalid tokens, allow missing tokens during migration)
  var authResult = validateJwt(event);
  if (authResult && authResult.error) return { statusCode: 401, headers: hdrs, body: JSON.stringify({ error: authResult.error }) };

  // RBAC: check user role from MongoDB (lazy db import — same pattern as processAndSave)
  if (authResult && authResult.email) {
    try {
      var { getDb } = require('./db');
      var authDb = await getDb();
      var authUserDoc = await authDb.collection('users').findOne({ email: authResult.email });
      if (!authUserDoc || authUserDoc.status !== 'active') return { statusCode: 403, headers: hdrs, body: JSON.stringify({ error: 'User not active or not found' }) };
      if (authUserDoc.role === 'viewer' || authUserDoc.role === 'pending') return { statusCode: 403, headers: hdrs, body: JSON.stringify({ error: 'Insufficient permissions' }) };
    } catch (dbErr) { /* db unavailable — allow JWT-validated user through */ }
  }

  try {
    var body = JSON.parse(event.body || '{}');
    var action = body.action;
    if (!APIFY_TOKEN) return { statusCode: 500, headers: hdrs, body: JSON.stringify({ error: 'APIFY_API_TOKEN not set' }) };

    // ACTION: startSearch - kick off Bebity scraper run
    if (action === 'startSearch') {
      var title = body.title || 'SOC Analyst';
      var location = body.location || 'United States';
      var rows = body.rows || 25;

      // Map datePosted to Bebity publishedAt format
      var publishedAt = '';
      if (body.datePosted === 'day') publishedAt = 'r86400';
      else if (body.datePosted === 'week') publishedAt = 'r604800';
      else if (body.datePosted === 'month' || body.datePosted === 'all') publishedAt = 'r2592000';
      else publishedAt = 'r604800'; // Default: last week

      // Map contractType: C=Contract, F=Full-time, empty=All
      var contractType = '';
      if (body.contractType === 'Contract' || body.contractType === 'C') contractType = 'C';
      else if (body.contractType === 'Full-time' || body.contractType === 'F') contractType = 'F';

      // Build structured input for Bebity LinkedIn Jobs Scraper
      var actorInput = {
        title: title,
        location: location,
        rows: rows,
        publishedAt: publishedAt,
        proxy: {
          useApifyProxy: true,
          apifyProxyGroups: ['RESIDENTIAL']
        }
      };
      if (contractType) actorInput.contractType = contractType;

      var resp = await fetch('https://api.apify.com/v2/acts/' + ACTOR_ID + '/runs?token=' + APIFY_TOKEN, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(actorInput)
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

        // #273: LinkedIn companyUrl is actually the LinkedIn page, not the website
        var rawCompanyUrl = (j.companyUrl || '').replace(/\?trk=.*$/, '');
        var isLinkedIn = rawCompanyUrl.indexOf('linkedin.com/company') > -1;

        return {
          jobId: 'li_' + (j.id || ''),
          linkedinJobId: j.id || '',
          title: j.title || '',
          company: j.companyName || '',
          companyUrl: isLinkedIn ? '' : rawCompanyUrl,
          companyLinkedin: isLinkedIn ? rawCompanyUrl : '',
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
    // ACTION: scrapeCompany - Scrape LinkedIn company page for size/type/website
    if (action === 'scrapeCompany') {
      var linkedinUrl = body.linkedinUrl || '';
      var companyName = body.company || '';

      // Build LinkedIn company URL if not provided
      if (!linkedinUrl && companyName) {
        var slug = companyName.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
        linkedinUrl = 'https://www.linkedin.com/company/' + slug + '/';
      }
      if (!linkedinUrl) return { statusCode: 200, headers: hdrs, body: JSON.stringify({ error: 'No LinkedIn URL or company name provided' }) };

      try {
        // Start the Company Scraper actor
        var resp = await fetch('https://api.apify.com/v2/acts/' + COMPANY_ACTOR_ID + '/runs?token=' + APIFY_TOKEN, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            urls: [linkedinUrl],
            proxy: { useApifyProxy: true, apifyProxyGroups: ['RESIDENTIAL'] }
          })
        });
        var run = await resp.json();
        if (!run.data || !run.data.id) return { statusCode: 200, headers: hdrs, body: JSON.stringify({ error: 'Failed to start company scraper', details: run }) };

        var runId = run.data.id;
        var datasetId = run.data.defaultDatasetId;

        // Poll for completion (max 60 seconds)
        var maxPolls = 12, pollCount = 0, status = 'RUNNING';
        while (status === 'RUNNING' || status === 'READY') {
          await new Promise(function(r) { setTimeout(r, 5000); });
          pollCount++;
          var cr = await fetch('https://api.apify.com/v2/actor-runs/' + runId + '?token=' + APIFY_TOKEN);
          var cd = await cr.json();
          status = cd.data ? cd.data.status : 'FAILED';
          datasetId = (cd.data && cd.data.defaultDatasetId) || datasetId;
          if (pollCount >= maxPolls) break;
        }

        if (status !== 'SUCCEEDED') return { statusCode: 200, headers: hdrs, body: JSON.stringify({ error: 'Company scraper timed out or failed', status: status }) };

        // Fetch results
        var dr = await fetch('https://api.apify.com/v2/datasets/' + datasetId + '/items?token=' + APIFY_TOKEN);
        var items = await dr.json();

        if (!items || !items.length) return { statusCode: 200, headers: hdrs, body: JSON.stringify({ error: 'No company data returned' }) };

        var c = items[0];
        // Extract and normalize company data
        var result = {
          found: true,
          name: c.name || c.companyName || companyName,
          size: 0,
          sizeRange: '',
          industry: c.industry || c.sector || '',
          website: c.website || c.websiteUrl || '',
          linkedin: linkedinUrl,
          headquarters: c.headquarters || c.hqLocation || '',
          description: (c.description || '').slice(0, 500),
          specialties: c.specialties || []
        };

        // Parse employee count
        var empCount = c.employeeCount || c.staffCount || c.employeesCount || 0;
        var empRange = c.employeeCountRange || c.staffCountRange || c.companySize || '';
        if (typeof empCount === 'number' && empCount > 0) {
          result.size = empCount;
        } else if (empRange) {
          result.sizeRange = empRange;
          // Parse range like "1,001-5,000" or "1001-5000"
          var rangeMatch = empRange.replace(/,/g, '').match(/(\d+)\s*[-–]\s*(\d+)/);
          if (rangeMatch) result.size = Math.round((parseInt(rangeMatch[1]) + parseInt(rangeMatch[2])) / 2);
          // Handle "10,001+" format
          var plusMatch = empRange.replace(/,/g, '').match(/(\d+)\+/);
          if (plusMatch && !result.size) result.size = parseInt(plusMatch[1]);
        }

        // Map industry to company type
        var ind = (result.industry || '').toLowerCase();
        if (/security|cyber|infosec/i.test(ind)) result.companyType = 'MSSP/MDR';
        else if (/government|defense|military|federal/i.test(ind)) result.companyType = 'Government';
        else if (/consult|advisory|professional\s*services/i.test(ind)) result.companyType = 'IT Consulting';
        else if (/staffing|recruit|talent|employment/i.test(ind)) result.companyType = 'Staffing/Recruiting';
        else result.companyType = 'Enterprise';

        return { statusCode: 200, headers: hdrs, body: JSON.stringify(result) };
      } catch (e) {
        return { statusCode: 200, headers: hdrs, body: JSON.stringify({ error: 'Company scraper error: ' + e.message }) };
      }
    }

    // ACTION: startProfileScrape - kick off scrape, return runId immediately (no wait)
    if (action === 'startProfileScrape') {
      var profileUrls = body.urls || [];
      if (!profileUrls.length) return { statusCode: 200, headers: hdrs, body: JSON.stringify({ error: 'No profile URLs provided' }) };
      try {
        var resp = await fetch('https://api.apify.com/v2/acts/' + PROFILE_ACTOR_ID + '/runs?token=' + APIFY_TOKEN, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            action: 'get-profiles',
            // #496: two modes — search by person name (+location), or by URL (slug-derived name)
            ...(body.searchName ? {} : {}),
            // #496c: URL mode passes the RAW URL as the keyword — the actor resolves URL
            // targets via a direct path that avoids the flaky text-search handler (user-verified
            // in the Apify console). Name mode remains a text search.
            keywords: body.searchName ? [ (body.searchName + ' ' + (body.searchCity || '')).trim() ]
                     : profileUrls,
            // #496: country geo filter for name search (LinkedIn geoUrn ids)
            ...(body.searchName && body.searchCountry && ({ 'india':'102713980','united states':'103644278','usa':'103644278','united kingdom':'101165590','uk':'101165590','canada':'101174742' })[String(body.searchCountry).trim().toLowerCase()]
               ? { location: [ ({ 'india':'102713980','united states':'103644278','usa':'103644278','united kingdom':'101165590','uk':'101165590','canada':'101174742' })[String(body.searchCountry).trim().toLowerCase()] ] } : {}),
            limit: body.searchName ? 8 : 3,
            profileFields: ['about','experience','organizations','skills','languages','honors','projects']
          })
        });
        var run = await resp.json();
        if (!run.data || !run.data.id) {
          return { statusCode: 200, headers: hdrs, body: JSON.stringify({
            error: 'Failed to start profile scraper',
            apifyStatus: resp.status,
            apifyResponse: run && run.error ? (run.error.message || run.error.type || JSON.stringify(run.error)) : JSON.stringify(run).slice(0, 300),
            urlCount: profileUrls.length
          }) };
        }
        return { statusCode: 200, headers: hdrs, body: JSON.stringify({ runId: run.data.id, datasetId: run.data.defaultDatasetId }) };
      } catch (e) {
        return { statusCode: 200, headers: hdrs, body: JSON.stringify({ error: 'Start error: ' + e.message }) };
      }
    }

    // ACTION: checkProfileScrape - poll status once, return results if done
    if (action === 'checkProfileScrape') {
      var runId = body.runId;
      var datasetId = body.datasetId;
      if (!runId) return { statusCode: 200, headers: hdrs, body: JSON.stringify({ error: 'No runId' }) };
      try {
        var statusResp = await fetch('https://api.apify.com/v2/actor-runs/' + runId + '?token=' + APIFY_TOKEN);
        var statusData = await statusResp.json();
        var status = statusData.data ? statusData.data.status : 'UNKNOWN';
        if (status === 'RUNNING' || status === 'READY') {
          return { statusCode: 200, headers: hdrs, body: JSON.stringify({ status: status, done: false }) };
        }
        if (status !== 'SUCCEEDED') {
          return { statusCode: 200, headers: hdrs, body: JSON.stringify({ status: status, done: true, error: 'Scraper ' + status }) };
        }
        // Succeeded — fetch results
        var resultsResp = await fetch('https://api.apify.com/v2/datasets/' + datasetId + '/items?token=' + APIFY_TOKEN + '&format=json');
        var profiles = await resultsResp.json();
        // #496b: the actor emits NOT_FOUND placeholder items on barren searches — drop them
        // so an all-stub result counts as empty and the frontend auto-retry engages.
        profiles = (profiles || []).filter(function (p) { return p && p.status !== 'NOT_FOUND'; });
        // #490: when the original url is provided, keep only the slug-matching profile
        if (body.url) {
          var wantSlug = (String(body.url).split('/in/')[1] || '').replace(/[\/?#].*$/,'').toLowerCase();
          if (wantSlug) {
            var hit = (profiles || []).filter(function(p){
              var vn = (p.vanityName || '').toLowerCase();
              var lu = (p.linkedinUrl || p.url || '').toLowerCase();
              return vn === wantSlug || lu.indexOf('/in/' + wantSlug) >= 0;
            });
            if (hit.length) profiles = hit;
          }
        }
        var results = (profiles || []).map(function(p) {
          var company = '';
          var title = p.headline || '';
          // Priority 1: experience array (when available)
          if (p.experience && p.experience.length > 0) {
            company = p.experience[0].companyName || '';
            if (p.experience[0].title) title = p.experience[0].title;
          }
          // Priority 2: extract from headline "Title at Company" or "Title | ... at Company"
          if (!company && p.headline) {
            company = extractCompanyFromHeadline(p.headline);
          }
          return {
            url: p.linkedinUrl || p.url || '',
            name: ((p.firstName || '') + ' ' + (p.lastName || '')).trim() || p.vanityName || '',
            company: company, title: title, status: p.status || '',
            // #490: pass the rich fields through instead of discarding them
            headline: p.headline || '', location: p.location || '',
            summary: p.summary || p.about || '',
            experience: p.experience || [], education: p.education || [],
            certifications: p.certifications || [], skills: p.skills || [],
            linkedinUrl: p.linkedinUrl || p.url || '', vanityName: p.vanityName || ''
          };
        });
        return { statusCode: 200, headers: hdrs, body: JSON.stringify({ status: status, done: true, profiles: results }) };
      } catch (e) {
        return { statusCode: 200, headers: hdrs, body: JSON.stringify({ error: 'Check error: ' + e.message }) };
      }
    }

    // ACTION: scrapeProfiles - Scrape LinkedIn person profiles to get current company
    if (action === 'scrapeProfiles') {
      var profileUrls = body.urls || [];
      if (!profileUrls.length) return { statusCode: 200, headers: hdrs, body: JSON.stringify({ error: 'No profile URLs provided' }) };
      try {
        // Start Bebity LinkedIn Premium Actor (get-profiles)
        var resp = await fetch('https://api.apify.com/v2/acts/' + PROFILE_ACTOR_ID + '/runs?token=' + APIFY_TOKEN, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            action: 'get-profiles',
            keywords: profileUrls,
            profileFields: ['about', 'experience', 'organizations']
          })
        });
        var run = await resp.json();
        if (!run.data || !run.data.id) return { statusCode: 200, headers: hdrs, body: JSON.stringify({ error: 'Failed to start profile scraper' }) };
        var runId = run.data.id;

        // Poll for completion (max 4 minutes)
        var maxPolls = 48;
        for (var p = 0; p < maxPolls; p++) {
          await new Promise(function(r) { setTimeout(r, 5000) });
          var statusResp = await fetch('https://api.apify.com/v2/actor-runs/' + runId + '?token=' + APIFY_TOKEN);
          var statusData = await statusResp.json();
          if (statusData.data && (statusData.data.status === 'SUCCEEDED' || statusData.data.status === 'FAILED' || statusData.data.status === 'ABORTED')) {
            if (statusData.data.status !== 'SUCCEEDED') return { statusCode: 200, headers: hdrs, body: JSON.stringify({ error: 'Profile scraper ' + statusData.data.status }) };
            break;
          }
        }

        // Fetch results
        var datasetId = run.data.defaultDatasetId;
        var resultsResp = await fetch('https://api.apify.com/v2/datasets/' + datasetId + '/items?token=' + APIFY_TOKEN + '&format=json');
        var profiles = await resultsResp.json();

        // Extract current company from experience array (first entry = most recent)
        var results = (profiles || []).map(function(p) {
          var company = '';
          var title = p.headline || '';
          if (p.experience && p.experience.length > 0) {
            // First experience entry is the current/most recent role
            company = p.experience[0].companyName || '';
            if (p.experience[0].title) title = p.experience[0].title;
          }
          return {
            url: p.linkedinUrl || p.url || '',
            name: ((p.firstName || '') + ' ' + (p.lastName || '')).trim() || p.vanityName || '',
            company: company,
            title: title,
            status: p.status || ''
          };
        });

        return { statusCode: 200, headers: hdrs, body: JSON.stringify({ profiles: results, total: results.length }) };
      } catch (e) {
        return { statusCode: 200, headers: hdrs, body: JSON.stringify({ error: 'Profile scraper error: ' + e.message }) };
      }
    }

    if (action === 'processAndSave') {
      var jobs = body.jobs || [];
      // Filter for cybersecurity relevance
      jobs = jobs.filter(function(j) { return isCyberRelevant(j.title, j.description); });
      if (!jobs.length) return { statusCode: 200, headers: hdrs, body: JSON.stringify({ saved: 0, filtered: true }) };

      var { getDb } = require('./db');
      var db = await getDb();
      var col = db.collection('jobs');

      // Extraction patterns (same as job-search.js)
      var TOOL_RE = /Microsoft\s*Defender(?:\s*(?:for\s*)?(?:Endpoint|Cloud|Identity|Office|Cloud\s*Apps))?|Microsoft\s*Sentinel|Microsoft\s*Entra(?:\s*ID)?|Microsoft\s*(?:Information\s*Protection|Purview|Intune)|M365(?:\s*Security)?|Azure\s*(?:Sentinel|AD|Monitor|Log\s*Analytics)|Conditional\s*Access|Azure|Splunk|QRadar|CrowdStrike|SentinelOne|Palo\s*Alto|Cortex\s*XDR|Cortex\s*XSOAR|LogRhythm|Elastic\s*(?:Security|SIEM)|Chronicle|Tenable|Qualys|Nessus|Rapid7|Carbon\s*Black|Fortinet|FortiSIEM|FortiGate|FortiAnalyzer|FortiManager|Check\s*Point|Cisco\s*(?:ASA|Firepower|SecureX|Umbrella)|Snort|Suricata|Wireshark|Burp\s*Suite|Metasploit|Phantom|Swimlane|KQL|SPL|YARA|Sigma|ServiceNow|Jira|Proofpoint|Mimecast|Zscaler|Okta|CyberArk|BeyondTrust|Varonis|DarkTrace|Vectra|Tanium|Exabeam|Securonix|AWS|GCP|Google\s*Cloud|Prisma\s*Cloud|Wiz|Terraform|Ansible|Kubernetes|Docker|Jenkins|Python|Bash|PowerShell|SIEM|SOAR|EDR|XDR|NDR|IDS[\s\/]*IPS|DLP|WAF|CASB|CSPM|IAM|PAM|MFA|SSO|UEBA|Aqua|Twistlock|Trivy|Falco|Sysdig|Anchore|Checkov|McAfee(?:\s*(?:SIEM|ESM|ePO))?|Trellix|SD[\s-]*WAN|SCADA|Modbus|DNP3|OPC[\s-]*UA?|Federated\s*Identity|AWS\s*VPC\s*Flow\s*Logs|TCP\/IP|DNS|VPN|IPSec|SAST|DAST|CI\/CD|DevSecOps/gi;
      var CERT_RE = /CISSP|CISM|CISA|CEH|OSCP|OSCE|GPEN|GCIH|GCIA|GCED|GCFA|GCFE|GNFA|GMON|GSEC|GREM|GWAPT|CompTIA\s*Security\+|CompTIA\s*CySA\+|CompTIA\s*CASP\+|CompTIA\s*Network\+|CompTIA\s*Server\+|CompTIA\s*A\+|CompTIA\s*Linux\+|CompTIA\s*Cloud\+|CompTIA\s*PenTest\+|CompTIA\s*SecurityX|(?<![\w+])Security\+|(?<![\w+])Network\+|(?<![\w+])CySA\+|(?<![\w+])PenTest\+|(?<![\w+])CASP\+|SC-100|SC-200|SC-300|SC-400|AZ-\d{3}|DP-\d{3}|AI-\d{3}|MS-\d{3}|PL-\d{3}|CCSP|CCNA|CCNP|CRISC|SSCP|SANS|GIAC|ITIL|PCNSE|SABSA|NSE\s*[4-8]|Fortinet\s*NSE|Azure\s*Security\s*Engineer(?:\s*Associate)?/gi;
      var COMP_RE = /SOC\s*2|ISO\s*27001|NIST\s*(?:SP\s*)?800-53|NIST\s*(?:SP\s*)?800-61|NIST\s*(?:SP\s*)?800-171|NIST\s*CSF|PCI[\s-]*DSS|HIPAA|GDPR|FedRAMP|HITRUST|CMMC|CCPA|FISMA|SOX|COBIT|CIS\s*Controls|MITRE\s*ATT&CK|Zero\s*Trust|NERC\s*CIP|OWASP\s*Top\s*10|NIST\s*RMF|STIX[\s\/]*TAXII|\bNIST\b/gi;

      function uniqueMatch(text, re) {
        if (!text) return [];
        var NORM = {'siem':'SIEM','soar':'SOAR','edr':'EDR','xdr':'XDR','ndr':'NDR','ids/ips':'IDS/IPS','dlp':'DLP','waf':'WAF','casb':'CASB','cspm':'CSPM','cwpp':'CWPP','cnapp':'CNAPP','iam':'IAM','pam':'PAM','mfa':'MFA','sso':'SSO','ueba':'UEBA','tcp/ip':'TCP/IP','dns':'DNS','vpn':'VPN','ipsec':'IPSec','sast':'SAST','dast':'DAST','ci/cd':'CI/CD','devsecops':'DevSecOps','spl':'SPL','kql':'KQL','yara':'YARA','aws':'AWS','gcp':'GCP','azure':'Azure','python':'Python','bash':'Bash','powershell':'PowerShell','golang':'Golang','splunk':'Splunk','crowdstrike':'CrowdStrike','sentinelone':'SentinelOne','microsoft sentinel':'Microsoft Sentinel','microsoft defender':'Microsoft Defender','zero trust':'Zero Trust','mitre att&ck':'MITRE ATT&CK','cyber kill chain':'Cyber Kill Chain','rbac':'RBAC','grc':'GRC','osint':'OSINT'};
        var m = text.match(re) || [], seen = {};
        return m.filter(function(v) { var k = v.toLowerCase().trim(); if (seen[k]) return false; seen[k] = true; return true; }).map(function(v) {
          var k = v.toLowerCase().trim(); return NORM[k] || v;
        }).slice(0, 12);
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

        // #273: Ensure LinkedIn URL goes to companyLinkedin, not companyUrl
        var saveCompanyUrl = j.companyUrl || '';
        var saveCompanyLinkedin = j.companyLinkedin || '';
        if (saveCompanyUrl.indexOf('linkedin.com/company') > -1) {
          saveCompanyLinkedin = saveCompanyLinkedin || saveCompanyUrl;
          saveCompanyUrl = '';
        }

        var jobDoc = {
          jobId: j.jobId,
          linkedinJobId: j.linkedinJobId,
          title: j.title,
          titleClean: j.title,
          company: j.company,
          companyUrl: saveCompanyUrl,
          companyLinkedin: saveCompanyLinkedin,
          companyLogo: j.companyLogo,
          location: j.location,
          description: desc,
          salary: j.salary || 'Not disclosed',
          datePosted: j.datePosted ? new Date(j.datePosted) : null,
          jobType: jobType,
          contractDuration: extractContractDuration(desc),   // #411
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
                contractDuration: jobDoc.contractDuration,
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

    // ACTION: cleanupNonCyber - remove non-cybersecurity jobs from DB
    if (action === 'cleanupNonCyber') {
      var { getDb } = require('./db');
      var db = await getDb();
      var col = db.collection('jobs');
      // Check ALL jobs from LinkedIn sources (apify-bebity, linkedin.com, etc.)
      var linkedinJobs = await col.find({
        $or: [
          { sourceApi: 'apify-bebity' },
          { source: { $regex: 'linkedin', $options: 'i' } },
          { applyLink: { $regex: 'linkedin\\.com', $options: 'i' } },
          { jobUrl: { $regex: 'linkedin\\.com', $options: 'i' } }
        ]
      }).project({ _id: 1, title: 1, description: 1 }).toArray();
      var toDelete = [];
      linkedinJobs.forEach(function(j) {
        if (!isCyberRelevant(j.title, j.description)) toDelete.push(j._id);
      });
      var deleted = 0;
      if (toDelete.length > 0) {
        var result = await col.deleteMany({ _id: { $in: toDelete } });
        deleted = result.deletedCount || 0;
      }
      return { statusCode: 200, headers: hdrs, body: JSON.stringify({ checked: linkedinJobs.length, deleted: deleted, kept: linkedinJobs.length - deleted }) };
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

  // Strip "with Security Clearance" — it's not a cyber keyword
  t = t.replace(/\bwith\s+security\s+clearance\b/gi, '').replace(/\bsecurity\s+clearance\b/gi, '').trim();

  // Reject known non-IT titles immediately
  var NON_IT = /\b(humint|sigint|geoint|masint|imint|osint\s*analyst|maintenance|customer\s*success|optimizer|program\s*analyst|budget\s*analyst|financial\s*analyst|hr\s*analyst|compensation\s*analyst|operations?\s*(?:concept\s*)?analyst|concept\s*analyst|business\s*analyst|supply\s*chain|logistics|nurse|clinical|pharmacist|medical|social\s*worker|case\s*manager|paralegal|loan\s*officer|mortgage|real\s*estate|truck\s*driver|warehouse|forklift|cashier|retail|food\s*service|janitor|custodian|landscap|plumber|intelligence\s*analyst(?!\s*(?:cyber|threat\s*intel))|policy\s*analyst|research\s*analyst(?!\s*(?:cyber|security|threat))|space\s*(?:threat|analyst|operations)|operational\s*concept|weapons?\s*analyst|mission\s*analyst|battle|combat|acquisition\s*analyst|contracts?\s*(?:specialist|analyst|manager)|procurement|j-?\s*\d+\b)\b/i;
  if (NON_IT.test(t)) return false;

  // Defense/military context — even if cyber keywords present, verify with description
  var DEFENSE_CONTEXT = /\b(clearance|dod|military|defense|army|navy|air\s*force|marines|pentagon|joint\s*staff|combatant|classified|top\s*secret|ts[\s\/]*sci|space\s*command|norad|stratcom|centcom|socom)\b/i;
  var hasDefenseContext = DEFENSE_CONTEXT.test(title || '');

  // Title contains specific cybersecurity keywords
  var CYBER_TITLE = /\b(soc\s*analyst|soc\s*engineer|soc\s*manager|soc\s*lead|security\s*(?:analyst|engineer|architect|consultant|operations|specialist|administrator|manager|director|researcher)|cyber(?:security)?|infosec|siem|threat\s*(?:analyst|hunter|intelligence|researcher)|incident\s*(?:response|handler|analyst)|malware\s*analyst|forensic|pentest|penetration\s*test|vulnerability\s*(?:analyst|engineer|manager)|devsecops|secops|ciso|csirt|dfir|blue\s*team|red\s*team|purple\s*team|cloud\s*security|network\s*security|information\s*security|it\s*security|application\s*security|security\s*monitoring|detection\s*(?:engineer|analyst)|endpoint\s*security)\b/i;

  if (CYBER_TITLE.test(t)) {
    // If defense context, also require 2+ cyber signals in description
    if (hasDefenseContext) {
      var cyberCount = 0;
      [/\bsiem\b/i, /\bedr\b/i, /\bsecurity\s*operations\s*center\b/i, /\bfirewall/i,
       /\bsplunk|crowdstrike|sentinel/i, /\bmalware\b/i, /\bphishing\b/i,
       /\bcybersecurity\b/i, /\bincident\s*response/i, /\bids[\s\/]*ips\b/i
      ].forEach(function(re) { if (re.test(d)) cyberCount++; });
      return cyberCount >= 2;
    }
    return true;
  }

  // Title is generic — check description for 3+ cyber signals
  var cyberSignals = 0;
  var SIGNALS = [/\bsiem\b/i, /\bedr\b/i, /\bsoc\b/i, /\bsecurity\s*operations/i, /\bincident\s*response/i,
    /\bthreat\s*(?:hunt|detect|intel)/i, /\bfirewall/i, /\bids[\s\/]*ips\b/i, /\bmitre\s*att/i,
    /\bcrowdstrike|sentinel(?:one)?|splunk|qradar\b/i, /\bmalware\b/i, /\bphishing\b/i,
    /\bcybersecurity\b/i, /\bvulnerability/i, /\bpenetration\s*test/i, /\bnist\b/i,
    /\bcompti?a\s*security/i, /\bcissp\b/i, /\boscp\b/i, /\bgcih\b/i];
  SIGNALS.forEach(function(re) { if (re.test(d)) cyberSignals++; });

  return cyberSignals >= 3;
}

// #411: Extract contract length from the description. This existed only in the JSearch
// path (job-search.js), so LinkedIn-scanned jobs never got a duration — even when the
// description clearly said "Contract Length: 18 Months".
function extractContractDuration(desc) {
  var d = String(desc || '');
  var patterns = [
    // Ranges first, so "6-12 months" doesn't match as just "6 months"
    /\b(?:duration|length|term|period)\s*(?:[\-–—:]\s*)?(\d+)\s*(?:[\-–—]|to)\s*(\d+)\s*(?:months?|mos?)/i,
    /\b(\d+)\s*(?:[\-–—]|to)\s*(\d+)\s*(?:months?|mos?)\s*(?:contract|engagement|initial|assignment)/i,
    // Single values — covers "Contract Length: 18 Months", "Duration - 12 months"
    /\b(?:contract\s*)?(?:duration|length|term|period)\s*(?:[\-–:]\s*)?(\d+)[\s-]*(?:months?|mos?)/i,
    /\b(\d+)[\s-]*(?:months?|mos?)\s*(?:contract|engagement|assignment|initial|rolling|duration)/i,
    /\b(?:initial\s*)?(?:contract|engagement)\s*(?:[\-–:]\s*)?(\d+)[\s-]*(?:months?|mos?)/i,
    /\b(?:contract|engagement)(?:\s+\w+){0,2}\s*\(\s*(\d+)[\s-]*(?:months?|mos?)[^)]*\)/i,
    /\b(?:contract[\s-]*to[\s-]*hire|c2h|temp[\s-]*to[\s-]*perm)\s*(?:after\s*)?(\d+)[\s-]*(?:months?|mos?)/i,
    /\b(\d+)[\s-]*(?:months?|mos?)\s*(?:\+\s*(?:\d+\s*)?(?:months?|extension))/i,
    /\b(?:duration|length|term|period)\s*(?:[\-–:]\s*)?(\d+)[\s-]*(?:weeks?)/i,
    // Year-based
    /\b(\d+)[\s-]*(?:year|yr)s?\s*(?:renewable|rolling|extendable|fixed[\s-]*term)?\s*(?:contract|engagement|assignment)/i,
    /\b(?:contract|engagement)\s*(?:[\-–:(]\s*)?(\d+)[\s-]*(?:year|yr)/i
  ];
  for (var i = 0; i < patterns.length; i++) {
    var m = d.match(patterns[i]);
    if (!m) continue;
    if (m[2] && i <= 1) {
      var r1 = parseInt(m[1]), r2 = parseInt(m[2]);
      if (r1 >= 1 && r1 <= 36 && r2 >= 1 && r2 <= 36 && r2 > r1) return r1 + '-' + r2 + ' months';
      continue;
    }
    var num = parseInt(m[1]);
    if (i >= 9) {                                   // year patterns
      if (num >= 1 && num <= 5) return num === 1 ? '1 year' : num + ' years';
      continue;
    }
    if (i === 8) {                                  // weeks pattern
      if (num >= 1 && num <= 104) return num + ' weeks';
      continue;
    }
    if (num >= 1 && num <= 36) return num + ' months';
  }
  return '';
}

function detectCountryFromLocation(loc) {
  if (!loc) return 'Unknown';
  var l = loc.toLowerCase();

  // Canadian provinces/territories are decisive — check BEFORE the US state codes,
  // because "CA" is ambiguous (California vs the ISO code for Canada) and several
  // Canadian job boards write locations as "Halifax, Nova Scotia, CA" or just "CA".
  var CA_PROVINCE = /\b(Alberta|British Columbia|Manitoba|New Brunswick|Newfoundland|Labrador|Nova Scotia|Ontario|Prince Edward|Quebec|Saskatchewan|Yukon|Nunavut|Northwest Territories)\b/i;
  if (CA_PROVINCE.test(loc) || /\bcanada\b/i.test(l)) return 'Canada';

  // Bare "CA" with no other geography = the ISO country code for Canada
  // (that's how Canadian boards populate it), NOT California.
  if (/^\s*CA\s*$/i.test(loc)) return 'Canada';

  // "<City>, CA" with no Canadian signal => California, i.e. United States.
  // Known Canadian cities are excluded so "Toronto, CA" stays Canada.
  var CA_CITY = /\b(toronto|montreal|montréal|vancouver|calgary|edmonton|ottawa|winnipeg|hamilton|kitchener|victoria|halifax|oshawa|windsor|saskatoon|regina|barrie|kelowna|abbotsford|sudbury|kingston|guelph|moncton|brantford|thunder bay|sherbrooke|peterborough|lethbridge|nanaimo|kamloops|fredericton|mississauga|brampton|surrey|laval|markham|vaughan|gatineau|longueuil|burnaby|richmond hill|oakville|burlington|waterloo|milton|cambridge|whitby|coquitlam|langley)\s*,\s*CA\b/i;
  if (CA_CITY.test(loc)) return 'Canada';

  var US_STATES = /\b(AL|AK|AZ|AR|CA|CO|CT|DE|FL|GA|HI|ID|IL|IN|IA|KS|KY|LA|ME|MD|MA|MI|MN|MS|MO|MT|NE|NV|NH|NJ|NM|NY|NC|ND|OH|OK|OR|PA|RI|SC|SD|TN|TX|UT|VT|VA|WA|WV|WI|WY|DC)\b/;
  var US_STATE_NAMES = /\b(California|Texas|New York|Florida|Illinois|Virginia|Washington|Georgia|Massachusetts|Colorado|Arizona|Ohio|Michigan|Pennsylvania|Maryland|Minnesota|Oregon|Nevada|Utah|Missouri|Indiana|Wisconsin|Tennessee|Alabama|Connecticut|New Jersey|North Carolina|South Carolina|Kentucky|Louisiana|Oklahoma|Iowa|Kansas|Arkansas|Mississippi|Nebraska|Idaho|Hawaii|Maine|New Hampshire|Rhode Island|Montana|Delaware|South Dakota|North Dakota|Vermont|Wyoming|West Virginia|New Mexico)\b/i;
  if (US_STATES.test(loc) || US_STATE_NAMES.test(loc) || /united states|usa/i.test(loc)) return 'United States';

  if (/united kingdom|england|scotland|wales/i.test(l)) return 'United Kingdom';
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
