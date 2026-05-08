const { getDb } = require('./db');

exports.handler = async (event) => {
  if (event.httpMethod === 'OPTIONS')
    return { statusCode: 204, headers: { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': 'Content-Type', 'Access-Control-Allow-Methods': 'POST, OPTIONS' }, body: '' };
  if (event.httpMethod !== 'POST')
    return { statusCode: 405, body: JSON.stringify({ error: 'Method not allowed' }) };
  var hdrs = { 'Access-Control-Allow-Origin': '*', 'Content-Type': 'application/json' };

  try {
    var body = JSON.parse(event.body);
    var action = body.action;
    var db = await getDb();
    var col = db.collection('jobs');

    // ACTION: search - query saved jobs from database
    if (action === 'search') {
      var filter = {};
      if (body.query) {
        filter.$or = [
          { title: { $regex: body.query, $options: 'i' } },
          { titleClean: { $regex: body.query, $options: 'i' } },
          { company: { $regex: body.query, $options: 'i' } },
          { skills: { $regex: body.query, $options: 'i' } },
          { tools: { $regex: body.query, $options: 'i' } },
          { certifications: { $regex: body.query, $options: 'i' } },
          { description: { $regex: body.query, $options: 'i' } }
        ];
      }
      if (body.status && body.status !== 'all') filter.status = body.status;
      if (body.company) filter.company = body.company;
      if (body.companyType && body.companyType !== 'all') filter.companyType = body.companyType;
      if (body.jobType && body.jobType !== 'all') filter.jobType = body.jobType;
      if (body.country && body.country !== 'all') filter.searchCountry = body.country;
      if (body.detectedCountry && body.detectedCountry !== 'all') filter.detectedCountry = body.detectedCountry;
      if (body.dateFrom || body.dateTo) {
        filter.datePosted = {};
        if (body.dateFrom) filter.datePosted.$gte = new Date(body.dateFrom);
        if (body.dateTo) filter.datePosted.$lte = new Date(body.dateTo + 'T23:59:59Z');
      }

      var page = body.page || 1;
      var limit = body.limit || 100;
      var skip = (page - 1) * limit;
      var sort = body.sort || { dateScanned: -1 };

      var total = await col.countDocuments(filter);
      var jobs = await col.find(filter)
        .project({ description: 0 }) // exclude large field for list view
        .sort(sort)
        .skip(skip)
        .limit(limit)
        .toArray();

      // Map _id to string and add idx
      jobs = jobs.map(function(j, i) {
        j._id = j._id.toString();
        j.idx = skip + i + 1;
        return j;
      });

      return { statusCode: 200, headers: hdrs, body: JSON.stringify({ jobs, total, page, pages: Math.ceil(total / limit) }) };
    }

    // ACTION: get - get single job with full description
    if (action === 'get') {
      var { ObjectId } = require('mongodb');
      var job = await col.findOne({ _id: new ObjectId(body.id) });
      if (!job) return { statusCode: 404, headers: hdrs, body: JSON.stringify({ error: 'Job not found' }) };
      job._id = job._id.toString();
      return { statusCode: 200, headers: hdrs, body: JSON.stringify({ job }) };
    }

    // ACTION: updateStatus - update job status by _id
    if (action === 'updateStatus') {
      var { ObjectId } = require('mongodb');
      var result = await col.updateOne(
        { _id: new ObjectId(body.id) },
        { $set: { status: body.status, statusUpdatedAt: new Date() } }
      );
      return { statusCode: 200, headers: hdrs, body: JSON.stringify({ modified: result.modifiedCount }) };
    }

    // ACTION: updateStatusByJobId - update job status by jobId (for web search results)
    if (action === 'updateStatusByJobId') {
      var result = await col.updateOne(
        { jobId: body.jobId },
        { $set: { status: body.status, statusUpdatedAt: new Date() } }
      );
      return { statusCode: 200, headers: hdrs, body: JSON.stringify({ modified: result.modifiedCount }) };
    }

    // ACTION: updateCountry - update detected country by _id
    if (action === 'updateCountry') {
      var { ObjectId } = require('mongodb');
      var result = await col.updateOne(
        { _id: new ObjectId(body.id) },
        { $set: { detectedCountry: body.country, countryUpdatedAt: new Date() } }
      );
      return { statusCode: 200, headers: hdrs, body: JSON.stringify({ modified: result.modifiedCount }) };
    }

    // ACTION: updateCountryByJobId - update detected country by jobId
    if (action === 'updateCountryByJobId') {
      var result = await col.updateOne(
        { jobId: body.jobId },
        { $set: { detectedCountry: body.country, countryUpdatedAt: new Date() } }
      );
      return { statusCode: 200, headers: hdrs, body: JSON.stringify({ modified: result.modifiedCount }) };
    }

    // ACTION: updateCompanyType - classify company
    if (action === 'updateCompanyType') {
      var { ObjectId } = require('mongodb');
      var result = await col.updateOne(
        { _id: new ObjectId(body.id) },
        { $set: { companyType: body.companyType, companyTypeUpdatedAt: new Date() } }
      );
      return { statusCode: 200, headers: hdrs, body: JSON.stringify({ modified: result.modifiedCount }) };
    }

    // ACTION: bulkUpdateCompanyType - classify multiple jobs for same company
    if (action === 'bulkUpdateCompanyType') {
      var result = await col.updateMany(
        { company: body.company },
        { $set: { companyType: body.companyType, companyTypeUpdatedAt: new Date() } }
      );
      return { statusCode: 200, headers: hdrs, body: JSON.stringify({ modified: result.modifiedCount }) };
    }

    // ACTION: updateCompanyUrl - fix wrong company website for all jobs of same company
    if (action === 'updateCompanyUrl') {
      var result = await col.updateMany(
        { company: body.company },
        { $set: { companyUrl: body.companyUrl, companyUrlUpdatedAt: new Date() } }
      );
      return { statusCode: 200, headers: hdrs, body: JSON.stringify({ modified: result.modifiedCount }) };
    }

    // ACTION: updateNotes - add notes to a job
    if (action === 'updateNotes') {
      var { ObjectId } = require('mongodb');
      var result = await col.updateOne(
        { _id: new ObjectId(body.id) },
        { $set: { notes: body.notes, notesUpdatedAt: new Date() } }
      );
      return { statusCode: 200, headers: hdrs, body: JSON.stringify({ modified: result.modifiedCount }) };
    }

    // ACTION: stats - get dashboard statistics
    if (action === 'stats') {
      var totalJobs = await col.countDocuments({});
      var statusCounts = await col.aggregate([
        { $group: { _id: '$status', count: { $sum: 1 } } }
      ]).toArray();
      var typeCounts = await col.aggregate([
        { $match: { companyType: { $ne: '' } } },
        { $group: { _id: '$companyType', count: { $sum: 1 } } },
        { $sort: { count: -1 } }
      ]).toArray();
      var countryCounts = await col.aggregate([
        { $match: { detectedCountry: { $ne: null } } },
        { $group: { _id: '$detectedCountry', count: { $sum: 1 } } },
        { $sort: { count: -1 } },
        { $limit: 10 }
      ]).toArray();
      var companyCounts = await col.aggregate([
        { $group: { _id: '$company', count: { $sum: 1 } } },
        { $sort: { count: -1 } },
        { $limit: 10 }
      ]).toArray();
      // Split comma-separated fields, normalize case, then count
      var certCounts = await col.aggregate([
        { $match: { certifications: { $ne: 'See details' } } },
        { $project: { items: { $split: ['$certifications', ', '] } } },
        { $unwind: '$items' },
        { $match: { items: { $ne: '' } } },
        { $group: { _id: { $toUpper: { $trim: { input: '$items' } } }, count: { $sum: 1 } } },
        { $sort: { count: -1 } },
        { $limit: 10 }
      ]).toArray();
      var complianceCounts = await col.aggregate([
        { $match: { compliance: { $ne: 'See details' } } },
        { $project: { items: { $split: ['$compliance', ', '] } } },
        { $unwind: '$items' },
        { $match: { items: { $ne: '' } } },
        { $group: { _id: { $toUpper: { $trim: { input: '$items' } } }, count: { $sum: 1 } } },
        { $sort: { count: -1 } },
        { $limit: 10 }
      ]).toArray();
      var toolsCounts = await col.aggregate([
        { $match: { tools: { $ne: 'See details' } } },
        { $project: { items: { $split: ['$tools', ', '] } } },
        { $unwind: '$items' },
        { $match: { items: { $ne: '' } } },
        { $group: { _id: { $toUpper: { $trim: { input: '$items' } } }, count: { $sum: 1 } } },
        { $sort: { count: -1 } },
        { $limit: 10 }
      ]).toArray();
      var locationCounts = await col.aggregate([
        { $match: { location: { $ne: 'Remote' } } },
        { $group: { _id: '$location', count: { $sum: 1 }, country: { $first: '$detectedCountry' } } },
        { $sort: { count: -1 } },
        { $limit: 10 }
      ]).toArray();
      // Append country name to location for display
      locationCounts.forEach(function(l) {
        if (l.country && l.country !== 'Unknown' && l._id && l._id.indexOf(l.country) === -1) {
          l._id = l._id + ' (' + l.country + ')';
        }
      });
      var recentScans = await col.aggregate([
        { $group: { _id: { $dateToString: { format: '%Y-%m-%d', date: '$dateScanned' } }, count: { $sum: 1 } } },
        { $sort: { _id: -1 } },
        { $limit: 14 }
      ]).toArray();

      // Partnership targets: companies with most openings, grouped by type
      var partnerTargets = await col.aggregate([
        { $group: { _id: { company: '$company', type: '$companyType' }, count: { $sum: 1 },
          statuses: { $push: '$status' }, locations: { $addToSet: '$location' },
          companyUrl: { $first: '$companyUrl' } } },
        { $sort: { count: -1 } },
        { $limit: 20 }
      ]).toArray();

      // Role distribution - case insensitive, normalize variants
      var roleCounts = await col.aggregate([
        { $match: { titleClean: { $ne: null } } },
        { $group: { _id: { $toLower: '$titleClean' }, count: { $sum: 1 } } },
        { $sort: { count: -1 } },
        { $limit: 10 }
      ]).toArray();

      // Skills distribution (comma-separated) - case insensitive
      var skillCounts = await col.aggregate([
        { $match: { skills: { $ne: 'See details' } } },
        { $project: { items: { $split: ['$skills', ', '] } } },
        { $unwind: '$items' },
        { $match: { items: { $ne: '' } } },
        { $group: { _id: { $toLower: { $trim: { input: '$items' } } }, count: { $sum: 1 } } },
        { $sort: { count: -1 } },
        { $limit: 15 }
      ]).toArray();

      // Salary distribution (count by ranges)
      var salaryJobs = await col.aggregate([
        { $match: { salary: { $ne: 'Not disclosed' } } },
        { $group: { _id: '$salary', count: { $sum: 1 } } },
        { $sort: { count: -1 } },
        { $limit: 10 }
      ]).toArray();

      // Post-process: title-case, merge variants
      function titleCase(s) {
        if (!s) return 'Unknown';
        // Keep acronyms uppercase
        var acronyms = ['SIEM','SOAR','EDR','XDR','NDR','IDS','IPS','DLP','WAF','CASB','CSPM','CWPP','CNAPP','IAM','PAM','MFA','SSO','UEBA','KQL','SPL','SOC','NIST','MITRE','CISSP','CISM','CISA','CEH','OSCP','OSCE','CCSP','CCNA','CCNP','GCIH','GCIA','GSEC','GREM','GPEN','GIAC','SANS','ITIL','TOGAF','HIPAA','GDPR','FISMA','CMMC','CCPA','COBIT','DFARS','ITAR','FAIR','ISMS','OCTAVE','STRIDE','DREAD','CRISC','CGEIT','SSCP','CPTS','PNPT','HITRUST'];
        return s.replace(/\w\S*/g, function(t) {
          var upper = t.toUpperCase();
          if (acronyms.indexOf(upper) !== -1) return upper;
          if (/^(SC|AZ|MS)-\d+$/i.test(t)) return t.toUpperCase();
          if (/^(NIST|ISO|PCI|SOC|CIS|CSA|TIC|NERC)/i.test(t)) return t.toUpperCase();
          return t.charAt(0).toUpperCase() + t.slice(1).toLowerCase();
        });
      }
      // Merge known variants
      var VARIANTS = {
        'cybersecurity analyst': 'Cybersecurity Analyst',
        'cyber security analyst': 'Cybersecurity Analyst',
        'cybersecurity engineer': 'Cybersecurity Engineer',
        'cyber security engineer': 'Cybersecurity Engineer',
        'microsoft sentinel': 'Microsoft Sentinel',
        'azure sentinel': 'Microsoft Sentinel',
        'microsoft defender': 'Microsoft Defender',
        'microsoft defender for endpoint': 'Microsoft Defender for Endpoint',
        'ids/ips': 'IDS/IPS',
        'ids / ips': 'IDS/IPS',
        'nist sp 800-53': 'NIST SP 800-53',
        'nist sp 800-61': 'NIST SP 800-61',
        'nist sp 800-171': 'NIST SP 800-171',
        'nist csf': 'NIST CSF',
        'nist rmf': 'NIST RMF',
        'mitre att&ck': 'MITRE ATT&CK',
        'mitre att&amp;ck': 'MITRE ATT&CK',
        'zero trust': 'Zero Trust',
        'pci-dss': 'PCI-DSS',
        'pci dss': 'PCI-DSS',
        'soc 2': 'SOC 2',
        'soc2': 'SOC 2',
        'cyber kill chain': 'Cyber Kill Chain',
        'owasp top 10': 'OWASP Top 10',
        'cis controls': 'CIS Controls',
        'cis benchmarks': 'CIS Benchmarks',
        'fair': 'FAIR',
        'isms': 'ISMS',
        'octave': 'OCTAVE',
        'stride': 'STRIDE',
        'dread': 'DREAD',
        'itar': 'ITAR',
        'glba': 'GLBA',
        'ferpa': 'FERPA',
        'dfars': 'DFARS',
        'fisma': 'FISMA',
        'hipaa': 'HIPAA',
        'gdpr': 'GDPR',
        'ccpa': 'CCPA',
        'sox': 'SOX',
        'cobit': 'COBIT',
        'hitrust': 'HITRUST',
        'fedramp': 'FedRAMP',
        'cmmc': 'CMMC',
        'giac': 'GIAC',
        'sans': 'SANS',
        'crisc': 'CRISC',
        'cgeit': 'CGEIT',
        'sscp': 'SSCP',
        'cpts': 'CPTS',
        'ejpt': 'eJPT',
        'ecppt': 'eCPPT',
        'pnpt': 'PNPT',
        'oscp': 'OSCP',
        'osce': 'OSCE',
        'gpen': 'GPEN',
        'gcih': 'GCIH',
        'gcia': 'GCIA',
        'gsec': 'GSEC',
        'grem': 'GREM',
        'incident response': 'Incident Response',
        'threat hunting': 'Threat Hunting',
        'threat intelligence': 'Threat Intelligence',
        'threat detection': 'Threat Detection',
        'vulnerability management': 'Vulnerability Management',
        'penetration testing': 'Penetration Testing',
        'cloud security': 'Cloud Security',
        'network security': 'Network Security',
        'security operations': 'Security Operations',
        'digital forensics': 'Digital Forensics',
        'malware analysis': 'Malware Analysis',
        'detection engineering': 'Detection Engineering',
        'security monitoring': 'Security Monitoring',
        'log analysis': 'Log Analysis',
        'alert triage': 'Alert Triage',
        'risk assessment': 'Risk Assessment',
        'security architecture': 'Security Architecture',
        'security engineering': 'Security Engineering',
        'endpoint security': 'Endpoint Security',
        'email security': 'Email Security',
        'container security': 'Container Security',
        'soc analyst': 'SOC Analyst',
        'security engineer': 'Security Engineer',
        'security architect': 'Security Architect',
        'siem engineer': 'SIEM Engineer',
        'threat hunter': 'Threat Hunter',
        'cloud security engineer': 'Cloud Security Engineer',
        'incident responder': 'Incident Responder',
      };
      function normList(arr) {
        if (!arr) return [];
        var merged = {};
        arr.forEach(function(item) {
          var key = (item._id || '').toLowerCase().trim();
          var display = VARIANTS[key] || titleCase(item._id || '');
          if (!merged[display]) merged[display] = 0;
          merged[display] += item.count;
        });
        return Object.keys(merged).map(function(k) { return { _id: k, count: merged[k] }; })
          .sort(function(a, b) { return b.count - a.count; });
      }

      certCounts = normList(certCounts);
      complianceCounts = normList(complianceCounts);
      toolsCounts = normList(toolsCounts);
      skillCounts = normList(skillCounts);
      roleCounts = normList(roleCounts);

      return { statusCode: 200, headers: hdrs, body: JSON.stringify({
        totalJobs, statusCounts, typeCounts, countryCounts, companyCounts,
        certCounts, complianceCounts, toolsCounts, locationCounts, recentScans,
        partnerTargets, roleCounts, skillCounts, salaryJobs
      })};
    }

    // ACTION: fixCountries - retroactively detect country for Unknown records
    if (action === 'fixCountries') {
      var unknowns = await col.find({ $or: [{ detectedCountry: 'Unknown' }, { detectedCountry: null }, { detectedCountry: '' }] })
        .project({ _id: 1, location: 1, title: 1, description: 1, searchCountry: 1 }).toArray();
      var fixed = 0;
      var US_STATE_NAMES = /\b(?:Alabama|Alaska|Arizona|Arkansas|California|Colorado|Connecticut|Delaware|Florida|Georgia|Hawaii|Idaho|Illinois|Indiana|Iowa|Kansas|Kentucky|Louisiana|Maine|Maryland|Massachusetts|Michigan|Minnesota|Mississippi|Missouri|Montana|Nebraska|Nevada|New Hampshire|New Jersey|New Mexico|New York|North Carolina|North Dakota|Ohio|Oklahoma|Oregon|Pennsylvania|Rhode Island|South Carolina|South Dakota|Tennessee|Texas|Utah|Vermont|Virginia|Washington|West Virginia|Wisconsin|Wyoming|District of Columbia)\b/i;
      var US_STATE_CD = /,\s*(?:AL|AK|AZ|AR|CA|CO|CT|DE|FL|GA|HI|ID|IL|IN|IA|KS|KY|LA|ME|MD|MA|MI|MN|MS|MO|MT|NE|NV|NH|NJ|NM|NY|NC|ND|OH|OK|OR|PA|RI|SC|SD|TN|TX|UT|VT|VA|WA|WV|WI|WY|DC)\b/;
      var US_CITIES = /\b(?:New York|Los Angeles|Chicago|Houston|Phoenix|Dallas|San Jose|Austin|San Francisco|Seattle|Denver|Nashville|Washington|Boston|Portland|Las Vegas|Baltimore|Atlanta|Raleigh|Miami|Tampa|Orlando|Minneapolis|Cleveland|Pittsburgh|Cincinnati|Irvine|Arlington|Plano|Durham|Richmond|Huntsville|McLean|Tysons|Bethesda|Herndon|Reston|Chantilly|Springfield|Columbia|Annapolis|Fort Meade|Salt Lake City|Charlotte|San Diego|San Antonio|Sacramento|Philadelphia|Detroit|Memphis|Louisville|Milwaukee|Tucson|Fresno|Omaha|Oklahoma City|Scottsdale|Chandler|Boise)\b/i;
      var UK_CITIES = /\b(?:London|Manchester|Birmingham|Leeds|Glasgow|Edinburgh|Bristol|Liverpool|Sheffield|Newcastle|Nottingham|Cardiff|Belfast|Cambridge|Oxford|Reading)\b/i;
      var CA_CITIES = /\b(?:Toronto|Vancouver|Montreal|Ottawa|Calgary|Edmonton|Winnipeg|Mississauga)\b/i;
      var IN_CITIES = /\b(?:Bangalore|Bengaluru|Mumbai|Hyderabad|Pune|Delhi|New Delhi|Chennai|Kolkata|Noida|Gurgaon|Gurugram|Ahmedabad|Kochi|Chandigarh)\b/i;
      var AU_CITIES = /\b(?:Sydney|Melbourne|Brisbane|Perth|Adelaide|Canberra)\b/i;
      var DE_CITIES = /\b(?:Berlin|Munich|Frankfurt|Hamburg|Stuttgart|Dusseldorf|Cologne)\b/i;

      var ops = [];
      unknowns.forEach(function(j) {
        var loc = j.location || '';
        var text = (j.title || '') + ' ' + (j.description || '').slice(0, 1500);
        var country = null;
        // Check location field first
        if (US_STATE_NAMES.test(loc) || US_STATE_CD.test(loc) || US_CITIES.test(loc)) country = 'United States';
        else if (UK_CITIES.test(loc) || /\bUnited Kingdom\b/i.test(loc)) country = 'United Kingdom';
        else if (CA_CITIES.test(loc) || /\bCanada\b/i.test(loc)) country = 'Canada';
        else if (IN_CITIES.test(loc) || /\bIndia\b/i.test(loc)) country = 'India';
        else if (AU_CITIES.test(loc) || /\bAustralia\b/i.test(loc)) country = 'Australia';
        else if (DE_CITIES.test(loc) || /\bGermany\b/i.test(loc)) country = 'Germany';
        else if (/\bSingapore\b/i.test(loc)) country = 'Singapore';
        else if (/\bDublin\b|\bIreland\b/i.test(loc)) country = 'Ireland';
        else if (/\bAmsterdam\b|\bNetherlands\b/i.test(loc)) country = 'Netherlands';
        else if (/\bParis\b|\bFrance\b/i.test(loc)) country = 'France';
        else if (/\bTokyo\b|\bJapan\b/i.test(loc)) country = 'Japan';
        else if (/\bDubai\b|\bAbu Dhabi\b|UAE/i.test(loc)) country = 'United Arab Emirates';
        else if (/\bTel Aviv\b|\bIsrael\b/i.test(loc)) country = 'Israel';
        // Fallback: check description
        if (!country) {
          if (/\b(?:USA|United\s*States|U\.S\.)\b/i.test(text) || US_STATE_NAMES.test(text) || US_CITIES.test(text)) country = 'United States';
          else if (/\bUnited\s*Kingdom\b/i.test(text) || UK_CITIES.test(text)) country = 'United Kingdom';
          else if (/\bCanada\b/i.test(text) || CA_CITIES.test(text)) country = 'Canada';
          else if (/\bIndia\b/i.test(text) || IN_CITIES.test(text)) country = 'India';
          else if (/\bAustralia\b/i.test(text) || AU_CITIES.test(text)) country = 'Australia';
          else if (/\bGermany\b/i.test(text)) country = 'Germany';
        }
        // Final fallback: use searchCountry (the country param used when searching)
        if (!country && j.searchCountry) {
          var scMap = {'us':'United States','ca':'Canada','uk':'United Kingdom','gb':'United Kingdom','in':'India','au':'Australia','de':'Germany','fr':'France','jp':'Japan','sg':'Singapore','nl':'Netherlands','ie':'Ireland','ch':'Switzerland','se':'Sweden','ae':'United Arab Emirates','il':'Israel','br':'Brazil','mx':'Mexico','nz':'New Zealand','za':'South Africa','es':'Spain','it':'Italy','pl':'Poland','no':'Norway','dk':'Denmark','fi':'Finland'};
          country = scMap[j.searchCountry.toLowerCase()] || null;
        }
        // Last resort: records without searchCountry were from early US searches
        if (!country) country = 'United States';
        if (country) {
          ops.push({ updateOne: { filter: { _id: j._id }, update: { $set: { detectedCountry: country } } } });
          fixed++;
        }
      });
      if (ops.length > 0) await col.bulkWrite(ops, { ordered: false });
      return { statusCode: 200, headers: hdrs, body: JSON.stringify({ total: unknowns.length, fixed: fixed, remaining: unknowns.length - fixed }) };
    }

    return { statusCode: 400, headers: hdrs, body: JSON.stringify({ error: 'Unknown action: ' + action }) };
  } catch (err) {
    console.error('DB function error:', err);
    return { statusCode: 500, headers: hdrs, body: JSON.stringify({ error: 'Database error: ' + err.message }) };
  }
};
