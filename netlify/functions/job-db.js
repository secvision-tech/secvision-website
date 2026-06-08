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
      if (body.company) {
        var compSearch = body.company.replace(/[®™©]/g, '').trim().replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        filter.company = { $regex: compSearch, $options: 'i' };
      }
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
      var sort = body.sort ? (typeof body.sort === 'string' ? JSON.parse(body.sort) : body.sort) : { dateScanned: -1 };

      var total = await col.countDocuments(filter);
      var jobs = await col.find(filter)
        .project({ description: 0 }) // exclude large field for list view
        .sort(sort)
        .skip(skip)
        .limit(limit)
        .toArray();

      // Hybrid sort: jobs with datePosted first (newest), nulls at end (by dateScanned)
      jobs.sort(function(a, b) {
        var aDate = a.datePosted ? new Date(a.datePosted).getTime() : 0;
        var bDate = b.datePosted ? new Date(b.datePosted).getTime() : 0;
        if (aDate && bDate) return bDate - aDate; // both have dates: newest first
        if (aDate && !bDate) return -1; // a has date, b doesn't: a first
        if (!aDate && bDate) return 1;  // b has date, a doesn't: b first
        // both null: sort by dateScanned
        var aScan = a.dateScanned ? new Date(a.dateScanned).getTime() : 0;
        var bScan = b.dateScanned ? new Date(b.dateScanned).getTime() : 0;
        return bScan - aScan;
      });

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
      var compPattern = body.company.replace(/[®™©]/g, '').trim().replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      var result = await col.updateMany(
        { company: { $regex: compPattern, $options: 'i' } },
        { $set: { companyType: body.companyType, companyTypeUpdatedAt: new Date() } }
      );
      return { statusCode: 200, headers: hdrs, body: JSON.stringify({ modified: result.modifiedCount }) };
    }

    // ACTION: updateCompanyUrl - fix wrong company website for all jobs of same company
    if (action === 'updateCompanyUrl') {
      var compPattern = body.company.replace(/[®™©]/g, '').trim().replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      var result = await col.updateMany(
        { company: { $regex: compPattern, $options: 'i' } },
        { $set: { companyUrl: body.companyUrl, companyUrlUpdatedAt: new Date() } }
      );
      return { statusCode: 200, headers: hdrs, body: JSON.stringify({ modified: result.modifiedCount }) };
    }

    // ACTION: updateField - update any editable field by _id
    if (action === 'updateField') {
      var { ObjectId } = require('mongodb');
      var allowed = ['jobType','salary','experience','location','remote','eligibility'];
      if (allowed.indexOf(body.field) === -1) return { statusCode: 400, headers: hdrs, body: JSON.stringify({ error: 'Field not editable: ' + body.field }) };
      var upd = {}; upd[body.field] = body.value; upd[body.field + 'UpdatedAt'] = new Date();
      var result = await col.updateOne({ _id: new ObjectId(body.id) }, { $set: upd });
      return { statusCode: 200, headers: hdrs, body: JSON.stringify({ modified: result.modifiedCount }) };
    }

    // ACTION: updateFieldByJobId - update any editable field by jobId
    if (action === 'updateFieldByJobId') {
      var allowed = ['jobType','salary','experience','location','remote','eligibility'];
      if (allowed.indexOf(body.field) === -1) return { statusCode: 400, headers: hdrs, body: JSON.stringify({ error: 'Field not editable: ' + body.field }) };
      var upd = {}; upd[body.field] = body.value; upd[body.field + 'UpdatedAt'] = new Date();
      var result = await col.updateOne({ jobId: body.jobId }, { $set: upd });
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
        { $project: { companyNorm: { $trim: { input: { $replaceAll: { input: { $replaceAll: { input: { $replaceAll: { input: { $toLower: '$company' }, find: '®', replacement: '' } }, find: '™', replacement: '' } }, find: '©', replacement: '' } } } }, companyUrl: 1 } },
        { $group: { _id: '$companyNorm', count: { $sum: 1 }, url: { $first: '$companyUrl' } } },
        { $sort: { count: -1 } },
        { $limit: 10 }
      ]).toArray();
      companyCounts.forEach(function(c) {
        if (c._id) c._id = c._id.replace(/\b\w/g, function(l) { return l.toUpperCase(); });
      });
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
        { $project: { companyNorm: { $trim: { input: { $toLower: { $replaceAll: { input: { $replaceAll: { input: { $replaceAll: { input: '$company', find: '®', replacement: '' } }, find: '™', replacement: '' } }, find: '©', replacement: '' } } } } }, companyType: 1, status: 1, location: 1, companyUrl: 1, companySize: 1 } },
        { $group: { _id: { company: '$companyNorm', type: '$companyType' }, count: { $sum: 1 },
          statuses: { $push: '$status' }, locations: { $addToSet: '$location' },
          companyUrl: { $first: '$companyUrl' }, companySize: { $first: '$companySize' } } },
        { $sort: { count: -1 } },
        { $limit: 20 }
      ]).toArray();
      // Title-case company names
      partnerTargets.forEach(function(p) {
        if (p._id && p._id.company) p._id.company = p._id.company.replace(/\b\w/g, function(l) { return l.toUpperCase(); });
      });

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

      // Contract-specific aggregations
      var contractFilter = { jobType: 'Contract' };
      var contractTotal = await col.countDocuments(contractFilter);
      var contractNew = await col.countDocuments({ jobType: 'Contract', status: 'new' });
      var contractByCountry = await col.aggregate([
        { $match: contractFilter },
        { $group: { _id: '$detectedCountry', count: { $sum: 1 } } },
        { $sort: { count: -1 } },
        { $limit: 10 }
      ]).toArray();
      var contractByCompany = await col.aggregate([
        { $match: contractFilter },
        { $project: { companyNorm: { $toLower: { $replaceAll: { input: { $replaceAll: { input: { $replaceAll: { input: '$company', find: '\u00AE', replacement: '' } }, find: '\u2122', replacement: '' } }, find: '\u00A9', replacement: '' } } }, status: 1, location: 1, companyUrl: 1, salary: 1, companyType: 1, companySize: 1 } },
        { $group: { _id: '$companyNorm', count: { $sum: 1 }, statuses: { $push: '$status' }, locations: { $addToSet: '$location' }, companyUrl: { $first: '$companyUrl' }, salary: { $first: '$salary' }, companyType: { $first: '$companyType' }, companySize: { $first: '$companySize' } } },
        { $sort: { count: -1 } },
        { $limit: 25 }
      ]).toArray();
      contractByCompany.forEach(function(c) {
        if (c._id) c._id = c._id.replace(/\b\w/g, function(l) { return l.toUpperCase(); });
      });
      var contractSkills = await col.aggregate([
        { $match: { jobType: 'Contract', tools: { $ne: 'See details' } } },
        { $project: { items: { $split: ['$tools', ', '] } } },
        { $unwind: '$items' },
        { $match: { items: { $ne: '' } } },
        { $group: { _id: { $toUpper: { $trim: { input: '$items' } } }, count: { $sum: 1 } } },
        { $sort: { count: -1 } },
        { $limit: 20 }
      ]).toArray();
      // Average hourly rate for contracts (convert all to hourly USD)
      var contractSalaries = await col.find({ jobType: 'Contract', salary: { $ne: 'Not disclosed' } }).project({ salary: 1 }).limit(200).toArray();
      var avgRate = '-';
      if (contractSalaries.length > 0) {
        var hourlyRates = [];
        contractSalaries.forEach(function(s) {
          var sal = s.salary || '';
          var m = sal.match(/([\$£€])\s*([\d,]+(?:\.\d{1,2})?)/);
          if (!m) return;
          var amount = parseFloat(m[2].replace(/,/g, ''));
          if (isNaN(amount) || amount === 0) return;
          // Convert currency to USD (approximate)
          if (m[1] === '£') amount *= 1.27;
          else if (m[1] === '€') amount *= 1.08;
          // Convert period to hourly (assuming 2080 hrs/yr, 160 hrs/mo, 8 hrs/day, 40 hrs/wk)
          if (/\/yr/i.test(sal)) amount = amount / 2080;
          else if (/\/mo/i.test(sal)) amount = amount / 160;
          else if (/\/day/i.test(sal)) amount = amount / 8;
          else if (/\/wk/i.test(sal)) amount = amount / 40;
          // /hr is already hourly
          if (amount > 0 && amount < 500) hourlyRates.push(amount); // sanity check
        });
        if (hourlyRates.length > 0) {
          var sum = 0; hourlyRates.forEach(function(r) { sum += r; });
          avgRate = '$' + Math.round(sum / hourlyRates.length) + '/hr';
        }
      }

      // Post-process: title-case, merge variants
      function titleCase(s) {
        if (!s) return 'Unknown';
        // Keep acronyms uppercase
        var acronyms = ['SIEM','SOAR','EDR','XDR','NDR','IDS','IPS','DLP','WAF','CASB','CSPM','CWPP','CNAPP','IAM','PAM','MFA','SSO','UEBA','KQL','SPL','SOC','NIST','MITRE','CISSP','CISM','CISA','CEH','OSCP','OSCE','CCSP','CCNA','CCNP','GCIH','GCIA','GSEC','GREM','GPEN','GIAC','SANS','ITIL','TOGAF','HIPAA','GDPR','FISMA','CMMC','CCPA','COBIT','DFARS','ITAR','FAIR','ISMS','OCTAVE','STRIDE','DREAD','CRISC','CGEIT','SSCP','CPTS','PNPT','HITRUST','AWS','GCP','API','SDK','CI','CD','DNS','TCP','UDP','HTTP','HTTPS','SSH','VPN','TLS','SSL'];
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
        'aws': 'AWS',
        'amazon web services': 'Amazon Web Services',
        'guardduty': 'GuardDuty',
        'aws security hub': 'AWS Security Hub',
        'aws cloudtrail': 'AWS CloudTrail',
        'gcp': 'GCP',
        'google cloud platform': 'Google Cloud Platform',
        'google cloud': 'Google Cloud',
        'security command center': 'Security Command Center',
        'google chronicle': 'Google Chronicle',
        'azure': 'Azure',
        'prisma cloud': 'Prisma Cloud',
        'wiz': 'Wiz',
        'terraform': 'Terraform',
        'ansible': 'Ansible',
        'kubernetes': 'Kubernetes',
        'docker': 'Docker',
        'jenkins': 'Jenkins',
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
      contractSkills = normList(contractSkills);

      return { statusCode: 200, headers: hdrs, body: JSON.stringify({
        totalJobs, statusCounts, typeCounts, countryCounts, companyCounts,
        certCounts, complianceCounts, toolsCounts, locationCounts, recentScans,
        partnerTargets, roleCounts, skillCounts, salaryJobs,
        contractTotal, contractNew, contractByCountry, contractByCompany, contractSkills, avgRate
      })};
    }

    // ACTION: reExtract - re-process all jobs to update extracted fields from stored descriptions
    // #176: Contact management
    if (action === 'saveContacts') {
      var contactsCol = db.collection('contacts');
      var contacts = body.contacts || [];
      var company = body.company || '';
      if (!company || !contacts.length) return { statusCode: 400, headers: hdrs, body: JSON.stringify({ error: 'Company and contacts required' }) };
      var ops = contacts.map(function(c) {
        return { updateOne: { filter: { company: { $regex: company.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), $options: 'i' }, email: c.email },
          update: { $set: { company: company, name: c.name, designation: c.designation, email: c.email, linkedin: c.linkedin || '', source: c.source || 'Manual', updatedAt: new Date() },
            $setOnInsert: { createdAt: new Date() } }, upsert: true } };
      });
      var result = await contactsCol.bulkWrite(ops, { ordered: false });
      // Also update the contact field on matching jobs
      var contactStr = contacts.map(function(c) { return c.name + ' (' + c.designation + (c.email && c.email !== 'N/A' ? ' - ' + c.email : '') + ')'; }).join(', ');
      var compPattern = company.replace(/[®™©]/g, '').trim().replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      await col.updateMany({ company: { $regex: compPattern, $options: 'i' } }, { $set: { contact: contactStr } });
      return { statusCode: 200, headers: hdrs, body: JSON.stringify({ saved: contacts.length, contactStr: contactStr }) };
    }

    // Get unique companies (for bulk enrichment)
    // Get companies needing enrichment (missing size OR type OR LinkedIn)
    if (action === 'getCompaniesNeedingEnrichment') {
      var skip = body.skip || 0;
      var limit = body.limit || 20;
      var companies = await col.aggregate([
        { $match: { company: { $ne: null } } },
        { $group: {
          _id: { $toLower: '$company' },
          company: { $first: '$company' },
          companySize: { $max: '$companySize' },
          companyType: { $first: { $cond: [{ $and: [{ $ne: ['$companyType', ''] }, { $ne: ['$companyType', null] }] }, '$companyType', null] } },
          companyLinkedin: { $first: { $cond: [{ $and: [{ $ne: ['$companyLinkedin', ''] }, { $ne: ['$companyLinkedin', null] }] }, '$companyLinkedin', null] } },
          companyUrl: { $first: { $cond: [{ $and: [{ $ne: ['$companyUrl', ''] }, { $ne: ['$companyUrl', null] }, { $not: { $regexMatch: { input: { $ifNull: ['$companyUrl', ''] }, regex: /google\.com\/search/ } } }] }, '$companyUrl', null] } },
          jobCount: { $sum: 1 }
        } },
        { $match: { $or: [
          { companySize: { $in: [null, 0] } },
          { companyType: null },
          { companyLinkedin: null }
        ] } },
        { $sort: { jobCount: -1 } },
        { $skip: skip },
        { $limit: limit }
      ]).toArray();
      var totalCount = await col.aggregate([
        { $match: { company: { $ne: null } } },
        { $group: { _id: { $toLower: '$company' }, companySize: { $max: '$companySize' }, companyType: { $first: { $cond: [{ $and: [{ $ne: ['$companyType', ''] }, { $ne: ['$companyType', null] }] }, '$companyType', null] } }, companyLinkedin: { $first: { $cond: [{ $and: [{ $ne: ['$companyLinkedin', ''] }, { $ne: ['$companyLinkedin', null] }] }, '$companyLinkedin', null] } } } },
        { $match: { $or: [{ companySize: { $in: [null, 0] } }, { companyType: null }, { companyLinkedin: null }] } },
        { $count: 'total' }
      ]).toArray();
      return { statusCode: 200, headers: hdrs, body: JSON.stringify({ companies: companies, total: totalCount[0] ? totalCount[0].total : 0 }) };
    }

    // Update company fields ONLY if currently empty (safe — never overwrites)
    if (action === 'updateCompanyIfEmpty') {
      var company = body.company;
      var updates = body.updates || {}; // {companySize, companyType, companyLinkedin, companyUrl}
      if (!company) return { statusCode: 200, headers: hdrs, body: JSON.stringify({ error: 'No company name' }) };

      var setFields = {};
      var filter = { company: { $regex: company.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), $options: 'i' } };

      // Only update fields that are currently empty in DB
      if (updates.companySize && updates.companySize > 0) {
        // Use $max to only increase, never decrease
        await col.updateMany(
          { ...filter, $or: [{ companySize: { $in: [null, 0, ''] } }, { companySize: { $exists: false } }] },
          { $set: { companySize: updates.companySize } }
        );
      }
      if (updates.companyType) {
        await col.updateMany(
          { ...filter, $or: [{ companyType: { $in: [null, ''] } }, { companyType: { $exists: false } }] },
          { $set: { companyType: updates.companyType } }
        );
      }
      if (updates.companyLinkedin) {
        await col.updateMany(
          { ...filter, $or: [{ companyLinkedin: { $in: [null, ''] } }, { companyLinkedin: { $exists: false } }] },
          { $set: { companyLinkedin: updates.companyLinkedin } }
        );
      }
      if (updates.companyUrl) {
        await col.updateMany(
          { ...filter, $or: [{ companyUrl: { $in: [null, ''] } }, { companyUrl: { $exists: false } }, { companyUrl: { $regex: /google\.com\/search/ } }] },
          { $set: { companyUrl: updates.companyUrl } }
        );
      }
      return { statusCode: 200, headers: hdrs, body: JSON.stringify({ updated: true, company: company }) };
    }

    // Get single job by ID (for View from dashboard)
    if (action === 'getJob') {
      var { ObjectId } = require('mongodb');
      try {
        var job = await col.findOne({ _id: new ObjectId(body.id) });
        return { statusCode: 200, headers: hdrs, body: JSON.stringify({ job: job }) };
      } catch(e) {
        return { statusCode: 200, headers: hdrs, body: JSON.stringify({ job: null, error: e.message }) };
      }
    }

    // Get latest 100 contract jobs
    if (action === 'getRecentContracts') {
      var contracts = await col.find({ jobType: 'Contract' })
        .sort({ datePosted: -1, dateScanned: -1 })
        .limit(100)
        .project({ title: 1, company: 1, companyType: 1, location: 1, salary: 1, datePosted: 1, status: 1, source: 1, applyLink: 1, detectedCountry: 1, tools: 1, certifications: 1 })
        .toArray();
      return { statusCode: 200, headers: hdrs, body: JSON.stringify({ contracts: contracts }) };
    }

    // Check which companies need enrichment (size or contacts)
    if (action === 'getEnrichmentStatus') {
      var companies = body.companies || [];
      if (!companies.length) return { statusCode: 200, headers: hdrs, body: JSON.stringify({ needsEnrichment: [] }) };
      var contactsCol = db.collection('contacts');
      var results = [];
      for (var ci = 0; ci < companies.length; ci++) {
        var comp = companies[ci];
        var compPattern = comp.replace(/[®™©]/g, '').trim().replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        // Check if company has size
        var jobWithSize = await col.findOne({ company: { $regex: compPattern, $options: 'i' }, companySize: { $gt: 0 } });
        // Check if company has contacts
        var contactCount = await contactsCol.countDocuments({ company: { $regex: compPattern, $options: 'i' } });
        if (!jobWithSize || contactCount === 0) {
          results.push({ company: comp, hasSize: !!jobWithSize, hasContacts: contactCount > 0 });
        }
      }
      return { statusCode: 200, headers: hdrs, body: JSON.stringify({ needsEnrichment: results }) };
    }

    // Get unique companies (for bulk enrichment)
    if (action === 'getUniqueCompanies') {
      var companies = await col.aggregate([
        { $match: { company: { $ne: null } } },
        { $group: { _id: { $toLower: '$company' }, company: { $first: '$company' }, companySize: { $first: '$companySize' }, companyLinkedin: { $first: '$companyLinkedin' }, companyUrl: { $first: '$companyUrl' }, companyType: { $first: '$companyType' } } },
        { $sort: { _id: 1 } }
      ]).toArray();
      return { statusCode: 200, headers: hdrs, body: JSON.stringify({ companies: companies }) };
    }

    if (action === 'getContacts') {
      var contactsCol = db.collection('contacts');
      var compPattern = (body.company || '').replace(/[®™©]/g, '').trim().replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      var contacts = await contactsCol.find({ company: { $regex: compPattern, $options: 'i' } }).toArray();
      return { statusCode: 200, headers: hdrs, body: JSON.stringify({ contacts: contacts }) };
    }

    if (action === 'deleteContact') {
      var contactsCol = db.collection('contacts');
      var { ObjectId } = require('mongodb');
      await contactsCol.deleteOne({ _id: new ObjectId(body.contactId) });
      return { statusCode: 200, headers: hdrs, body: JSON.stringify({ deleted: true }) };
    }

    // Update company size for all jobs of a company
    if (action === 'updateCompanySize' || action === 'updateCompanyInfo') {
      var compPattern = (body.company || '').replace(/[®™©]/g, '').trim().replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      var setFields = {};
      if (body.companySize) {
        var sizeStr = String(body.companySize).replace(/[^0-9]/g, '');
        var sizeNum = parseInt(sizeStr);
        setFields.companySize = isNaN(sizeNum) ? 0 : sizeNum;
      }
      if (body.companyLinkedin) setFields.companyLinkedin = body.companyLinkedin;
      if (body.companyWebsite) setFields.companyUrl = body.companyWebsite;
      if (Object.keys(setFields).length === 0) return { statusCode: 400, headers: hdrs, body: JSON.stringify({ error: 'No fields to update' }) };
      var result = await col.updateMany(
        { company: { $regex: compPattern, $options: 'i' } },
        { $set: setFields }
      );
      return { statusCode: 200, headers: hdrs, body: JSON.stringify({ modified: result.modifiedCount }) };
    }

    if (action === 'reExtract') {
      var allJobs = await col.find({}).project({ _id: 1, title: 1, titleClean: 1, description: 1, jobType: 1, jobTypeUpdatedAt: 1, remote: 1, tools: 1, compliance: 1, certifications: 1, experience: 1, salary: 1 }).toArray();
      var TOOL_RE = /Microsoft\s*Defender(?:\s*(?:for\s*)?(?:Endpoint|Cloud|Identity|Office|365))?|Microsoft\s*Sentinel|Azure\s*Sentinel|Azure|Splunk|QRadar|CrowdStrike|SentinelOne|Palo\s*Alto|Cortex\s*XDR|Cortex\s*XSOAR|LogRhythm|Elastic\s*(?:Security|SIEM|Stack)|Chronicle|Google\s*Chronicle|Tenable|Qualys|Nessus|Rapid7|InsightVM|Carbon\s*Black|Fortinet|FortiSIEM|FortiGate|Check\s*Point|Cisco\s*(?:ASA|Firepower|SecureX|Umbrella)|Snort|Suricata|Wireshark|Burp\s*Suite|Metasploit|XSOAR|Phantom|Swimlane|KQL|SPL|YARA|Sigma|ServiceNow|Jira|Proofpoint|Mimecast|Zscaler|Okta|CyberArk|BeyondTrust|Varonis|DarkTrace|Vectra|Tanium|Exabeam|Securonix|NetWitness|ArcSight|AWS|Amazon\s*Web\s*Services|GuardDuty|AWS\s*(?:Security\s*Hub|CloudTrail|WAF|Shield|Inspector|Config|Macie)|GCP|Google\s*Cloud(?:\s*Platform)?|Security\s*Command\s*Center|Cloud\s*Armor|Prisma\s*Cloud|Wiz|Lacework|Orca\s*Security|Snyk|Aqua\s*Security|HashiCorp\s*Vault|Terraform|Ansible|Kubernetes|Docker|Jenkins|SIEM|SOAR|EDR|XDR|NDR|IDS[\s\/]*IPS|DLP|WAF|CASB|CSPM|CWPP|CNAPP|IAM|PAM|MFA|SSO|UEBA/gi;
      var COMP_RE = /SOC\s*2|SOC2|ISO\s*27001|ISO\s*27002|NIST\s*(?:SP\s*)?800-53|NIST\s*(?:SP\s*)?800-61|NIST\s*(?:SP\s*)?800-171|NIST\s*(?:SP\s*)?800-37|NIST\s*CSF|PCI[\s-]*DSS|HIPAA|GDPR|FedRAMP|HITRUST|CMMC|CCPA|FISMA|SOX|COBIT|CIS\s*Controls|CIS\s*Benchmarks|MITRE\s*ATT&CK|Zero\s*Trust|COSO|ITAR|NERC\s*CIP|FERPA|GLBA|DFARS|ISMS|ISO\s*22301|CSA\s*STAR|cyber\s*kill\s*chain|OWASP\s*Top\s*10|STRIDE|DREAD|FAIR|OCTAVE|ISO\s*31000|NIST\s*RMF|STIX[\s\/]*TAXII|\bNIST\b/gi;
      function uniqueMatch(text, re) {
        if (!text) return [];
        var m = text.match(re) || [], seen = {};
        return m.filter(function(v) { var k = v.toLowerCase().trim(); if (seen[k]) return false; seen[k] = true; return true; }).slice(0, 12);
      }
      var updated = 0, ops = [];
      allJobs.forEach(function(j) {
        var d = (j.description || '');
        var t = (j.title || '');
        var fullText = t + ' ' + d;
        var changes = {};

        // Re-detect job type (re-evaluate all except manually edited)
        var contractSig = 0, fulltimeSig = 0;
        if (/\bcontract\b/i.test(t)) contractSig += 4;
        if (/\b(?:position|employment|job)\s*(?:type|status)\s*:?\s*contract\b/i.test(d)) contractSig += 4;
        if (/\bcontract\s*(?:position|role|opportunity|assignment|engagement)\b/i.test(d)) contractSig += 3;
        if (/\binitial\s*contract\s*:?\s*\d+/i.test(d)) contractSig += 3;
        if (/\b(?:IR35|W-?2|1099|C2C)\b/i.test(d)) contractSig += 3;
        if (/\b\d+\+?\s*(?:month|months)\s*(?:contract|engagement)\b/i.test(d)) contractSig += 3;
        if (/\b(?:likelihood\s*of\s*extension|option\s*to\s*extend)\b/i.test(d)) contractSig += 2;
        if (/\bcontract\s*(?:only|worker|staff)\b/i.test(d)) contractSig += 2;
        if (/\/\s*(?:hr|hour)\b/i.test(j.salary||'')) contractSig += 2;
        if (/\/\s*day\b/i.test(j.salary||'')) contractSig += 2;
        if (/\bfull[\s-]*time\b/i.test(t)) fulltimeSig += 3;
        if (/\b(?:position|employment|job)\s*(?:type|status)\s*:?\s*full[\s-]*time\b/i.test(d)) fulltimeSig += 4;
        if (/\bfull[\s-]*time\s*(?:position|role|opportunity|employee)\b/i.test(d)) fulltimeSig += 3;
        if (/\b(?:benefits|401k|PTO|paid\s*time\s*off|medical|dental)\b/i.test(d)) fulltimeSig += 2;
        if (/[£€]\s*\d/.test(j.salary || '')) fulltimeSig += 2;
        var newType = 'Full-time'; // default
        if (contractSig >= 3 && contractSig > fulltimeSig) newType = 'Contract';
        else if (/\bpart[\s-]*time\b/i.test(t) || /\b(?:position|employment)\s*(?:type|status)\s*:?\s*part[\s-]*time\b/i.test(d)) newType = 'Part-time';
        else if (/\bintern(?:ship)?\b/i.test(t)) newType = 'Internship';
        // Only update if not manually edited (no jobTypeUpdatedAt) or still default
        if (!j.jobTypeUpdatedAt && j.jobType !== newType) changes.jobType = newType;

        // Re-detect remote (always re-evaluate)
        var newRemote = 'No';
        if (/\bLocation\s*:\s*Remote\b/i.test(d) || /\b(?:fully\s*remote|100%\s*remote|remote\s*(?:position|role|work|only)|work\s*(?:from\s*home|remotely))\b/i.test(d)) newRemote = 'Yes';
        else if (/\bhybrid\b/i.test(d)) newRemote = 'Hybrid';
        if (newRemote !== 'No' && j.remote !== newRemote) changes.remote = newRemote;

        // Re-extract tools (always - merge new with existing, apply proper casing)
        var TOOL_CASE = {'siem':'SIEM','soar':'SOAR','edr':'EDR','xdr':'XDR','ndr':'NDR','dlp':'DLP','waf':'WAF','casb':'CASB','cspm':'CSPM','cwpp':'CWPP','cnapp':'CNAPP','iam':'IAM','pam':'PAM','mfa':'MFA','sso':'SSO','ueba':'UEBA','kql':'KQL','spl':'SPL','aws':'AWS','gcp':'GCP','ids/ips':'IDS/IPS','python':'Python','bash':'Bash','powershell':'PowerShell','kubernetes':'Kubernetes','docker':'Docker','terraform':'Terraform','ansible':'Ansible','jenkins':'Jenkins'};
        var COMP_CASE = {'nist':'NIST','isms':'ISMS','itar':'ITAR','fair':'FAIR','hipaa':'HIPAA','gdpr':'GDPR','fisma':'FISMA','ccpa':'CCPA','sox':'SOX','cobit':'COBIT','hitrust':'HITRUST','cmmc':'CMMC','fedramp':'FedRAMP','octave':'OCTAVE','stride':'STRIDE','dread':'DREAD','glba':'GLBA','ferpa':'FERPA','dfars':'DFARS','coso':'COSO'};
        function fixCase(val, caseMap) {
          var k = val.toLowerCase().trim();
          return caseMap[k] || val;
        }
        var newToolsArr = uniqueMatch(fullText, TOOL_RE);
        // Cleanup: remove incorrectly extracted values
        var BAD_TOOLS = {'go':1,'sso':0,'fair':0};  // 'go' always bad; others context-dependent
        var TOOL_REMOVE = /^go$/i;
        if (newToolsArr.length > 0 || (j.tools && j.tools !== 'See details')) {
          var existingTools = (j.tools && j.tools !== 'See details') ? j.tools.split(', ') : [];
          var merged = {}, mergedArr = [];
          existingTools.concat(newToolsArr).forEach(function(t) {
            var k = t.toLowerCase().trim();
            if (TOOL_REMOVE.test(k)) return; // Skip bad values
            if (!merged[k]) { merged[k] = true; mergedArr.push(fixCase(t, TOOL_CASE)); }
          });
          var newToolsStr = mergedArr.slice(0, 15).join(', ');
          if (newToolsStr !== j.tools) changes.tools = newToolsStr;
        }

        // Re-extract compliance (always - merge new with existing, apply proper casing)
        var newCompArr = uniqueMatch(fullText, COMP_RE);
        if (newCompArr.length > 0 || (j.compliance && j.compliance !== 'See details')) {
          var existingComp = (j.compliance && j.compliance !== 'See details') ? j.compliance.split(', ') : [];
          var mergedC = {}, mergedCArr = [];
          existingComp.concat(newCompArr).forEach(function(c) {
            var k = c.toLowerCase().trim();
            if (!mergedC[k]) { mergedC[k] = true; mergedCArr.push(fixCase(c, COMP_CASE)); }
          });
          var newCompStr = mergedCArr.slice(0, 15).join(', ');
          if (newCompStr !== j.compliance) changes.compliance = newCompStr;
        }

        // Re-extract salary (always - fix wrong periods)
        var newSalary = null;
        // $180k-$230k
        var salK = d.match(/\$\s*([\d,.]+)\s*k\s*[\-\u2013to]+\s*\$?\s*([\d,.]+)\s*k/i);
        if (salK) {
          var kL = Math.round(parseFloat(salK[1].replace(/,/g,''))*1000);
          var kH = Math.round(parseFloat(salK[2].replace(/,/g,''))*1000);
          newSalary = '$'+kL.toLocaleString()+'-$'+kH.toLocaleString()+'/yr';
        }
        // $90-97hr (no slash)
        if (!newSalary) {
        var salNoSlash = d.match(/\$\s*([\d,.]+)\s*[\-\u2013to]+\s*\$?\s*([\d,.]+)\s*(hr|hour)\b/i);
        if (salNoSlash) newSalary = '$'+salNoSlash[1]+'-$'+salNoSlash[2]+'/hr';
        }
        // £ IR35 rate (always daily in UK)
        var salIR35 = d.match(/[£]\s*([\d,]+(?:\.\d{1,2})?)\s*[\-\u2013to]+\s*[£]?\s*([\d,]+(?:\.\d{1,2})?)\s*(?:per\s*day\s*)?(?:inside|outside)\s*IR35/i);
        if (salIR35) newSalary = '£'+salIR35[1]+'-£'+salIR35[2]+'/day';
        if (!newSalary) {
          var salIR35s = d.match(/[£]\s*([\d,]+(?:\.\d{1,2})?)\s*(?:per\s*day\s*)?(?:inside|outside)\s*IR35/i);
          if (salIR35s) newSalary = '£'+salIR35s[1]+'/day';
        }
        // £ with explicit day/hour
        var salGBPday = d.match(/[£]\s*([\d,]+(?:\.\d{1,2})?)\s*(?:\/|\s+)(per\s*day|day|per\s*hour|hour|per\s*week|week|per\s*month|month)/i);
        if (salGBPday) {
          var s6a = salGBPday[2].toLowerCase();
          newSalary = '£'+salGBPday[1]+(/day/.test(s6a)?'/day':/hour/.test(s6a)?'/hr':/week/.test(s6a)?'/wk':/month/.test(s6a)?'/mo':'/day');
        }
        if (!newSalary) {
          // $X to $Y/hr explicit
          var salExplicit = d.match(/\$\s*([\d,.]+)\s*(?:to|[\-\u2013])\s*\$?\s*([\d,.]+)\s*\/(hr|hour|mo|month|day|wk|week)/i);
          if (salExplicit) {
            var sfxE = {'hr':'/hr','hour':'/hr','mo':'/mo','month':'/mo','day':'/day','wk':'/wk','week':'/wk'};
            newSalary = '$'+salExplicit[1]+'-$'+salExplicit[2]+(sfxE[salExplicit[3].toLowerCase()]||'/hr');
          }
        }
        if (!newSalary) {
          // $ range with context
          var salRange = d.match(/\$\s*([\d,]+(?:\.\d{1,2})?)\s*[\-\u2013to]+\s*\$?\s*([\d,]+(?:\.\d{1,2})?)/i);
          if (salRange) {
            var ctx = d.substring(Math.max(0,d.indexOf(salRange[0])-40), d.indexOf(salRange[0])+salRange[0].length+60);
            var prd = '/yr';
            if (/per\s*hour|hourly|\/\s*hr|\bhr\b/i.test(ctx)) prd = '/hr';
            else if (/per\s*month|monthly|\/\s*mo/i.test(ctx)) prd = '/mo';
            else if (/per\s*day|\bday\b|daily|\/\s*day|IR35/i.test(ctx)) prd = '/day';
            else if (/per\s*week|weekly|\/\s*wk/i.test(ctx)) prd = '/wk';
            newSalary = '$'+salRange[1]+'-$'+salRange[2]+prd;
          }
        }
        if (!newSalary) {
          // Pay Rate: $60/hr
          var salRate = d.match(/(?:pay\s*rate|rate|hourly\s*rate)\s*:?\s*\$\s*([\d,.]+)\s*(?:\/|\s*per\s*)(hr|hour|day|mo|month)/i);
          if (salRate) {
            var sfxR = {'hr':'/hr','hour':'/hr','day':'/day','mo':'/mo','month':'/mo'};
            newSalary = '$'+salRate[1]+(sfxR[salRate[2].toLowerCase()]||'/hr');
          }
        }
        if (!newSalary) {
          // Standalone $XX/hr
          var salStandalone = d.match(/\$\s*([\d,.]+)\s*\/(hr|hour)/i);
          if (salStandalone) newSalary = '$'+salStandalone[1]+'/hr';
        }
        if (!newSalary) {
          // £ range
          var salGBP = d.match(/[£]\s*([\d,]+(?:\.\d{1,2})?)\s*[\-\u2013to]+\s*[£]?\s*([\d,]+)/i);
          if (salGBP) {
            var ctxG = d.substring(Math.max(0,d.indexOf(salGBP[0])-40), d.indexOf(salGBP[0])+salGBP[0].length+60);
            var prdG = /day/.test(ctxG)?'/day':/hour|hr/.test(ctxG)?'/hr':/month|mo/.test(ctxG)?'/mo':'/yr';
            newSalary = '£'+salGBP[1]+'-£'+salGBP[2]+prdG;
          }
        }
        if (newSalary && newSalary !== j.salary) changes.salary = newSalary;

        // Append contract duration to titleClean
        var tc = j.titleClean || j.title || '';
        if (!/\d+\s*(?:month|week|year)/i.test(tc)) {
          var durPatterns = [
            /(\d+)[\s-]+(?:months?|mos?)[\s-]+(?:contract|engagement|assignment|mandate|placement)/i,
            /(\d+)[\s-]+(?:months?|mos?)[\s\w-]{0,20}(?:contract|engagement|assignment|mandate|placement)/i,
            /\((\d+)[\s-]+(?:months?|mos?)[\s-]*(?:contract|engagement|mandate)?\)/i,
            /(?:initial\s*)?(?:contract|engagement|assignment|duration|period|length|mandate)\s*(?:of|:)?\s*(\d+)[\s-]*\+?\s*(?:months?|mos?)\b/i,
            /(\d+)[\s-]*\+?\s*(?:months?|mos?)[\s-]*(?:contract|engagement|assignment|duration|renewable|mandate|placement)\b/i,
            /(?:for\s*a?\s*)(\d+)[\s-]*(?:months?|mos?)[\s-]*(?:contract|mandate|engagement|assignment|period|placement)\b/i,
            /\ba\s+(\d+)[\s-]*(?:months?|mos?)\b[^.]{0,40}\b(?:contract|mandate|engagement)\b/i,
            /(\d+)[\s-]*\+?\s*(?:weeks?|wks?)[\s-]*(?:contract|engagement|assignment|mandate)\b/i,
            /(?:contract|engagement|mandate)\s*(?:of|:)?\s*(\d+)[\s-]*\+?\s*(?:weeks?|wks?)\b/i,
            /(\d+)[\s-]*\+?\s*(?:years?|yrs?)[\s-]*(?:contract|engagement|assignment|mandate)\b/i,
            /(?:contract|engagement|mandate)\s*(?:of|:)?\s*(\d+)[\s-]*\+?\s*(?:years?|yrs?)\b/i,
            /(\d+)[\s-]*\+?\s*days?[\s-]*(?:contract|engagement|assignment|mandate)\b/i,
            /(?:contract|engagement|mandate|duration)\s*(?:of|:)?\s*(\d+)[\s-]*\+?\s*days?\b/i,
            /duration\s*:?\s*[\n\r\s]*(\d+)\s*(?:days?|months?|weeks?|years?)\b/i,
          ];
          for (var dp = 0; dp < durPatterns.length; dp++) {
            var durMatch = (t + ' ' + d).match(durPatterns[dp]);
            if (durMatch) {
              var durNum = durMatch[1];
              var durUnit = /week/i.test(durMatch[0]) ? ' Weeks' : /year/i.test(durMatch[0]) ? ' Years' : /day/i.test(durMatch[0]) ? ' Days' : ' Months';
              changes.titleClean = tc + ' - ' + durNum + durUnit;
              break;
            }
          }
        }

        // Cleanup certifications: remove non-cybersecurity certs (CKA, CKAD, CKS)
        var CERT_REMOVE = /^(?:cka|ckad|cks)$/i;
        if (j.certifications && j.certifications !== 'See details') {
          var certParts = j.certifications.split(/[,\n]+/).map(function(c){return c.trim()}).filter(Boolean);
          var cleanedCerts = certParts.filter(function(c) { return !CERT_REMOVE.test(c); });
          if (cleanedCerts.length < certParts.length) {
            changes.certifications = cleanedCerts.length ? cleanedCerts.join(', ') : 'See details';
          }
        }

        // Dedup experience
        if (j.experience && j.experience !== 'Not specified') {
          var expParts = j.experience.split(', ');
          var seen = {}, deduped = [];
          expParts.forEach(function(p) { var k = p.toLowerCase().trim(); if (!seen[k]) { seen[k] = true; deduped.push(p); } });
          if (deduped.length < expParts.length) changes.experience = deduped.join(', ');
        }

        if (Object.keys(changes).length > 0) {
          changes.reExtractedAt = new Date();
          ops.push({ updateOne: { filter: { _id: j._id }, update: { $set: changes } } });
          updated++;
        }
      });
      if (ops.length > 0) await col.bulkWrite(ops, { ordered: false });
      return { statusCode: 200, headers: hdrs, body: JSON.stringify({ total: allJobs.length, updated: updated }) };
    }

    // ACTION: fixCountries - comprehensive country detection and fix
    if (action === 'fixCountries') {
      var ccMap = {'US':'United States','CA':'Canada','GB':'United Kingdom','UK':'United Kingdom','IN':'India','AU':'Australia','DE':'Germany','FR':'France','JP':'Japan','SG':'Singapore','NL':'Netherlands','IE':'Ireland','CH':'Switzerland','SE':'Sweden','AE':'United Arab Emirates','IL':'Israel','BR':'Brazil','MX':'Mexico','NZ':'New Zealand','ZA':'South Africa','ES':'Spain','IT':'Italy','PL':'Poland','EG':'Egypt','MY':'Malaysia','PH':'Philippines','TH':'Thailand','ID':'Indonesia','KR':'South Korea','TW':'Taiwan','HK':'Hong Kong','PK':'Pakistan','SA':'Saudi Arabia','QA':'Qatar','NG':'Nigeria','KE':'Kenya','PT':'Portugal','CZ':'Czech Republic','RO':'Romania','BE':'Belgium','AT':'Austria','TR':'Turkey','RU':'Russia','UA':'Ukraine','NO':'Norway','DK':'Denmark','FI':'Finland','HU':'Hungary','GR':'Greece','BH':'Bahrain','KW':'Kuwait','CL':'Chile','CO':'Colombia','AR':'Argentina','PE':'Peru','BD':'Bangladesh','MA':'Morocco','GH':'Ghana','LU':'Luxembourg','OM':'Oman'};
      // Country patterns in URLs/domains
      var urlCountryMap = {'egypt':'Egypt','india':'India','uk.':'United Kingdom','australia':'Australia','canada':'Canada','germany':'Germany','france':'France','japan':'Japan','singapore':'Singapore','malaysia':'Malaysia','philippines':'Philippines','brazil':'Brazil','mexico':'Mexico','southafrica':'South Africa','nigeria':'Nigeria','kenya':'Kenya','israel':'Israel','dubai':'United Arab Emirates','uae':'United Arab Emirates','hongkong':'Hong Kong','saudi':'Saudi Arabia'};
      // Country names in text
      var textCountryPatterns = [
        [/\bEgypt\b/i, 'Egypt'], [/\bMalaysia\b/i, 'Malaysia'], [/\bPhilippines\b/i, 'Philippines'],
        [/\bThailand\b/i, 'Thailand'], [/\bIndonesia\b/i, 'Indonesia'], [/\bSouth\s*Korea\b/i, 'South Korea'],
        [/\bTaiwan\b/i, 'Taiwan'], [/\bHong\s*Kong\b/i, 'Hong Kong'], [/\bPakistan\b/i, 'Pakistan'],
        [/\bBangladesh\b/i, 'Bangladesh'], [/\bTurkey\b|\bTürkiye\b/i, 'Turkey'],
        [/\bSaudi\s*Arabia\b/i, 'Saudi Arabia'], [/\bQatar\b/i, 'Qatar'], [/\bBahrain\b/i, 'Bahrain'],
        [/\bKuwait\b/i, 'Kuwait'], [/\bNigeria\b/i, 'Nigeria'], [/\bKenya\b/i, 'Kenya'],
        [/\bGhana\b/i, 'Ghana'], [/\bMorocco\b/i, 'Morocco'],
        [/\bUnited\s*States\b|\bUSA\b/i, 'United States'], [/\bUnited\s*Kingdom\b/i, 'United Kingdom'],
        [/\bCanada\b/i, 'Canada'], [/\bIndia\b/i, 'India'], [/\bAustralia\b/i, 'Australia'],
        [/\bGermany\b/i, 'Germany'], [/\bFrance\b/i, 'France'], [/\bJapan\b/i, 'Japan'],
        [/\bSingapore\b/i, 'Singapore'], [/\bNetherlands\b/i, 'Netherlands'],
        [/\bIreland\b/i, 'Ireland'], [/\bSwitzerland\b/i, 'Switzerland'],
        [/\bSweden\b/i, 'Sweden'], [/\bIsrael\b/i, 'Israel'],
        [/\bBrazil\b/i, 'Brazil'], [/\bMexico\b/i, 'Mexico'],
        [/\bNew\s*Zealand\b/i, 'New Zealand'], [/\bSouth\s*Africa\b/i, 'South Africa'],
        [/\bSpain\b/i, 'Spain'], [/\bItaly\b/i, 'Italy'], [/\bPoland\b/i, 'Poland'],
      ];
      var US_STATE_NAMES = /\b(?:Alabama|Alaska|Arizona|Arkansas|California|Colorado|Connecticut|Delaware|Florida|Georgia|Hawaii|Idaho|Illinois|Indiana|Iowa|Kansas|Kentucky|Louisiana|Maine|Maryland|Massachusetts|Michigan|Minnesota|Mississippi|Missouri|Montana|Nebraska|Nevada|New Hampshire|New Jersey|New Mexico|New York|North Carolina|North Dakota|Ohio|Oklahoma|Oregon|Pennsylvania|Rhode Island|South Carolina|South Dakota|Tennessee|Texas|Utah|Vermont|Virginia|Washington|West Virginia|Wisconsin|Wyoming|District of Columbia)\b/i;
      var US_STATE_CD = /,\s*(?:AL|AK|AZ|AR|CA|CO|CT|DE|FL|GA|HI|ID|IL|IN|IA|KS|KY|LA|ME|MD|MA|MI|MN|MS|MO|MT|NE|NV|NH|NJ|NM|NY|NC|ND|OH|OK|OR|PA|RI|SC|SD|TN|TX|UT|VT|VA|WA|WV|WI|WY|DC)\b/;
      var US_CITIES = /\b(?:New York|Los Angeles|Chicago|Houston|Phoenix|Dallas|San Jose|Austin|San Francisco|Seattle|Denver|Nashville|Washington|Boston|Portland|Las Vegas|Baltimore|Atlanta|Raleigh|Miami|Tampa|Orlando|Minneapolis|Cleveland|Pittsburgh|Cincinnati|Irvine|Arlington|Plano|Durham|Richmond|Huntsville|McLean|Tysons|Bethesda|Herndon|Reston|Chantilly|Springfield|Columbia|Annapolis|Fort Meade|Salt Lake City|Charlotte|San Diego|Sacramento|Philadelphia|Detroit|Memphis|Louisville|Milwaukee)\b/i;

      function detectFromAll(j) {
        var loc = j.location || '';
        var src = j.applyLink || j.source || '';
        var comp = j.company || '';
        var text = (j.title || '') + ' ' + comp + ' ' + (j.description || '').slice(0, 2000);

        // Check 1: 2-letter code at end of location
        var ccMatch = loc.match(/,\s*([A-Z]{2})\s*$/);
        if (ccMatch && ccMap[ccMatch[1]]) return ccMap[ccMatch[1]];

        // Check 2: 2-letter code anywhere in location (e.g. "HK" standalone)
        var parts = loc.split(/[,\s]+/);
        for (var p = 0; p < parts.length; p++) {
          var code = parts[p].trim().toUpperCase();
          if (code.length === 2 && ccMap[code] && code !== 'IN') return ccMap[code];
        }

        // Check 3: Source URL domain
        var srcLower = src.toLowerCase();
        for (var uk in urlCountryMap) {
          if (srcLower.indexOf(uk) !== -1) return urlCountryMap[uk];
        }

        // Check 4: Company name has country (e.g. "Solutions - Egypt")
        for (var tp = 0; tp < textCountryPatterns.length; tp++) {
          if (textCountryPatterns[tp][0].test(comp)) return textCountryPatterns[tp][1];
        }

        // Check 5: Location has country/state names
        if (US_STATE_NAMES.test(loc) || US_STATE_CD.test(loc) || US_CITIES.test(loc)) return 'United States';

        // Check 6: Description/title has country names
        for (var tp2 = 0; tp2 < textCountryPatterns.length; tp2++) {
          if (textCountryPatterns[tp2][0].test(text)) return textCountryPatterns[tp2][1];
        }

        // Check 7: Detect non-English text by script (don't default to US/UK)
        var descSample = (j.description || '').slice(0, 500);
        if (/[\u0600-\u06FF\u0750-\u077F]/.test(descSample)) return null; // Arabic
        if (/[\u4E00-\u9FFF]/.test(descSample)) return null; // Chinese
        if (/[\u3040-\u309F\u30A0-\u30FF]/.test(descSample)) return 'Japan';
        if (/[\uAC00-\uD7AF]/.test(descSample)) return 'South Korea';
        if (/[\u0E00-\u0E7F]/.test(descSample)) return 'Thailand';
        if (/[\u0400-\u04FF]/.test(descSample)) return null; // Cyrillic
        if (/[\u0900-\u097F]/.test(descSample)) return 'India'; // Hindi

        // Check 8: searchCountry fallback (only for Latin-script descriptions)
        if (j.searchCountry) {
          var scLower = j.searchCountry.toLowerCase();
          if (ccMap[scLower.toUpperCase()]) return ccMap[scLower.toUpperCase()];
        }

        return null;
      }

      // Pass 1: Check ALL records for misclassification
      var allRecs = await col.find({}).project({ _id: 1, location: 1, detectedCountry: 1, title: 1, description: 1, searchCountry: 1, applyLink: 1, source: 1, company: 1 }).toArray();
      var fixOps = [];
      var misclassifiedFixed = 0;
      // Also unify GB → United Kingdom
      allRecs.forEach(function(j) {
        if (j.detectedCountry === 'GB' || j.detectedCountry === 'UK') {
          fixOps.push({ updateOne: { filter: { _id: j._id }, update: { $set: { detectedCountry: 'United Kingdom' } } } });
          misclassifiedFixed++;
          return;
        }
        var detected = detectFromAll(j);
        if (detected && j.detectedCountry !== detected) {
          fixOps.push({ updateOne: { filter: { _id: j._id }, update: { $set: { detectedCountry: detected } } } });
          misclassifiedFixed++;
        }
      });
      if (fixOps.length > 0) await col.bulkWrite(fixOps, { ordered: false });

      // Count remaining unknowns
      var remaining = await col.countDocuments({ $or: [{ detectedCountry: 'Unknown' }, { detectedCountry: null }, { detectedCountry: '' }] });

      return { statusCode: 200, headers: hdrs, body: JSON.stringify({ total: allRecs.length, fixed: misclassifiedFixed, remaining: remaining }) };
    }

    // ACTION: fixDescriptions - clean HTML/CSS, fix URLs, fix Remote locations
    if (action === 'fixDescriptions') {
      // Fix old btnI company URLs
      var btnIfix = await col.updateMany(
        { companyUrl: { $regex: 'btnI=1' } },
        [{ $set: { companyUrl: { $replaceAll: { input: '$companyUrl', find: 'btnI=1&', replacement: '' } } } }]
      );
      var urlsFixed = btnIfix.modifiedCount || 0;

      // Fix "Remote" locations by extracting city from description
      var remotes = await col.find({ location: 'Remote' }).project({ _id: 1, description: 1, company: 1, detectedCountry: 1 }).toArray();
      var locsFixed = 0;
      var locOps = [];
      var cityPatterns = [
        /(?:Location|Office|Based\s*in|Work\s*Location|Job\s*Location|Position\s*Location|Standort|Lieu|Ubicación)\s*:?\s*([A-Z\u00C0-\u024F][a-z\u00C0-\u024F]+(?:[\s,\-]+[A-Z\u00C0-\u024F][a-z\u00C0-\u024F]+){0,3})/,
        /(?:Onsite|On-site|Hybrid)\s*(?:[\-–:]\s*)?([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)/,
      ];
      remotes.forEach(function(j) {
        var d = (j.description || '').slice(0, 3000);
        for (var i = 0; i < cityPatterns.length; i++) {
          var m = d.match(cityPatterns[i]);
          if (m && m[1] && m[1].length > 2 && m[1].length < 50) {
            var city = m[1].trim().replace(/[,\s]+$/, '');
            if (/^(?:Remote|Hybrid|The|This|Our|Full|Part|Any|Not|See|TBD)$/i.test(city)) continue;
            var newLoc = city;
            if (j.detectedCountry && j.detectedCountry !== 'Unknown') newLoc += ', ' + j.detectedCountry;
            locOps.push({ updateOne: { filter: { _id: j._id }, update: { $set: { location: newLoc } } } });
            locsFixed++;
            break;
          }
        }
      });
      if (locOps.length > 0) await col.bulkWrite(locOps, { ordered: false });

      var dirty = await col.find({ description: { $regex: '<style|<script|<[a-z]|\\{\\s*[a-z-]+\\s*:', $options: 'i' } })
        .project({ _id: 1, description: 1 }).toArray();
      var fixed = 0;
      var ops = [];
      dirty.forEach(function(j) {
        var desc = j.description || '';
        var clean = desc
          .replace(/<style[^>]*>[\s\S]*?<\/style>/gi, '')
          .replace(/<script[^>]*>[\s\S]*?<\/script>/gi, '')
          .replace(/<br\s*\/?>/gi, '\n')
          .replace(/<\/p>/gi, '\n\n')
          .replace(/<\/li>/gi, '\n')
          .replace(/<li[^>]*>/gi, '• ')
          .replace(/<\/h[1-6]>/gi, '\n')
          .replace(/<[^>]+>/g, ' ')
          .replace(/\{[^}]*\}/g, '')
          .replace(/&nbsp;/gi, ' ')
          .replace(/&amp;/gi, '&')
          .replace(/&lt;/gi, '<')
          .replace(/&gt;/gi, '>')
          .replace(/&quot;/gi, '"')
          .replace(/&#39;/gi, "'")
          .replace(/\s{3,}/g, '\n\n')
          .trim();
        if (clean !== desc) {
          ops.push({ updateOne: { filter: { _id: j._id }, update: { $set: { description: clean } } } });
          fixed++;
        }
      });
      if (ops.length > 0) await col.bulkWrite(ops, { ordered: false });
      return { statusCode: 200, headers: hdrs, body: JSON.stringify({ total: dirty.length, fixed: fixed, urlsFixed: urlsFixed, locsFixed: locsFixed }) };
    }

    return { statusCode: 400, headers: hdrs, body: JSON.stringify({ error: 'Unknown action: ' + action }) };
  } catch (err) {
    console.error('DB function error:', err);
    return { statusCode: 500, headers: hdrs, body: JSON.stringify({ error: 'Database error: ' + err.message }) };
  }
};
