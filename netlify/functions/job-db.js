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
        { $project: { companyNorm: { $trim: { input: { $replaceAll: { input: { $replaceAll: { input: { $replaceAll: { input: '$company', find: '®', replacement: '' } }, find: '™', replacement: '' } }, find: '©', replacement: '' } } } }, companyType: 1, status: 1, location: 1, companyUrl: 1 } },
        { $group: { _id: { company: '$companyNorm', type: '$companyType' }, count: { $sum: 1 },
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

      return { statusCode: 200, headers: hdrs, body: JSON.stringify({
        totalJobs, statusCounts, typeCounts, countryCounts, companyCounts,
        certCounts, complianceCounts, toolsCounts, locationCounts, recentScans,
        partnerTargets, roleCounts, skillCounts, salaryJobs
      })};
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

    // ACTION: fixDescriptions - clean HTML/CSS from stored descriptions and fix formatting
    if (action === 'fixDescriptions') {
      // Also fix old btnI company URLs
      var btnIfix = await col.updateMany(
        { companyUrl: { $regex: 'btnI=1' } },
        [{ $set: { companyUrl: { $replaceAll: { input: '$companyUrl', find: 'btnI=1&', replacement: '' } } } }]
      );
      var urlsFixed = btnIfix.modifiedCount || 0;

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
      return { statusCode: 200, headers: hdrs, body: JSON.stringify({ total: dirty.length, fixed: fixed, urlsFixed: urlsFixed }) };
    }

    return { statusCode: 400, headers: hdrs, body: JSON.stringify({ error: 'Unknown action: ' + action }) };
  } catch (err) {
    console.error('DB function error:', err);
    return { statusCode: 500, headers: hdrs, body: JSON.stringify({ error: 'Database error: ' + err.message }) };
  }
};
