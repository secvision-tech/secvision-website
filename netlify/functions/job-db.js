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
        { $group: { _id: '$location', count: { $sum: 1 } } },
        { $sort: { count: -1 } },
        { $limit: 10 }
      ]).toArray();
      var recentScans = await col.aggregate([
        { $group: { _id: { $dateToString: { format: '%Y-%m-%d', date: '$dateScanned' } }, count: { $sum: 1 } } },
        { $sort: { _id: -1 } },
        { $limit: 14 }
      ]).toArray();

      // Partnership targets: companies with most openings, grouped by type
      var partnerTargets = await col.aggregate([
        { $group: { _id: { company: '$company', type: '$companyType' }, count: { $sum: 1 },
          statuses: { $push: '$status' }, locations: { $addToSet: '$location' } } },
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
        var acronyms = ['SIEM','SOAR','EDR','XDR','NDR','IDS','IPS','DLP','WAF','CASB','CSPM','CWPP','CNAPP','IAM','PAM','MFA','SSO','UEBA','KQL','SPL','SOC','NIST','MITRE','CISSP','CISM','CISA','CEH','OSCP','CCSP','CCNA','CCNP','GCIH','GCIA','GSEC','GREM','GPEN','ITIL','TOGAF','HIPAA','GDPR','FISMA','CMMC','CCPA','COBIT','DFARS','ITAR'];
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

    return { statusCode: 400, headers: hdrs, body: JSON.stringify({ error: 'Unknown action: ' + action }) };
  } catch (err) {
    console.error('DB function error:', err);
    return { statusCode: 500, headers: hdrs, body: JSON.stringify({ error: 'Database error: ' + err.message }) };
  }
};
