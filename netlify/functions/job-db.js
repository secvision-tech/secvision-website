const { getDb } = require('./db');

// JWT decode (base64url → JSON, no signature verification — token comes from MSAL via HTTPS)
function decodeJwt(token) {
  try {
    var parts = token.split('.');
    if (parts.length !== 3) return null;
    var payload = parts[1].replace(/-/g, '+').replace(/_/g, '/');
    var decoded = Buffer.from(payload, 'base64').toString('utf-8');
    return JSON.parse(decoded);
  } catch (e) { return null; }
}

// Validate JWT claims
var TENANT_ID = process.env.ENTRA_TENANT_ID || '';
var CLIENT_ID = process.env.ENTRA_CLIENT_ID || '';
var BOOTSTRAP_ADMIN = (process.env.BOOTSTRAP_ADMIN_EMAIL || '').toLowerCase();

function validateToken(event) {
  var authHeader = (event.headers || {}).authorization || (event.headers || {}).Authorization || '';
  if (!authHeader.startsWith('Bearer ')) return null;
  var token = authHeader.slice(7);
  var claims = decodeJwt(token);
  if (!claims) return null;
  // Validate issuer (Microsoft Entra ID)
  if (claims.iss && !claims.iss.includes(TENANT_ID)) return null;
  // Validate audience
  if (claims.aud && claims.aud !== CLIENT_ID) return null;
  // Validate expiration
  if (claims.exp && claims.exp < Math.floor(Date.now() / 1000)) return null;
  return {
    email: (claims.preferred_username || claims.email || claims.upn || '').toLowerCase(),
    name: claims.name || '',
    entraId: claims.oid || claims.sub || '',
    tenantId: claims.tid || ''
  };
}

exports.handler = async (event) => {
  if (event.httpMethod === 'OPTIONS')
    return { statusCode: 204, headers: { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': 'Content-Type, Authorization', 'Access-Control-Allow-Methods': 'POST, OPTIONS' }, body: '' };
  if (event.httpMethod !== 'POST')
    return { statusCode: 405, body: JSON.stringify({ error: 'Method not allowed' }) };
  var hdrs = { 'Access-Control-Allow-Origin': '*', 'Content-Type': 'application/json' };

  try {
    var body = JSON.parse(event.body);
    var action = body.action;
    var db = await getDb();
    var col = db.collection('jobs');

    // Validate auth token (allow provisionUser without full user record)
    var authUser = validateToken(event);

    // ACTION: provisionUser — create/update user on login
    if (action === 'provisionUser') {
      if (!authUser || !authUser.email) return { statusCode: 401, headers: hdrs, body: JSON.stringify({ error: 'Invalid token' }) };
      var usersCol = db.collection('users');
      var existing = await usersCol.findOne({ email: authUser.email });
      if (existing) {
        // Update last login
        await usersCol.updateOne({ _id: existing._id }, { $set: { lastLogin: new Date(), name: authUser.name || existing.name } });
        return { statusCode: 200, headers: hdrs, body: JSON.stringify({ user: existing, isNew: false }) };
      }
      // New user — check if bootstrap admin
      var isBootstrap = authUser.email === BOOTSTRAP_ADMIN;
      var newUser = {
        email: authUser.email,
        name: body.name || authUser.name || '',
        entraId: authUser.entraId,
        userType: 'internal',
        externalCompany: null,
        department: '',
        groups: [],
        role: isBootstrap ? 'super_admin' : 'pending',
        status: isBootstrap ? 'active' : 'pending',
        preferences: {},
        invitedBy: null,
        lastLogin: new Date(),
        createdAt: new Date(),
        updatedAt: new Date()
      };
      var result = await usersCol.insertOne(newUser);
      newUser._id = result.insertedId;
      if (!isBootstrap) {
        return { statusCode: 200, headers: hdrs, body: JSON.stringify({ user: newUser, isNew: true, message: 'Account pending admin approval' }) };
      }
      return { statusCode: 200, headers: hdrs, body: JSON.stringify({ user: newUser, isNew: true }) };
    }

    // ===== RBAC PERMISSION MATRIX =====
    var ACTION_PERMISSIONS = {
      // Data Maintenance: super_admin only
      reExtract: ['super_admin'], fixCountries: ['super_admin'], fixCompanyTypes: ['super_admin'],
      fixCompanyUrls: ['super_admin'], fixDescriptions: ['super_admin'], cleanNonCyber: ['super_admin'],
      // Settings: global = super_admin, user = all
      // User Management: admin+
      listUsers: ['super_admin', 'admin'], addUser: ['super_admin', 'admin'],
      updateUser: ['super_admin', 'admin'], deleteUser: ['super_admin', 'admin'],
      // Enrichment: manager+
      enrichCompany: ['super_admin', 'admin', 'manager'],
      getCompaniesNeedingEnrichment: ['super_admin', 'admin', 'manager'],
      updateCompanyIfEmpty: ['super_admin', 'admin', 'manager'],
      // Edit: analyst+
      updateField: ['super_admin', 'admin', 'manager', 'analyst'],
      updateStatus: ['super_admin', 'admin', 'manager', 'analyst'],
      // Read: all authenticated
      search: ['super_admin', 'admin', 'manager', 'analyst', 'viewer'],
      dashboard: ['super_admin', 'admin', 'manager', 'analyst', 'viewer'],
      getJob: ['super_admin', 'admin', 'manager', 'analyst', 'viewer'],
      getRecentContracts: ['super_admin', 'admin', 'manager', 'analyst', 'viewer'],
      getEnrichmentStatus: ['super_admin', 'admin', 'manager', 'analyst'],
      // Pie chart searches: all
      searchDashPie: ['super_admin', 'admin', 'manager', 'analyst', 'viewer'],
      searchContractByCountry: ['super_admin', 'admin', 'manager', 'analyst', 'viewer'],
      searchContractBySkill: ['super_admin', 'admin', 'manager', 'analyst', 'viewer'],
      // Contacts: analyst+ (not viewer)
      findContacts: ['super_admin', 'admin', 'manager', 'analyst'],
      saveContacts: ['super_admin', 'admin', 'manager', 'analyst'],
    };

    // Check RBAC for protected actions (skip for provisionUser and settings)
    if (action !== 'provisionUser' && action !== 'getSettings' && action !== 'saveSettings' && action !== 'updateUserPreferences') {
      var allowedRoles = ACTION_PERMISSIONS[action];
      if (allowedRoles && authUser) {
        var actionUser = await db.collection('users').findOne({ email: authUser.email });
        if (!actionUser || allowedRoles.indexOf(actionUser.role) === -1) {
          return { statusCode: 403, headers: hdrs, body: JSON.stringify({ error: 'Access denied. Required role: ' + allowedRoles.join(' or ') }) };
        }
        if (actionUser.status !== 'active') {
          return { statusCode: 403, headers: hdrs, body: JSON.stringify({ error: 'Account is ' + actionUser.status + '. Contact your administrator.' }) };
        }
      }
    }

    // ===== PHASE 4: RBAC ENFORCEMENT =====
    // Get authenticated user's role from MongoDB
    var authRole = null;
    if (authUser && authUser.email) {
      var authUserDoc = await db.collection('users').findOne({ email: authUser.email });
      if (authUserDoc) authRole = authUserDoc.role;
    }

    // RBAC helper
    function requireRole(allowedRoles) {
      if (!authUser || !authRole) return { statusCode: 401, headers: hdrs, body: JSON.stringify({ error: 'Authentication required' }) };
      if (authRole === 'pending') return { statusCode: 403, headers: hdrs, body: JSON.stringify({ error: 'Account pending approval' }) };
      if (allowedRoles.indexOf(authRole) === -1) return { statusCode: 403, headers: hdrs, body: JSON.stringify({ error: 'Insufficient permissions. Required: ' + allowedRoles.join(' or ') }) };
      return null;
    }
    var ALL_ACTIVE = ['super_admin', 'admin', 'manager', 'analyst', 'viewer'];
    var WRITE_ROLES = ['super_admin', 'admin', 'manager', 'analyst'];
    var MANAGER_UP = ['super_admin', 'admin', 'manager'];
    var ADMIN_UP = ['super_admin', 'admin'];
    var SUPER_ONLY = ['super_admin'];

    // Define RBAC rules per action
    var ACTION_ROLES = {
      'search': ALL_ACTIVE, 'getDashboard': ALL_ACTIVE, 'getJob': ALL_ACTIVE,
      'getRecentContracts': ALL_ACTIVE, 'searchDashPie': ALL_ACTIVE,
      'searchContractByCountry': ALL_ACTIVE, 'searchContractBySkill': ALL_ACTIVE,
      'updateField': WRITE_ROLES, 'updateCompanyInfo': WRITE_ROLES, 'updateCompanyName': WRITE_ROLES,
      'updateCompanyIfEmpty': MANAGER_UP, 'updateStatus': WRITE_ROLES,
      'getEnrichmentStatus': MANAGER_UP, 'getCompaniesNeedingEnrichment': ADMIN_UP, 'propagateCompanyData': SUPER_ONLY, 'clearContaminatedSize': SUPER_ONLY, 'getCompaniesBySize': ADMIN_UP, 'getTopCompaniesNeedingSize': ADMIN_UP,
      'fixCountries': SUPER_ONLY, 'fixCompanyTypes': SUPER_ONLY,
      'fixCompanyUrls': SUPER_ONLY, 'reExtract': SUPER_ONLY,
      'fixDescriptions': SUPER_ONLY, 'cleanupNonCyber': SUPER_ONLY, 'fixExcessContacts': SUPER_ONLY,
      'getOrphanedContacts': ADMIN_UP, 'bulkUpdateContactCompanies': ADMIN_UP, 'fixOrphanedByEmail': SUPER_ONLY, 'fixContaminatedUrls': SUPER_ONLY, 'getContactsForLinkedinScrape': ADMIN_UP, 'tagScrapeFailed': ADMIN_UP, 'deleteCompanyContacts': ADMIN_UP,
      'listUsers': ADMIN_UP, 'addUser': ADMIN_UP,
      'updateUser': ADMIN_UP, 'deleteUser': ADMIN_UP,
      'saveSettings': null, 'getSettings': ALL_ACTIVE,
      'updateUserPreferences': ALL_ACTIVE,
      'provisionUser': null // handled separately above
    };

    // Enforce RBAC (skip if no auth header — migration grace period)
    if (authUser && ACTION_ROLES[action] !== undefined && ACTION_ROLES[action] !== null) {
      var roleCheck = requireRole(ACTION_ROLES[action]);
      if (roleCheck) return roleCheck;
    }

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
        // #328: exactCompany flag for dashboard drill-down (clicking a company name) → exact match
        if (body.exactCompany) {
          filter.company = { $regex: '^' + compSearch + '$', $options: 'i' };
        } else {
          filter.company = { $regex: compSearch, $options: 'i' };
        }
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

    // ACTION: updateCompanyName - rename company across all jobs
    if (action === 'updateCompanyName') {
      var oldName = body.oldName;
      var newName = body.newName;
      if (!newName) return { statusCode: 400, headers: hdrs, body: JSON.stringify({ error: 'New name required' }) };
      var result = await col.updateMany(
        { company: oldName },
        { $set: { company: newName } }
      );
      // Also update contacts collection (only if oldName is not empty)
      if (oldName && oldName.trim()) {
        await db.collection('contacts').updateMany(
          { company: { $regex: '^' + oldName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '$', $options: 'i' } },
          { $set: { company: newName } }
        );
      }
      return { statusCode: 200, headers: hdrs, body: JSON.stringify({ updated: result.modifiedCount }) };
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
        { $match: { companyType: { $nin: [null, ''] } } },
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
      // #322: also compute average required experience (years) per role
      var roleCounts = await col.aggregate([
        { $match: { titleClean: { $ne: null } } },
        { $project: {
          role: { $toLower: '$titleClean' },
          // Extract first number from experience text (e.g. "Minimum 8 years..." -> 8)
          expYears: {
            $let: {
              vars: { m: { $regexFind: { input: { $ifNull: ['$experience', ''] }, regex: /(\d+)/ } } },
              in: { $cond: [{ $ne: ['$$m', null] }, { $toInt: { $arrayElemAt: ['$$m.captures', 0] } }, null] }
            }
          }
        } },
        { $group: {
          _id: '$role',
          count: { $sum: 1 },
          avgExp: { $avg: '$expYears' }
        } },
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
        { $match: { jobType: 'Contract', tools: { $type: 'string', $nin: ['', 'See details'] } } },
        { $project: { items: { $split: ['$tools', ', '] } } },
        { $unwind: '$items' },
        { $match: { items: { $ne: '' } } },
        { $group: { _id: { $toUpper: { $trim: { input: '$items' } } }, count: { $sum: 1 } } },
        { $sort: { count: -1 } },
        { $limit: 20 }
      ]).toArray();
      var contractCerts = await col.aggregate([
        { $match: { jobType: 'Contract', certifications: { $type: 'string', $nin: ['', 'See details'] } } },
        { $project: { items: { $split: ['$certifications', ', '] } } },
        { $unwind: '$items' },
        { $match: { items: { $ne: '' } } },
        { $group: { _id: { $trim: { input: '$items' } }, count: { $sum: 1 } } },
        { $sort: { count: -1 } },
        { $limit: 15 }
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
      // #327: normalize roles but preserve weighted-average experience
      (function normRolesWithExp() {
        var merged = {};
        roleCounts.forEach(function(item) {
          var key = (item._id || '').toLowerCase().trim();
          var display = VARIANTS[key] || titleCase(item._id || '');
          if (!merged[display]) merged[display] = { count: 0, expSum: 0, expCount: 0 };
          merged[display].count += item.count;
          if (item.avgExp && item.avgExp > 0) {
            // weight by job count to get a true average across merged variants
            merged[display].expSum += item.avgExp * item.count;
            merged[display].expCount += item.count;
          }
        });
        roleCounts = Object.keys(merged).map(function(k) {
          var m = merged[k];
          return { _id: k, count: m.count, avgExp: m.expCount > 0 ? (m.expSum / m.expCount) : null };
        }).sort(function(a, b) { return b.count - a.count; });
      })();
      contractSkills = normList(contractSkills);
      contractCerts = normList(contractCerts);

      return { statusCode: 200, headers: hdrs, body: JSON.stringify({
        totalJobs, statusCounts, typeCounts, countryCounts, companyCounts,
        certCounts, complianceCounts, toolsCounts, locationCounts, recentScans,
        partnerTargets, roleCounts, skillCounts, salaryJobs,
        contractTotal, contractNew, contractByCountry, contractByCompany, contractSkills, contractCerts, avgRate
      })};
    }

    // ACTION: reExtract - re-process all jobs to update extracted fields from stored descriptions
    // #176: Contact management
    if (action === 'saveContacts') {
      var contactsCol = db.collection('contacts');
      var contacts = body.contacts || [];
      var company = body.company || '';
      if (!company || !contacts.length) return { statusCode: 400, headers: hdrs, body: JSON.stringify({ error: 'Company and contacts required' }) };
      // Cap at 20 contacts per company
      var MAX_CONTACTS = 20;
      var existingCount = await contactsCol.countDocuments({ company: { $regex: company.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), $options: 'i' } });
      var allowedNew = Math.max(0, MAX_CONTACTS - existingCount);
      if (allowedNew === 0) return { statusCode: 200, headers: hdrs, body: JSON.stringify({ saved: 0, message: 'Contact limit (20) reached for ' + company }) };
      contacts = contacts.slice(0, allowedNew);
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

    // ACTION: getTopCompaniesNeedingSize - top-N companies by job count that lack size
    if (action === 'getTopCompaniesNeedingSize') {
      var topN = Math.min(body.topN || 100, 200);
      var companies = await col.aggregate([
        { $match: { company: { $nin: [null, ''] } } },
        { $group: {
          _id: '$company',
          jobCount: { $sum: 1 },
          maxSize: { $max: '$companySize' },
          companyLinkedin: { $first: { $cond: [{ $and: [{ $ne: ['$companyLinkedin', ''] }, { $ne: ['$companyLinkedin', null] }] }, '$companyLinkedin', null] } },
          companyUrl: { $first: { $cond: [{ $and: [{ $ne: ['$companyUrl', ''] }, { $ne: ['$companyUrl', null] }, { $not: { $regexMatch: { input: { $ifNull: ['$companyUrl', ''] }, regex: /google\.com\/search/ } } }] }, '$companyUrl', null] } }
        } },
        // Only companies that still lack a real size
        { $match: { $or: [{ maxSize: { $in: [null, 0] } }, { maxSize: { $exists: false } }] } },
        { $sort: { jobCount: -1 } },
        { $limit: topN }
      ]).toArray();
      var withLinkedin = companies.filter(function(c){ return c.companyLinkedin; }).length;
      return { statusCode: 200, headers: hdrs, body: JSON.stringify({ companies: companies, total: companies.length, withLinkedin: withLinkedin }) };
    }

    // ACTION: getCompaniesBySize - list companies whose jobs have a specific size (for targeted re-enrichment)
    if (action === 'getCompaniesBySize') {
      var targetSize = body.targetSize;
      var sizeMatch;
      if (targetSize === 0 || targetSize === '0') {
        sizeMatch = { $or: [{ companySize: { $in: [null, 0, ''] } }, { companySize: { $exists: false } }] };
      } else {
        sizeMatch = { companySize: parseInt(targetSize) };
      }
      var companies = await col.aggregate([
        { $match: sizeMatch },
        { $match: { company: { $nin: [null, ''] } } },
        { $group: {
          _id: '$company',
          companyLinkedin: { $first: { $cond: [{ $and: [{ $ne: ['$companyLinkedin', ''] }, { $ne: ['$companyLinkedin', null] }] }, '$companyLinkedin', null] } },
          jobCount: { $sum: 1 }
        } },
        { $sort: { jobCount: -1 } }
      ]).toArray();
      return { statusCode: 200, headers: hdrs, body: JSON.stringify({ companies: companies, total: companies.length }) };
    }

    // ACTION: clearContaminatedSize - clear a wrong company size that contaminated many companies
    if (action === 'clearContaminatedSize') {
      var badSize = body.badSize || 220;
      // Clear the size on jobs where it matches the bad value (it was wrongly propagated)
      var result = await col.updateMany(
        { companySize: badSize },
        { $unset: { companySize: '' } }
      );
      return { statusCode: 200, headers: hdrs, body: JSON.stringify({ cleared: result.modifiedCount, badSize: badSize }) };
    }

    // ACTION: propagateCompanyData - copy known-good URL/LinkedIn/size/type across all jobs of same company
    if (action === 'propagateCompanyData') {
      // Group by company, find the best (non-empty, non-google) values
      var groups = await col.aggregate([
        { $match: { company: { $nin: [null, ''] } } },
        { $group: {
          _id: '$company',
          bestUrl: { $max: { $cond: [{ $and: [
            { $ne: ['$companyUrl', ''] }, { $ne: ['$companyUrl', null] },
            { $not: { $regexMatch: { input: { $ifNull: ['$companyUrl', ''] }, regex: /google\.com\/search/ } } }
          ] }, '$companyUrl', null] } },
          bestLinkedin: { $max: { $cond: [{ $and: [{ $ne: ['$companyLinkedin', ''] }, { $ne: ['$companyLinkedin', null] }] }, '$companyLinkedin', null] } },
          bestSize: { $max: '$companySize' },
          bestType: { $max: { $cond: [{ $and: [{ $ne: ['$companyType', ''] }, { $ne: ['$companyType', null] }] }, '$companyType', null] } },
          jobCount: { $sum: 1 }
        } },
        // Only companies with 2+ jobs AND some good data to propagate (single-job companies have nothing to propagate to)
        { $match: { jobCount: { $gt: 1 }, $or: [
          { bestUrl: { $ne: null } }, { bestLinkedin: { $ne: null } },
          { bestSize: { $gt: 0 } }, { bestType: { $ne: null } }
        ] } }
      ]).toArray();

      // Build bulk operations (one updateMany per fill-type per company, batched)
      var ops = [];
      for (var gi = 0; gi < groups.length; gi++) {
        var g = groups[gi];
        if (g.bestUrl) {
          ops.push({ updateMany: {
            filter: { company: g._id, $or: [{ companyUrl: { $in: [null, ''] } }, { companyUrl: { $exists: false } }, { companyUrl: { $regex: /google\.com\/search/ } }] },
            update: { $set: { companyUrl: g.bestUrl } }
          }});
        }
        if (g.bestLinkedin) {
          ops.push({ updateMany: {
            filter: { company: g._id, $or: [{ companyLinkedin: { $in: [null, ''] } }, { companyLinkedin: { $exists: false } }] },
            update: { $set: { companyLinkedin: g.bestLinkedin } }
          }});
        }
        if (g.bestSize && g.bestSize > 0) {
          ops.push({ updateMany: {
            filter: { company: g._id, $or: [{ companySize: { $in: [null, 0, ''] } }, { companySize: { $exists: false } }] },
            update: { $set: { companySize: g.bestSize } }
          }});
        }
        if (g.bestType) {
          ops.push({ updateMany: {
            filter: { company: g._id, $or: [{ companyType: { $in: [null, ''] } }, { companyType: { $exists: false } }] },
            update: { $set: { companyType: g.bestType } }
          }});
        }
      }

      var jobsUpdated = 0;
      if (ops.length) {
        // Execute in chunks of 500 ops to stay within limits
        for (var ci = 0; ci < ops.length; ci += 500) {
          var chunk = ops.slice(ci, ci + 500);
          var res = await col.bulkWrite(chunk, { ordered: false });
          jobsUpdated += (res.modifiedCount || 0);
        }
      }
      return { statusCode: 200, headers: hdrs, body: JSON.stringify({ companiesUpdated: groups.length, jobsUpdated: jobsUpdated }) };
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

    // ===== USER MANAGEMENT ACTIONS =====

    // ACTION: listUsers - get all users (admin/super_admin only)
    if (action === 'listUsers') {
      if (authUser) {
        var reqUser = await db.collection('users').findOne({ email: authUser.email });
        if (!reqUser || (reqUser.role !== 'super_admin' && reqUser.role !== 'admin')) {
          return { statusCode: 403, headers: hdrs, body: JSON.stringify({ error: 'Admin access required' }) };
        }
      }
      var users = await db.collection('users').find({}).sort({ createdAt: 1 }).toArray();
      return { statusCode: 200, headers: hdrs, body: JSON.stringify({ users: users }) };
    }

    // ACTION: addUser - create a new user (admin/super_admin only)
    if (action === 'addUser') {
      if (authUser) {
        var reqUser = await db.collection('users').findOne({ email: authUser.email });
        if (!reqUser || (reqUser.role !== 'super_admin' && reqUser.role !== 'admin')) {
          return { statusCode: 403, headers: hdrs, body: JSON.stringify({ error: 'Admin access required' }) };
        }
        // Only super_admin can create super_admin users
        if (body.role === 'super_admin' && reqUser.role !== 'super_admin') {
          return { statusCode: 403, headers: hdrs, body: JSON.stringify({ error: 'Only Super Admin can assign Super Admin role' }) };
        }
      }
      var email = (body.email || '').toLowerCase().trim();
      if (!email) return { statusCode: 400, headers: hdrs, body: JSON.stringify({ error: 'Email is required' }) };
      // Check if user already exists
      var existing = await db.collection('users').findOne({ email: email });
      if (existing) return { statusCode: 200, headers: hdrs, body: JSON.stringify({ error: 'User ' + email + ' already exists', user: existing }) };
      var newUser = {
        email: email,
        name: body.name || '',
        entraId: body.entraId || '',
        userType: body.userType || 'internal',
        externalCompany: body.externalCompany || null,
        department: body.department || '',
        groups: body.groups || [],
        role: body.role || 'analyst',
        status: body.status || 'active',
        preferences: {},
        invitedBy: authUser ? authUser.email : null,
        lastLogin: null,
        createdAt: new Date(),
        updatedAt: new Date()
      };
      var result = await db.collection('users').insertOne(newUser);
      newUser._id = result.insertedId;
      return { statusCode: 200, headers: hdrs, body: JSON.stringify({ user: newUser, created: true }) };
    }

    // ACTION: updateUser - update role/status/groups (admin/super_admin only)
    if (action === 'updateUser') {
      if (authUser) {
        var reqUser = await db.collection('users').findOne({ email: authUser.email });
        if (!reqUser || (reqUser.role !== 'super_admin' && reqUser.role !== 'admin')) {
          return { statusCode: 403, headers: hdrs, body: JSON.stringify({ error: 'Admin access required' }) };
        }
        if (body.updates && body.updates.role === 'super_admin' && reqUser.role !== 'super_admin') {
          return { statusCode: 403, headers: hdrs, body: JSON.stringify({ error: 'Only Super Admin can assign Super Admin role' }) };
        }
      }
      var ObjectId = require('mongodb').ObjectId;
      var userId = body.userId;
      var updates = body.updates || {};
      updates.updatedAt = new Date();
      await db.collection('users').updateOne({ _id: new ObjectId(userId) }, { $set: updates });
      return { statusCode: 200, headers: hdrs, body: JSON.stringify({ updated: true }) };
    }

    // ACTION: deleteUser - remove a user (admin/super_admin only)
    if (action === 'deleteUser') {
      if (authUser) {
        var reqUser = await db.collection('users').findOne({ email: authUser.email });
        if (!reqUser || (reqUser.role !== 'super_admin' && reqUser.role !== 'admin')) {
          return { statusCode: 403, headers: hdrs, body: JSON.stringify({ error: 'Admin access required' }) };
        }
      }
      var ObjectId2 = require('mongodb').ObjectId;
      // Prevent deleting yourself
      var targetUser = await db.collection('users').findOne({ _id: new ObjectId2(body.userId) });
      if (targetUser && authUser && targetUser.email === authUser.email) {
        return { statusCode: 400, headers: hdrs, body: JSON.stringify({ error: 'Cannot delete your own account' }) };
      }
      // Prevent non-super deleting super_admin
      if (targetUser && targetUser.role === 'super_admin') {
        var delReqUser = await db.collection('users').findOne({ email: authUser.email });
        if (!delReqUser || delReqUser.role !== 'super_admin') {
          return { statusCode: 403, headers: hdrs, body: JSON.stringify({ error: 'Only Super Admin can remove Super Admin users' }) };
        }
      }
      await db.collection('users').deleteOne({ _id: new ObjectId2(body.userId) });
      return { statusCode: 200, headers: hdrs, body: JSON.stringify({ deleted: true }) };
    }

    // ACTION: deleteCompanyContacts - delete all contacts for a company
    if (action === 'deleteCompanyContacts') {
      var company = (body.company || '').trim();
      if (!company) return { statusCode: 400, headers: hdrs, body: JSON.stringify({ error: 'Company name required' }) };
      var contactsCol = db.collection('contacts');
      var result = await contactsCol.deleteMany({ company: { $regex: '^' + company.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '$', $options: 'i' } });
      return { statusCode: 200, headers: hdrs, body: JSON.stringify({ deleted: result.deletedCount, company: company }) };
    }

    // ACTION: fixContaminatedUrls - clear wrong URLs (e.g. ideahelix) from jobs where company differs
    if (action === 'fixContaminatedUrls') {
      var badDomain = body.badDomain || 'ideahelix';
      var batchLimit = Math.min(body.batchSize || 200, 500);
      var escBad = badDomain.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      var badRe = new RegExp(escBad, 'i');
      // Find jobs where URL contains badDomain but company name does NOT
      var contaminated = await col.find({
        $or: [
          { companyUrl: { $regex: escBad, $options: 'i' } },
          { companyLinkedin: { $regex: escBad, $options: 'i' } }
        ],
        company: { $not: { $regex: escBad, $options: 'i' } }
      }).limit(batchLimit).toArray();

      var totalRemaining = await col.countDocuments({
        $or: [
          { companyUrl: { $regex: escBad, $options: 'i' } },
          { companyLinkedin: { $regex: escBad, $options: 'i' } }
        ],
        company: { $not: { $regex: escBad, $options: 'i' } }
      });

      // Use bulkWrite for speed
      var ops = [];
      contaminated.forEach(function(j) {
        var upd = {};
        if (j.companyUrl && badRe.test(j.companyUrl)) upd.companyUrl = '';
        if (j.companyLinkedin && badRe.test(j.companyLinkedin)) upd.companyLinkedin = '';
        if (Object.keys(upd).length) ops.push({ updateOne: { filter: { _id: j._id }, update: { $set: upd } } });
      });
      if (ops.length) await col.bulkWrite(ops);

      return { statusCode: 200, headers: hdrs, body: JSON.stringify({ cleared: ops.length, totalRemaining: totalRemaining - ops.length }) };
    }

    // ACTION: tagScrapeFailed - mark contacts that LinkedIn scraper couldn't resolve
    if (action === 'tagScrapeFailed') {
      var contactIds = body.contactIds || [];
      if (!contactIds.length) return { statusCode: 200, headers: hdrs, body: JSON.stringify({ tagged: 0 }) };
      var ObjectId = require('mongodb').ObjectId;
      var contactsCol = db.collection('contacts');
      var oids = contactIds.map(function(id) { try { return new ObjectId(id); } catch (e) { return null; } }).filter(Boolean);
      var result = await contactsCol.updateMany({ _id: { $in: oids } }, { $set: { scrapeFailed: true } });
      return { statusCode: 200, headers: hdrs, body: JSON.stringify({ tagged: result.modifiedCount }) };
    }

    // ACTION: getContactsForLinkedinScrape - get orphaned contacts with LinkedIn but no email
    if (action === 'getContactsForLinkedinScrape') {
      var wrongCompany = body.wrongCompany || 'ideaHelix';
      var batchSize = Math.min(body.batchSize || 10, 25);
      var contactsCol = db.collection('contacts');
      var escWrong = '^' + wrongCompany.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '$';
      var contacts = await contactsCol.find({
        company: { $regex: escWrong, $options: 'i' },
        linkedin: { $nin: [null, '', 'N/A'] },
        scrapeFailed: { $ne: true }
      }).limit(batchSize).project({ _id: 1, name: 1, linkedin: 1 }).toArray();
      var totalRemaining = await contactsCol.countDocuments({
        company: { $regex: escWrong, $options: 'i' },
        linkedin: { $nin: [null, '', 'N/A'] },
        scrapeFailed: { $ne: true }
      });
      return { statusCode: 200, headers: hdrs, body: JSON.stringify({ contacts: contacts, totalRemaining: totalRemaining }) };
    }

    // ACTION: getOrphanedContacts - get contacts with wrong company
    if (action === 'getOrphanedContacts') {
      var wrongCompany = body.wrongCompany || 'ideaHelix';
      var contactsCol = db.collection('contacts');
      var escWrong = '^' + wrongCompany.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '$';
      var totalRemaining = await contactsCol.countDocuments({
        company: { $regex: escWrong, $options: 'i' }
      });
      var withEmail = await contactsCol.countDocuments({
        company: { $regex: escWrong, $options: 'i' },
        email: { $nin: [null, '', 'N/A'] }
      });
      var noEmailWithLinkedin = await contactsCol.countDocuments({
        company: { $regex: escWrong, $options: 'i' },
        email: { $in: [null, '', 'N/A'] },
        linkedin: { $nin: [null, '', 'N/A'] }
      });
      var noEmailNoLinkedin = await contactsCol.countDocuments({
        company: { $regex: escWrong, $options: 'i' },
        email: { $in: [null, '', 'N/A'] },
        linkedin: { $in: [null, '', 'N/A'] }
      });
      return { statusCode: 200, headers: hdrs, body: JSON.stringify({
        totalRemaining: totalRemaining, withEmail: withEmail,
        noEmailWithLinkedin: noEmailWithLinkedin, noEmailNoLinkedin: noEmailNoLinkedin
      })};
    }

    // ACTION: fixOrphanedByEmail - match contacts to companies via email domain
    if (action === 'fixOrphanedByEmail') {
      // Helper: turn a domain prefix into a presentable company name
      // "akkodis" → "Akkodis", "apexsystems" → "Apex Systems", "boozallen" → "Booz Allen"
      function prettifyDomain(prefix) {
        if (!prefix) return '';
        var s = prefix.replace(/[^a-z0-9]/gi, '');
        // Common company-name word boundaries to split on
        var words = ['systems', 'solutions', 'technologies', 'technology', 'consulting', 'consultants',
          'services', 'group', 'global', 'partners', 'staffing', 'recruiting', 'recruitment', 'software',
          'security', 'cyber', 'tech', 'labs', 'digital', 'data', 'health', 'capital', 'financial',
          'allen', 'systems', 'networks', 'network', 'corp', 'inc', 'llc', 'international', 'worldwide'];
        var lower = s.toLowerCase();
        // Try to split off a trailing known word
        for (var wi = 0; wi < words.length; wi++) {
          var w = words[wi];
          if (lower.length > w.length && lower.slice(-w.length) === w) {
            var head = lower.slice(0, lower.length - w.length);
            if (head.length >= 2) {
              return cap(head) + ' ' + cap(w);
            }
          }
        }
        return cap(lower);
      }
      function cap(str) { return str.charAt(0).toUpperCase() + str.slice(1); }

      var wrongCompany = body.wrongCompany || 'ideaHelix';
      var batchSize = Math.min(body.batchSize || 50, 100);
      var contactsCol = db.collection('contacts');
      var escapedWrong = wrongCompany.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

      // Get contacts with emails
      var contacts = await contactsCol.find({
        company: { $regex: '^' + escapedWrong + '$', $options: 'i' },
        email: { $nin: [null, '', 'N/A'] }
      }).limit(batchSize).toArray();

      if (!contacts.length) return { statusCode: 200, headers: hdrs, body: JSON.stringify({ fixed: 0, noEmail: 0, message: 'No contacts with emails found' }) };

      // Extract unique email domains
      var domainMap = {};
      contacts.forEach(function(c) {
        var email = (c.email || '').toLowerCase();
        var atIdx = email.indexOf('@');
        if (atIdx > 0) {
          var domain = email.slice(atIdx + 1).trim();
          if (domain && domain.indexOf('.') > 0) {
            if (!domainMap[domain]) domainMap[domain] = [];
            domainMap[domain].push(c._id);
          }
        }
      });

      // For each domain, find matching company in jobs collection
      var domains = Object.keys(domainMap);
      var fixed = 0;
      var companiesFound = {};
      var unmatchedDomains = [];

      // Build company lookup map from jobs (strip spaces for fuzzy matching)
      var allCompanyNames = await col.distinct('company');
      var companyMap = {};
      allCompanyNames.forEach(function(c) {
        if (c && c.trim()) {
          var key = c.toLowerCase().replace(/[\s\-_\.,']+/g, '');
          if (!companyMap[key]) companyMap[key] = c; // keep first occurrence
        }
      });

      for (var di = 0; di < domains.length; di++) {
        var domain = domains[di];
        // Skip generic email providers
        if (/^(gmail|yahoo|hotmail|outlook|aol|icloud|protonmail|mail|live|msn|ymail)\./i.test(domain)) continue;

        var domainPrefix = domain.split('.')[0].toLowerCase();

        // Match 1: exact match (stripped) — "apexsystems" matches "Apex Systems"
        var companyName = companyMap[domainPrefix] || '';

        // Match 2: try domain prefix as substring of company name (min 4 chars to avoid false matches)
        if (!companyName && domainPrefix.length >= 4) {
          var keys = Object.keys(companyMap);
          // First pass: company name STARTS WITH domain prefix (most reliable)
          for (var ki = 0; ki < keys.length; ki++) {
            if (keys[ki].indexOf(domainPrefix) === 0) {
              companyName = companyMap[keys[ki]];
              break;
            }
          }
          // Second pass: domain prefix appears anywhere in company name
          if (!companyName) {
            for (var kj = 0; kj < keys.length; kj++) {
              if (keys[kj].indexOf(domainPrefix) > -1) {
                companyName = companyMap[keys[kj]];
                break;
              }
            }
          }
        }

        // Match 3: try companyUrl or companyLinkedin in jobs
        if (!companyName) {
          var job = await col.findOne({
            $or: [
              { companyUrl: { $regex: domain.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), $options: 'i' } },
              { companyLinkedin: { $regex: domainPrefix.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), $options: 'i' } }
            ],
            company: { $nin: [null, ''] }
          });
          if (job && job.company) companyName = job.company;
        }

        // Match 4: derive from domain itself (their true employer — agency or end client)
        if (!companyName) {
          companyName = prettifyDomain(domainPrefix);
        }

        if (!companyName) { unmatchedDomains.push(domain); continue; } // no match

        // Update all contacts with this domain (contactIds already ObjectIds from toArray)
        var contactIds = domainMap[domain];
        await contactsCol.updateMany({ _id: { $in: contactIds } }, { $set: { company: companyName } });
        fixed += contactIds.length;
        companiesFound[companyName] = (companiesFound[companyName] || 0) + contactIds.length;
      }

      var totalRemaining = await contactsCol.countDocuments({
        company: { $regex: '^' + escapedWrong + '$', $options: 'i' }
      });

      return { statusCode: 200, headers: hdrs, body: JSON.stringify({
        fixed: fixed, totalRemaining: totalRemaining, companiesFound: companiesFound,
        domainsProcessed: domains.length,
        unmatchedDomains: unmatchedDomains.slice(0, 15),
        sampleCompanyKeys: Object.keys(companyMap).slice(0, 10)
      })};
    }

    // ACTION: bulkUpdateContactCompanies - update company name for multiple contacts by ID
    if (action === 'bulkUpdateContactCompanies') {
      var updates = body.updates || [];
      if (!updates.length) return { statusCode: 200, headers: hdrs, body: JSON.stringify({ updated: 0 }) };
      var ObjectId = require('mongodb').ObjectId;
      var contactsCol = db.collection('contacts');
      var updated = 0;
      for (var ui = 0; ui < updates.length; ui++) {
        var u = updates[ui];
        if (u.contactId && u.newCompany && u.newCompany.trim()) {
          await contactsCol.updateOne({ _id: new ObjectId(u.contactId) }, { $set: { company: u.newCompany.trim() } });
          updated++;
        }
      }
      return { statusCode: 200, headers: hdrs, body: JSON.stringify({ updated: updated }) };
    }

    // ACTION: fixExcessContacts - cap contacts at N per company (default 20)
    if (action === 'fixExcessContacts') {
      var maxPerCompany = body.maxPerCompany || 20;
      var contactsCol = db.collection('contacts');
      // Find companies with more than maxPerCompany contacts
      var companies = await contactsCol.aggregate([
        { $group: { _id: '$company', count: { $sum: 1 } } },
        { $match: { count: { $gt: maxPerCompany } } }
      ]).toArray();
      var totalDeleted = 0;
      for (var ci = 0; ci < companies.length; ci++) {
        var comp = companies[ci]._id;
        var excess = companies[ci].count - maxPerCompany;
        // Keep the first N (oldest), delete the rest
        var toKeep = await contactsCol.find({ company: comp }).sort({ _id: 1 }).limit(maxPerCompany).project({ _id: 1 }).toArray();
        var keepIds = toKeep.map(function(c) { return c._id; });
        var delResult = await contactsCol.deleteMany({ company: comp, _id: { $nin: keepIds } });
        totalDeleted += delResult.deletedCount;
      }
      return { statusCode: 200, headers: hdrs, body: JSON.stringify({ companiesFixed: companies.length, totalDeleted: totalDeleted }) };
    }

    // ACTION: getSettings - fetch settings from MongoDB
    if (action === 'getSettings') {
      var settingsCol = db.collection('settings');
      var scope = body.scope || 'global';
      var userId = body.userId || 'default';
      var query = scope === 'global' ? { scope: 'global' } : { scope: 'user', userId: userId };
      var doc = await settingsCol.findOne(query);
      return { statusCode: 200, headers: hdrs, body: JSON.stringify({ settings: doc ? doc.settings : null }) };
    }

    // ACTION: saveSettings - save settings to MongoDB
    if (action === 'saveSettings') {
      var settingsCol2 = db.collection('settings');
      var scope2 = body.scope || 'global';
      var userId2 = body.userId || 'default';
      // Role check: only super_admin can save global settings
      if (scope2 === 'global' && authUser) {
        var reqUser = await db.collection('users').findOne({ email: authUser.email });
        if (!reqUser || reqUser.role !== 'super_admin') {
          return { statusCode: 403, headers: hdrs, body: JSON.stringify({ error: 'Only Super Admin can modify global settings' }) };
        }
      }
      var filter2 = scope2 === 'global' ? { scope: 'global' } : { scope: 'user', userId: userId2 };
      await settingsCol2.updateOne(filter2, {
        $set: { scope: scope2, userId: scope2 === 'user' ? userId2 : null, settings: body.settings, updatedAt: new Date() },
        $setOnInsert: { createdAt: new Date() }
      }, { upsert: true });
      return { statusCode: 200, headers: hdrs, body: JSON.stringify({ saved: true }) };
    }

    // ACTION: updateUserPreferences - save preferences to users collection
    if (action === 'updateUserPreferences') {
      var email = body.email;
      if (!email) return { statusCode: 400, headers: hdrs, body: JSON.stringify({ error: 'Email required' }) };
      // Users can only update their own preferences
      if (authUser && authUser.email !== email) {
        var reqUser2 = await db.collection('users').findOne({ email: authUser.email });
        if (!reqUser2 || (reqUser2.role !== 'super_admin' && reqUser2.role !== 'admin')) {
          return { statusCode: 403, headers: hdrs, body: JSON.stringify({ error: 'Cannot update other user preferences' }) };
        }
      }
      await db.collection('users').updateOne({ email: email }, { $set: { preferences: body.preferences, updatedAt: new Date() } });
      return { statusCode: 200, headers: hdrs, body: JSON.stringify({ updated: true }) };
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
      var oneMonthAgo = new Date();
      oneMonthAgo.setMonth(oneMonthAgo.getMonth() - 1);
      var contracts = await col.find({ jobType: 'Contract', $or: [{ datePosted: { $gte: oneMonthAgo } }, { dateScanned: { $gte: oneMonthAgo } }] })
        .sort({ datePosted: -1, dateScanned: -1 })
        .project({ title: 1, company: 1, companyType: 1, companySize: 1, companyLinkedin: 1, companyUrl: 1, location: 1, salary: 1, datePosted: 1, status: 1, source: 1, applyLink: 1, detectedCountry: 1, tools: 1, certifications: 1, experience: 1, contractDuration: 1 })
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
      var compRaw = (body.company || '').replace(/[®™©]/g, '').trim();
      if (!compRaw) return { statusCode: 200, headers: hdrs, body: JSON.stringify({ contacts: [] }) };
      var compPattern = '^' + compRaw.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '$';
      var contacts = await contactsCol.find({ company: { $regex: compPattern, $options: 'i' } }).limit(20).toArray();
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
        var CERT_REMOVE = /^(?:cka|ckad|cks|zero\s*trust)$/i;
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

        // Re-extract experience from description if currently empty/Not specified
        if ((!j.experience || j.experience === 'Not specified') && j.description) {
          var desc = j.description.replace(/<br\s*\/?>/gi, '\n').replace(/<\/?(p|div|li|ul|ol|h[1-6])[^>]*>/gi, '\n').replace(/<[^>]+>/g, '').replace(/&amp;/g, '&').replace(/&#?\w+;/g, ' ');
          var expParts2 = [], seenExp = {};
          // Pattern A: "X+ years of experience in [field]"
          var pA = /(\d+)(?:\+|\s*plus)?\s*(?:years?|yrs?)['\u2019]?\s*(?:of\s*)?(?:\w+\s*)?(?:experience|expertise|background)\s*(?:in|with|as|focused\s*on|implementing|deploying|working\s*(?:in|with)|supporting|managing|performing|using|on)?\s*([\w\s,\/&\-()]+?)(?:\.|;|\n|$|,\s*(?:with|including|and|or))/gi;
          var em; while ((em = pA.exec(desc)) !== null && expParts2.length < 4) {
            var yr = parseInt(em[1]); if (yr < 1 || yr > 30) continue;
            var ctx = em[2].trim().slice(0, 35).replace(/\s+\S{0,4}$/, '').replace(/^\s*(?:a|an|the)\s+/i, '');
            if (ctx.length >= 3) { var k = ctx.substring(0,25).toLowerCase(); if (!seenExp[k]) { seenExp[k] = true; expParts2.push(yr+'+ yr '+ctx); } }
          }
          // Pattern B: "X-Y years [of experience]"
          var pB = /(\d+)\s*[\-\u2013\u2014]+\s*(\d+)\s*(?:years?|yrs?)\s*(?:of\s*)?(?:[\w\s]*?)(?:experience|expertise)?/gi;
          while ((em = pB.exec(desc)) !== null && expParts2.length < 4) {
            var y1 = parseInt(em[1]), y2 = parseInt(em[2]);
            if (y1 >= 1 && y1 <= 30 && y2 > y1 && y2 <= 30 && !(y1 === 1 && (y2 === 5 || y2 === 10))) {
              var k2 = 'range'+y1+'-'+y2; if (!seenExp[k2]) { seenExp[k2] = true; expParts2.push(y1+'-'+y2+' years'); }
            }
          }
          // Pattern C: "X+ years in [field]" (no experience keyword, common in LinkedIn)
          var pC = /(?:^|[\n\u2022\-\*;,])\s*(\d+)(?:\+|\s*plus)?\s*(?:years?|yrs?)['\u2019]?\s*(?:of\s*)?(?:in|with)\s+([\w\s,\/&\-]+?)(?:\.|;|\n|$|,)/gim;
          while ((em = pC.exec(desc)) !== null && expParts2.length < 4) {
            var yr3 = parseInt(em[1]); if (yr3 < 1 || yr3 > 30) continue;
            var ctx3 = em[2].trim().slice(0, 35).replace(/\s+\S{0,4}$/, '').replace(/^\s*(?:a|an|the)\s+/i, '');
            if (ctx3.length >= 3 && !/\b(?:the company|business|prison|service)\b/i.test(ctx3)) {
              var k3 = ctx3.substring(0,25).toLowerCase(); if (!seenExp[k3]) { seenExp[k3] = true; expParts2.push(yr3+'+ yr '+ctx3); }
            }
          }
          if (expParts2.length > 0) changes.experience = expParts2.join(', ');
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

    // ACTION: fixCompanyUrls - move LinkedIn URLs from companyUrl to companyLinkedin
    if (action === 'fixCompanyUrls') {
      // Find records where companyUrl contains linkedin.com
      var linkedinInUrl = await col.find({
        companyUrl: { $regex: /linkedin\.com\/company/i }
      }).project({ _id: 1, company: 1, companyUrl: 1, companyLinkedin: 1 }).toArray();

      var ops = [];
      linkedinInUrl.forEach(function(j) {
        var update = {};
        // Move LinkedIn URL to companyLinkedin if empty
        if (!j.companyLinkedin || j.companyLinkedin === '') {
          update.companyLinkedin = j.companyUrl;
        }
        // Clear companyUrl (it's a LinkedIn URL, not a website)
        update.companyUrl = '';
        ops.push({ updateOne: { filter: { _id: j._id }, update: { $set: update } } });
      });

      if (ops.length > 0) await col.bulkWrite(ops, { ordered: false });
      return { statusCode: 200, headers: hdrs, body: JSON.stringify({ total: linkedinInUrl.length, fixed: ops.length }) };
    }

    // ACTION: fixCompanyTypes - set empty companyType to Enterprise (default)
    if (action === 'fixCompanyTypes') {
      // Known classification lists
      var JOB_BOARDS = /\b(?:indeed|glassdoor|ziprecruiter|monster|careerbuilder|dice|linkedin|hired|angel\.co|wellfound|simplyhired|ladders|lensa|talent\.com|themuse|remote\.co|flexjobs|weworkremotely|remoteok|jobvite|greenhouse|lever|workday|smartrecruiters|icims|jazz\s*hr|breezy\s*hr|bamboo\s*hr|bullhorn|clearance\s*jobs|usajobs|governmentjobs|govcio|clearancejobs|cybercoders)\b/i;
      var STAFFING = /\b(?:robert\s*half|hays|adecco|randstad|manpower|kelly\s*services|kforce|insight\s*global|teksystems|apex\s*systems|modis|aston\s*carter|aerotek|beacon\s*hill|cybercoders|michael\s*page|page\s*group|harvey\s*nash|nigel\s*frank|brewer\s*morris|la\s*fosse|barclay\s*simpson|spencer\s*ogden|lorien|reed|huxley|sthree|talentworks|glocomms|akkodis|mondo|addison\s*group|vaco|judge\s*group|motionpoint|genesis10|artech|compuGain|aquent|mastech|net2source|softnice|synergy|hirekeyz|teksky|collabera|wipro)\b/i;

      var allRecs = await col.find({
        $or: [{ companyType: null }, { companyType: '' }, { companyType: { $exists: false } }, { companyType: 'IT Consulting' }]
      }).project({ _id: 1, company: 1, description: 1 }).toArray();

      var ops = [];
      allRecs.forEach(function(j) {
        var name = (j.company || '');
        var nameLower = name.toLowerCase();
        var desc = (j.description || '').slice(0, 2000).toLowerCase();
        var type = 'Enterprise'; // default

        // Check company NAME for classification (not description — too many false positives)
        if (JOB_BOARDS.test(nameLower)) type = 'Job Board';
        else if (STAFFING.test(nameLower)) type = 'Staffing/Recruiting';
        // Consulting: check company NAME only (not description)
        else if (/\bconsult(?:ing|ants?|ancy)\b|\badvisory\b|\bprofessional\s*services\b|\bsystem\s*integrat/i.test(nameLower)) type = 'IT Consulting';
        // MSSP/MDR: description is OK (specific enough terms)
        else if (/\bmssp\b|\bmdr\b|managed\s*(?:security|detection|soc)|security\s*(?:operations\s*center|service\s*provider)/i.test(desc)) type = 'MSSP/MDR';
        // Government: description is OK (specific terms)
        else if (/\bgovernment\b|\bfederal\b|\bdod\b|\bdefense\b|\bintelligence\s*community\b|\bclearance\b/i.test(desc)) type = 'Government';
        // Startup: description is OK
        else if (/\bstartup\b|\bseries\s*[a-d]\b|\bfounded\s*in\s*20[12]\d\b/i.test(desc)) type = 'Startup';

        ops.push({ updateOne: { filter: { _id: j._id }, update: { $set: { companyType: type } } } });
      });

      if (ops.length > 0) await col.bulkWrite(ops, { ordered: false });

      // Count breakdown
      var counts = await col.aggregate([
        { $group: { _id: '$companyType', count: { $sum: 1 } } },
        { $sort: { count: -1 } }
      ]).toArray();

      return { statusCode: 200, headers: hdrs, body: JSON.stringify({ total: allRecs.length, fixed: ops.length, breakdown: counts }) };
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
      var US_CITIES = /\b(?:New York|Los Angeles|Chicago|Houston|Phoenix|Dallas|San Jose|Austin|San Francisco|Seattle|Denver|Nashville|Washington|Boston|Portland|Las Vegas|Baltimore|Atlanta|Raleigh|Miami|Tampa|Orlando|Minneapolis|Cleveland|Pittsburgh|Cincinnati|Irvine|Arlington|Plano|Durham|Richmond|Huntsville|McLean|Tysons|Bethesda|Herndon|Reston|Chantilly|Springfield|Columbia|Annapolis|Fort Meade|Salt Lake City|Charlotte|San Diego|Sacramento|Philadelphia|Detroit|Memphis|Louisville|Milwaukee|San Antonio|Jacksonville|Fort Worth|Columbus|Indianapolis|Virginia Beach|Oklahoma City|Albuquerque|Tucson|Fresno|Mesa|Kansas City|Omaha|Colorado Springs|Long Beach|Scottsdale|Chandler|Gilbert|Boise|Quantico|Fort Belvoir|Lake Mary|Sterling|Manassas|Ewing)\b/i;
      var UK_CITIES = /\b(?:London|Manchester|Birmingham|Leeds|Glasgow|Edinburgh|Bristol|Liverpool|Sheffield|Newcastle|Nottingham|Cardiff|Belfast|Cambridge|Oxford|Reading|Southampton|Brighton|Cheltenham|Canary Wharf|Milton Keynes)\b/i;
      var CA_CITIES = /\b(?:Toronto|Vancouver|Montreal|Ottawa|Calgary|Edmonton|Winnipeg|Quebec|Hamilton|Mississauga|Kitchener|Halifax|Victoria)\b/i;
      var IN_CITIES = /\b(?:Bangalore|Bengaluru|Mumbai|Hyderabad|Pune|Delhi|New Delhi|Chennai|Kolkata|Noida|Gurgaon|Gurugram|Ahmedabad|Jaipur|Lucknow|Kochi|Chandigarh|Indore|Thiruvananthapuram)\b/i;
      var AU_CITIES = /\b(?:Sydney|Melbourne|Brisbane|Perth|Adelaide|Canberra|Hobart|Darwin|Gold Coast)\b/i;
      var DE_CITIES = /\b(?:Berlin|Munich|Frankfurt|Hamburg|Stuttgart|Dusseldorf|Cologne|Bonn|Leipzig|Dresden)\b/i;
      var CITY_COUNTRY_MAP = [
        [/\b(?:Paris|Lyon|Marseille|Toulouse|Nice|Nantes|Strasbourg|Lille)\b/i, 'France'],
        [/\b(?:Tokyo|Osaka|Yokohama|Nagoya|Kyoto)\b/i, 'Japan'],
        [/\b(?:Dublin|Cork|Galway|Limerick)\b/i, 'Ireland'],
        [/\b(?:Amsterdam|Rotterdam|The Hague|Utrecht|Eindhoven)\b/i, 'Netherlands'],
        [/\b(?:Zurich|Geneva|Basel|Bern|Lausanne)\b/i, 'Switzerland'],
        [/\b(?:Stockholm|Gothenburg|Malmo)\b/i, 'Sweden'],
        [/\b(?:Dubai|Abu Dhabi|Sharjah)\b/i, 'United Arab Emirates'],
        [/\b(?:Tel Aviv|Jerusalem|Haifa)\b/i, 'Israel'],
        [/\b(?:Sao Paulo|Rio de Janeiro|Brasilia)\b/i, 'Brazil'],
        [/\b(?:Mexico City|Guadalajara|Monterrey)\b/i, 'Mexico'],
        [/\b(?:Kuala Lumpur|Penang|Johor|Cyberjaya)\b/i, 'Malaysia'],
        [/\b(?:Hong Kong)\b/i, 'Hong Kong'],
        [/\b(?:Seoul|Busan|Incheon)\b/i, 'South Korea'],
        [/\b(?:Riyadh|Jeddah|Dammam)\b/i, 'Saudi Arabia'],
        [/\b(?:Doha)\b/i, 'Qatar'],
        [/\b(?:Manama)\b/i, 'Bahrain'],
        [/\b(?:Madrid|Barcelona|Valencia|Seville)\b/i, 'Spain'],
        [/\b(?:Rome|Milan|Turin|Naples)\b/i, 'Italy'],
        [/\b(?:Warsaw|Krakow|Wroclaw|Gdansk)\b/i, 'Poland'],
        [/\b(?:Brussels|Antwerp|Ghent)\b/i, 'Belgium'],
        [/\b(?:Vienna|Graz|Linz)\b/i, 'Austria'],
        [/\b(?:Oslo|Bergen|Trondheim)\b/i, 'Norway'],
        [/\b(?:Copenhagen|Aarhus)\b/i, 'Denmark'],
        [/\b(?:Helsinki|Espoo|Tampere)\b/i, 'Finland'],
        [/\b(?:Prague|Brno)\b/i, 'Czech Republic'],
        [/\b(?:Bucharest|Cluj)\b/i, 'Romania'],
        [/\b(?:Budapest|Debrecen)\b/i, 'Hungary'],
        [/\b(?:Lisbon|Porto)\b/i, 'Portugal'],
        [/\b(?:Auckland|Wellington|Christchurch)\b/i, 'New Zealand'],
        [/\b(?:Cape Town|Johannesburg|Durban|Pretoria)\b/i, 'South Africa'],
        [/\b(?:Lagos|Abuja)\b/i, 'Nigeria'],
        [/\b(?:Nairobi|Mombasa)\b/i, 'Kenya'],
        [/\b(?:Cairo|Alexandria)\b/i, 'Egypt'],
        [/\bSingapore\b/i, 'Singapore'],
      ];

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

        // Check 5: Location has country/state names or known cities
        if (US_STATE_NAMES.test(loc) || US_STATE_CD.test(loc) || US_CITIES.test(loc)) return 'United States';
        if (UK_CITIES.test(loc)) return 'United Kingdom';
        if (CA_CITIES.test(loc)) return 'Canada';
        if (IN_CITIES.test(loc)) return 'India';
        if (AU_CITIES.test(loc)) return 'Australia';
        if (DE_CITIES.test(loc)) return 'Germany';
        for (var cm = 0; cm < CITY_COUNTRY_MAP.length; cm++) {
          if (CITY_COUNTRY_MAP[cm][0].test(loc)) return CITY_COUNTRY_MAP[cm][1];
        }

        // Check 6: Description/title has country names or known cities
        for (var tp2 = 0; tp2 < textCountryPatterns.length; tp2++) {
          if (textCountryPatterns[tp2][0].test(text)) return textCountryPatterns[tp2][1];
        }
        if (US_STATE_NAMES.test(text) || US_CITIES.test(text)) return 'United States';
        if (UK_CITIES.test(text)) return 'United Kingdom';
        if (CA_CITIES.test(text)) return 'Canada';
        if (IN_CITIES.test(text)) return 'India';
        if (AU_CITIES.test(text)) return 'Australia';
        if (DE_CITIES.test(text)) return 'Germany';
        for (var cm2 = 0; cm2 < CITY_COUNTRY_MAP.length; cm2++) {
          if (CITY_COUNTRY_MAP[cm2][0].test(text)) return CITY_COUNTRY_MAP[cm2][1];
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
