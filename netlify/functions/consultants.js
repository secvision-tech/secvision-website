// ============================================================================
// SecVision Consultants — managed consultant/engineer/architect profile CRM
//
// Profiles live in `consultant_profiles`. A profile is either:
//   - "sourced": raw from the Apify/LinkedIn matching cache (source: apify-linkedin)
//   - "managed": adopted/created as an owned CRM record (managed: true)
// This module manages the OWNED records: create, edit, status, availability,
// placement, enrichment, and listing/search.
//
// Auto-availability: when availability='busy' and availableFrom date has passed,
// (or a SecVision placement's endDate has passed) the profile auto-flips to
// 'available' on read.
// ============================================================================

const { getDb } = require('./db');

const TENANT_ID = process.env.ENTRA_TENANT_ID || '';
const CLIENT_ID = process.env.ENTRA_CLIENT_ID || '';
const CACHE_COLLECTION = 'consultant_profiles';

// Pipeline statuses in canonical order (Phase A onboarding -> Phase B placement)
var PIPELINE_STATUSES = [
  'none', 'not_eligible', 'contacted', 'interested', 'not_interested', 'contacted_no_response',
  'screening_pending', 'screening_in_progress', 'screening_failed', 'screening_successful',
  'negotiations_in_progress', 'secvision_agreement_signing', 'secvision_agreement_signed',
  'proposed_to_client', 'interview_in_progress', 'client_interview_successful', 'client_interview_failed',
  'client_agreement_signing', 'client_agreement_signed', 'placed'
];
// Stages at/after which a HARD lock applies (only claiming analyst / managers may change)
var HARD_LOCK_STAGES = ['client_agreement_signing', 'client_agreement_signed', 'placed'];
// Stages representing an ACTIVE working claim
var ACTIVE_CLAIM_STAGES = PIPELINE_STATUSES.filter(function (s) {
  return s !== 'none' && s !== 'not_eligible' && s !== 'not_interested' && s !== 'contacted_no_response' && s !== 'screening_failed' && s !== 'client_interview_failed';
});

const hdrs = {
  'Content-Type': 'application/json',
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'POST,OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization'
};

// RBAC
var VIEW_ROLES = ['super_admin', 'admin', 'manager', 'analyst', 'viewer'];
var STATUS_ROLES = ['super_admin', 'admin', 'manager', 'analyst']; // set status/availability/pipeline
var MANAGER_UP = ['super_admin', 'admin', 'manager'];              // edit/enrich/place
var ADMIN_UP = ['super_admin', 'admin'];                           // delete, bulk promote
var ACTION_ROLES = {
  'listConsultants': VIEW_ROLES,
  'getConsultant': VIEW_ROLES,
  'setConsultantStatus': STATUS_ROLES,
  'setPipelineStatus': STATUS_ROLES,
  'claimConsultant': STATUS_ROLES,
  'releaseConsultant': STATUS_ROLES,
  'createConsultant': MANAGER_UP,
  'updateConsultant': MANAGER_UP,
  'deleteConsultant': ADMIN_UP,          // delete NOT allowed to manager
  'enrichConsultant': STATUS_ROLES,
  'adoptConsultant': MANAGER_UP,
  'importResume': MANAGER_UP,
  'placeConsultant': MANAGER_UP,
  'updatePlacementEnd': MANAGER_UP,
  'deletePlacementHistory': ADMIN_UP,
  'countCached': VIEW_ROLES,
  'uploadResume': STATUS_ROLES,
  'getResume': VIEW_ROLES,
  'removeResume': STATUS_ROLES,
  'promoteAllCached': ADMIN_UP           // one-time cached -> managed transfer
};

// ---- JWT ----
function decodeJwt(token) {
  try {
    var p = token.split('.'); if (p.length !== 3) return null;
    var pl = p[1].replace(/-/g, '+').replace(/_/g, '/'); while (pl.length % 4) pl += '=';
    return JSON.parse(Buffer.from(pl, 'base64').toString('utf8'));
  } catch (e) { return null; }
}
function validateToken(event) {
  var a = (event.headers || {}).authorization || (event.headers || {}).Authorization || '';
  if (!a.startsWith('Bearer ')) return null;
  var c = decodeJwt(a.slice(7)); if (!c) return null;
  if (c.iss && TENANT_ID && !c.iss.includes(TENANT_ID)) return null;
  if (c.aud && CLIENT_ID && c.aud !== CLIENT_ID) return null;
  if (c.exp && c.exp < Math.floor(Date.now() / 1000)) return null;
  return { email: (c.preferred_username || c.email || c.upn || '').toLowerCase(), name: c.name || '' };
}

// Derive country from a location string (city/state/country embedded)
function deriveCountryFromLocation(loc) {
  if (!loc) return '';
  var l = loc.trim();
  // explicit country name wins
  if (/\bunited states\b|\busa\b|\bu\.s\.\b/i.test(l)) return 'United States';
  if (/\bcanada\b/i.test(l)) return 'Canada';
  if (/\bunited kingdom\b|\buk\b|\bengland\b|\bscotland\b|\bwales\b/i.test(l)) return 'United Kingdom';
  if (/\baustralia\b/i.test(l)) return 'Australia';
  if (/\bindia\b/i.test(l)) return 'India';
  if (/\bgermany\b/i.test(l)) return 'Germany';
  if (/\bfrance\b/i.test(l)) return 'France';
  if (/\bsingapore\b/i.test(l)) return 'Singapore';
  if (/\bnetherlands\b/i.test(l)) return 'Netherlands';
  if (/\bireland\b/i.test(l)) return 'Ireland';
  if (/\bunited arab emirates\b|\buae\b|\bdubai\b|\babu dhabi\b/i.test(l)) return 'United Arab Emirates';
  if (/\bsaudi arabia\b/i.test(l)) return 'Saudi Arabia';
  // US state codes/names (a sample of common ones)
  if (/\b(AL|AK|AZ|AR|CA|CO|CT|DE|FL|GA|HI|ID|IL|IN|IA|KS|KY|LA|ME|MD|MA|MI|MN|MS|MO|MT|NE|NV|NH|NJ|NM|NY|NC|ND|OH|OK|OR|PA|RI|SC|SD|TN|TX|UT|VT|VA|WA|WV|WI|WY|DC)\b/.test(l) &&
      /\b[A-Z]{2}\b/.test(l)) return 'United States';
  if (/\b(california|texas|new york|florida|virginia|washington|massachusetts|illinois|georgia|arizona|colorado|maryland)\b/i.test(l)) return 'United States';
  // US metro-area labels
  if (/\b(San Francisco|New York|Washington|Boston|Chicago|Seattle|Austin|Atlanta|Dallas|Denver|Los Angeles|Miami)\b/i.test(l)) return 'United States';
  // Canada cities
  if (/\b(Toronto|Vancouver|Montreal|Ottawa|Calgary|Edmonton|Winnipeg)\b/i.test(l)) return 'Canada';
  // India cities
  if (/\b(Bangalore|Bengaluru|Mumbai|Hyderabad|Pune|Delhi|Chennai|Kolkata|Noida|Gurgaon|Gurugram)\b/i.test(l)) return 'India';
  // UK cities
  if (/\b(London|Manchester|Birmingham|Leeds|Glasgow|Edinburgh|Bristol|Swansea)\b/i.test(l)) return 'United Kingdom';
  // Australia
  if (/\b(Sydney|Melbourne|Brisbane|Perth|Adelaide|Canberra)\b/i.test(l)) return 'Australia';
  return '';
}

// ---- auto-availability: flip busy→available when the availableFrom / placement end has passed ----
function applyAutoAvailability(p) {
  if (!p) return p;
  var now = new Date();
  if (p.availability === 'busy' || p.availability === 'placed') {
    var freeDate = null;
    if (p.placementInfo && p.placementInfo.endDate) freeDate = new Date(p.placementInfo.endDate);
    else if (p.availableFrom) freeDate = new Date(p.availableFrom);
    if (freeDate && !isNaN(freeDate.getTime()) && freeDate <= now) {
      p.availability = 'available';
      p.availableFrom = null;
      // #374: placement ended — reset pipeline so consultant can be re-placed from a clean state
      if (p.pipelineStatus === 'placed') { p.pipelineStatus = 'none'; p._autoPipelineReset = true; }
      p._autoFreed = true; // marker so caller can persist
    }
  }
  // Auto-timeout: 'contacted' with no progression for >3 days -> 'contacted_no_response'
  if (p.pipelineStatus === 'contacted') {
    var since = p.contactedAt ? new Date(p.contactedAt) : (p.updatedAt ? new Date(p.updatedAt) : null);
    if (since && !isNaN(since.getTime())) {
      var days = (now - since) / (1000 * 60 * 60 * 24);
      if (days > 3) { p.pipelineStatus = 'contacted_no_response'; p.claimedBy = null; p.claimedAt = null; p._autoTimedOut = true; }
    }
  }
  return p;
}

exports.handler = async function (event) {
  if (event.httpMethod === 'OPTIONS') return { statusCode: 200, headers: hdrs, body: '' };
  if (event.httpMethod !== 'POST') return { statusCode: 405, headers: hdrs, body: JSON.stringify({ error: 'POST only' }) };

  var authUser = validateToken(event);
  if (!authUser || !authUser.email) return { statusCode: 401, headers: hdrs, body: JSON.stringify({ error: 'Invalid token' }) };

  var body;
  try { body = JSON.parse(event.body || '{}'); } catch (e) { return { statusCode: 400, headers: hdrs, body: JSON.stringify({ error: 'Bad JSON' }) }; }
  var action = body.action;

  try {
    var db = await getDb();
    var col = db.collection(CACHE_COLLECTION);
    var ObjectId = require('mongodb').ObjectId;

    // resolve role for RBAC
    var authRole = null;
    var emailRe = new RegExp('^' + authUser.email.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '$', 'i');
    var userDoc = await db.collection('users').findOne({ email: emailRe });
    if (userDoc) authRole = userDoc.role;

    // RBAC check
    if (ACTION_ROLES[action] && (!authRole || ACTION_ROLES[action].indexOf(authRole) === -1)) {
      return { statusCode: 403, headers: hdrs, body: JSON.stringify({ error: 'Insufficient permissions for ' + action }) };
    }

    // #371: When a consultant is PLACED, freeze edits for everyone except admin/super.
    var FROZEN_WHEN_PLACED = ['setConsultantStatus', 'setPipelineStatus', 'updateConsultant', 'enrichConsultant',
      'uploadResume', 'removeResume', 'claimConsultant', 'releaseConsultant', 'placeConsultant'];
    var isAdminUp = ADMIN_UP.indexOf(authRole) > -1;
    if (FROZEN_WHEN_PLACED.indexOf(action) > -1 && !isAdminUp && body.id) {
      var frozenChk = await col.findOne({ _id: new ObjectId(body.id) }, { projection: { availability: 1, pipelineStatus: 1 } });
      if (frozenChk && (frozenChk.availability === 'placed' || frozenChk.pipelineStatus === 'placed')) {
        return { statusCode: 423, headers: hdrs, body: JSON.stringify({ error: 'placed_frozen', message: 'This consultant is currently placed. Their profile is frozen until the placement ends. Contact an admin to make changes.' }) };
      }
    }

    // ---- LIST / SEARCH ----
    if (action === 'listConsultants') {
      var filter = { managed: true }; // only owned CRM records in the Consultants tab
      var q = (body.query || '').trim();
      // #444: 24-hex query = consultant ID lookup (keep managed scope).
      var _qIsId = /^[0-9a-f]{24}$/i.test(q);
      if (_qIsId) { try { filter._id = new ObjectId(q); } catch (e) { _qIsId = false; } }
      if (q) {
        var re = q.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        if(!_qIsId)filter.$or = [
          { name: { $regex: re, $options: 'i' } },
          { headline: { $regex: re, $options: 'i' } },
          { currentRole: { $regex: re, $options: 'i' } },
          { skills: { $regex: re, $options: 'i' } },
          { certifications: { $regex: re, $options: 'i' } },
          { location: { $regex: re, $options: 'i' } }
        ];
      }
      if (body.engagementType && body.engagementType !== 'all') filter.engagementType = body.engagementType;
      if (body.availability && body.availability !== 'all') filter.availability = body.availability;
      if (body.pipelineStatus && body.pipelineStatus !== 'all') filter.pipelineStatus = body.pipelineStatus;
      if (body.location) filter.location = { $regex: body.location.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), $options: 'i' };
      // Country/region: a specific country (if chosen) wins; otherwise expand region to its countries
      if (body.country && body.country !== 'all') {
        filter.country = body.country;
      } else if (body.region && body.region !== 'all') {
        var REGION_MAP = {
          'NA': ['United States', 'Canada', 'Mexico'],
          'EU': ['United Kingdom', 'Germany', 'France', 'Netherlands', 'Ireland', 'Switzerland', 'Sweden', 'Spain', 'Italy', 'Poland'],
          'AP': ['India', 'Australia', 'Singapore', 'Japan', 'South Korea', 'New Zealand', 'Malaysia', 'Philippines'],
          'ME': ['United Arab Emirates', 'Saudi Arabia', 'Israel', 'Qatar'],
          'AF': ['South Africa', 'Nigeria', 'Kenya', 'Egypt'],
          'SA': ['Brazil', 'Argentina', 'Chile', 'Colombia']
        };
        if (REGION_MAP[body.region]) filter.country = { $in: REGION_MAP[body.region] };
      }
      // time period on updatedAt/createdAt
      if (body.dateFrom || body.dateTo) {
        filter.updatedAt = {};
        if (body.dateFrom) filter.updatedAt.$gte = new Date(body.dateFrom);
        if (body.dateTo) filter.updatedAt.$lte = new Date(body.dateTo + 'T23:59:59Z');
      }

      var page = body.page || 1, limit = body.limit || 100, skip = (page - 1) * limit;
      var sort = body.sort ? (typeof body.sort === 'string' ? JSON.parse(body.sort) : body.sort) : { updatedAt: -1 };
      if (!sort._id) sort._id = -1;

      var total = await col.countDocuments(filter);
      var list = await col.find(filter).sort(sort).skip(skip).limit(limit).toArray();

      // apply auto-availability, persist any that auto-freed
      var freedOps = [];
      list.forEach(function (p) {
        applyAutoAvailability(p);
        var setFields = {};
        if (p._autoFreed) { setFields.availability = 'available'; setFields.availableFrom = null; delete p._autoFreed; }
        if (p._autoPipelineReset) { setFields.pipelineStatus = 'none'; delete p._autoPipelineReset; }
        if (p._autoTimedOut) { setFields.pipelineStatus = 'contacted_no_response'; setFields.claimedBy = null; setFields.claimedAt = null; delete p._autoTimedOut; }
        if (Object.keys(setFields).length) freedOps.push({ updateOne: { filter: { _id: p._id }, update: { $set: setFields } } });
        p.hasResume = !!(p.resume && p.resume.data);
        if (p.resume) delete p.resume; // keep list payload light
        // #430: surface a lightweight match indicator; drop the heavy array from the list.
        // #492: the 🎯 badge must see job-side scores too (matchCache/jobMatchCache),
        // not just the saved matchedJobs list — same union rule as the popup display merge:
        // >=60 only, deletions respected, deduped against saved entries.
        var savedArr = Array.isArray(p.matchedJobs) ? p.matchedJobs : [];
        var bRemoved = {}; (p.matchedJobsRemoved || []).forEach(function (id) { bRemoved[String(id)] = 1; });
        var bHave = {}; savedArr.forEach(function (m) { if (m.jobId) bHave[String(m.jobId)] = 1; });
        var bCount = savedArr.length;
        var bTop = savedArr.length ? Math.max.apply(null, savedArr.map(function (m) { return m.overall || 0; })) : 0;
        var bCache = Object.assign({}, p.matchCache || {}, p.jobMatchCache || {});
        Object.keys(bCache).forEach(function (k) {
          var e = bCache[k];
          if (e && e.overall >= 60 && !bRemoved[k] && !bHave[k]) {
            bCount++; bHave[k] = 1;
            if (e.overall > bTop) bTop = e.overall;
          }
        });
        p.matchedJobsCount = bCount;
        p.topJobMatch = bTop;
        if (p.matchedJobs) delete p.matchedJobs;
        if (p.matchCache) delete p.matchCache;
        if (p.jobMatchCache) delete p.jobMatchCache;
        if (p.jobMatchCache) delete p.jobMatchCache; // never needed in the list, can be large
        p._id = p._id.toString();
      });
      if (freedOps.length) { try { await col.bulkWrite(freedOps); } catch (e) {} }

      return { statusCode: 200, headers: hdrs, body: JSON.stringify({ consultants: list, total: total, page: page }) };
    }

    // ---- GET ONE ----
    if (action === 'getConsultant') {
      var one = await col.findOne({ _id: new ObjectId(body.id) });
      if (!one) return { statusCode: 404, headers: hdrs, body: JSON.stringify({ error: 'Not found' }) };
      applyAutoAvailability(one);
      if (one._autoFreed) { var gset = { availability: 'available', availableFrom: null }; if (one._autoPipelineReset) { gset.pipelineStatus = 'none'; delete one._autoPipelineReset; } await col.updateOne({ _id: one._id }, { $set: gset }); delete one._autoFreed; }
      // Don't ship the heavy resume blob in the profile fetch; just flag presence + filename
      one.hasResume = !!(one.resume && one.resume.data);
      if (one.resume) { one.resumeFileName = one.resume.fileName; delete one.resume; }
      one._id = one._id.toString();
      return { statusCode: 200, headers: hdrs, body: JSON.stringify({ consultant: one }) };
    }

    // ---- CREATE (manual add) ----
    if (action === 'createConsultant') {
      // Duplicate guard: email is the unique consultant identity. Case-insensitive.
      var dupEmail = (body.consultant && body.consultant.email) || body.email;
      if (dupEmail) {
        var dupRe = new RegExp('^' + String(dupEmail).trim().replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '$', 'i');
        var dup = await col.findOne({ email: dupRe }, { projection: { _id: 1, name: 1 } });
        if (dup) return { statusCode: 200, headers: hdrs, body: JSON.stringify({
          duplicate: true, existingId: String(dup._id), existingName: dup.name || '',
          error: 'A consultant with this email already exists: ' + (dup.name || dup._id)
        }) };
      }
      var c = body.consultant || {};
      if (!c.name) return { statusCode: 400, headers: hdrs, body: JSON.stringify({ error: 'Name required' }) };
      var doc = {
        managed: true, source: c.source || 'manual', sourceId: c.sourceId || ('manual-' + Date.now()),
        name: c.name, headline: c.headline || '', currentRole: c.currentRole || '', currentCompany: c.currentCompany || '',
        location: c.location || '', country: c.country || deriveCountryFromLocation(c.location || ''), linkedinUrl: c.linkedinUrl || '',
        email: c.email || '', phone: c.phone || '',
        skills: Array.isArray(c.skills) ? c.skills : (c.skills ? String(c.skills).split(',').map(function (s) { return s.trim(); }) : []),
        certifications: Array.isArray(c.certifications) ? c.certifications : (c.certifications ? String(c.certifications).split(',').map(function (s) { return s.trim(); }) : []),
        yearsExperience: c.yearsExperience || 0, summary: c.summary || '',
        engagementType: c.engagementType || 'Unknown',
        availability: c.availability || 'available', availableFrom: c.availableFrom || null,
        pipelineStatus: c.pipelineStatus || 'none', claimedBy: null, claimedAt: null,
        placementInfo: c.placementInfo || null,
        rateExpectation: c.rateExpectation || null,
        workAuthorization: c.workAuthorization || 'unknown', securityClearance: c.securityClearance || 'unknown',
        notes: c.notes || '',
        createdAt: new Date(), updatedAt: new Date(), createdBy: authUser.email
      };
      var res = await col.insertOne(doc);
      return { statusCode: 200, headers: hdrs, body: JSON.stringify({ id: res.insertedId.toString(), created: true }) };
    }

    // ---- ADOPT (promote a sourced/cached profile into a managed record) ----
    if (action === 'adoptConsultant') {
      var srcId = body.id;
      var src = await col.findOne({ _id: new ObjectId(srcId) });
      if (!src) return { statusCode: 404, headers: hdrs, body: JSON.stringify({ error: 'Not found' }) };
      await col.updateOne({ _id: src._id }, {
        $set: {
          managed: true,
          engagementType: src.engagementType || (src.contractorSignal && src.contractorSignal.likely ? 'Contractor' : 'Unknown'),
          availability: src.availability && src.availability !== 'unknown' ? src.availability : 'available',
          country: src.country || '',
          updatedAt: new Date(), adoptedBy: authUser.email, adoptedAt: new Date()
        }
      });
      return { statusCode: 200, headers: hdrs, body: JSON.stringify({ adopted: true, id: srcId }) };
    }

    // ---- UPDATE (edit fields) ----
    if (action === 'updateConsultant') {
      var upd = body.updates || {};
      // normalize array fields if sent as strings
      ['skills', 'certifications'].forEach(function (f) {
        if (typeof upd[f] === 'string') upd[f] = upd[f].split(',').map(function (s) { return s.trim(); }).filter(Boolean);
      });
      upd.updatedAt = new Date(); upd.updatedBy = authUser.email;
      await col.updateOne({ _id: new ObjectId(body.id) }, { $set: upd });
      return { statusCode: 200, headers: hdrs, body: JSON.stringify({ updated: true }) };
    }

    // ---- SET STATUS / AVAILABILITY (analyst+) ----
    if (action === 'setConsultantStatus') {
      // #379: 'placed' cannot be set directly — it is a consequence of the Mark-as-Placed action,
      // which requires client/role/start/rate. This keeps availability+pipeline+placementInfo consistent.
      if (body.availability === 'placed') {
        return { statusCode: 400, headers: hdrs, body: JSON.stringify({ error: 'use_place_action', message: 'To place a consultant, fill in Client, Role, Start Date and Rate, then use "Mark as Placed".' }) };
      }
      var set = { updatedAt: new Date(), updatedBy: authUser.email };
      if (body.availability) set.availability = body.availability;
      if (body.availableFrom !== undefined) set.availableFrom = body.availableFrom ? new Date(body.availableFrom) : null;
      if (body.engagementType) set.engagementType = body.engagementType;
      if (body.email !== undefined) set.email = body.email;
      if (body.phone !== undefined) set.phone = body.phone;
      if (body.linkedinUrl !== undefined) set.linkedinUrl = body.linkedinUrl;
      // #396: location is editable (Apify sometimes returns it localized, e.g. "Nowy Jork, Stany Zjednoczone")
      if (body.location !== undefined) {
        set.location = body.location;
        // if the caller didn't also send an explicit country, try to re-derive it from the new location
        if (body.country === undefined || body.country === '') {
          var derived = deriveCountryFromLocation(body.location || '');
          if (derived) set.country = derived;
        }
      }
      if (body.country !== undefined && body.country !== '') set.country = body.country;
      if (body.yearsExperience !== undefined) set.yearsExperience = parseInt(body.yearsExperience) || 0;
      if (body.workAuthorization !== undefined) set.workAuthorization = body.workAuthorization || 'unknown';
      if (body.securityClearance !== undefined) set.securityClearance = body.securityClearance || 'unknown';
      if (body.rateExpectation !== undefined) set.rateExpectation = body.rateExpectation;
      await col.updateOne({ _id: new ObjectId(body.id) }, { $set: set });
      return { statusCode: 200, headers: hdrs, body: JSON.stringify({ updated: true }) };
    }

    // ---- PLACE via SecVision ----
    if (action === 'placeConsultant') {
      var pi = body.placementInfo || {};
      // #379: all four are compulsory — placement is the only way to reach 'placed' state
      if (!pi.client || !pi.role || !pi.startDate || !pi.rateAgreed) {
        return { statusCode: 400, headers: hdrs, body: JSON.stringify({ error: 'missing_fields', message: 'Client, Role, Start Date and Rate are all required to mark a consultant as placed.' }) };
      }
      var pdoc = await col.findOne({ _id: new ObjectId(body.id) });
      if (!pdoc) return { statusCode: 404, headers: hdrs, body: JSON.stringify({ error: 'Not found' }) };

      var placement = { client: pi.client, role: pi.role, startDate: pi.startDate, endDate: pi.endDate || null, rateAgreed: pi.rateAgreed, placedBy: authUser.email, placedAt: new Date() };
      var hist = pdoc.placementHistory || [];
      var cur = pdoc.placementInfo || null;
      var isCurrentlyPlaced = (pdoc.availability === 'placed' || pdoc.pipelineStatus === 'placed');

      // #384: Decide UPDATE-in-place vs NEW placement.
      // Same client+role+start as the active placement => the user is editing it (e.g. adding an
      // end date), so update the last history row rather than appending a duplicate.
      function sameKey(a, b) {
        if (!a || !b) return false;
        var da = a.startDate ? new Date(a.startDate).toISOString().slice(0, 10) : '';
        var db_ = b.startDate ? new Date(b.startDate).toISOString().slice(0, 10) : '';
        return (a.client || '').trim().toLowerCase() === (b.client || '').trim().toLowerCase()
          && (a.role || '').trim().toLowerCase() === (b.role || '').trim().toLowerCase()
          && da === db_;
      }
      var isUpdateOfCurrent = isCurrentlyPlaced && sameKey(cur, placement);

      var setFields = {
        availability: 'placed',
        pipelineStatus: 'placed',
        placementInfo: placement,
        availableFrom: pi.endDate ? new Date(pi.endDate) : null,
        updatedAt: new Date()
      };

      if (isUpdateOfCurrent && hist.length) {
        // Update the matching (latest) history row in place — preserve original placedAt/placedBy
        var li = -1;
        for (var hI = hist.length - 1; hI >= 0; hI--) { if (sameKey(hist[hI], placement)) { li = hI; break; } }
        if (li === -1) li = hist.length - 1;
        hist[li] = Object.assign({}, hist[li], {
          client: placement.client, role: placement.role, startDate: placement.startDate,
          endDate: placement.endDate, rateAgreed: placement.rateAgreed
        });
        setFields.placementHistory = hist;
        // keep the original placedAt/placedBy on the live placementInfo too
        setFields.placementInfo = Object.assign({}, placement, { placedAt: hist[li].placedAt || placement.placedAt, placedBy: hist[li].placedBy || placement.placedBy });
        await col.updateOne({ _id: pdoc._id }, { $set: setFields });
        return { statusCode: 200, headers: hdrs, body: JSON.stringify({ placed: true, updated: true }) };
      }

      // Genuinely new placement → append a history row
      await col.updateOne({ _id: pdoc._id }, { $set: setFields, $push: { placementHistory: placement } });
      return { statusCode: 200, headers: hdrs, body: JSON.stringify({ placed: true, created: true }) };
    }

    // ---- UPDATE PLACEMENT END DATE (for history entries) ----
    if (action === 'updatePlacementEnd') {
      var idx = body.historyIndex;
      var endDate = body.endDate ? new Date(body.endDate) : null;
      var prof2 = await col.findOne({ _id: new ObjectId(body.id) });
      if (!prof2) return { statusCode: 404, headers: hdrs, body: JSON.stringify({ error: 'Not found' }) };
      var hist = prof2.placementHistory || [];
      if (typeof idx === 'number' && hist[idx]) {
        hist[idx].endDate = endDate;
        var set2 = { placementHistory: hist, updatedAt: new Date() };
        // if this is the current placement, update placementInfo + availableFrom too
        if (prof2.placementInfo && prof2.placementInfo.startDate === hist[idx].startDate && prof2.placementInfo.client === hist[idx].client) {
          set2.placementInfo = hist[idx];
          set2.availableFrom = endDate;
        }
        await col.updateOne({ _id: prof2._id }, { $set: set2 });
      }
      return { statusCode: 200, headers: hdrs, body: JSON.stringify({ updated: true }) };
    }

    // ---- DELETE ----
    if (action === 'deleteConsultant') {
      await col.deleteOne({ _id: new ObjectId(body.id) });
      return { statusCode: 200, headers: hdrs, body: JSON.stringify({ deleted: true }) };
    }

    // ---- SET PIPELINE STATUS (with claim + lock enforcement) ----
    if (action === 'setPipelineStatus') {
      var newStatus = body.pipelineStatus;
      if (PIPELINE_STATUSES.indexOf(newStatus) === -1) return { statusCode: 400, headers: hdrs, body: JSON.stringify({ error: 'Invalid pipeline status' }) };
      // #379: 'placed' cannot be selected directly — use the Mark-as-Placed action
      if (newStatus === 'placed') {
        return { statusCode: 400, headers: hdrs, body: JSON.stringify({ error: 'use_place_action', message: 'To place a consultant, fill in Client, Role, Start Date and Rate, then use "Mark as Placed".' }) };
      }
      var prof = await col.findOne({ _id: new ObjectId(body.id) });
      if (!prof) return { statusCode: 404, headers: hdrs, body: JSON.stringify({ error: 'Not found' }) };

      var isManager = MANAGER_UP.indexOf(authRole) > -1;
      var currentClaim = prof.claimedBy || null;
      var currentStage = prof.pipelineStatus || 'none';
      var currentlyHardLocked = HARD_LOCK_STAGES.indexOf(currentStage) > -1;

      // HARD LOCK: at/after client_agreement_signing, only the claiming analyst or a manager may change
      if (currentlyHardLocked && !isManager && currentClaim && currentClaim !== authUser.email) {
        return { statusCode: 423, headers: hdrs, body: JSON.stringify({ error: 'locked', message: 'This consultant is locked at a client-agreement stage by ' + currentClaim + '. Only they or a manager can change it.' }) };
      }
      // SOFT LOCK: someone else holds an active claim — warn unless caller confirms/override or is manager
      if (currentClaim && currentClaim !== authUser.email && !isManager && !body.overrideClaim && ACTIVE_CLAIM_STAGES.indexOf(currentStage) > -1) {
        return { statusCode: 409, headers: hdrs, body: JSON.stringify({ error: 'claimed', message: currentClaim + ' is already working this consultant (' + currentStage + '). Coordinate before proceeding.', claimedBy: currentClaim, claimedAt: prof.claimedAt }) };
      }

      var set = { pipelineStatus: newStatus, updatedAt: new Date(), updatedBy: authUser.email };
      if (newStatus === 'contacted') set.contactedAt = new Date();  // start the 3-day timeout clock
      // #370: auto-sync — pipeline=placed implies availability=placed
      if (newStatus === 'placed') set.availability = 'placed';
      set['pipelineHistory'] = undefined; // placeholder to avoid accidental overwrite
      delete set.pipelineHistory;

      // Manage the claim based on the new stage
      if (ACTIVE_CLAIM_STAGES.indexOf(newStatus) > -1) {
        // becomes/continues an active claim → assign to this analyst if unclaimed or override
        if (!currentClaim || body.overrideClaim || currentClaim === authUser.email || isManager) {
          set.claimedBy = body.claimForSelf === false ? currentClaim : authUser.email;
          if (!prof.claimedAt || set.claimedBy !== currentClaim) set.claimedAt = new Date();
        }
      } else {
        // terminal/negative stage → release the claim
        set.claimedBy = null; set.claimedAt = null;
      }

      await col.updateOne({ _id: prof._id }, {
        $set: set,
        $push: { pipelineHistory: { status: newStatus, by: authUser.email, at: new Date() } }
      });
      return { statusCode: 200, headers: hdrs, body: JSON.stringify({ updated: true, pipelineStatus: newStatus, claimedBy: set.claimedBy }) };
    }

    // ---- CLAIM / RELEASE ----
    if (action === 'claimConsultant') {
      var pc = await col.findOne({ _id: new ObjectId(body.id) });
      if (!pc) return { statusCode: 404, headers: hdrs, body: JSON.stringify({ error: 'Not found' }) };
      if (pc.claimedBy && pc.claimedBy !== authUser.email && MANAGER_UP.indexOf(authRole) === -1 && !body.overrideClaim) {
        return { statusCode: 409, headers: hdrs, body: JSON.stringify({ error: 'claimed', message: pc.claimedBy + ' already owns this consultant.', claimedBy: pc.claimedBy }) };
      }
      await col.updateOne({ _id: pc._id }, { $set: { claimedBy: authUser.email, claimedAt: new Date(), updatedAt: new Date() } });
      return { statusCode: 200, headers: hdrs, body: JSON.stringify({ claimed: true, claimedBy: authUser.email }) };
    }
    if (action === 'releaseConsultant') {
      var pr = await col.findOne({ _id: new ObjectId(body.id) });
      if (!pr) return { statusCode: 404, headers: hdrs, body: JSON.stringify({ error: 'Not found' }) };
      if (pr.claimedBy && pr.claimedBy !== authUser.email && MANAGER_UP.indexOf(authRole) === -1) {
        return { statusCode: 403, headers: hdrs, body: JSON.stringify({ error: 'Only the owner or a manager can release this claim.' }) };
      }
      await col.updateOne({ _id: pr._id }, { $set: { claimedBy: null, claimedAt: null, updatedAt: new Date() } });
      return { statusCode: 200, headers: hdrs, body: JSON.stringify({ released: true }) };
    }

    // ---- #435: AI resume parsing — extract structured fields from raw resume text ----
    // The old client-side regex only found email/phone/linkedin; name, location, country,
    // company, years and summary need real understanding. Haiku costs a fraction of a cent.
    if (action === 'parseResumeText') {
      var rtext = String(body.text || '').slice(0, 15000);
      if (!rtext.trim()) return { statusCode: 400, headers: hdrs, body: JSON.stringify({ error: 'No resume text provided' }) };
      var AKEY = process.env.ANTHROPIC_API_KEY;
      if (!AKEY) return { statusCode: 200, headers: hdrs, body: JSON.stringify({ error: 'ANTHROPIC_API_KEY not configured' }) };
      var rPrompt = 'Extract structured data from this resume text. Respond with ONLY a JSON object '
        + '(no prose, no code fences) with these keys:\n'
        + '  name: full name of the person (string)\n'
        + '  email: email address or ""\n'
        + '  phone: phone number or ""\n'
        + '  linkedinUrl: full LinkedIn profile URL or ""\n'
        + '  location: city/state where they are based, e.g. "Pune, Maharashtra" (string)\n'
        + '  country: country they are based in, in English, e.g. "India" (string)\n'
        + '  currentRole: their current/most recent job title (string)\n'
        + '  currentCompany: their current/most recent employer (string)\n'
        + '  yearsExperience: total years of professional experience as an integer (infer from '
        + 'stated totals like "over 15 years" or from career date ranges; 0 if unknown)\n'
        + '  skills: array of technical skills/tools mentioned (max 25)\n'
        + '  certifications: array of certification names mentioned (max 15)\n'
        + '  summary: their professional summary in 2-3 sentences, based on the resume\'s own '
        + 'summary section if present\n\nRESUME TEXT:\n' + rtext;
      try {
        var rctrl = new AbortController();
        var rtmo = setTimeout(function () { rctrl.abort(); }, 20000);
        var rresp = await fetch('https://api.anthropic.com/v1/messages', {
          method: 'POST', signal: rctrl.signal,
          headers: { 'Content-Type': 'application/json', 'x-api-key': AKEY, 'anthropic-version': '2023-06-01' },
          body: JSON.stringify({ model: 'claude-haiku-4-5-20251001', max_tokens: 1200, messages: [{ role: 'user', content: rPrompt }] })
        });
        clearTimeout(rtmo);
        if (!rresp.ok) throw new Error('Anthropic ' + rresp.status);
        var rdata = await rresp.json();
        var rtxt = (rdata.content || []).filter(function (b) { return b.type === 'text'; }).map(function (b) { return b.text; }).join('').trim();
        rtxt = rtxt.replace(/^```(?:json)?\s*/i, '').replace(/```\s*$/, '').trim();
        var parsed = JSON.parse(rtxt);
        return { statusCode: 200, headers: hdrs, body: JSON.stringify({ parsed: parsed }) };
      } catch (e) {
        return { statusCode: 200, headers: hdrs, body: JSON.stringify({ error: 'Parse failed: ' + e.message }) };
      }
    }

    // ---- RESUME upload / get / remove (base64 in Mongo) ----
    if (action === 'uploadResume') {
      if (!body.fileData || !body.fileName) return { statusCode: 400, headers: hdrs, body: JSON.stringify({ error: 'File data and name required' }) };
      // size guard: base64 ~1.37x binary; cap ~8MB base64 (~6MB file) to stay well under 16MB doc limit
      if (body.fileData.length > 8 * 1024 * 1024) return { statusCode: 400, headers: hdrs, body: JSON.stringify({ error: 'File too large (max ~6MB)' }) };
      await col.updateOne({ _id: new ObjectId(body.id) }, {
        $set: {
          resume: { fileName: body.fileName, mimeType: body.mimeType || 'application/octet-stream', data: body.fileData, uploadedAt: new Date(), uploadedBy: authUser.email },
          updatedAt: new Date()
        }
      });
      return { statusCode: 200, headers: hdrs, body: JSON.stringify({ uploaded: true, fileName: body.fileName }) };
    }
    if (action === 'getResume') {
      var rp = await col.findOne({ _id: new ObjectId(body.id) }, { projection: { resume: 1 } });
      if (!rp || !rp.resume) return { statusCode: 404, headers: hdrs, body: JSON.stringify({ error: 'No resume on file' }) };
      return { statusCode: 200, headers: hdrs, body: JSON.stringify({ fileName: rp.resume.fileName, mimeType: rp.resume.mimeType, data: rp.resume.data }) };
    }
    if (action === 'removeResume') {
      await col.updateOne({ _id: new ObjectId(body.id) }, { $unset: { resume: '' }, $set: { updatedAt: new Date() } });
      return { statusCode: 200, headers: hdrs, body: JSON.stringify({ removed: true }) };
    }

    // ---- #378: DELETE a placement history entry (admin/super only) ----
    if (action === 'deletePlacementHistory') {
      var dp = await col.findOne({ _id: new ObjectId(body.id) });
      if (!dp) return { statusCode: 404, headers: hdrs, body: JSON.stringify({ error: 'Not found' }) };
      var dhist = dp.placementHistory || [];
      var didx = body.historyIndex;
      if (typeof didx !== 'number' || !dhist[didx]) return { statusCode: 400, headers: hdrs, body: JSON.stringify({ error: 'Invalid history index' }) };
      dhist.splice(didx, 1);
      await col.updateOne({ _id: dp._id }, { $set: { placementHistory: dhist, updatedAt: new Date() } });
      return { statusCode: 200, headers: hdrs, body: JSON.stringify({ deleted: true, remaining: dhist.length }) };
    }

    // ---- #380: how many unmanaged (cached) profiles are available to import ----
    if (action === 'countCached') {
      var cnt = await col.countDocuments({ $or: [{ managed: { $exists: false } }, { managed: false }] });
      return { statusCode: 200, headers: hdrs, body: JSON.stringify({ pending: cnt }) };
    }

    // ---- PROMOTE ALL CACHED -> MANAGED (one-time, super/admin) ----
    if (action === 'promoteAllCached') {
      var res = await col.updateMany(
        { $or: [{ managed: { $exists: false } }, { managed: false }] },
        {
          $set: {
            managed: true, availability: 'available', pipelineStatus: 'none',
            promotedAt: new Date(), promotedBy: authUser.email
          }
        }
      );
      // set engagementType from contractorSignal where missing
      await col.updateMany(
        { managed: true, engagementType: { $exists: false }, 'contractorSignal.likely': true },
        { $set: { engagementType: 'Contractor' } }
      );
      await col.updateMany(
        { managed: true, engagementType: { $exists: false } },
        { $set: { engagementType: 'Unknown' } }
      );
      // Derive country from location for promoted profiles missing it
      var needCountry = await col.find({ managed: true, $or: [{ country: { $exists: false } }, { country: '' }, { country: null }], location: { $nin: [null, ''] } }).limit(2000).toArray();
      var cOps = [];
      needCountry.forEach(function (p) {
        var ctry = deriveCountryFromLocation(p.location || '');
        if (ctry) cOps.push({ updateOne: { filter: { _id: p._id }, update: { $set: { country: ctry } } } });
      });
      if (cOps.length) { try { await col.bulkWrite(cOps); } catch (e) {} }
      return { statusCode: 200, headers: hdrs, body: JSON.stringify({ promoted: res.modifiedCount || 0 }) };
    }

    return { statusCode: 400, headers: hdrs, body: JSON.stringify({ error: 'Unknown action: ' + action }) };
  } catch (e) {
    return { statusCode: 500, headers: hdrs, body: JSON.stringify({ error: e.message }) };
  }
};
