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
  'none', 'contacted', 'interested', 'not_interested', 'contacted_no_response',
  'screening_pending', 'screening_in_progress', 'screening_failed', 'screening_successful',
  'negotiations_in_progress', 'secvision_agreement_signing', 'secvision_agreement_signed',
  'proposed_to_client', 'interview_in_progress', 'client_interview_successful', 'client_interview_failed',
  'client_agreement_signing', 'client_agreement_signed', 'placed'
];
// Stages at/after which a HARD lock applies (only claiming analyst / managers may change)
var HARD_LOCK_STAGES = ['client_agreement_signing', 'client_agreement_signed', 'placed'];
// Stages representing an ACTIVE working claim
var ACTIVE_CLAIM_STAGES = PIPELINE_STATUSES.filter(function (s) {
  return s !== 'none' && s !== 'not_interested' && s !== 'contacted_no_response' && s !== 'screening_failed' && s !== 'client_interview_failed';
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
  'enrichConsultant': MANAGER_UP,
  'adoptConsultant': MANAGER_UP,
  'importResume': MANAGER_UP,
  'placeConsultant': MANAGER_UP,
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
      p._autoFreed = true; // marker so caller can persist
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

    // ---- LIST / SEARCH ----
    if (action === 'listConsultants') {
      var filter = { managed: true }; // only owned CRM records in the Consultants tab
      var q = (body.query || '').trim();
      if (q) {
        var re = q.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        filter.$or = [
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
      if (body.country && body.country !== 'all') filter.country = body.country;
      if (body.location) filter.location = { $regex: body.location.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), $options: 'i' };
      // region → countries
      if (body.region && body.region !== 'all') {
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
        if (p._autoFreed) { freedOps.push({ updateOne: { filter: { _id: p._id }, update: { $set: { availability: 'available', availableFrom: null } } } }); delete p._autoFreed; }
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
      if (one._autoFreed) { await col.updateOne({ _id: one._id }, { $set: { availability: 'available', availableFrom: null } }); delete one._autoFreed; }
      one._id = one._id.toString();
      return { statusCode: 200, headers: hdrs, body: JSON.stringify({ consultant: one }) };
    }

    // ---- CREATE (manual add) ----
    if (action === 'createConsultant') {
      var c = body.consultant || {};
      if (!c.name) return { statusCode: 400, headers: hdrs, body: JSON.stringify({ error: 'Name required' }) };
      var doc = {
        managed: true, source: c.source || 'manual', sourceId: c.sourceId || ('manual-' + Date.now()),
        name: c.name, headline: c.headline || '', currentRole: c.currentRole || '', currentCompany: c.currentCompany || '',
        location: c.location || '', country: c.country || '', linkedinUrl: c.linkedinUrl || '',
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
      var set = { updatedAt: new Date(), updatedBy: authUser.email };
      if (body.availability) set.availability = body.availability;         // available | busy | placed | do_not_contact
      if (body.availableFrom !== undefined) set.availableFrom = body.availableFrom ? new Date(body.availableFrom) : null;
      if (body.engagementType) set.engagementType = body.engagementType;    // Contractor | Permanent | Unknown
      await col.updateOne({ _id: new ObjectId(body.id) }, { $set: set });
      return { statusCode: 200, headers: hdrs, body: JSON.stringify({ updated: true }) };
    }

    // ---- PLACE via SecVision ----
    if (action === 'placeConsultant') {
      var pi = body.placementInfo || {};
      await col.updateOne({ _id: new ObjectId(body.id) }, {
        $set: {
          availability: 'placed',
          placementInfo: { client: pi.client || '', role: pi.role || '', startDate: pi.startDate || null, endDate: pi.endDate || null, placedBy: authUser.email, placedAt: new Date() },
          availableFrom: pi.endDate ? new Date(pi.endDate) : null,
          updatedAt: new Date()
        }
      });
      return { statusCode: 200, headers: hdrs, body: JSON.stringify({ placed: true }) };
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
      return { statusCode: 200, headers: hdrs, body: JSON.stringify({ promoted: res.modifiedCount || 0 }) };
    }

    return { statusCode: 400, headers: hdrs, body: JSON.stringify({ error: 'Unknown action: ' + action }) };
  } catch (e) {
    return { statusCode: 500, headers: hdrs, body: JSON.stringify({ error: e.message }) };
  }
};
