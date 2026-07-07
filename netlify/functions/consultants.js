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

const hdrs = {
  'Content-Type': 'application/json',
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'POST,OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization'
};

// RBAC
var VIEW_ROLES = ['super_admin', 'admin', 'manager', 'analyst', 'viewer'];
var STATUS_ROLES = ['super_admin', 'admin', 'manager', 'analyst']; // set status/availability
var MANAGER_UP = ['super_admin', 'admin', 'manager'];              // edit/enrich/delete/place
var ACTION_ROLES = {
  'listConsultants': VIEW_ROLES,
  'getConsultant': VIEW_ROLES,
  'setConsultantStatus': STATUS_ROLES,
  'createConsultant': MANAGER_UP,
  'updateConsultant': MANAGER_UP,
  'deleteConsultant': MANAGER_UP,
  'enrichConsultant': MANAGER_UP,
  'adoptConsultant': MANAGER_UP,
  'importResume': MANAGER_UP,
  'placeConsultant': MANAGER_UP
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

    return { statusCode: 400, headers: hdrs, body: JSON.stringify({ error: 'Unknown action: ' + action }) };
  } catch (e) {
    return { statusCode: 500, headers: hdrs, body: JSON.stringify({ error: e.message }) };
  }
};
