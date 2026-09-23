// #603: English rendering of non-Latin profile fields (role / headline / location).
// LinkedIn returns city names and headlines in the scraping session's locale (e.g. Russian
// "Хайдарабад, Телингана" for Hyderabad, Telangana). One Haiku call per batch translates them;
// results are cached on the profile as currentRoleEn / headlineEn / locationEn, and the
// location field itself is replaced by the English form (original kept in locationOrig) so
// country gating, filters and exports all work on English text.
var NONLATIN = /[^\u0000-ɏḀ-ỿ -⁯₠-⃏℀-⅏←-⇿☀-➿]/;
function hasNonLatin(v) { return !!v && NONLATIN.test(String(v)); }

// col: consultants collection; ids: array of ObjectId (max ~40 per call). Returns { id: {fieldEn:..} }.
async function translateProfilesNonLatin(col, ids) {
  var out = {};
  if (!ids || !ids.length) return out;
  var docs = await col.find({ _id: { $in: ids } }).project({ currentRole: 1, headline: 1, location: 1, currentRoleEn: 1, headlineEn: 1, locationEn: 1 }).toArray();
  var need = [];
  docs.forEach(function (d) {
    var id = String(d._id), item = { id: id };
    ['currentRole', 'headline', 'location'].forEach(function (f) {
      if (d[f + 'En']) { out[id] = out[id] || {}; out[id][f + 'En'] = d[f + 'En']; }
      else if (hasNonLatin(d[f])) item[f] = String(d[f]).slice(0, 300);
    });
    if (Object.keys(item).length > 1) need.push(item);
  });
  if (!need.length) return out;
  var KEY = process.env.ANTHROPIC_API_KEY;
  if (!KEY) throw new Error('ANTHROPIC_API_KEY not configured');
  var prompt = 'Translate the following LinkedIn profile fields into concise professional English. Keep proper nouns, product names and certifications as-is; '
    + 'for locations give the standard English place name (e.g. "Hyderabad, Telangana, India"). Respond with ONLY a JSON array of objects with the same "id" and the same field names, values in English. No prose, no code fences.\n\n' + JSON.stringify(need);
  var ctrl = new AbortController(); var tmo = setTimeout(function () { ctrl.abort(); }, 18000);
  var resp = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST', signal: ctrl.signal,
    headers: { 'Content-Type': 'application/json', 'x-api-key': KEY, 'anthropic-version': '2023-06-01' },
    body: JSON.stringify({ model: 'claude-haiku-4-5-20251001', max_tokens: 2500, messages: [{ role: 'user', content: prompt }] })
  });
  clearTimeout(tmo);
  if (!resp.ok) throw new Error('Anthropic ' + resp.status);
  var data = await resp.json();
  var txt = (data.content || []).filter(function (b) { return b.type === 'text'; }).map(function (b) { return b.text; }).join('').trim().replace(/^```(?:json)?\s*/i, '').replace(/```\s*$/, '').trim();
  var m = txt.match(/\[[\s\S]*\]/); var arr = JSON.parse(m ? m[0] : txt);
  var ObjectId = require('mongodb').ObjectId, ops = [];
  (arr || []).forEach(function (r) {
    if (!r || !r.id) return;
    var setv = {};
    ['currentRole', 'headline', 'location'].forEach(function (f) { if (r[f] && typeof r[f] === 'string') setv[f + 'En'] = r[f].slice(0, 300); });
    if (!Object.keys(setv).length) return;
    setv.translatedAt = new Date();
    var src = need.filter(function (n) { return n.id === r.id; })[0] || {};
    if (setv.locationEn && src.location) { setv.locationOrig = src.location; setv.location = setv.locationEn; }   // location becomes English
    out[r.id] = Object.assign(out[r.id] || {}, setv);
    try { ops.push({ updateOne: { filter: { _id: new ObjectId(r.id) }, update: { $set: setv } } }); } catch (e) {}
  });
  if (ops.length) await col.bulkWrite(ops, { ordered: false });
  return out;
}

// Convenience for harvest paths: translate every profile in `ids` that has non-Latin text; never throws.
async function translateAfterHarvest(col, ids) {
  try {
    var ObjectId = require('mongodb').ObjectId;
    var oids = (ids || []).map(function (x) { try { return x instanceof ObjectId ? x : new ObjectId(String(x)); } catch (e) { return null; } }).filter(Boolean);
    var n = 0;
    for (var i = 0; i < oids.length; i += 40) { var r = await translateProfilesNonLatin(col, oids.slice(i, i + 40)); n += Object.keys(r).length; }
    return n;
  } catch (e) { return 0; }
}
module.exports = { translateProfilesNonLatin: translateProfilesNonLatin, translateAfterHarvest: translateAfterHarvest, hasNonLatin: hasNonLatin };
