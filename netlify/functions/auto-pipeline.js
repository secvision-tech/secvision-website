// #678 — Phase 1 of pipeline automation: scheduled demand run.
//
// Deterministic, state-mediated orchestration (patent FIG. 3): a run is a record in `automation_runs`
// with a step pointer; every invocation executes ONE bounded slice of the current step (<= 20 s),
// persists progress and returns. Invocations come from (a) the Netlify schedule (netlify.toml:
// every 10 minutes between 06:00 and 09:50 IST) and (b) the UI "Run now" loop. No LLM decides what
// runs next — the step table below does.
//
//   steps: harvest (job-search in-process, saved roles x countries, contract only)
//       -> classify (engagement AI on the jobs harvested in this run)
//       -> select  (auto-queue: contract + remote + offshoreOk != no; everything else tagged with the reason)
//       -> done    (summary persisted; shown in Settings -> Automation)
//
// Caps and the kill switch live in settings {_id:'automation'} and are editable by super admin.

const { getDb } = require('./db');

var TENANT_ID = process.env.ENTRA_TENANT_ID || '';
var CLIENT_ID = process.env.ENTRA_CLIENT_ID || '';
var STEP_BUDGET_MS = 21000;   // one slice; the Netlify gateway allows ~26 s
var IST_OFFSET_MIN = 330;

var DEFAULT_CONFIG = {
  enabled: true,
  runHourIST: 6,
  roles: ['SOC Analyst', 'Security Engineer', 'Security Architect', 'Threat Hunter', 'Incident Responder', 'SIEM Engineer', 'Cloud Security Engineer',
          'Cybersecurity Analyst', 'SOC Consultant', 'Security Consultant', 'SIEM Consultant', 'Cybersecurity Contractor', 'Security Operations Consultant',
          'InfoSec Consultant', 'Cloud Security Consultant', 'Cyber Contractor'],
  countries: ['us', 'ca', 'uk'],
  datePosted: '3days',            // JSearch window; the run itself only counts jobs first seen today
  workModes: ['remote'],          // automation scope today; hybrid / onsite can be ticked when a regional partner is live
  caps: { harvest: 100, eligible: 50, matches: 10, contacts: 10, reveals: 30, dailyBudgetInr: 800 },
  costInr: { aiClassify: 0.10, jsearchCall: 0.00 }   // estimates used by the cost meter; adjust from Settings
};
var COUNTRY_NAMES = { us: 'United States', ca: 'Canada', mx: 'Mexico', uk: 'United Kingdom', gb: 'United Kingdom', de: 'Germany', fr: 'France', nl: 'Netherlands', ie: 'Ireland',
  ch: 'Switzerland', se: 'Sweden', no: 'Norway', dk: 'Denmark', fi: 'Finland', be: 'Belgium', at: 'Austria', es: 'Spain', it: 'Italy', pl: 'Poland', au: 'Australia', nz: 'New Zealand',
  sg: 'Singapore', in: 'India', ae: 'United Arab Emirates', sa: 'Saudi Arabia', za: 'South Africa', jp: 'Japan' };

function decodeJwt(token) {
  try { var p = token.split('.'); if (p.length !== 3) return null; return JSON.parse(Buffer.from(p[1].replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf-8')); } catch (e) { return null; }
}
async function authUserFromEvent(event, db) {
  var h = (event.headers || {}).authorization || (event.headers || {}).Authorization || '';
  if (!h.startsWith('Bearer ')) return null;
  var c = decodeJwt(h.slice(7)); if (!c) return null;
  if (c.iss && TENANT_ID && !c.iss.includes(TENANT_ID)) return null;
  if (c.aud && CLIENT_ID && c.aud !== CLIENT_ID) return null;
  if (c.exp && c.exp < Math.floor(Date.now() / 1000)) return null;
  var email = (c.preferred_username || c.email || c.upn || '').toLowerCase();
  if (!email) return null;
  var u = await db.collection('users').findOne({ email: new RegExp('^' + email.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '$', 'i') });
  if (!u || u.status !== 'active') return null;
  return { email: email, role: u.role || 'viewer' };
}
function istDate(d) { return new Date((d || new Date()).getTime() + IST_OFFSET_MIN * 60000).toISOString().slice(0, 10); }
function istHour(d) { return new Date((d || new Date()).getTime() + IST_OFFSET_MIN * 60000).getUTCHours(); }

async function loadConfig(db) {
  var doc = await db.collection('settings').findOne({ _id: 'automation' });
  var c = Object.assign({}, DEFAULT_CONFIG, doc || {});
  c.caps = Object.assign({}, DEFAULT_CONFIG.caps, (doc && doc.caps) || {});
  c.costInr = Object.assign({}, DEFAULT_CONFIG.costInr, (doc && doc.costInr) || {});
  delete c._id; return c;
}

// ---------- step: harvest ----------
// Sub-steps are (country, role-chunk) pairs; the cursor is persisted after every call so a run resumes exactly where it stopped.
async function stepHarvest(db, run, cfg, deadline) {
  var jobSearch = require('./job-search');
  var CH = 4, roles = cfg.roles.length ? cfg.roles : DEFAULT_CONFIG.roles, countries = cfg.countries.length ? cfg.countries : DEFAULT_CONFIG.countries;
  var units = [];
  countries.forEach(function (c) { for (var i = 0; i < roles.length; i += CH) units.push({ country: c, roles: roles.slice(i, i + CH) }); });
  var h = run.harvest;
  while (h.cursor < units.length && Date.now() < deadline - 11000) {   // a unit (4 roles x 1 page) takes up to ~11 s
    if (h.newJobs >= cfg.caps.harvest) { h.cappedAt = h.cursor; break; }
    var u = units[h.cursor];
    var ev = { httpMethod: 'POST', headers: {}, body: JSON.stringify({ roles: u.roles, pages: 1, datePosted: cfg.datePosted || '3days', employmentTypes: 'CONTRACTOR',
      country: u.country, countryName: u.country === 'us' ? '' : (COUNTRY_NAMES[u.country] || ''), userEmail: 'automation@secvisiontech.com', automation: true }) };
    try {
      var before = await db.collection('jobs').countDocuments({ createdAt: { $gte: run.startedAt } });
      var r = await jobSearch.handler(ev);
      var d = {}; try { d = JSON.parse(r.body || '{}'); } catch (e) {}
      var after = await db.collection('jobs').countDocuments({ createdAt: { $gte: run.startedAt } });
      h.calls += (d.apiCalls || 0); h.seen += (d.totalResults || 0); h.newJobs = after;
      if (d.error) h.errors.push(u.country + '/' + u.roles[0] + ': ' + d.error);
    } catch (e) { h.errors.push(u.country + '/' + u.roles[0] + ': ' + String(e && e.message || e)); }
    h.cursor++;
    await persist(db, run);
  }
  if (h.cursor >= units.length || h.cappedAt != null) { h.units = units.length; run.step = 'classify'; }
}

// ---------- step: classify ----------
async function stepClassify(db, run, cfg, deadline) {
  var eng = require('./engagement');
  var col = db.collection('jobs');
  var c = run.classify;
  if (!process.env.ANTHROPIC_API_KEY) { c.errors.push('AI key not configured'); run.step = 'select'; return; }
  while (Date.now() < deadline - 13000) {   // a batch of 8 classifications takes up to ~12 s
    if (run.costInr >= cfg.caps.dailyBudgetInr) { c.budgetStop = true; break; }
    var batch = await col.find({ createdAt: { $gte: run.startedAt }, engagementAI: { $ne: true }, autoClassifyFailed: { $ne: run._id } })
      .project({ title: 1, company: 1, companyType: 1, description: 1, jobType: 1, salary: 1, contractDuration: 1, source: 1, detectedCountry: 1, location: 1, remote: 1, workType: 1, tools: 1 })
      .limit(8).toArray();
    if (!batch.length) { run.step = 'select'; return; }
    var errs = [], results = await Promise.all(batch.map(function (j) { return eng.classifyEngagementAI(j, { errors: errs, timeoutMs: 12000, attempts: 2 }).catch(function () { return null; }); }));
    var ops = [];
    batch.forEach(function (j, i) {
      var r = results[i];
      if (!r) { c.failed++; ops.push({ updateOne: { filter: { _id: j._id }, update: { $set: { engagementAIFailedAt: new Date(), autoClassifyFailed: run._id } } } }); return; }
      var set = eng.aiSetFields(r, j);
      try { if (eng.isBareLocation(j.location) && r.ai.jdCity && !eng.isBareLocation(r.ai.jdCity)) { set.location = r.ai.jdCity; set.locationOrig = j.location || ''; } } catch (e) {}
      ops.push({ updateOne: { filter: { _id: j._id }, update: { $set: set } } });
      c.done++;
    });
    if (ops.length) await col.bulkWrite(ops, { ordered: false });
    run.costInr += batch.length * (cfg.costInr.aiClassify || 0);
    if (errs.length) c.errors = c.errors.concat(errs.slice(0, 3)).slice(-10);
    await persist(db, run);
  }
}

// ---------- step: select (auto-queue) ----------
// Same rules the user applies by hand today: contract + remote + not offshore-barred. Nothing else is changed on the job.
async function stepSelect(db, run, cfg) {
  var col = db.collection('jobs');
  var jobs = await col.find({ createdAt: { $gte: run.startedAt } }).project({ jobType: 1, contractDuration: 1, workMode: 1, remote: 1, offshoreOk: 1, engagementAI: 1, engagementModel: 1, detectedCountry: 1, title: 1, company: 1 }).toArray();
  var modes = (cfg.workModes && cfg.workModes.length) ? cfg.workModes : ['remote'];
  var s = run.select, ops = [];
  jobs.forEach(function (j) {
    var isContract = /contract/i.test(j.jobType || '') || !!(j.contractDuration) || /C2C/i.test(j.engagementModel || '');
    var wm = String(j.workMode || '').toLowerCase();
    if (!wm) { var rf = String(j.remote || '').toLowerCase(); wm = /^(yes|true|remote)/.test(rf) ? 'remote' : (/hybrid/.test(rf) ? 'hybrid' : (/^(no|false)/.test(rf) ? 'onsite' : 'unknown')); }
    var reason = '';
    if (!isContract) reason = 'not a contract role';
    else if (!j.engagementAI) reason = 'not classified (AI failed)';
    else if (modes.indexOf(wm) < 0) reason = 'work mode ' + (wm || 'unknown') + ' — outside automation scope';
    else if (String(j.offshoreOk || '').toLowerCase() === 'no') reason = 'offshore not possible (residency / clearance / US-only)';
    else if (s.queued >= cfg.caps.eligible) reason = 'eligible cap reached for today';
    if (!reason) { s.queued++; ops.push({ updateOne: { filter: { _id: j._id }, update: { $set: { autoQueue: { runId: run._id, date: run.date, at: new Date(), status: 'queued' } }, $unset: { autoSkipReason: '' } } } }); }
    else { s.skipped++; s.reasons[reason] = (s.reasons[reason] || 0) + 1; ops.push({ updateOne: { filter: { _id: j._id }, update: { $set: { autoSkipReason: reason, autoSkipRunId: run._id }, $unset: { autoQueue: '' } } } }); }
  });
  if (ops.length) await col.bulkWrite(ops, { ordered: false });
  s.total = jobs.length;
  run.step = 'done'; run.finishedAt = new Date(); run.status = 'done';
}

function newRun(date, by) {
  return { _id: 'run_' + date + '_' + Date.now().toString(36), date: date, startedAt: new Date(), finishedAt: null, status: 'running', step: 'harvest', by: by || 'schedule', costInr: 0, ticks: 0,
    harvest: { cursor: 0, units: 0, calls: 0, seen: 0, newJobs: 0, errors: [], cappedAt: null },
    classify: { done: 0, failed: 0, errors: [], budgetStop: false },
    select: { total: 0, queued: 0, skipped: 0, reasons: {} } };
}
async function persist(db, run) { run.updatedAt = new Date(); await db.collection('automation_runs').replaceOne({ _id: run._id }, run, { upsert: true }); }

// Execute one bounded slice of the given run.
async function tick(db, run, cfg) {
  var deadline = Date.now() + STEP_BUDGET_MS;
  run.ticks++;
  try {
    if (run.step === 'harvest') await stepHarvest(db, run, cfg, deadline);
    if (run.step === 'classify' && Date.now() < deadline) await stepClassify(db, run, cfg, deadline);
    if (run.step === 'select') await stepSelect(db, run, cfg);
  } catch (e) { run.lastError = String(e && e.message || e); }
  await persist(db, run);
  return run;
}

exports.handler = async function (event) {
  var hdrs = { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': 'Content-Type, Authorization', 'Content-Type': 'application/json' };
  if (event.httpMethod === 'OPTIONS') return { statusCode: 200, headers: hdrs, body: '' };
  var db = await getDb();
  var runs = db.collection('automation_runs');
  var body = {}; try { body = JSON.parse(event.body || '{}'); } catch (e) {}
  // Netlify's scheduler invokes the function without an Authorization header (body carries next_run). In production a
  // scheduled function is not reachable over HTTP, so an unauthenticated call can only be the scheduler; it can at most
  // advance today's capped run, never change settings.
  var authHdr = (event.headers || {}).authorization || (event.headers || {}).Authorization || '';
  var scheduled = !authHdr.startsWith('Bearer ');
  var cfg = await loadConfig(db);

  // ---- scheduled tick: start today's run at/after the configured IST hour, then advance it one slice per tick ----
  if (scheduled) {
    if (!cfg.enabled) return { statusCode: 200, headers: hdrs, body: JSON.stringify({ skipped: 'automation disabled' }) };
    var today = istDate();
    if (istHour() < (cfg.runHourIST || 6)) return { statusCode: 200, headers: hdrs, body: JSON.stringify({ skipped: 'before run hour' }) };
    var run = await runs.findOne({ date: today, by: 'schedule' });
    if (run && run.status === 'done') return { statusCode: 200, headers: hdrs, body: JSON.stringify({ skipped: 'today done' }) };
    if (!run) { run = newRun(today, 'schedule'); await persist(db, run); }
    run = await tick(db, run, cfg);
    return { statusCode: 200, headers: hdrs, body: JSON.stringify({ ok: true, step: run.step, status: run.status }) };
  }

  // ---- UI actions (JWT) ----
  var user = await authUserFromEvent(event, db);
  if (!user) return { statusCode: 401, headers: hdrs, body: JSON.stringify({ error: 'Authentication required' }) };
  var isSuper = user.role === 'super_admin', isAdmin = isSuper || user.role === 'admin';
  var action = body.action;

  if (action === 'getConfig') {
    var last = await runs.find({}).sort({ startedAt: -1 }).limit(10).toArray();
    return { statusCode: 200, headers: hdrs, body: JSON.stringify({ config: cfg, defaults: DEFAULT_CONFIG, runs: last, canEdit: isSuper, canRun: isAdmin }) };
  }
  if (action === 'saveConfig') {
    if (!isSuper) return { statusCode: 403, headers: hdrs, body: JSON.stringify({ error: 'Only Super Admin can change automation settings' }) };
    var inc = body.config || {}, set = {};
    if (typeof inc.enabled === 'boolean') set.enabled = inc.enabled;
    if (Array.isArray(inc.roles)) set.roles = inc.roles.map(String).map(function (s) { return s.trim(); }).filter(Boolean).slice(0, 40);
    if (Array.isArray(inc.countries)) set.countries = inc.countries.map(function (s) { return String(s).toLowerCase().trim(); }).filter(function (s) { return COUNTRY_NAMES[s]; }).slice(0, 12);
    if (Array.isArray(inc.workModes)) set.workModes = inc.workModes.filter(function (m) { return ['remote', 'hybrid', 'onsite'].indexOf(m) >= 0; });
    if (inc.datePosted && ['today', '3days', 'week'].indexOf(inc.datePosted) >= 0) set.datePosted = inc.datePosted;
    if (inc.runHourIST != null) set.runHourIST = Math.min(23, Math.max(0, parseInt(inc.runHourIST) || 6));
    if (inc.caps) { set.caps = {}; Object.keys(DEFAULT_CONFIG.caps).forEach(function (k) { var v = parseFloat(inc.caps[k]); set.caps[k] = isNaN(v) ? DEFAULT_CONFIG.caps[k] : Math.max(0, v); }); }
    if (inc.costInr) { set.costInr = {}; Object.keys(DEFAULT_CONFIG.costInr).forEach(function (k) { var v = parseFloat(inc.costInr[k]); set.costInr[k] = isNaN(v) ? DEFAULT_CONFIG.costInr[k] : Math.max(0, v); }); }
    set.updatedAt = new Date(); set.updatedBy = user.email;
    await db.collection('settings').updateOne({ _id: 'automation' }, { $set: set }, { upsert: true });
    return { statusCode: 200, headers: hdrs, body: JSON.stringify({ ok: true, config: await loadConfig(db) }) };
  }
  if (action === 'runNow') {
    if (!isAdmin) return { statusCode: 403, headers: hdrs, body: JSON.stringify({ error: 'Admin or Super Admin required' }) };
    var active = await runs.findOne({ status: 'running' });
    if (active && body.resume !== false) { active = await tick(db, active, cfg); return { statusCode: 200, headers: hdrs, body: JSON.stringify({ run: active }) }; }
    var r2 = newRun(istDate(), user.email); await persist(db, r2); r2 = await tick(db, r2, cfg);
    return { statusCode: 200, headers: hdrs, body: JSON.stringify({ run: r2 }) };
  }
  if (action === 'step') {   // UI loop: advance a running run by one slice
    if (!isAdmin) return { statusCode: 403, headers: hdrs, body: JSON.stringify({ error: 'Admin or Super Admin required' }) };
    var cur = await runs.findOne({ _id: String(body.runId || '') });
    if (!cur) return { statusCode: 404, headers: hdrs, body: JSON.stringify({ error: 'Run not found' }) };
    if (cur.status !== 'running') return { statusCode: 200, headers: hdrs, body: JSON.stringify({ run: cur }) };
    cur = await tick(db, cur, cfg);
    return { statusCode: 200, headers: hdrs, body: JSON.stringify({ run: cur }) };
  }
  if (action === 'stopRun') {
    if (!isAdmin) return { statusCode: 403, headers: hdrs, body: JSON.stringify({ error: 'Admin or Super Admin required' }) };
    await runs.updateOne({ _id: String(body.runId || ''), status: 'running' }, { $set: { status: 'stopped', finishedAt: new Date(), stoppedBy: user.email } });
    return { statusCode: 200, headers: hdrs, body: JSON.stringify({ ok: true }) };
  }
  return { statusCode: 400, headers: hdrs, body: JSON.stringify({ error: 'Unknown action: ' + action }) };
};
