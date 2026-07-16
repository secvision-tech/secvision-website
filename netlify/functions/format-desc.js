// ============================================================================
// format-desc.js — AI-assisted job description formatting
// ----------------------------------------------------------------------------
// WHY THIS EXISTS
//   Many scraped descriptions arrive as one unbroken run of prose:
//     "Job#: 3040326 Job Description: SOC Analyst 1 Location: Harrisburg,
//      Pennsylvania (On-site) Role Overview The SOC Analyst I is an entry..."
//   The client-side formatDesc() is a line-based regex formatter — it needs real
//   newlines to find headers and key/value pairs, so it can do nothing with this.
//   Deciding where "Location: Harrisburg, PA" ends and "Role Overview" begins
//   requires understanding the text, not pattern matching.
//
// COST CONTROL (deliberate)
//   * Formats ONCE, then caches the result on the job as `descFormatted`.
//     Re-opening a job costs nothing.
//   * Uses Haiku — this is reformatting, not reasoning. ~$0.008/job vs ~$0.024 Sonnet.
//   * Scoped to recent jobs only (default: last 1 month) — set by the caller.
//   * On-demand by default; the batch action is opt-in and capped.
//
// SAFETY
//   * The ORIGINAL description is never modified. We only ADD `descFormatted`.
//     So this is always reversible: $unset descFormatted to go back.
//   * The model is instructed to restructure only — never to invent or drop content.
// ============================================================================

const { getDb } = require('./db');
const crypto = require('crypto');

const ANTHROPIC_KEY = process.env.ANTHROPIC_API_KEY;
const MODEL = 'claude-haiku-4-5-20251001';   // cheap: this is formatting, not reasoning
const FORMAT_VERSION = 1;                     // bump to force re-format after a prompt change
const MAX_CHARS = 12000;                      // guard against giant descriptions
const BATCH_CAP = 25;                         // max jobs per batch call (Netlify 26s limit)

function validateToken(event) {
  try {
    var auth = (event.headers.authorization || event.headers.Authorization || '');
    var token = auth.replace(/^Bearer\s+/i, '');
    if (!token) return null;
    var payload = JSON.parse(Buffer.from(token.split('.')[1], 'base64').toString());
    return payload;
  } catch (e) { return null; }
}

function hashOf(s) {
  return crypto.createHash('sha1').update(String(s || '')).digest('hex').slice(0, 16);
}

// ---------------------------------------------------------------------------
// The prompt: restructure, never rewrite.
// ---------------------------------------------------------------------------
function buildPrompt(desc) {
  return 'Below is a job description that was scraped from a job board. Its line breaks were '
    + 'lost, so headings, labels and paragraphs all run together.\n\n'
    + 'Reformat it into clean, readable Markdown. Rules:\n'
    + '1. DO NOT invent, summarise, reword or omit ANY content. Every fact, sentence and list '
    + 'item in the input must appear in the output. This is purely a formatting task.\n'
    + '2. Put section headings (e.g. "Role Overview", "Key Responsibilities", "Required '
    + 'Qualifications", "Work Environment") on their own line as "## Heading".\n'
    + '3. Put label/value pairs (e.g. "Location: Harrisburg, PA", "Job#: 3040326") on their own '
    + 'line as "**Label:** value".\n'
    + '4. Turn run-on lists into "- " bullet points, one item per line.\n'
    + '5. Separate paragraphs with a blank line.\n'
    + '6. Keep URLs and email addresses exactly as they appear.\n'
    + '7. Fix obvious scraping artefacts where a word was split or glued '
    + '(e.g. "CONTRAC T" -> "CONTRACT", "candidate sCandidate" -> "candidates. Candidate"). '
    + 'Only fix clear artefacts; never change meaning.\n\n'
    + 'Respond with ONLY the reformatted Markdown. No preamble, no commentary, no code fences.\n\n'
    + '---BEGIN JOB DESCRIPTION---\n'
    + desc.slice(0, MAX_CHARS)
    + '\n---END JOB DESCRIPTION---';
}

async function formatOne(desc) {
  var ctrl = new AbortController();
  var tmo = setTimeout(function () { ctrl.abort(); }, 20000);
  try {
    var resp = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      signal: ctrl.signal,
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': ANTHROPIC_KEY,
        'anthropic-version': '2023-06-01'
      },
      body: JSON.stringify({
        model: MODEL,
        max_tokens: 4000,
        messages: [{ role: 'user', content: buildPrompt(desc) }]
      })
    });
    if (!resp.ok) {
      var errTxt = await resp.text();
      throw new Error('Anthropic ' + resp.status + ': ' + errTxt.slice(0, 200));
    }
    var data = await resp.json();
    var out = (data.content || []).filter(function (b) { return b.type === 'text'; })
      .map(function (b) { return b.text; }).join('\n').trim();
    // strip accidental code fences
    out = out.replace(/^```(?:markdown)?\s*/i, '').replace(/```\s*$/, '').trim();
    return out;
  } finally { clearTimeout(tmo); }
}

// Sanity guard: the model must not have dropped or invented substantial content.
// Compare word counts — a legit reformat stays close; a summary would shrink a lot.
function looksSane(original, formatted) {
  var wo = (original.match(/\b[\w']+\b/g) || []).length;
  var wf = (formatted.match(/\b[\w']+\b/g) || []).length;
  if (!wo) return false;
  var ratio = wf / wo;
  return ratio >= 0.80 && ratio <= 1.35;   // allow markup words, reject summarisation
}

exports.handler = async function (event) {
  var hdrs = { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' };
  if (event.httpMethod === 'OPTIONS') return { statusCode: 200, headers: hdrs, body: '' };
  if (event.httpMethod !== 'POST') return { statusCode: 405, headers: hdrs, body: JSON.stringify({ error: 'POST only' }) };

  var user = validateToken(event);
  if (!user || !user.email) return { statusCode: 401, headers: hdrs, body: JSON.stringify({ error: 'Invalid token' }) };
  if (!ANTHROPIC_KEY) return { statusCode: 200, headers: hdrs, body: JSON.stringify({ error: 'ANTHROPIC_API_KEY not configured' }) };

  var body = {};
  try { body = JSON.parse(event.body || '{}'); } catch (e) {}
  var action = body.action || 'formatOne';

  var db = await getDb();
  var jobs = db.collection('jobs');
  var ObjectId = require('mongodb').ObjectId;

  async function findJob(jobId) {
    var j = null;
    try { j = await jobs.findOne({ _id: new ObjectId(jobId) }); } catch (e) {}
    if (!j) j = await jobs.findOne({ jobId: jobId });
    return j;
  }

  try {
    // ---- getFormatted: read cached formatting only. NEVER calls the LLM (free). ----
    if (action === 'getFormatted') {
      var jg = await findJob(body.jobId);
      if (!jg) return { statusCode: 200, headers: hdrs, body: JSON.stringify({ formatted: null }) };
      var okCache = jg.descFormatted
        && jg.descFormatVersion === FORMAT_VERSION
        && jg.descFormattedHash === hashOf(jg.description || '');
      return { statusCode: 200, headers: hdrs, body: JSON.stringify({ formatted: okCache ? jg.descFormatted : null }) };
    }

    // ---- formatOne: format a single job's description on demand ----
    if (action === 'formatOne') {
      var job = await findJob(body.jobId);
      if (!job) return { statusCode: 404, headers: hdrs, body: JSON.stringify({ error: 'Job not found' }) };
      var desc = job.description || '';
      if (!desc.trim()) return { statusCode: 200, headers: hdrs, body: JSON.stringify({ error: 'No description to format' }) };

      var h = hashOf(desc);
      // Already formatted for this exact text + prompt version? Return the cache.
      if (job.descFormatted && job.descFormattedHash === h && job.descFormatVersion === FORMAT_VERSION && !body.force) {
        return { statusCode: 200, headers: hdrs, body: JSON.stringify({ formatted: job.descFormatted, cached: true }) };
      }

      var formatted = await formatOne(desc);
      if (!formatted) return { statusCode: 200, headers: hdrs, body: JSON.stringify({ error: 'Formatter returned nothing' }) };
      if (!looksSane(desc, formatted)) {
        return { statusCode: 200, headers: hdrs, body: JSON.stringify({
          error: 'content_mismatch',
          message: 'The reformatted text differed too much from the original, so it was discarded. Showing the original instead.'
        }) };
      }

      // Store ALONGSIDE the original — the original description is never touched.
      await jobs.updateOne({ _id: job._id }, { $set: {
        descFormatted: formatted,
        descFormattedHash: h,
        descFormatVersion: FORMAT_VERSION,
        descFormattedAt: new Date(),
        descFormattedBy: user.email
      } });
      return { statusCode: 200, headers: hdrs, body: JSON.stringify({ formatted: formatted, cached: false }) };
    }

    // ---- countPending: how many recent jobs still need formatting (for the UI) ----
    if (action === 'countPending') {
      var days = parseInt(body.days) || 30;
      var since = new Date(Date.now() - days * 24 * 60 * 60 * 1000);
      var q = pendingQuery(since);
      var n = await jobs.countDocuments(q);
      return { statusCode: 200, headers: hdrs, body: JSON.stringify({ pending: n, days: days }) };
    }

    // ---- formatBatch: format up to BATCH_CAP recent jobs (admin, opt-in) ----
    if (action === 'formatBatch') {
      if (['admin', 'super_admin'].indexOf(user.role) === -1) {
        return { statusCode: 403, headers: hdrs, body: JSON.stringify({ error: 'Admin only' }) };
      }
      var daysB = parseInt(body.days) || 30;
      var sinceB = new Date(Date.now() - daysB * 24 * 60 * 60 * 1000);
      var limit = Math.min(parseInt(body.limit) || 10, BATCH_CAP);

      var pending = await jobs.find(pendingQuery(sinceB), { projection: { description: 1, title: 1 } })
        .limit(limit).toArray();
      if (!pending.length) {
        return { statusCode: 200, headers: hdrs, body: JSON.stringify({ done: 0, remaining: 0, message: 'Nothing left to format.' }) };
      }

      var okCount = 0, skipped = 0;
      for (var i = 0; i < pending.length; i++) {
        var p = pending[i];
        try {
          var f = await formatOne(p.description || '');
          if (f && looksSane(p.description || '', f)) {
            await jobs.updateOne({ _id: p._id }, { $set: {
              descFormatted: f, descFormattedHash: hashOf(p.description || ''),
              descFormatVersion: FORMAT_VERSION, descFormattedAt: new Date(), descFormattedBy: user.email
            } });
            okCount++;
          } else {
            // mark as attempted so the batch doesn't loop on it forever
            await jobs.updateOne({ _id: p._id }, { $set: { descFormatSkipped: true, descFormatVersion: FORMAT_VERSION } });
            skipped++;
          }
        } catch (e) {
          // leave it unmarked; a later run can retry (e.g. transient timeout)
          break; // stop the batch on a hard error rather than burning budget
        }
      }
      var remaining = await jobs.countDocuments(pendingQuery(sinceB));
      return { statusCode: 200, headers: hdrs, body: JSON.stringify({
        done: okCount, skipped: skipped, remaining: remaining
      }) };
    }

    // ---- clearFormatted: remove AI formatting (rollback) ----
    if (action === 'clearFormatted') {
      if (['admin', 'super_admin'].indexOf(user.role) === -1) {
        return { statusCode: 403, headers: hdrs, body: JSON.stringify({ error: 'Admin only' }) };
      }
      var r = await jobs.updateMany(
        { descFormatted: { $exists: true } },
        { $unset: { descFormatted: '', descFormattedHash: '', descFormatVersion: '', descFormattedAt: '', descFormattedBy: '', descFormatSkipped: '' } }
      );
      return { statusCode: 200, headers: hdrs, body: JSON.stringify({ cleared: r.modifiedCount }) };
    }

    return { statusCode: 400, headers: hdrs, body: JSON.stringify({ error: 'Unknown action' }) };
  } catch (e) {
    return { statusCode: 200, headers: hdrs, body: JSON.stringify({ error: e.message }) };
  }

  // Jobs in the window that have a description but no current formatting yet
  function pendingQuery(since) {
    return {
      $and: [
        { $or: [{ datePosted: { $gte: since } }, { dateScanned: { $gte: since } }] },
        { description: { $exists: true, $ne: '' } },
        { descFormatSkipped: { $ne: true } },
        { $or: [
          { descFormatted: { $exists: false } },
          { descFormatVersion: { $ne: FORMAT_VERSION } }
        ] }
      ]
    };
  }
};
