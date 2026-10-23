// #678 — scheduled trigger for the daily demand run (schedule set in netlify.toml). Netlify blocks HTTP calls to
// scheduled functions in production, so this function holds nothing but the trigger; all logic and the UI endpoint
// live in auto-pipeline.js.
exports.handler = async function () {
  try {
    var r = await require('./auto-pipeline').scheduledTick();
    return { statusCode: 200, body: JSON.stringify(r) };
  } catch (e) {
    return { statusCode: 200, body: JSON.stringify({ error: String(e && e.message || e) }) };
  }
};
