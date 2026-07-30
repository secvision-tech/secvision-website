const { MongoClient } = require('mongodb');

let cachedClient = null;

async function getDb() {
  // Reusing a cached client is right for serverless — but the old check
  // (topology.isConnected()) reports "connected" even after Atlas has closed the
  // idle socket server-side, which surfaced as:
  //   "Database error: This socket has been ended by the other party"
  // A ping actually proves the socket is alive; if it isn't, rebuild silently.
  if (cachedClient) {
    try {
      await cachedClient.db('secvision_hunt').command({ ping: 1 });
      return cachedClient.db('secvision_hunt');
    } catch (e) {
      try { await cachedClient.close(); } catch (e2) { /* already dead */ }
      cachedClient = null;
    }
  }
  const uri = process.env.MONGODB_URI;
  if (!uri) throw new Error('MONGODB_URI not configured');
  cachedClient = new MongoClient(uri, {
    maxPoolSize: 5,
    serverSelectionTimeoutMS: 5000,
    // Prune idle sockets ourselves before Atlas kills them from its side.
    maxIdleTimeMS: 60000
  });
  await cachedClient.connect();
  return cachedClient.db('secvision_hunt');
}

module.exports = { getDb };
