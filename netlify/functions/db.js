const { MongoClient } = require('mongodb');

let cachedClient = null;

async function getDb() {
  if (cachedClient && cachedClient.topology && cachedClient.topology.isConnected()) {
    return cachedClient.db('secvision_hunt');
  }
  const uri = process.env.MONGODB_URI;
  if (!uri) throw new Error('MONGODB_URI not configured');
  cachedClient = new MongoClient(uri, { maxPoolSize: 5, serverSelectionTimeoutMS: 5000 });
  await cachedClient.connect();
  return cachedClient.db('secvision_hunt');
}

module.exports = { getDb };
