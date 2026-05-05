const { getDb } = require('./db');

exports.handler = async (event) => {
  if (event.httpMethod === 'OPTIONS')
    return { statusCode: 204, headers: { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': 'Content-Type', 'Access-Control-Allow-Methods': 'POST, OPTIONS' }, body: '' };
  if (event.httpMethod !== 'POST')
    return { statusCode: 405, body: JSON.stringify({ error: 'Method not allowed' }) };
  var hdrs = { 'Access-Control-Allow-Origin': '*', 'Content-Type': 'application/json' };

  try {
    var body = JSON.parse(event.body);
    var action = body.action;
    var db = await getDb();
    var col = db.collection('jobs');

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
      var sort = body.sort || { dateScanned: -1 };

      var total = await col.countDocuments(filter);
      var jobs = await col.find(filter)
        .project({ description: 0 }) // exclude large field for list view
        .sort(sort)
        .skip(skip)
        .limit(limit)
        .toArray();

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
      var result = await col.updateMany(
        { company: body.company },
        { $set: { companyType: body.companyType, companyTypeUpdatedAt: new Date() } }
      );
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
        { $match: { companyType: { $ne: '' } } },
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
        { $group: { _id: '$company', count: { $sum: 1 } } },
        { $sort: { count: -1 } },
        { $limit: 15 }
      ]).toArray();
      // Split comma-separated fields and count each value
      var certCounts = await col.aggregate([
        { $match: { certifications: { $ne: 'See details' } } },
        { $project: { items: { $split: ['$certifications', ', '] } } },
        { $unwind: '$items' },
        { $match: { items: { $ne: '' } } },
        { $group: { _id: { $trim: { input: '$items' } }, count: { $sum: 1 } } },
        { $sort: { count: -1 } },
        { $limit: 15 }
      ]).toArray();
      var complianceCounts = await col.aggregate([
        { $match: { compliance: { $ne: 'See details' } } },
        { $project: { items: { $split: ['$compliance', ', '] } } },
        { $unwind: '$items' },
        { $match: { items: { $ne: '' } } },
        { $group: { _id: { $trim: { input: '$items' } }, count: { $sum: 1 } } },
        { $sort: { count: -1 } },
        { $limit: 15 }
      ]).toArray();
      var toolsCounts = await col.aggregate([
        { $match: { tools: { $ne: 'See details' } } },
        { $project: { items: { $split: ['$tools', ', '] } } },
        { $unwind: '$items' },
        { $match: { items: { $ne: '' } } },
        { $group: { _id: { $trim: { input: '$items' } }, count: { $sum: 1 } } },
        { $sort: { count: -1 } },
        { $limit: 15 }
      ]).toArray();
      var locationCounts = await col.aggregate([
        { $match: { location: { $ne: 'Remote' } } },
        { $group: { _id: '$location', count: { $sum: 1 } } },
        { $sort: { count: -1 } },
        { $limit: 15 }
      ]).toArray();
      var recentScans = await col.aggregate([
        { $group: { _id: { $dateToString: { format: '%Y-%m-%d', date: '$dateScanned' } }, count: { $sum: 1 } } },
        { $sort: { _id: -1 } },
        { $limit: 14 }
      ]).toArray();

      return { statusCode: 200, headers: hdrs, body: JSON.stringify({
        totalJobs, statusCounts, typeCounts, countryCounts, companyCounts,
        certCounts, complianceCounts, toolsCounts, locationCounts, recentScans
      })};
    }

    return { statusCode: 400, headers: hdrs, body: JSON.stringify({ error: 'Unknown action: ' + action }) };
  } catch (err) {
    console.error('DB function error:', err);
    return { statusCode: 500, headers: hdrs, body: JSON.stringify({ error: 'Database error: ' + err.message }) };
  }
};
