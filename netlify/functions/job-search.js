exports.handler = async (event) => {
  if (event.httpMethod === 'OPTIONS') {
    return { statusCode: 204, headers: { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': 'Content-Type, Authorization', 'Access-Control-Allow-Methods': 'POST, OPTIONS' }, body: '' };
  }
  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, body: JSON.stringify({ error: 'Method not allowed' }) };
  }
  const headers = { 'Access-Control-Allow-Origin': '*', 'Content-Type': 'application/json' };
  try {
    const { query, page, datePosted, jobSources } = JSON.parse(event.body);
    if (!query) return { statusCode: 400, headers, body: JSON.stringify({ error: 'Query required' }) };
    const apiKey = process.env.JSEARCH_API_KEY;
    if (!apiKey) return { statusCode: 500, headers, body: JSON.stringify({ error: 'API key not configured' }) };
    const params = new URLSearchParams({
      query: query,
      page: String(page || 1),
      num_pages: '1',
      country: 'us',
      date_posted: datePosted || 'all'
    });
    const response = await fetch(`https://jsearch.p.rapidapi.com/search?${params}`, {
      method: 'GET',
      headers: {
        'x-rapidapi-host': 'jsearch.p.rapidapi.com',
        'x-rapidapi-key': apiKey
      }
    });
    if (!response.ok) {
      const errText = await response.text();
      console.error('JSearch API error:', response.status, errText);
      return { statusCode: 502, headers, body: JSON.stringify({ error: 'Job search service temporarily unavailable' }) };
    }
    const data = await response.json();
    const jobs = (data.data || []).map(job => ({
      id: job.job_id,
      date: job.job_posted_at_datetime_utc ? new Date(job.job_posted_at_datetime_utc).toLocaleDateString('en-US') : 'N/A',
      title: job.job_title || 'N/A',
      company: job.employer_name || 'N/A',
      location: [job.job_city, job.job_state, job.job_country].filter(Boolean).join(', ') || 'Remote',
      experience: job.job_required_experience?.required_experience_in_months ? Math.round(job.job_required_experience.required_experience_in_months / 12) + '+ years' : 'Not specified',
      skills: (job.job_required_skills || []).slice(0, 6).join(', ') || 'See details',
      certifications: job.job_highlights?.Qualifications ? job.job_highlights.Qualifications.filter(q => /certif|SC-|AZ-|CISSP|CEH|OSCP|CompTIA|CISM|CISA/i.test(q)).slice(0, 2).join('; ') || 'See details' : 'See details',
      postedBy: job.employer_name || 'N/A',
      education: job.job_required_education?.degree || 'Not specified',
      contactEmail: job.job_apply_link ? 'Apply online' : 'N/A',
      applyLink: job.job_apply_link || '',
      source: job.job_publisher || 'Unknown',
      type: job.job_employment_type || 'N/A',
      description: job.job_description || 'No description available',
      qualifications: job.job_highlights?.Qualifications || [],
      responsibilities: job.job_highlights?.Responsibilities || [],
      benefits: job.job_highlights?.Benefits || [],
      salary: job.job_min_salary && job.job_max_salary ? `$${job.job_min_salary.toLocaleString()} - $${job.job_max_salary.toLocaleString()}` : 'Not disclosed',
      remote: job.job_is_remote ? 'Yes' : 'No'
    }));
    return {
      statusCode: 200, headers,
      body: JSON.stringify({
        jobs,
        totalResults: data.total || jobs.length,
        page: page || 1,
        hasMore: jobs.length === 10
      })
    };
  } catch (err) {
    console.error('Function error:', err);
    return { statusCode: 500, headers, body: JSON.stringify({ error: 'Internal server error' }) };
  }
};
