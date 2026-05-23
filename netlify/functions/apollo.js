// Apollo.io API integration for contact discovery and company enrichment
const APOLLO_KEY = process.env.APOLLO_API_KEY;
const hdrs = { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Methods': 'POST,OPTIONS', 'Access-Control-Allow-Headers': 'Content-Type' };

async function apolloFetch(endpoint, body) {
  var resp = await fetch('https://api.apollo.io/api/v1/' + endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-api-key': APOLLO_KEY },
    body: JSON.stringify(body)
  });
  if (!resp.ok) {
    var errText = await resp.text();
    throw new Error('Apollo API ' + resp.status + ': ' + errText.slice(0, 200));
  }
  return resp.json();
}

exports.handler = async function(event) {
  if (event.httpMethod === 'OPTIONS') return { statusCode: 200, headers: hdrs, body: '' };
  if (event.httpMethod !== 'POST') return { statusCode: 405, headers: hdrs, body: 'Method not allowed' };

  try {
    var body = JSON.parse(event.body || '{}');
    var action = body.action;

    // ACTION: searchPeople - find contacts at a company by title
    if (action === 'searchPeople') {
      var company = body.company || '';
      var titles = body.titles || ['CISO', 'VP Security', 'Hiring Manager', 'HR Head', 'Recruiter', 'Talent Acquisition', 'SOC Manager', 'Security Director'];
      if (!company) return { statusCode: 400, headers: hdrs, body: JSON.stringify({ error: 'Company required' }) };

      var data = await apolloFetch('mixed_people/search', {
        q_organization_name: company,
        person_titles: titles,
        page: 1,
        per_page: 15
      });

      var people = (data.people || []).map(function(p) {
        return {
          name: [p.first_name, p.last_name].filter(Boolean).join(' '),
          designation: p.title || 'N/A',
          email: p.email || '',
          phone: p.phone_numbers && p.phone_numbers.length ? p.phone_numbers[0].sanitized_number : '',
          linkedin: p.linkedin_url || '',
          company: p.organization && p.organization.name || company,
          photo: p.photo_url || '',
          city: p.city || '',
          country: p.country || '',
          source: 'Apollo.io'
        };
      });

      return { statusCode: 200, headers: hdrs, body: JSON.stringify({ 
        people: people, 
        total: data.pagination ? data.pagination.total_entries : people.length 
      })};
    }

    // ACTION: enrichCompany - get company details including employee count
    if (action === 'enrichCompany') {
      var company = body.company || '';
      var domain = body.domain || '';
      if (!company && !domain) return { statusCode: 400, headers: hdrs, body: JSON.stringify({ error: 'Company or domain required' }) };

      var searchBody = {};
      if (domain) searchBody.domain = domain;
      else searchBody.domain = ''; // Will search by name

      // Try organization search first
      var data;
      try {
        if (domain) {
          data = await apolloFetch('organizations/enrich', { domain: domain });
        } else {
          // Search by name
          var searchResult = await apolloFetch('mixed_companies/search', {
            q_organization_name: company,
            page: 1,
            per_page: 1
          });
          if (searchResult.organizations && searchResult.organizations.length) {
            var org = searchResult.organizations[0];
            data = { organization: org };
          } else {
            return { statusCode: 200, headers: hdrs, body: JSON.stringify({ company: company, size: '', industry: '', notFound: true }) };
          }
        }
      } catch(e) {
        return { statusCode: 200, headers: hdrs, body: JSON.stringify({ company: company, size: '', error: e.message }) };
      }

      var org = data.organization || data || {};
      var sizeRange = '';
      if (org.estimated_num_employees) {
        sizeRange = org.estimated_num_employees.toLocaleString();
      } else if (org.raw_address) {
        sizeRange = '';
      }

      return { statusCode: 200, headers: hdrs, body: JSON.stringify({
        company: org.name || company,
        size: sizeRange,
        industry: org.industry || '',
        website: org.website_url || org.primary_domain || '',
        linkedin: org.linkedin_url || '',
        founded: org.founded_year || '',
        country: org.country || '',
        city: org.city || '',
        logo: org.logo_url || '',
        technologies: (org.current_technologies || []).slice(0, 10).map(function(t) { return t.name || t; }),
        description: (org.short_description || '').slice(0, 200)
      })};
    }

    return { statusCode: 400, headers: hdrs, body: JSON.stringify({ error: 'Unknown action. Use searchPeople or enrichCompany' }) };
  } catch(e) {
    console.error('Apollo error:', e);
    return { statusCode: 500, headers: hdrs, body: JSON.stringify({ error: e.message }) };
  }
};
