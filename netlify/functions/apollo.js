// Apollo.io API integration
const APOLLO_KEY = process.env.APOLLO_API_KEY;
const hdrs = { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Methods': 'POST,OPTIONS', 'Access-Control-Allow-Headers': 'Content-Type' };

async function apolloFetch(endpoint, body) {
  body.api_key = APOLLO_KEY;
  var resp = await fetch('https://api.apollo.io/api/v1/' + endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-api-key': APOLLO_KEY },
    body: JSON.stringify(body)
  });
  if (!resp.ok) {
    var errText = await resp.text();
    throw new Error('Apollo ' + resp.status + ': ' + errText.slice(0, 300));
  }
  return resp.json();
}

exports.handler = async function(event) {
  if (event.httpMethod === 'OPTIONS') return { statusCode: 200, headers: hdrs, body: '' };
  if (event.httpMethod !== 'POST') return { statusCode: 405, headers: hdrs, body: 'Method not allowed' };

  try {
    var body = JSON.parse(event.body || '{}');
    var action = body.action;
    if (!APOLLO_KEY) return { statusCode: 500, headers: hdrs, body: JSON.stringify({ error: 'APOLLO_API_KEY not set' }) };

    // ACTION: searchPeople - find contacts at a company
    // Step 1: Find company domain via mixed_companies/search
    // Step 2: Search people via mixed_people/api_search with domain
    if (action === 'searchPeople') {
      var company = body.company || '';
      var domain = body.domain || '';
      var titles = body.titles || ['CISO', 'VP Security', 'Hiring Manager', 'HR Head', 'Recruiter', 'Talent Acquisition', 'SOC Manager', 'Security Director'];
      if (!company && !domain) return { statusCode: 400, headers: hdrs, body: JSON.stringify({ error: 'Company required' }) };

      // Step 1: Get company domain if not provided
      if (!domain) {
        try {
          var companyResult = await apolloFetch('mixed_companies/search', {
            q_organization_name: company, page: 1, per_page: 1
          });
          if (companyResult.organizations && companyResult.organizations.length) {
            domain = companyResult.organizations[0].primary_domain || '';
          }
        } catch(e) { /* proceed without domain */ }
      }

      // Step 2: Search people
      var searchBody = { person_titles: titles, page: 1, per_page: 15 };
      if (domain) {
        searchBody.q_organization_domains_list = [domain];
      } else {
        // Fallback: use keyword search
        searchBody.q_keywords = company;
      }

      var data = await apolloFetch('mixed_people/api_search', searchBody);
      var people = (data.people || []).map(function(p) {
        return {
          id: p.id || '',
          name: [p.first_name, p.last_name].filter(Boolean).join(' '),
          firstName: p.first_name || '',
          lastName: p.last_name || '',
          designation: p.title || '',
          linkedin: p.linkedin_url || '',
          company: (p.organization && p.organization.name) || company,
          city: p.city || '',
          country: p.country || '',
          source: 'Apollo.io'
        };
      });

      return { statusCode: 200, headers: hdrs, body: JSON.stringify({
        people: people,
        total: data.pagination ? data.pagination.total_entries : people.length,
        domain: domain
      })};
    }

    // ACTION: matchPerson - enrich a person to get email (1 credit)
    if (action === 'matchPerson') {
      var name = body.name || '';
      var company = body.company || '';
      if (!name) return { statusCode: 400, headers: hdrs, body: JSON.stringify({ error: 'Name required' }) };
      var parts = name.trim().split(/\s+/);
      var matchBody = { organization_name: company };
      if (parts[0]) matchBody.first_name = parts[0];
      if (parts.length > 1) matchBody.last_name = parts.slice(1).join(' ');

      var data = await apolloFetch('people/match', matchBody);
      var p = data.person || {};
      if (!p.id) return { statusCode: 200, headers: hdrs, body: JSON.stringify({ found: false }) };

      return { statusCode: 200, headers: hdrs, body: JSON.stringify({
        found: true,
        name: [p.first_name, p.last_name].filter(Boolean).join(' ') || name,
        designation: p.title || '',
        email: p.email || '',
        phone: (p.phone_numbers && p.phone_numbers.length) ? p.phone_numbers[0].sanitized_number : '',
        linkedin: p.linkedin_url || '',
        company: (p.organization && p.organization.name) || company,
        city: p.city || '',
        country: p.country || ''
      })};
    }

    // ACTION: enrichCompany - get company details
    if (action === 'enrichCompany') {
      var company = body.company || '';
      var domain = body.domain || '';
      if (!company && !domain) return { statusCode: 400, headers: hdrs, body: JSON.stringify({ error: 'Company or domain required' }) };

      var org = null;

      // Try domain first
      if (domain) {
        try {
          var data = await apolloFetch('organizations/enrich', { domain: domain });
          org = data.organization || null;
        } catch(e) {}
      }

      // Search by name, then enrich by domain
      if (!org) {
        try {
          var sr = await apolloFetch('mixed_companies/search', { q_organization_name: company, page: 1, per_page: 1 });
          if (sr.organizations && sr.organizations.length) {
            org = sr.organizations[0];
            if (org.primary_domain) {
              try {
                var enriched = await apolloFetch('organizations/enrich', { domain: org.primary_domain });
                if (enriched.organization) org = enriched.organization;
              } catch(e) {}
            }
          }
        } catch(e) {
          return { statusCode: 200, headers: hdrs, body: JSON.stringify({ company: company, size: '', notFound: true, error: e.message }) };
        }
      }

      if (!org) return { statusCode: 200, headers: hdrs, body: JSON.stringify({ company: company, size: '', notFound: true }) };

      return { statusCode: 200, headers: hdrs, body: JSON.stringify({
        company: org.name || company,
        domain: org.primary_domain || '',
        size: org.estimated_num_employees ? org.estimated_num_employees.toLocaleString() : '',
        industry: org.industry || '',
        website: org.website_url || org.primary_domain || '',
        linkedin: org.linkedin_url || '',
        founded: org.founded_year || '',
        country: org.country || '',
        city: org.city || '',
        logo: org.logo_url || '',
        description: (org.short_description || '').slice(0, 200)
      })};
    }

    return { statusCode: 400, headers: hdrs, body: JSON.stringify({ error: 'Unknown action. Use searchPeople, matchPerson, or enrichCompany' }) };
  } catch(e) {
    console.error('Apollo error:', e);
    return { statusCode: 500, headers: hdrs, body: JSON.stringify({ error: e.message }) };
  }
};
