// Apollo.io API integration
const APOLLO_KEY = process.env.APOLLO_API_KEY;
const hdrs = { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Methods': 'POST,OPTIONS', 'Access-Control-Allow-Headers': 'Content-Type, Authorization' };

async function apolloFetch(endpoint, body) {

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

      // Step 2: Search people - try multiple strategies
      var data = null;
      var strategies = [];

      // Strategy 1: Search by domain + titles
      if (domain) {
        strategies.push({ q_organization_domains_list: [domain], person_titles: titles, page: 1, per_page: 15 });
      }
      // Strategy 2: Search by company keyword + titles
      strategies.push({ q_keywords: company, person_titles: titles, page: 1, per_page: 15 });
      // Strategy 3: Search by domain without title filter (broader)
      if (domain) {
        strategies.push({ q_organization_domains_list: [domain], page: 1, per_page: 15 });
      }
      // Strategy 4: Search by company keyword without title filter (broadest)
      strategies.push({ q_keywords: company, page: 1, per_page: 15 });

      for (var s = 0; s < strategies.length; s++) {
        try {
          data = await apolloFetch('mixed_people/api_search', strategies[s]);
          if (data && data.people && data.people.length > 0) break;
        } catch(e) { data = null; }
      }
      // All strategies failed or returned nothing (often Apollo credits exhausted, or no matches)
      if (!data) {
        return { statusCode: 200, headers: hdrs, body: JSON.stringify({
          people: [], total: 0,
          warning: 'Apollo returned no data. This usually means Apollo API credits are exhausted, or no contacts matched. Try "Enrich from LinkedIn" or add contacts manually.'
        })};
      }
      var people = (data.people || []).map(function(p) {
        return {
          id: p.id || '',
          name: [p.first_name, p.last_name].filter(Boolean).join(' '),
          firstName: p.first_name || '',
          lastName: p.last_name || '',
          designation: p.title || p.headline || '',
          linkedin: p.linkedin_url || '',
          company: (p.organization && p.organization.name) || company,
          city: p.city || '',
          state: p.state || '',
          country: p.country || '',
          seniority: p.seniority || '',
          departments: (p.departments || []).join(', '),
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
      var personId = body.personId || '';
      var domain = body.domain || '';
      if (!name && !personId) return { statusCode: 400, headers: hdrs, body: JSON.stringify({ error: 'Name or person ID required' }) };

      var matchBody = {};
      // Best match: use Apollo person ID
      if (personId) matchBody.id = personId;
      // Add name
      var parts = name.trim().split(/\s+/);
      if (parts[0]) matchBody.first_name = parts[0];
      if (parts.length > 1) matchBody.last_name = parts.slice(1).join(' ');
      // Add company info
      if (company) matchBody.organization_name = company;
      if (domain) matchBody.domain = domain;

      var data = await apolloFetch('people/match?reveal_personal_emails=true', matchBody);
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

      // If explicit domain provided, enrich directly
      if (domain) {
        try {
          var data = await apolloFetch('organizations/enrich', { domain: domain });
          org = data.organization || null;
        } catch(e) {}
      }

      // Search by company name (don't guess domains)
      if (!org && company) {
        try {
          var sr = await apolloFetch('mixed_companies/search', { q_organization_name: company, page: 1, per_page: 3 });
          if (sr.organizations && sr.organizations.length) {
            // Find best matching org from results
            var stopWords = ['the','and','for','of','in','a','an','to','at','by','on','inc','llc','ltd','corp','co','group','company','technologies','solutions','services','consulting','international','global'];
            function getWords(name) {
              return (name || '').toLowerCase().replace(/[^a-z0-9\s]/g, '').split(/\s+/).filter(function(w) { return w.length > 2 && stopWords.indexOf(w) === -1; });
            }
            var searchWords = getWords(company);
            var bestOrg = null, bestScore = 0;
            sr.organizations.forEach(function(o) {
              var orgWords = getWords(o.name || '');
              var matches = 0;
              searchWords.forEach(function(w) { if (orgWords.indexOf(w) > -1) matches++; });
              var score = searchWords.length > 0 ? matches / searchWords.length : 0;
              if (score > bestScore) { bestScore = score; bestOrg = o; }
            });
            if (bestScore >= 0.4 && bestOrg) {
              org = bestOrg;
              // Enrich by domain for full details
              if (org.primary_domain) {
                try {
                  var enriched = await apolloFetch('organizations/enrich', { domain: org.primary_domain });
                  if (enriched.organization) org = enriched.organization;
                } catch(e) {}
              }
            } else {
              var foundNames = sr.organizations.map(function(o) { return o.name; }).join(', ');
              return { statusCode: 200, headers: hdrs, body: JSON.stringify({ company: company, size: '', notFound: true, mismatch: true, foundCompany: foundNames }) };
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
