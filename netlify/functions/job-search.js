const CERT_RE = /CISSP|CISM|CISA|CEH|OSCP|OSCE|GPEN|GCIH|GCIA|GSEC|GREM|CompTIA\s*Security\+|CompTIA\s*CySA\+|CompTIA\s*CASP\+|CompTIA\s*Network\+|SC-100|SC-200|SC-300|SC-400|AZ-500|AZ-900|MS-500|CCSP|CCNA|CCNP|CRISC|CGEIT|SSCP|CPTS|eJPT|eCPPT|PNPT|SANS|GIAC|ITIL|TOGAF/gi;
const COMP_RE = /SOC\s*2|SOC2|ISO\s*27001|ISO\s*27002|NIST\s*(?:SP\s*)?800-53|NIST\s*(?:SP\s*)?800-61|NIST\s*(?:SP\s*)?800-171|NIST\s*(?:SP\s*)?800-37|NIST\s*CSF|PCI[\s-]*DSS|HIPAA|GDPR|FedRAMP|HITRUST|CMMC|CCPA|FISMA|SOX|COBIT|CIS\s*Controls|CIS\s*Benchmarks|MITRE\s*ATT&CK|Zero\s*Trust|TIC\s*3\.0|COSO|ITAR|NERC\s*CIP|FERPA|GLBA|DFARS|ISMS|ISO\s*22301|CSA\s*STAR|cyber\s*kill\s*chain|kill\s*chain\s*framework|Lockheed\s*Martin\s*kill\s*chain|Diamond\s*Model|OWASP\s*Top\s*10|STRIDE|DREAD|FAIR|OCTAVE|ISO\s*31000|NIST\s*RMF|STIX[\s/]*TAXII/gi;
const TOOL_RE = /Microsoft\s*Defender(?:\s*(?:for\s*)?(?:Endpoint|Cloud|Identity|Office|365))?|Microsoft\s*Sentinel|Azure\s*Sentinel|Splunk|QRadar|CrowdStrike|SentinelOne|Palo\s*Alto|Cortex\s*XDR|Cortex\s*XSOAR|LogRhythm|Elastic\s*(?:Security|SIEM|Stack)|Chronicle|Tenable|Qualys|Nessus|Rapid7|InsightVM|Carbon\s*Black|VMware\s*Carbon\s*Black|Fortinet|FortiSIEM|FortiGate|Check\s*Point|Cisco\s*(?:ASA|Firepower|SecureX|Umbrella)|Snort|Suricata|Wireshark|Burp\s*Suite|Metasploit|XSOAR|Phantom|Swimlane|Demisto|KQL|SPL|YARA|Sigma|ServiceNow\s*(?:SecOps|ITSM)?|Jira|Proofpoint|Mimecast|Zscaler|Okta|CyberArk|BeyondTrust|Varonis|DarkTrace|Vectra|Tanium|Exabeam|Securonix|NetWitness|ArcSight|SIEM|SOAR|EDR|XDR|NDR|IDS[\s/]*IPS|DLP|WAF|CASB|CSPM|CWPP|CNAPP|IAM|PAM|MFA|SSO|UEBA|threat\s*intelligence\s*platform|cloud\s*security\s*(?:tools|platforms)/gi;
const SKILL_RE = /incident\s*response|threat\s*(?:hunting|analysis|detection|modeling|reporting|intelligence)|forensic\s*(?:analysis|investigation)|digital\s*forensics|malware\s*(?:analysis|reverse\s*engineering)|reverse\s*engineering|vulnerability\s*(?:management|assessment|scanning)|penetration\s*testing|pen\s*testing|red\s*team(?:ing)?|blue\s*team(?:ing)?|purple\s*team(?:ing)?|security\s*(?:monitoring|operations|engineering|architecture|assessment|automation|orchestration)|SOC\s*(?:operations|monitoring|analysis)|log\s*(?:analysis|management|correlation)|network\s*(?:security|forensics|analysis|monitoring)|cloud\s*security|endpoint\s*(?:security|protection)|identity\s*(?:management|governance)|access\s*(?:management|control)|data\s*(?:loss\s*prevention|protection|classification)|risk\s*(?:assessment|management|analysis)|compliance\s*(?:monitoring|management|auditing)|alert\s*triage|detection\s*engineering|rule\s*(?:writing|development|tuning)|playbook\s*(?:development|automation)|KQL|scripting|Python|PowerShell|Bash|JavaScript|SQL|RegEx|API\s*(?:security|integration)|SDLC|DevSecOps|CI[\s/]*CD|container\s*security|Kubernetes\s*security|RBAC|PKI|encryption|cryptography|PCAP\s*analysis|packet\s*analysis|memory\s*forensics|disk\s*forensics|evidence\s*(?:collection|preservation)|tabletop\s*exercises|disaster\s*recovery|business\s*continuity|patch\s*management|asset\s*management|phishing\s*(?:analysis|simulation)|email\s*security|DNS\s*security|web\s*application\s*security|mobile\s*security|IoT\s*security|OT\s*security|ICS\s*security|SCADA\s*security/gi;

function unique(text, re) {
  if (!text) return [];
  var m = text.match(re) || [], seen = {};
  // Known proper-case forms
  var PROPER = {'incident response':'Incident Response','threat hunting':'Threat Hunting','threat analysis':'Threat Analysis','threat detection':'Threat Detection','threat intelligence':'Threat Intelligence','threat modeling':'Threat Modeling','threat reporting':'Threat Reporting','forensic analysis':'Forensic Analysis','forensic investigation':'Forensic Investigation','digital forensics':'Digital Forensics','malware analysis':'Malware Analysis','reverse engineering':'Reverse Engineering','vulnerability management':'Vulnerability Management','vulnerability assessment':'Vulnerability Assessment','vulnerability scanning':'Vulnerability Scanning','penetration testing':'Penetration Testing','pen testing':'Penetration Testing','red teaming':'Red Teaming','blue teaming':'Blue Teaming','purple teaming':'Purple Teaming','security monitoring':'Security Monitoring','security operations':'Security Operations','security engineering':'Security Engineering','security architecture':'Security Architecture','security automation':'Security Automation','cloud security':'Cloud Security','network security':'Network Security','endpoint security':'Endpoint Security','email security':'Email Security','container security':'Container Security','kubernetes security':'Kubernetes Security','identity management':'Identity Management','access management':'Access Management','risk assessment':'Risk Assessment','risk management':'Risk Management','compliance monitoring':'Compliance Monitoring','alert triage':'Alert Triage','detection engineering':'Detection Engineering','log analysis':'Log Analysis','log management':'Log Management','patch management':'Patch Management','asset management':'Asset Management','disaster recovery':'Disaster Recovery','business continuity':'Business Continuity','soc operations':'SOC Operations','soc monitoring':'SOC Monitoring','web application security':'Web Application Security','mobile security':'Mobile Security','iot security':'IoT Security','ot security':'OT Security','ics security':'ICS Security','scada security':'SCADA Security','microsoft sentinel':'Microsoft Sentinel','azure sentinel':'Microsoft Sentinel','microsoft defender':'Microsoft Defender','microsoft defender for endpoint':'Microsoft Defender for Endpoint','microsoft defender for cloud':'Microsoft Defender for Cloud','microsoft defender for identity':'Microsoft Defender for Identity','microsoft defender for office':'Microsoft Defender for Office','carbon black':'Carbon Black','vmware carbon black':'VMware Carbon Black','palo alto':'Palo Alto','cortex xdr':'Cortex XDR','cortex xsoar':'Cortex XSOAR','check point':'Check Point','elastic security':'Elastic Security','elastic siem':'Elastic SIEM','elastic stack':'Elastic Stack','threat intelligence platform':'Threat Intelligence Platform','cloud security tools':'Cloud Security Tools','zero trust':'Zero Trust','cyber kill chain':'Cyber Kill Chain','ids/ips':'IDS/IPS','nist sp 800-53':'NIST SP 800-53','nist sp 800-61':'NIST SP 800-61','nist sp 800-171':'NIST SP 800-171','nist csf':'NIST CSF','nist rmf':'NIST RMF','mitre att&ck':'MITRE ATT&CK','cis controls':'CIS Controls','cis benchmarks':'CIS Benchmarks','owasp top 10':'OWASP Top 10','pci-dss':'PCI-DSS','pci dss':'PCI-DSS','soc 2':'SOC 2','soc2':'SOC 2','iso 27001':'ISO 27001','iso 27002':'ISO 27002','iso 22301':'ISO 22301','iso 31000':'ISO 31000','csa star':'CSA STAR','nerc cip':'NERC CIP','tic 3.0':'TIC 3.0','lockheed martin kill chain':'Lockheed Martin Kill Chain','stix/taxii':'STIX/TAXII','cybersecurity analyst':'Cybersecurity Analyst','cyber security analyst':'Cybersecurity Analyst','cybersecurity engineer':'Cybersecurity Engineer','cyber security engineer':'Cybersecurity Engineer'};
  return m.filter(function(v) {
    var k = v.toLowerCase().replace(/\s+/g,' ').trim();
    if (seen[k]) return false; seen[k] = true; return true;
  }).map(function(v) {
    var k = v.toLowerCase().replace(/\s+/g,' ').trim();
    return PROPER[k] || v;
  }).slice(0, 12);
}

function extractExp(job) {
  var d = job.job_description || '', parts = [], seen = {};
  // P1: "X+ years of [adj] experience in/with..." #70: added work|practical|industry|related|combined|prior|recent
  var p1 = /(\d+)\+?\s*years?\s*(?:of\s*)?(?:demonstrated\s*|proven\s*|hands[\s\-\u2010\u2011]*on\s*|relevant\s*|professional\s*|progressive\s*|direct\s*|solid\s*|extensive\s*|total\s*|work\s*|practical\s*|industry\s*|related\s*|combined\s*|cumulative\s*|prior\s*|recent\s*)?(?:experience|expertise|background)\s*(?:in|with|working\s*(?:in|with)|leading|managing|performing|supporting|conducting|across|within|using|on)?\s*([\w\s,\/&\-\u2010\u2013()]+?)(?:\.|;|\n|,\s*(?:with|including|and|or|in|plus|specific))/gi;
  var m; while ((m = p1.exec(d)) !== null && parts.length < 5) {
    var c = m[2].trim().slice(0, 40).replace(/^\s*(?:a|an|the)\s*/i, '');
    if (c.length < 3) continue; var k = m[1] + c.toLowerCase();
    if (!seen[k]) { seen[k] = true; parts.push(m[1] + '+ yr ' + c); }
  }
  // P2: "X-Y years [of experience]" - validate range 1-30
  var p2 = /(\d+)\s*[\-\u2013]+\s*(\d+)\s*(?:years?\s*)?(?:of\s*)?(?:[\w\s]*)?(?:experience|expertise)?/gi;
  while ((m = p2.exec(d)) !== null && parts.length < 5) {
    var y1 = parseInt(m[1]), y2 = parseInt(m[2]);
    if (y1 < 1 || y1 > 30 || y2 < 1 || y2 > 30 || y2 <= y1) continue;
    var k2 = m[1]+'-'+m[2]; if (!seen[k2]) { seen[k2] = true; parts.unshift(m[1]+'-'+m[2]+' years'); }
  }
  // P3: "minimum/at least/requires X years"
  var p3 = /(?:minimum|at\s*least|requires?)\s*(\d+)\+?\s*years?\s*(?:of\s*)?(?:[\w\-\u2010\u2011\s]*)?(?:experience|expertise)\s*(?:in|with|using)?\s*([\w\s,\/&\-]+?)(?:\.|;|,|\n|$)/gi;
  while ((m = p3.exec(d)) !== null && parts.length < 5) {
    var c3 = m[2].trim().slice(0, 35); if (c3.length < 3) continue;
    var k3 = 'min'+m[1]+c3.toLowerCase(); if (!seen[k3]) { seen[k3] = true; parts.push(m[1]+'+ yr '+c3); }
  }
  // P5: #71 "Experience Required: 8-10" or "Experience: 5+" or "Years of Experience: 7"
  var p5 = /(?:experience|expertise|years\s*of\s*experience)\s*(?:required|needed|level|range)?\s*:\s*(\d+)\s*[\-\u2013to]*\s*(\d+)?\s*\+?\s*(?:years?)?/gi;
  while ((m = p5.exec(d)) !== null && parts.length < 5) {
    var val = m[2] ? m[1]+'-'+m[2]+' years' : m[1]+'+ years';
    var k5 = 'p5'+m[1]+(m[2]||''); if (!seen[k5]) { seen[k5] = true; parts.push(val); }
  }
  // P6: Bullet point "* X+ years of work experience with..."
  var p6 = /[\u2022\-\*]\s*(\d+)\+?\s*years?\s*(?:of\s*)?(?:[\w\s]*?)(?:experience|expertise|background)\s*(?:in|with|on|across)?\s*([\w\s,\/&\-\u2010\u2013()]+?)(?:\.|;|\n|$)/gi;
  while ((m = p6.exec(d)) !== null && parts.length < 5) {
    var c6 = m[2].trim().slice(0, 35); if (c6.length < 3) continue;
    var k6 = 'p6'+m[1]+c6.toLowerCase(); if (!seen[k6]) { seen[k6] = true; parts.push(m[1]+'+ yr '+c6); }
  }
  // P4: Broad fallback
  if (parts.length === 0) {
    var p4 = /(\d+)\+?\s*years?\s*(?:of\s*)?(?:[\w\s,\-\u2010\u2011]*?)(?:experience|expertise)/gi;
    while ((m = p4.exec(d)) !== null && parts.length < 3) {
      var k4 = 'f'+m[1]; if (!seen[k4]) { seen[k4] = true; parts.push(m[1]+'+ years'); }
    }
  }
  if (parts.length === 0 && job.job_required_experience?.required_experience_in_months)
    parts.push(Math.round(job.job_required_experience.required_experience_in_months / 12) + '+ years');
  return parts.length ? parts.join(', ') : 'Not specified';
}

function extractElig(job) {
  var i = [], d = job.job_description || '', e = job.job_required_education;
  if (e) { if (e.postgraduate_degree) i.push('Postgraduate'); else if (e.bachelors_degree) i.push("Bachelor's"); else if (e.associates_degree) i.push("Associate's"); }
  if (/clearance|TS[\s/]*SCI|Secret\s*clearance/i.test(d)) i.push('Security Clearance');
  if (/U\.?S\.?\s*citizen/i.test(d)) i.push('US Citizen');
  if (/authorized\s*to\s*work/i.test(d)) i.push('Work Auth');
  return i.length ? i.join(', ') : 'See details';
}

// #46: Handle $XX.XX/hr, total compensation, salary range formats
function extractSalary(job) {
  if (job.job_min_salary && job.job_max_salary) {
    var s = job.job_salary_period === 'HOUR' ? '/hr' : '/yr';
    return '$'+Math.round(job.job_min_salary).toLocaleString()+'-$'+Math.round(job.job_max_salary).toLocaleString()+s;
  }
  var d = job.job_description || '';
  // Pattern: $XX.XX/hr - $YY.YY/hr or "set between $X and $Y"
  var m1 = d.match(/\$\s*([\d,.]+)\s*\/\s*(hr|hour)\s*(?:and|to|[\-\u2013])\s*\$?\s*([\d,.]+)\s*\/?\s*(?:hr|hour)?/i);
  if (m1) return '$'+m1[1]+'/hr - $'+m1[3]+'/hr';
  // Pattern: "between $X/hr and $Y/hr" or "set between $X and $Y"
  var m2 = d.match(/(?:between|from)\s*\$\s*([\d,.]+)\s*(?:\/\s*(?:hr|hour)\s*)?(?:and|to|[\-\u2013])\s*\$?\s*([\d,.]+)\s*(?:\/?\s*(?:hr|hour))?/i);
  if (m2) {
    var isHourly = /\/\s*(?:hr|hour)|per\s*hour|hourly/i.test(d.substring(Math.max(0,d.indexOf(m2[0])-30), d.indexOf(m2[0])+m2[0].length+30));
    return '$'+m2[1]+'-$'+m2[2]+(isHourly?'/hr':'/yr');
  }
  // Pattern: "$X,000 - $Y,000" with optional /yr /hr
  var m3 = d.match(/\$\s*([\d,]+(?:\.\d{1,2})?)\s*[\-\u2013to]+\s*\$?\s*([\d,]+(?:\.\d{1,2})?)\s*\+?\s*(?:\/?\s*)?(per\s*hour|per\s*year|hourly|annually|\/hr|\/yr|\/hour|\/year)?/i);
  if (m3) {
    var suffix = /hour|hr/i.test(m3[3]||'') ? '/hr' : '/yr';
    return '$'+m3[1]+'-$'+m3[2]+suffix;
  }
  // Pattern: "total compensation ... $X - $Y" or "compensation ... $X,000"
  var m4 = d.match(/(?:compensation|salary|pay)\s*(?:[\w\s]*?)\$\s*([\d,]+)\s*[\-\u2013to]+\s*\$?\s*([\d,]+)/i);
  if (m4) return '$'+m4[1]+'-$'+m4[2]+'/yr';
  return 'Not disclosed';
}

function extractContact(job) {
  var d = job.job_description || '';
  // Only extract real contact emails (not generic/company emails)
  var emailMatch = d.match(/(?:contact|email|reach|send|apply|submit|inquir)\w*\s*(?:at|to|:)\s*([\w.\-+]+@[\w.\-]+\.[\w]{2,})/i);
  if (!emailMatch) {
    // Try standalone email but validate it's a person email, not noreply/info/support
    var anyEmail = d.match(/([\w.\-+]+@[\w.\-]+\.[\w]{2,})/);
    if (anyEmail && !/noreply|no-reply|donotreply|notifications|info@|support@|careers@|jobs@|apply@|recruiting@|admin@/i.test(anyEmail[1])) {
      emailMatch = anyEmail;
    }
  }
  // Only match names that are explicitly labeled as recruiter/HR/contact
  var namePatterns = [
    /(?:recruiter|hiring\s*manager|talent\s*acquisition\s*(?:specialist|manager|lead)?|HR\s*(?:manager|director|contact))\s*:?\s*-?\s*([A-Z][a-z]{2,}\s+[A-Z][a-z]{2,})/,
    /(?:point\s*of\s*contact|POC)\s*:?\s*-?\s*([A-Z][a-z]{2,}\s+[A-Z][a-z]{2,})/,
    /([A-Z][a-z]{2,}\s+[A-Z][a-z]{2,})\s*,?\s*(?:Recruiter|Talent\s*Acquisition|HR\s*Manager|Hiring\s*Manager)/
  ];
  var name = '';
  for (var i = 0; i < namePatterns.length; i++) {
    var nm = d.match(namePatterns[i]);
    if (nm) { name = nm[1]; break; }
  }
  var email = emailMatch ? (emailMatch[1] || emailMatch[0]) : '';
  if (/noreply|no-reply|donotreply|notifications/i.test(email)) email = '';
  if (name && email) return name + ' (' + email + ')';
  if (email) return email;
  if (name) return name;
  return 'See details';
}

// #45, #49, #50: Smart job type detection from description
function detectJobType(job) {
  var apiType = job.job_employment_type || '';
  var d = job.job_description || '';
  var salary = extractSalary(job);

  // First check API structured type
  var typeMap = { 'FULLTIME':'Full-time','FULL_TIME':'Full-time','PARTTIME':'Part-time','PART_TIME':'Part-time',
    'CONTRACTOR':'Contract','CONTRACT':'Contract','INTERN':'Internship','INTERNSHIP':'Internship',
    'TEMPORARY':'Temporary','VOLUNTEER':'Volunteer','PER_DIEM':'Per Diem' };
  var mapped = typeMap[apiType.toUpperCase().trim()];

  // Now analyze description for contract signals
  var contractSignals = 0, fulltimeSignals = 0;

  // Strong contract indicators
  if (/\bcontract\s*(?:position|role|opportunity|assignment|engagement|basis|duration|length)\b/i.test(d)) contractSignals += 3;
  if (/\b(?:W-?2|1099|C2C|Corp[\s-]*to[\s-]*Corp)\b/i.test(d)) contractSignals += 3;
  if (/\b(?:contract[\s-]*to[\s-]*hire|temp[\s-]*to[\s-]*perm)\b/i.test(d)) contractSignals += 3;
  if (/\b\d+\+?\s*(?:month|months|mo)\s*(?:contract|engagement|assignment|duration)\b/i.test(d)) contractSignals += 3;
  if (/\bduration\s*:?\s*\d+\+?\s*(?:month|months|week|weeks)\b/i.test(d)) contractSignals += 3;
  if (/\b(?:contract|engagement)\s*(?:length|duration|period)\s*:?\s*\d+/i.test(d)) contractSignals += 3;
  if (/\b(?:with\s*(?:possible\s*)?extension)\b/i.test(d)) contractSignals += 2;
  if (/\/\s*(?:hr|hour)\b/i.test(salary)) contractSignals += 2;
  if (/\bcontract\s*(?:only|worker|staff|employee|personnel)\b/i.test(d)) contractSignals += 2;
  // Weak: just "contractor" mentioned in passing (like "manage contractor staff") - not counted

  // Strong full-time indicators
  if (/\bfull[\s-]*time\s*(?:position|role|opportunity|employee|employment)\b/i.test(d)) fulltimeSignals += 3;
  if (/\b(?:benefits|401k|401\(k\)|PTO|paid\s*time\s*off|medical|dental|vision)\b/i.test(d)) fulltimeSignals += 2;
  if (/\b(?:annual|yearly)\s*(?:salary|compensation|bonus)\b/i.test(d)) fulltimeSignals += 2;
  if (/\btotal\s*compensation\b/i.test(d)) fulltimeSignals += 2;
  if (/\/\s*(?:yr|year)\b/i.test(salary) && !salary.includes('Not disclosed')) fulltimeSignals += 1;
  if (/\bsalaried\b/i.test(d)) fulltimeSignals += 3;

  // Part-time indicators
  var partTimeSignals = /\bpart[\s-]*time\b/i.test(d) ? 3 : 0;

  // Internship indicators
  var internSignals = /\bintern(?:ship)?\b/i.test(d) ? 3 : 0;

  // Decision logic: description analysis overrides API type only if strong signals
  if (contractSignals >= 3 && contractSignals > fulltimeSignals) return 'Contract';
  if (fulltimeSignals >= 3 && fulltimeSignals > contractSignals) return 'Full-time';
  if (partTimeSignals >= 3) return 'Part-time';
  if (internSignals >= 3) return 'Internship';
  // Fall back to API type if available
  if (mapped) return mapped;
  // Final fallback: analyze salary hints
  if (salary.includes('/hr')) return 'Contract';
  if (salary.includes('/yr')) return 'Full-time';
  return 'Not specified';
}

// #60: Detect remote from both API field and description
function detectRemote(job) {
  if (job.job_is_remote) return 'Yes';
  var d = (job.job_description || '') + ' ' + (job.job_title || '');
  if (/\b(?:fully\s*remote|100%\s*remote|remote\s*(?:position|role|opportunity|work|only)|work\s*(?:from\s*home|remotely)|telecommute|telework)\b/i.test(d)) return 'Yes';
  if (/\bhybrid\b/i.test(d)) return 'Hybrid';
  return 'No';
}

// #68: Clean job title - strip clearance prefixes, location suffixes, keep core role
function cleanTitle(title) {
  if (!title) return 'N/A';
  var clean = title;
  // Remove clearance prefixes: "TS/SCI w/ CI Poly Cleared", "Secret Cleared", "Top Secret"
  clean = clean.replace(/^(?:TS[\s/]*SCI[\s/]*(?:w\/?\s*)?(?:CI\s*Poly\s*)?(?:Cleared\s*)?|Top[\s-]*Secret\s*(?:Cleared\s*)?|Secret\s*(?:Cleared\s*)?|Public\s*Trust\s*(?:Cleared\s*)?)/i, '').trim();
  // Remove trailing location/remote: "| Remote US", "- Remote", "(Hybrid)", "- Arlington, VA"
  clean = clean.replace(/\s*[\|–\-]\s*(?:Remote\s*(?:US|USA|UK|CA)?|Hybrid|On[\s-]*site|Onsite)\s*$/i, '').trim();
  clean = clean.replace(/\s*[\|–\-]\s*[A-Z][a-z]+(?:,\s*[A-Z]{2})?\s*$/i, '').trim();
  clean = clean.replace(/\s*\((?:Remote|Hybrid|On[\s-]*site|REMOTE|HYBRID)\)\s*$/i, '').trim();
  // Remove trailing clearance: "- TS/SCI Required", "(Secret Clearance)"
  clean = clean.replace(/\s*[\|–\-]\s*(?:TS[\s/]*SCI|Secret|Top\s*Secret|Clearance)[\w\s]*/i, '').trim();
  clean = clean.replace(/\s*\((?:TS[\s/]*SCI|Secret|Clearance)[^)]*\)\s*$/i, '').trim();
  // Remove leading/trailing dashes, pipes
  clean = clean.replace(/^[\s\-–|:]+|[\s\-–|:]+$/g, '').trim();
  // #92: Normalize "Cyber Security" to "Cybersecurity"
  clean = clean.replace(/\bCyber\s+Security\b/gi, 'Cybersecurity');
  return clean || title;
}

// #69: Detect actual country from job data and description
var COUNTRY_MAP = {
  'US':'United States','USA':'United States','United States':'United States',
  'CA':'Canada','Canada':'Canada',
  'GB':'United Kingdom','UK':'United Kingdom','United Kingdom':'United Kingdom',
  'DE':'Germany','Germany':'Germany',
  'FR':'France','France':'France',
  'AU':'Australia','Australia':'Australia',
  'IN':'India','India':'India',
  'SG':'Singapore','Singapore':'Singapore',
  'IE':'Ireland','Ireland':'Ireland',
  'NL':'Netherlands','Netherlands':'Netherlands',
  'CH':'Switzerland','Switzerland':'Switzerland',
  'SE':'Sweden','Sweden':'Sweden',
  'AE':'UAE','UAE':'United Arab Emirates','United Arab Emirates':'United Arab Emirates',
  'IL':'Israel','Israel':'Israel',
  'JP':'Japan','Japan':'Japan',
  'BR':'Brazil','Brazil':'Brazil',
  'MX':'Mexico','Mexico':'Mexico',
  'ZA':'South Africa','South Africa':'South Africa',
  'NZ':'New Zealand','New Zealand':'New Zealand'
};
var US_STATES = /\b(?:Alabama|Alaska|Arizona|Arkansas|California|Colorado|Connecticut|Delaware|Florida|Georgia|Hawaii|Idaho|Illinois|Indiana|Iowa|Kansas|Kentucky|Louisiana|Maine|Maryland|Massachusetts|Michigan|Minnesota|Mississippi|Missouri|Montana|Nebraska|Nevada|New\s*Hampshire|New\s*Jersey|New\s*Mexico|New\s*York|North\s*Carolina|North\s*Dakota|Ohio|Oklahoma|Oregon|Pennsylvania|Rhode\s*Island|South\s*Carolina|South\s*Dakota|Tennessee|Texas|Utah|Vermont|Virginia|Washington|West\s*Virginia|Wisconsin|Wyoming|D\.?C\.?)\b/i;
var US_STATE_CODES = /,\s*(?:AL|AK|AZ|AR|CA|CO|CT|DE|FL|GA|HI|ID|IL|IN|IA|KS|KY|LA|ME|MD|MA|MI|MN|MS|MO|MT|NE|NV|NH|NJ|NM|NY|NC|ND|OH|OK|OR|PA|RI|SC|SD|TN|TX|UT|VT|VA|WA|WV|WI|WY|DC)\b/;

function detectCountry(job, searchCountry) {
  // Priority 1: API structured country field
  var apiCountry = (job.job_country || '').trim();
  if (apiCountry) {
    var c = apiCountry.toUpperCase();
    if (c === 'US' || c === 'USA' || c === 'UNITED STATES') return 'United States';
    if (c === 'CA' || c === 'CANADA') return 'Canada';
    if (c === 'GB' || c === 'UK' || c === 'UNITED KINGDOM') return 'United Kingdom';
    if (c === 'IN' || c === 'INDIA') return 'India';
    if (c === 'AU' || c === 'AUSTRALIA') return 'Australia';
    if (c === 'DE' || c === 'GERMANY') return 'Germany';
    if (c === 'FR' || c === 'FRANCE') return 'France';
    if (c === 'JP' || c === 'JAPAN') return 'Japan';
    if (c === 'SG' || c === 'SINGAPORE') return 'Singapore';
    if (c === 'NL' || c === 'NETHERLANDS') return 'Netherlands';
    if (c === 'IE' || c === 'IRELAND') return 'Ireland';
    if (c === 'CH' || c === 'SWITZERLAND') return 'Switzerland';
    if (c === 'SE' || c === 'SWEDEN') return 'Sweden';
    if (c === 'AE' || c === 'UAE') return 'United Arab Emirates';
    if (c === 'IL' || c === 'ISRAEL') return 'Israel';
    if (c === 'BR' || c === 'BRAZIL') return 'Brazil';
    if (c === 'MX' || c === 'MEXICO') return 'Mexico';
    if (c === 'NZ' || c === 'NEW ZEALAND') return 'New Zealand';
    if (c === 'ZA' || c === 'SOUTH AFRICA') return 'South Africa';
    if (c === 'ES' || c === 'SPAIN') return 'Spain';
    if (c === 'IT' || c === 'ITALY') return 'Italy';
    if (c === 'PL' || c === 'POLAND') return 'Poland';
    if (c === 'BE' || c === 'BELGIUM') return 'Belgium';
    if (c === 'AT' || c === 'AUSTRIA') return 'Austria';
    if (c === 'NO' || c === 'NORWAY') return 'Norway';
    if (c === 'DK' || c === 'DENMARK') return 'Denmark';
    if (c === 'FI' || c === 'FINLAND') return 'Finland';
    if (c === 'SA' || c === 'SAUDI ARABIA') return 'Saudi Arabia';
    if (c === 'QA' || c === 'QATAR') return 'Qatar';
  }

  // Priority 2: Check location/state fields for US state codes
  var state = (job.job_state || '').trim().toUpperCase();
  var usStates = ['AL','AK','AZ','AR','CA','CO','CT','DE','FL','GA','HI','ID','IL','IN','IA','KS','KY','LA','ME','MD','MA','MI','MN','MS','MO','MT','NE','NV','NH','NJ','NM','NY','NC','ND','OH','OK','OR','PA','RI','SC','SD','TN','TX','UT','VT','VA','WA','WV','WI','WY','DC'];
  if (state && usStates.indexOf(state) !== -1) return 'United States';

  // Priority 3: Check full location string
  var loc = [job.job_city, job.job_state, job.job_country].filter(Boolean).join(', ');
  // US state names in location
  if (/\b(?:Alabama|Alaska|Arizona|Arkansas|California|Colorado|Connecticut|Delaware|Florida|Georgia|Hawaii|Idaho|Illinois|Indiana|Iowa|Kansas|Kentucky|Louisiana|Maine|Maryland|Massachusetts|Michigan|Minnesota|Mississippi|Missouri|Montana|Nebraska|Nevada|New Hampshire|New Jersey|New Mexico|New York|North Carolina|North Dakota|Ohio|Oklahoma|Oregon|Pennsylvania|Rhode Island|South Carolina|South Dakota|Tennessee|Texas|Utah|Vermont|Virginia|Washington|West Virginia|Wisconsin|Wyoming|District of Columbia)\b/i.test(loc)) return 'United States';
  // US state codes in location (2-letter after comma)
  if (/,\s*(?:AL|AK|AZ|AR|CA|CO|CT|DE|FL|GA|HI|ID|IL|IN|IA|KS|KY|LA|ME|MD|MA|MI|MN|MS|MO|MT|NE|NV|NH|NJ|NM|NY|NC|ND|OH|OK|OR|PA|RI|SC|SD|TN|TX|UT|VT|VA|WA|WV|WI|WY|DC)\b/.test(loc)) return 'United States';
  // Major US cities
  if (/\b(?:New York|Los Angeles|Chicago|Houston|Phoenix|San Antonio|San Diego|Dallas|San Jose|Austin|Jacksonville|Fort Worth|Columbus|Charlotte|Indianapolis|San Francisco|Seattle|Denver|Nashville|Washington|Boston|Memphis|Portland|Oklahoma City|Las Vegas|Louisville|Baltimore|Milwaukee|Albuquerque|Tucson|Fresno|Sacramento|Mesa|Kansas City|Atlanta|Omaha|Colorado Springs|Raleigh|Long Beach|Virginia Beach|Miami|Tampa|Orlando|Minneapolis|Cleveland|St\.? Louis|Pittsburgh|Cincinnati|Irvine|Arlington|Plano|Durham|Richmond|Huntsville|McLean|Tysons|Bethesda|Herndon|Reston|Chantilly|Springfield|Columbia|Annapolis|Fort Meade|Fort Belvoir|Quantico|San Bernardino|Scottsdale|Chandler|Gilbert|Boise|Salt Lake City)\b/i.test(loc)) return 'United States';
  // UK cities
  if (/\b(?:London|Manchester|Birmingham|Leeds|Glasgow|Edinburgh|Bristol|Liverpool|Sheffield|Newcastle|Nottingham|Cardiff|Belfast|Cambridge|Oxford|Reading|Southampton|Brighton)\b/i.test(loc)) return 'United Kingdom';
  // Canadian cities
  if (/\b(?:Toronto|Vancouver|Montreal|Ottawa|Calgary|Edmonton|Winnipeg|Quebec|Hamilton|Mississauga)\b/i.test(loc)) return 'Canada';
  // Indian cities
  if (/\b(?:Bangalore|Bengaluru|Mumbai|Hyderabad|Pune|Delhi|New Delhi|Chennai|Kolkata|Noida|Gurgaon|Gurugram|Ahmedabad|Jaipur|Lucknow|Kochi|Chandigarh|Indore|Thiruvananthapuram)\b/i.test(loc)) return 'India';
  // Australian cities
  if (/\b(?:Sydney|Melbourne|Brisbane|Perth|Adelaide|Canberra|Hobart|Darwin|Gold Coast)\b/i.test(loc)) return 'Australia';
  // German cities
  if (/\b(?:Berlin|Munich|Frankfurt|Hamburg|Stuttgart|Dusseldorf|Cologne|Bonn)\b/i.test(loc)) return 'Germany';
  // Other countries by city
  if (/\b(?:Paris|Lyon|Marseille)\b/i.test(loc)) return 'France';
  if (/\b(?:Tokyo|Osaka|Yokohama)\b/i.test(loc)) return 'Japan';
  if (/\b(?:Dublin|Cork|Galway)\b/i.test(loc)) return 'Ireland';
  if (/\b(?:Amsterdam|Rotterdam|The Hague)\b/i.test(loc)) return 'Netherlands';
  if (/\b(?:Zurich|Geneva|Basel|Bern)\b/i.test(loc)) return 'Switzerland';
  if (/\b(?:Stockholm|Gothenburg|Malmo)\b/i.test(loc)) return 'Sweden';
  if (/\b(?:Dubai|Abu Dhabi)\b/i.test(loc)) return 'United Arab Emirates';
  if (/\b(?:Tel Aviv|Jerusalem|Haifa)\b/i.test(loc)) return 'Israel';
  if (/\b(?:Sao Paulo|Rio de Janeiro)\b/i.test(loc)) return 'Brazil';
  if (/\b(?:Mexico City|Guadalajara|Monterrey)\b/i.test(loc)) return 'Mexico';
  if (/\bSingapore\b/i.test(loc)) return 'Singapore';

  // Priority 4: Check title + description (first 1500 chars)
  var text = (job.job_title || '') + ' ' + (job.job_description || '').slice(0, 1500);
  if (/\b(?:USA|United\s*States|U\.S\.)\b/i.test(text)) return 'United States';
  if (/\bRemote\s*[-,]?\s*US\b/i.test(text)) return 'United States';
  if (US_STATES.test(text)) return 'United States';
  if (/\bUnited\s*Kingdom\b|\bRemote\s*UK\b/i.test(text)) return 'United Kingdom';
  if (/\bCanada\b|\bRemote\s*CA\b/i.test(text)) return 'Canada';
  if (/\bAustralia\b/i.test(text)) return 'Australia';
  if (/\bIndia\b/i.test(text)) return 'India';
  if (/\bGermany\b/i.test(text)) return 'Germany';
  if (/\bFrance\b/i.test(text)) return 'France';
  if (/\bJapan\b/i.test(text)) return 'Japan';
  if (/\bSingapore\b/i.test(text)) return 'Singapore';
  if (/\bNetherlands\b/i.test(text)) return 'Netherlands';
  if (/\bIreland\b/i.test(text)) return 'Ireland';
  if (/\bSwitzerland\b/i.test(text)) return 'Switzerland';

  // Priority 5: Check 2-letter country code at end of location (", EG", ", MY")
  var locStr = [job.job_city, job.job_state, job.job_country].filter(Boolean).join(', ');
  var ccMatch = locStr.match(/,\s*([A-Z]{2})\s*$/);
  if (ccMatch) {
    var ccMap = {'US':'United States','CA':'Canada','GB':'United Kingdom','UK':'United Kingdom','IN':'India','AU':'Australia','DE':'Germany','FR':'France','JP':'Japan','SG':'Singapore','NL':'Netherlands','IE':'Ireland','CH':'Switzerland','SE':'Sweden','AE':'United Arab Emirates','IL':'Israel','BR':'Brazil','MX':'Mexico','NZ':'New Zealand','ZA':'South Africa','ES':'Spain','IT':'Italy','PL':'Poland','EG':'Egypt','MY':'Malaysia','PH':'Philippines','TH':'Thailand','ID':'Indonesia','KR':'South Korea','TW':'Taiwan','HK':'Hong Kong','PK':'Pakistan','SA':'Saudi Arabia','QA':'Qatar','NG':'Nigeria','KE':'Kenya','PT':'Portugal','CZ':'Czech Republic','RO':'Romania','BE':'Belgium','AT':'Austria','TR':'Turkey','RU':'Russia','UA':'Ukraine','NO':'Norway','DK':'Denmark','FI':'Finland','HU':'Hungary','GR':'Greece','LU':'Luxembourg','BH':'Bahrain','KW':'Kuwait','CL':'Chile','CO':'Colombia','AR':'Argentina','PE':'Peru'};
    if (ccMap[ccMatch[1]]) return ccMap[ccMatch[1]];
  }

  // Priority 6: Use search country as fallback
  if (searchCountry) {
    var scMap = {'us':'United States','ca':'Canada','uk':'United Kingdom','gb':'United Kingdom','in':'India','au':'Australia','de':'Germany','fr':'France','jp':'Japan','sg':'Singapore','nl':'Netherlands','ie':'Ireland','ch':'Switzerland','se':'Sweden','ae':'United Arab Emirates','il':'Israel','br':'Brazil','mx':'Mexico','nz':'New Zealand','za':'South Africa'};
    if (scMap[searchCountry.toLowerCase()]) return scMap[searchCountry.toLowerCase()];
  }

  return 'Unknown';
}

// Auto-classify company type from job description and company name
function classifyCompany(company, desc) {
  var text = (company + ' ' + desc).toLowerCase();
  var score = { mssp: 0, enterprise: 0, govt: 0, startup: 0, consulting: 0 };

  // MSSP/MDR signals
  if (/\bmssp\b/.test(text)) score.mssp += 5;
  if (/\bmdr\b/.test(text)) score.mssp += 5;
  if (/\bmanaged\s*(?:security|detection|soc|siem)\b/.test(text)) score.mssp += 4;
  if (/\bsoc[\s-]*as[\s-]*a[\s-]*service\b/.test(text)) score.mssp += 5;
  if (/\bmanaged\s*(?:service|services)\s*provider\b/.test(text)) score.mssp += 4;
  if (/\bsecurity\s*(?:operations|services)\s*(?:provider|company|firm)\b/.test(text)) score.mssp += 3;
  if (/\bclient(?:s|'s)?\s*(?:environment|network|infrastructure|tenant)\b/.test(text)) score.mssp += 3;
  if (/\bmulti[\s-]*tenant\b/.test(text)) score.mssp += 3;
  if (/\bazure\s*lighthouse\b/.test(text)) score.mssp += 3;
  if (/\bsecurity\s*partner\b/.test(text)) score.mssp += 2;

  // Government/Defense signals
  if (/\b(?:government|federal|dod|department\s*of\s*defense|military|army|navy|air\s*force)\b/.test(text)) score.govt += 5;
  if (/\b(?:clearance|ts[\s\/]*sci|secret\s*clearance|public\s*trust)\b/.test(text)) score.govt += 4;
  if (/\b(?:disa|cisa|nsa|fbi|cia|dhs|va\s*(?:health|medical)|cms)\b/.test(text)) score.govt += 4;
  if (/\b(?:fedramp|fisma|dod\s*stigs|itar|dfars|cmmc)\b/.test(text)) score.govt += 3;
  if (/\b(?:contractor|contracting\s*officer|government\s*contract)\b/.test(text)) score.govt += 2;

  // Enterprise signals
  if (/\b(?:fortune\s*\d+|global\s*leader|multinational|enterprise[\s-]*wide)\b/.test(text)) score.enterprise += 4;
  if (/\b(?:bank|banking|financial\s*services|insurance|pharmaceutical|healthcare|hospital|manufacturing|retail)\b/.test(text)) score.enterprise += 4;
  if (/\b(?:internal\s*(?:soc|security|it)|corporate\s*(?:security|it))\b/.test(text)) score.enterprise += 3;
  if (/\b(?:our\s*company|our\s*organization|in[\s-]*house)\b/.test(text)) score.enterprise += 2;
  if (/\b(?:401k|401\(k\)|pto|paid\s*time\s*off|medical|dental|vision)\b/.test(text)) score.enterprise += 1;

  // Startup signals
  if (/\b(?:startup|start[\s-]*up|seed\s*funding|series\s*[a-c]|venture|early[\s-]*stage|founding\s*(?:team|member))\b/.test(text)) score.startup += 5;
  if (/\b(?:fast[\s-]*paced|rapidly\s*growing|disrupt|innovative\s*(?:company|startup))\b/.test(text)) score.startup += 2;

  // Consulting signals
  if (/\b(?:consulting|consultancy|advisory|professional\s*services|staffing\s*(?:agency|firm|company))\b/.test(text)) score.consulting += 4;
  if (/\b(?:on\s*behalf\s*of|our\s*client|client\s*site)\b/.test(text)) score.consulting += 3;

  // Find highest score
  var best = '', bestScore = 0;
  var map = { mssp: 'MSSP/MDR', enterprise: 'Enterprise', govt: 'Government', startup: 'Startup', consulting: 'IT Consulting' };
  for (var k in score) {
    if (score[k] > bestScore) { bestScore = score[k]; best = map[k]; }
  }
  return bestScore >= 3 ? best : '';
}

exports.handler = async (event) => {
  if (event.httpMethod === 'OPTIONS')
    return { statusCode: 204, headers: { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': 'Content-Type', 'Access-Control-Allow-Methods': 'POST, OPTIONS' }, body: '' };
  if (event.httpMethod !== 'POST')
    return { statusCode: 405, body: JSON.stringify({ error: 'Method not allowed' }) };
  var hdrs = { 'Access-Control-Allow-Origin': '*', 'Content-Type': 'application/json' };
  try {
    var body = JSON.parse(event.body);
    var apiKey = process.env.JSEARCH_API_KEY;
    if (!apiKey) return { statusCode: 500, headers: hdrs, body: JSON.stringify({ error: 'API key not configured' }) };
    var roles = body.roles || [body.query || 'cybersecurity'];
    var country = body.country || 'us';
    var isUSCA = !body.country || body.country === 'us' || body.country === 'ca';
    var countryName = body.countryName || '';
    var pagesPerRole = Math.min(Math.max(1, Math.ceil((body.pages||10) / roles.length)), 5);
    var allJobs = [], seenIds = {}, totalApiCalls = 0, startTime = Date.now();

    async function fetchPage(query, page, ctry, useEmpType) {
      if (Date.now() - startTime > 22000) return [];
      var params = new URLSearchParams({ query: query, page: String(page), num_pages: '1', country: ctry, date_posted: body.datePosted || 'all' });
      if (useEmpType && body.employmentTypes) params.set('employment_types', body.employmentTypes);
      try {
        var r = await fetch('https://jsearch.p.rapidapi.com/search?' + params, {
          headers: { 'x-rapidapi-host': 'jsearch.p.rapidapi.com', 'x-rapidapi-key': apiKey }
        });
        totalApiCalls++;
        if (!r.ok) return []; var d = await r.json(); return d.data || [];
      } catch (e) { return []; }
    }

    function addJobs(jobs) {
      jobs.forEach(function(job) {
        var jid = job.job_id || (job.employer_name + '|' + job.job_title);
        if (!seenIds[jid]) { seenIds[jid] = true; allJobs.push(job); }
      });
    }

    await Promise.all(roles.map(async function(role) {
      var pp = [], gotResults = false;
      if (isUSCA) {
        // US/CA: use country param with employment filter
        for (var p = 1; p <= pagesPerRole; p++) pp.push(fetchPage(role, p, country, true));
        var results = await Promise.all(pp);
        results.forEach(function(jobs) { if (jobs.length) gotResults = true; addJobs(jobs); });
      } else {
        // Non-US/CA: try local country code first (works for India, Japan, etc.)
        for (var p = 1; p <= pagesPerRole; p++) pp.push(fetchPage(role, p, country, false));
        var results = await Promise.all(pp);
        results.forEach(function(jobs) { if (jobs.length) gotResults = true; addJobs(jobs); });

        // Per-role fallback: if local country returned 0, search US index with country name
        if (!gotResults && countryName) {
          var fbQuery = role + ' ' + countryName;
          var fb = await fetchPage(fbQuery, 1, 'us', false);
          addJobs(fb);
        }
      }
    }));

    var jobs = allJobs.map(function(job, i) {
      var rawDesc = job.job_description || '';
      // #73: Strip HTML tags, style blocks, and CSS from descriptions
      var desc = rawDesc.replace(/<style[^>]*>[\s\S]*?<\/style>/gi, '')
        .replace(/<script[^>]*>[\s\S]*?<\/script>/gi, '')
        .replace(/<[^>]+>/g, ' ')
        .replace(/\s{2,}/g, ' ')
        .trim();
      var fullText = desc + ' ' + (job.job_highlights?.Qualifications || []).join(' ') + ' ' + (job.job_highlights?.Responsibilities || []).join(' ');
      var apiSkills = (job.job_required_skills || []).slice(0, 6);
      var exSkills = unique(fullText, SKILL_RE);
      var ss = {}, fs = [];
      apiSkills.concat(exSkills).forEach(function(s) { var k = s.toLowerCase().trim(); if (!ss[k] && fs.length < 10) { ss[k] = true; fs.push(s); } });
      // #62: Extract actual client company if staffing agency pattern found
      var actualCompany = job.employer_name || 'N/A';
      var clientPatterns = [
        /(?:our\s*client|the\s*client|client\s*company)\s*,?\s*(?:is\s*)?([\w\s&.,']+?)\s*,?\s*(?:is\s*(?:seeking|looking|hiring|searching)|seeks|needs|requires)/i,
        /(?:on\s*behalf\s*of|partnered\s*with|working\s*with|representing)\s*([\w\s&.,']+?)\s*(?:,|to\s*find|who\s*is|that\s*is)/i,
        /(?:hiring\s*for|staffing\s*for|recruiting\s*for)\s*([\w\s&.,']+?)(?:\.|,|\s*-|\s*who)/i
      ];
      // Words that cannot start a company name
      var badStarts = /^(?:over|under|about|with|the|a|an|and|or|for|in|at|to|from|by|on|is|are|was|were|has|have|had|will|would|can|could|may|might|shall|should|must|not|no|all|any|each|every|some|many|much|more|most|few|less|other|another|such|this|that|these|those|than|then|now|here|there|where|when|how|what|which|who|whom|whose|why|if|so|up|out|off|down|\d+)\b/i;
      for (var cp = 0; cp < clientPatterns.length; cp++) {
        var cm = desc.match(clientPatterns[cp]);
        if (cm) {
          var candidate = cm[1].trim().replace(/[,.']+$/, '');
          // Validate: length 3-60, starts with uppercase letter, not a common word
          if (candidate.length >= 3 && candidate.length <= 60 && /^[A-Z]/.test(candidate) && !badStarts.test(candidate)) {
            actualCompany = candidate;
            break;
          }
        }
      }
      // #63: Build company URL - use employer_website if available, else Google I'm Feeling Lucky
      var companyWebUrl = job.employer_website || '';
      if (!companyWebUrl) {
        companyWebUrl = 'https://www.google.com/search?q=' + encodeURIComponent(actualCompany + ' official website');
      }
      return {
        idx: i + 1, id: job.job_id,
        date: job.job_posted_at_datetime_utc ? new Date(job.job_posted_at_datetime_utc).toLocaleDateString('en-US') : 'N/A',
        dateRaw: job.job_posted_at_datetime_utc || '',
        title: job.job_title || 'N/A', titleClean: cleanTitle(job.job_title), company: actualCompany,
        companyType: classifyCompany(actualCompany, desc),
        companyUrl: companyWebUrl,
        location: [job.job_city, job.job_state, job.job_country].filter(Boolean).join(', ') || 'Remote',
        detectedCountry: detectCountry(job, body.country),
        experience: extractExp(job),
        skills: fs.length ? fs.join(', ') : 'See details',
        certifications: unique(fullText, CERT_RE).join(', ') || 'See details',
        compliance: unique(fullText, COMP_RE).join(', ') || 'See details',
        tools: unique(fullText, TOOL_RE).join(', ') || 'See details',
        eligibility: extractElig(job), salary: extractSalary(job),
        contact: extractContact(job),
        source: job.job_publisher || 'Unknown',
        jobType: detectJobType(job),
        remote: detectRemote(job),
        applyLink: job.job_apply_link || '', description: desc,
        qualifications: job.job_highlights?.Qualifications || [],
        responsibilities: job.job_highlights?.Responsibilities || [],
        benefits: job.job_highlights?.Benefits || []
      };
    });

    // #82: Look up existing company classifications from DB
    // If a company was previously classified (manually or auto), reuse that classification
    var savedCount = 0;
    try {
      var { getDb } = require('./db');
      var db = await getDb();
      var col = db.collection('jobs');
      var userEmail = body.userEmail || 'anonymous';

      // Get unique company names from current results
      var companyNames = {};
      jobs.forEach(function(j) { if (j.company) companyNames[j.company] = true; });
      var uniqueCompanies = Object.keys(companyNames);

      // Query DB for existing classifications
      if (uniqueCompanies.length > 0) {
        var existingTypes = await col.aggregate([
          { $match: { company: { $in: uniqueCompanies }, companyType: { $ne: '' } } },
          { $group: { _id: '$company', companyType: { $first: '$companyType' } } }
        ]).toArray();

        // Build lookup map
        var typeMap = {};
        existingTypes.forEach(function(e) { typeMap[e._id] = e.companyType; });

        // Apply existing DB types over auto-classified (DB takes priority = manual overrides preserved)
        jobs.forEach(function(j) {
          if (typeMap[j.company]) j.companyType = typeMap[j.company];
        });
      }

      var ops = jobs.map(function(j) {
        return {
          updateOne: {
            filter: { jobId: j.id },
            update: { $set: {
              jobId: j.id, datePosted: j.dateRaw ? new Date(j.dateRaw) : null, dateScanned: new Date(),
              title: j.title, titleClean: j.titleClean, company: j.company, companyUrl: j.companyUrl,
              location: j.location, detectedCountry: j.detectedCountry, experience: j.experience,
              skills: j.skills, certifications: j.certifications, compliance: j.compliance,
              tools: j.tools, eligibility: j.eligibility, salary: j.salary, contact: j.contact,
              source: j.source, jobType: j.jobType, remote: j.remote, applyLink: j.applyLink,
              description: j.description, qualifications: j.qualifications,
              responsibilities: j.responsibilities, benefits: j.benefits
            }, $setOnInsert: { status: 'new', companyType: j.companyType || '', notes: '', searchedBy: userEmail,
              searchRegion: body.searchRegion || '', searchCountry: body.country || 'us', createdAt: new Date() }
            },
            upsert: true
          }
        };
      });
      if (ops.length > 0) {
        var result = await col.bulkWrite(ops, { ordered: false });
        savedCount = (result.upsertedCount || 0) + (result.modifiedCount || 0);
      }
    } catch (dbErr) {
      console.error('MongoDB save error:', dbErr.message);
      // Don't fail the response if DB save fails
    }

    return { statusCode: 200, headers: hdrs, body: JSON.stringify({ jobs: jobs, totalResults: jobs.length, apiCalls: totalApiCalls, rolesSearched: roles, savedToDb: savedCount }) };
  } catch (err) {
    console.error('Error:', err);
    return { statusCode: 500, headers: hdrs, body: JSON.stringify({ error: 'Internal server error' }) };
  }
};
