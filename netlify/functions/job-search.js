const CERT_RE = /CISSP|CISM|CISA|CEH|OSCP|OSCE|GPEN|GCIH|GCIA|GSEC|GREM|CompTIA\s*Security\+|CompTIA\s*CySA\+|CompTIA\s*CASP\+|CompTIA\s*Network\+|CompTIA\s*Server\+|CompTIA\s*A\+|CompTIA\s*Linux\+|CompTIA\s*Cloud\+|CompTIA\s*PenTest\+|CompTIA\s*SecurityX|SC-100|SC-200|SC-300|SC-400|AZ-\d{3}|DP-\d{3}|AI-\d{3}|MS-\d{3}|PL-\d{3}|MB-\d{3}|MD-\d{3}|AWS\s*Certified\s*[\w\s-]+|AWS\s*(?:Solutions?\s*Architect|Security\s*Specialty|Cloud\s*Practitioner|SysOps)|Google\s*Cloud\s*(?:Professional|Associate)\s*[\w\s-]+|CCSP|CCNA|CCNP|CCIE|CRISC|CGEIT|SSCP|CPTS|eJPT|eCPPT|PNPT|SANS|GIAC|ITIL|TOGAF|SABSA|CISSP-ISSAP|CISSP-ISSEP|CISSP-ISSMP|Zero\s*Trust|PCNSE|NSE\s*[4-8]|Fortinet\s*NSE|Azure\s*Security\s*Engineer(?:\s*Associate)?|Azure\s*(?:Network|Solutions?\s*Architect|Administrator|DevOps)\s*(?:Engineer\s*)?(?:Associate|Expert)?|Microsoft\s*Certified\s*:?\s*[\w\s-]{5,40}(?:Associate|Expert)|DoD\s*8570|DoD\s*8140|IAT\s*Level\s*(?:I{1,3}|[1-3])|IAM\s*Level\s*(?:I{1,3}|[1-3])/gi;
const COMP_RE = /SOC\s*2|SOC2|ISO\s*27001|ISO\s*27002|NIST\s*(?:SP\s*)?800-53|NIST\s*(?:SP\s*)?800-61|NIST\s*(?:SP\s*)?800-171|NIST\s*(?:SP\s*)?800-37|NIST\s*CSF|PCI[\s-]*DSS|HIPAA|GDPR|FedRAMP|HITRUST|CMMC|CCPA|FISMA|SOX|COBIT|CIS\s*Controls|CIS\s*Benchmarks|MITRE\s*ATT&CK|Zero\s*Trust|TIC\s*3\.0|COSO|ITAR|NERC\s*CIP|FERPA|GLBA|DFARS|ISMS|ISO\s*22301|CSA\s*STAR|cyber\s*kill\s*chain|kill\s*chain\s*framework|Lockheed\s*Martin\s*kill\s*chain|Diamond\s*Model|OWASP\s*Top\s*10|STRIDE|DREAD|FAIR|OCTAVE|ISO\s*31000|NIST\s*RMF|STIX[\s/]*TAXII|\bNIST\b/gi;
const TOOL_RE = /Microsoft\s*Defender(?:\s*(?:for\s*)?(?:Endpoint|Cloud|Identity|Office|365|Cloud\s*Apps))?|Microsoft\s*Sentinel|Microsoft\s*Entra(?:\s*ID)?|Microsoft\s*(?:Information\s*Protection|Purview|Intune)|M365(?:\s*Security)?|Azure\s*(?:Sentinel|AD|Active\s*Directory|Security\s*Center|Information\s*Protection)|Conditional\s*Access|Azure|Splunk|QRadar|CrowdStrike|SentinelOne|Palo\s*Alto|Cortex\s*XDR|Cortex\s*XSOAR|LogRhythm|Elastic\s*(?:Security|SIEM|Stack)|Chronicle|Google\s*Chronicle|Tenable|Qualys|Nessus|Rapid7|InsightVM|Carbon\s*Black|VMware\s*Carbon\s*Black|Fortinet|FortiSIEM|FortiGate|Check\s*Point|Cisco\s*(?:ASA|Firepower|SecureX|Umbrella)|Snort|Suricata|Wireshark|Burp\s*Suite|Metasploit|XSOAR|Phantom|Swimlane|Demisto|KQL|SPL|YARA|Sigma|ServiceNow\s*(?:SecOps|ITSM)?|Jira|Proofpoint|Mimecast|Zscaler|Okta|CyberArk|BeyondTrust|Varonis|DarkTrace|Vectra|Tanium|Exabeam|Securonix|NetWitness|ArcSight|AWS|Amazon\s*Web\s*Services|GuardDuty|AWS\s*(?:Security\s*Hub|CloudTrail|WAF|Shield|Inspector|Config|Macie)|GCP|Google\s*Cloud(?:\s*Platform)?|Security\s*Command\s*Center|Cloud\s*Armor|SIEM|SOAR|EDR|XDR|NDR|IDS[\s/]*IPS|DLP|WAF|CASB|CSPM|CWPP|CNAPP|IAM|PAM|MFA|SSO|UEBA|Prisma\s*Cloud|Prisma\s*Access|Wiz|Lacework|Orca\s*Security|Snyk|Aqua\s*Security|Aqua|Twistlock|Trivy|Falco|Sysdig|Anchore|Checkov|HashiCorp\s*Vault|Terraform|Ansible|Kubernetes|Docker|Jenkins|GitHub\s*Actions|Federated\s*Identity|threat\s*intelligence\s*platform|cloud\s*security\s*(?:tools|platforms)|SD[\s-]*WAN|SCADA|OT\s*(?:network|security)|ICS[\s\/]+(?:SCADA|security|systems?|networks?|environments?)|Modbus|DNP3|OPC[\s-]*UA?|BACnet|Profinet|IEC\s*61850|McAfee(?:\s*(?:SIEM|ESM|ePO|ENS))?|Trellix|FireEye(?:\s*(?:NX|EX|HX|CM))?|AWS\s*(?:VPC\s*Flow\s*Logs|CloudWatch|CloudTrail)|Azure\s*(?:Monitor|Log\s*Analytics|Arc)|Fortinet\s*NSE|FortiAnalyzer|FortiManager|SAML|OAuth(?:\s*2\.?0?)?|TLS[\s\/]*SSL|LDAP|RADIUS|Kerberos|OIDC|Node\.?js|Python|Bash|PowerShell|Golang|Go\s*Lang|Ruby|Perl/gi;
const SKILL_RE = /incident\s*response|threat\s*(?:hunting|analysis|detection|modeling|reporting|intelligence)|forensic\s*(?:analysis|investigation)|digital\s*forensics|malware\s*(?:analysis|reverse\s*engineering)|reverse\s*engineering|vulnerability\s*(?:management|assessment|scanning)|penetration\s*testing|pen\s*testing|red\s*team(?:ing)?|blue\s*team(?:ing)?|purple\s*team(?:ing)?|security\s*(?:monitoring|operations|engineering|architecture|assessment|automation|orchestration)|SOC\s*(?:operations|monitoring|analysis)|log\s*(?:analysis|management|correlation)|network\s*(?:security|forensics|analysis|monitoring)|cloud\s*security|endpoint\s*(?:security|protection)|identity\s*(?:management|governance)|access\s*(?:management|control)|data\s*(?:loss\s*prevention|protection|classification)|risk\s*(?:assessment|management|analysis)|compliance\s*(?:monitoring|management|auditing)|alert\s*triage|detection\s*engineering|rule\s*(?:writing|development|tuning)|playbook\s*(?:development|automation)|KQL|scripting|Python|PowerShell|Bash|JavaScript|SQL|RegEx|API\s*(?:security|integration)|SDLC|DevSecOps|CI[\s/]*CD|container\s*security|Kubernetes\s*security|RBAC|PKI|encryption|cryptography|PCAP\s*analysis|packet\s*analysis|memory\s*forensics|disk\s*forensics|evidence\s*(?:collection|preservation)|tabletop\s*exercises|disaster\s*recovery|business\s*continuity|patch\s*management|asset\s*management|phishing\s*(?:analysis|simulation)|email\s*security|DNS\s*security|web\s*application\s*security|mobile\s*security|IoT\s*security|OT\s*security|ICS\s*security|SCADA\s*security/gi;

function unique(text, re) {
  if (!text) return [];
  var m = text.match(re) || [], seen = {};
  // Known proper-case forms
  var PROPER = {'siem':'SIEM','soar':'SOAR','edr':'EDR','xdr':'XDR','ndr':'NDR','ids/ips':'IDS/IPS','dlp':'DLP','waf':'WAF','casb':'CASB','cspm':'CSPM','cwpp':'CWPP','cnapp':'CNAPP','iam':'IAM','pam':'PAM','mfa':'MFA','sso':'SSO','ueba':'UEBA','spl':'SPL','kql':'KQL','yara':'YARA','sigma':'Sigma','golang':'Golang','go lang':'Go Lang','sql':'SQL','rbac':'RBAC','ci/cd':'CI/CD','sdlc':'SDLC','pki':'PKI','m365':'M365','m365 security':'M365 Security','microsoft entra':'Microsoft Entra','microsoft entra id':'Microsoft Entra ID','microsoft information protection':'Microsoft Information Protection','microsoft purview':'Microsoft Purview','microsoft intune':'Microsoft Intune','azure ad':'Azure AD','azure active directory':'Azure AD','conditional access':'Conditional Access','federated identity':'Federated Identity','sd-wan':'SD-WAN','sd wan':'SD-WAN','scada':'SCADA','modbus':'Modbus','dnp3':'DNP3','opc-ua':'OPC-UA','opc ua':'OPC-UA','opc':'OPC','bacnet':'BACnet','profinet':'Profinet','mcafee':'McAfee','mcafee siem':'McAfee SIEM','mcafee esm':'McAfee ESM','mcafee epo':'McAfee ePO','trellix':'Trellix','fireeye':'FireEye','fireeye nx':'FireEye NX','fireeye ex':'FireEye EX','fireeye hx':'FireEye HX','aws vpc flow logs':'AWS VPC Flow Logs','azure monitor':'Azure Monitor','azure log analytics':'Azure Log Analytics','fortianalyzer':'FortiAnalyzer','fortimanager':'FortiManager','fortinet nse':'Fortinet NSE','saml':'SAML','oauth':'OAuth','oauth 2.0':'OAuth 2.0','oauth 2':'OAuth 2.0','tls/ssl':'TLS/SSL','tls ssl':'TLS/SSL','ldap':'LDAP','radius':'RADIUS','kerberos':'Kerberos','oidc':'OIDC','nodejs':'Node.js','node.js':'Node.js','iec 61850':'IEC 61850','ics/scada':'ICS/SCADA','ics security':'ICS Security','ics systems':'ICS Systems','ics networks':'ICS Networks','aws cloudtrail':'AWS CloudTrail','aws cloudwatch':'AWS CloudWatch','incident response':'Incident Response','threat hunting':'Threat Hunting','threat analysis':'Threat Analysis','threat detection':'Threat Detection','threat intelligence':'Threat Intelligence','threat modeling':'Threat Modeling','threat reporting':'Threat Reporting','forensic analysis':'Forensic Analysis','forensic investigation':'Forensic Investigation','digital forensics':'Digital Forensics','malware analysis':'Malware Analysis','reverse engineering':'Reverse Engineering','vulnerability management':'Vulnerability Management','vulnerability assessment':'Vulnerability Assessment','vulnerability scanning':'Vulnerability Scanning','penetration testing':'Penetration Testing','pen testing':'Penetration Testing','red teaming':'Red Teaming','blue teaming':'Blue Teaming','purple teaming':'Purple Teaming','security monitoring':'Security Monitoring','security operations':'Security Operations','security engineering':'Security Engineering','security architecture':'Security Architecture','security automation':'Security Automation','cloud security':'Cloud Security','network security':'Network Security','endpoint security':'Endpoint Security','email security':'Email Security','container security':'Container Security','kubernetes security':'Kubernetes Security','identity management':'Identity Management','access management':'Access Management','risk assessment':'Risk Assessment','risk management':'Risk Management','compliance monitoring':'Compliance Monitoring','alert triage':'Alert Triage','detection engineering':'Detection Engineering','log analysis':'Log Analysis','log management':'Log Management','patch management':'Patch Management','asset management':'Asset Management','disaster recovery':'Disaster Recovery','business continuity':'Business Continuity','soc operations':'SOC Operations','soc monitoring':'SOC Monitoring','web application security':'Web Application Security','mobile security':'Mobile Security','iot security':'IoT Security','ot security':'OT Security','ics security':'ICS Security','scada security':'SCADA Security','microsoft sentinel':'Microsoft Sentinel','azure sentinel':'Microsoft Sentinel','microsoft defender':'Microsoft Defender','microsoft defender for endpoint':'Microsoft Defender for Endpoint','microsoft defender for cloud':'Microsoft Defender for Cloud','microsoft defender for identity':'Microsoft Defender for Identity','microsoft defender for office':'Microsoft Defender for Office','carbon black':'Carbon Black','vmware carbon black':'VMware Carbon Black','palo alto':'Palo Alto','cortex xdr':'Cortex XDR','cortex xsoar':'Cortex XSOAR','check point':'Check Point','elastic security':'Elastic Security','elastic siem':'Elastic SIEM','elastic stack':'Elastic Stack','threat intelligence platform':'Threat Intelligence Platform','cloud security tools':'Cloud Security Tools','zero trust':'Zero Trust','cyber kill chain':'Cyber Kill Chain','ids/ips':'IDS/IPS','nist sp 800-53':'NIST SP 800-53','nist sp 800-61':'NIST SP 800-61','nist sp 800-171':'NIST SP 800-171','nist csf':'NIST CSF','nist rmf':'NIST RMF','mitre att&ck':'MITRE ATT&CK','cis controls':'CIS Controls','cis benchmarks':'CIS Benchmarks','owasp top 10':'OWASP Top 10','pci-dss':'PCI-DSS','pci dss':'PCI-DSS','soc 2':'SOC 2','soc2':'SOC 2','iso 27001':'ISO 27001','iso 27002':'ISO 27002','iso 22301':'ISO 22301','iso 31000':'ISO 31000','csa star':'CSA STAR','nerc cip':'NERC CIP','tic 3.0':'TIC 3.0','lockheed martin kill chain':'Lockheed Martin Kill Chain','stix/taxii':'STIX/TAXII','cybersecurity analyst':'Cybersecurity Analyst','cyber security analyst':'Cybersecurity Analyst','cybersecurity engineer':'Cybersecurity Engineer','cyber security engineer':'Cybersecurity Engineer','aws':'AWS','amazon web services':'Amazon Web Services','guardduty':'GuardDuty','aws security hub':'AWS Security Hub','aws cloudtrail':'AWS CloudTrail','aws waf':'AWS WAF','aws shield':'AWS Shield','aws inspector':'AWS Inspector','aws config':'AWS Config','aws macie':'AWS Macie','gcp':'GCP','google cloud platform':'Google Cloud Platform','google cloud':'Google Cloud','security command center':'Security Command Center','cloud armor':'Cloud Armor','google chronicle':'Google Chronicle','azure':'Azure','prisma cloud':'Prisma Cloud','prisma access':'Prisma Access','wiz':'Wiz','lacework':'Lacework','orca security':'Orca Security','snyk':'Snyk','aqua security':'Aqua Security','aqua':'Aqua','twistlock':'Twistlock','trivy':'Trivy','falco':'Falco','sysdig':'Sysdig','anchore':'Anchore','checkov':'Checkov','hashicorp vault':'HashiCorp Vault','terraform':'Terraform','ansible':'Ansible','kubernetes':'Kubernetes','docker':'Docker','jenkins':'Jenkins','github actions':'GitHub Actions','python':'Python','bash':'Bash','powershell':'PowerShell','golang':'Golang','ruby':'Ruby','perl':'Perl'};
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
  var p1 = /(\d+)(?:\+|\s*plus)?\s*(?:years?|yrs?)'?\s*(?:of\s*)?(?:demonstrated\s*|proven\s*|hands[\s\-\u2010\u2011]*on\s*|relevant\s*|professional\s*|progressive\s*|direct\s*|solid\s*|extensive\s*|total\s*|work\s*|practical\s*|industry\s*|related\s*|combined\s*|cumulative\s*|prior\s*|recent\s*|minimum\s*)?(?:experience|expertise|background)\s*(?:in|with|working\s*(?:in|with)|leading|managing|performing|supporting|conducting|across|within|using|on)?\s*([\w\s,\/&\-\u2010\u2013()]+?)(?:\.|;|\n|$|,\s*(?:with|including|and|or|in|plus|specific))/gi;
  var m; while ((m = p1.exec(d)) !== null && parts.length < 5) {
    var c = m[2].trim().slice(0, 40);
    // Remove trailing partial word (cut at last space if truncated)
    if (c.length >= 38) c = c.replace(/\s+\S{0,4}$/, '');
    c = c.replace(/^\s*(?:a|an|the|as|s)\s+/i, '').replace(/\s+$/,'');
    if (c.length < 3) continue; var k = m[1] + c.toLowerCase();
    if (!seen[k]) { seen[k] = true; parts.push(m[1] + '+ yr ' + c); }
  }
  // P2: "X-Y years [of experience]" - validate range 1-30, require 'years' or 'experience' context
  var p2 = /(\d+)\s*[\-\u2013]+\s*(\d+)\s*(?:(?:years?|yrs?)\s*)(?:of\s*)?(?:[\w\s]*)?(?:experience|expertise)?/gi;
  while ((m = p2.exec(d)) !== null && parts.length < 5) {
    var y1 = parseInt(m[1]), y2 = parseInt(m[2]);
    if (y1 < 1 || y1 > 30 || y2 < 1 || y2 > 30 || y2 <= y1) continue;
    // Skip rating scales: "rate...1-10", "scale of 1-10", "(1-10)", "skills (1-10)"
    var ctx = d.substring(Math.max(0, m.index - 80), m.index + m[0].length + 20).toLowerCase();
    if (/\b(?:rate|rating|scale|score|rank|level|grade|skill|proficien)\b/.test(ctx)) continue;
    if (d.charAt(m.index - 1) === '(' || /\(\d+[\s\-]+\d+\)/.test(ctx)) continue;
    // Skip if range is 1-10 or 1-5 (common rating scales, unlikely experience)
    if ((y1 === 1 && (y2 === 5 || y2 === 10))) continue;
    var k2 = m[1]+'-'+m[2]; if (!seen[k2]) { seen[k2] = true; parts.unshift(m[1]+'-'+m[2]+' years'); }
  }
  // P3: "minimum/at least/requires X years"
  var p3 = /(?:minimum|at\s*least|requires?)\s*(?:of\s*)?(\d+)(?:\+|\s*plus)?\s*(?:years?|yrs?)'?\s*(?:of\s*)?(?:[\w\-\u2010\u2011\s]*)?(?:experience|expertise)\s*(?:in|with|using)?\s*([\w\s,\/&\-]+?)(?:\.|;|,|\n|$)/gi;
  while ((m = p3.exec(d)) !== null && parts.length < 5) {
    var c3 = m[2].trim().slice(0, 40);
    if (c3.length >= 38) c3 = c3.replace(/\s+\S{0,4}$/, '');
    c3 = c3.replace(/^\s*(?:a|an|the|as|s)\s+/i, '').replace(/\s+$/,'');
    if (c3.length < 3) continue;
    var k3 = 'min'+m[1]+c3.toLowerCase(); if (!seen[k3]) { seen[k3] = true; parts.push(m[1]+'+ yr '+c3); }
  }
  // P5: #71 "Experience Required: 8-10" or "Experience: 5+" or "Years of Experience: 7"
  var p5 = /(?:experience|expertise|years\s*of\s*experience)\s*(?:required|needed|level|range)?\s*:\s*(\d+)\s*[\-\u2013to]*\s*(\d+)?\s*\+?\s*(?:(?:years?|yrs?))?/gi;
  while ((m = p5.exec(d)) !== null && parts.length < 5) {
    var val = m[2] ? m[1]+'-'+m[2]+' years' : m[1]+'+ years';
    var k5 = 'p5'+m[1]+(m[2]||''); if (!seen[k5]) { seen[k5] = true; parts.push(val); }
  }
  // P6: Bullet point "* X+ years of work experience with..."
  var p6 = /[\u2022\-\*]\s*(\d+)(?:\+|\s*plus)?\s*(?:years?|yrs?)'?\s*(?:of\s*)?(?:[\w\s]*?)(?:experience|expertise|background)\s*(?:in|with|on|across)?\s*([\w\s,\/&\-\u2010\u2013()]+?)(?:\.|;|\n|$)/gi;
  while ((m = p6.exec(d)) !== null && parts.length < 5) {
    var c6 = m[2].trim().slice(0, 40);
    if (c6.length >= 38) c6 = c6.replace(/\s+\S{0,4}$/, '');
    c6 = c6.replace(/^\s*(?:a|an|the|as|s)\s+/i, '').replace(/\s+$/,'');
    if (c6.length < 3) continue;
    var k6 = 'p6'+m[1]+c6.toLowerCase(); if (!seen[k6]) { seen[k6] = true; parts.push(m[1]+'+ yr '+c6); }
  }
  // P4: Broad fallback
  if (parts.length === 0) {
    // P7: Written-out numbers: "five (5) years" or "over five years"
    var WORD_NUMS = {'one':1,'two':2,'three':3,'four':4,'five':5,'six':6,'seven':7,'eight':8,'nine':9,'ten':10,'eleven':11,'twelve':12,'fifteen':15,'twenty':20};
    var p7 = /(?:over\s+|at\s*least\s+|minimum\s+)?(?:(\w+)\s*\((\d+)\)|(\w+))\s*(?:\+\s*)?(?:years?|yrs?)\s*(?:of\s*)?(?:[\w\s]*?)(?:experience|expertise)\s*(?:in|with|developing|managing|working)?\s*([\w\s,\/&\-]+?)(?:\.|;|\n|$)/gi;
    while ((m = p7.exec(d)) !== null && parts.length < 5) {
      var numVal = m[2] ? parseInt(m[2]) : (WORD_NUMS[(m[1]||m[3]||'').toLowerCase()] || 0);
      if (numVal < 1 || numVal > 30) continue;
      var c7 = (m[4]||'').trim().slice(0, 40);
      if (c7.length < 3) continue;
      var k7 = 'p7'+numVal+c7.toLowerCase();
      if (!seen[k7]) { seen[k7] = true; parts.push(numVal+'+ yr '+c7); }
    }
  }
  if (parts.length === 0) {
    var p4 = /(\d+)\+?\s*(?:years?|yrs?)\s*(?:of\s*)?(?:[\w\s,\-\u2010\u2011]*?)(?:experience|expertise)/gi;
    while ((m = p4.exec(d)) !== null && parts.length < 3) {
      var k4 = 'f'+m[1]; if (!seen[k4]) { seen[k4] = true; parts.push(m[1]+'+ years'); }
    }
  }
  if (parts.length === 0 && job.job_required_experience?.required_experience_in_months)
    parts.push(Math.round(job.job_required_experience.required_experience_in_months / 12) + '+ years');
  // Final dedup - remove exact duplicates, substrings, and near-duplicates (same prefix)
  var uniqueParts = [], seenParts = {};
  parts.forEach(function(p) {
    var k = p.toLowerCase().replace(/\s+/g,' ').trim();
    if (seenParts[k]) return;
    var isDup = false;
    for (var sk in seenParts) {
      // Substring check
      if (sk.indexOf(k) !== -1 || k.indexOf(sk) !== -1) { isDup = true; break; }
      // Prefix match: if first 25 chars are same, it's a near-duplicate from different truncation
      var prefixLen = Math.min(25, k.length, sk.length);
      if (prefixLen > 10 && k.slice(0, prefixLen) === sk.slice(0, prefixLen)) { isDup = true; break; }
    }
    if (!isDup) { seenParts[k] = true; uniqueParts.push(p); }
  });
  return uniqueParts.length ? uniqueParts.join(', ') : 'Not specified';
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
    var p = (job.job_salary_period || '').toUpperCase();
    var s = p === 'HOUR' ? '/hr' : p === 'MONTH' ? '/mo' : '/yr';
    return '$'+Math.round(job.job_min_salary).toLocaleString()+'-$'+Math.round(job.job_max_salary).toLocaleString()+s;
  }
  var d = job.job_description || '';
  // Helper: detect period from context
  function detectPeriod(text, matchStr) {
    var ctx = text.substring(Math.max(0, text.indexOf(matchStr) - 40), text.indexOf(matchStr) + matchStr.length + 60);
    if (/per\s*hour|an\s*hour|hourly|\/\s*hr|\/\s*hour/i.test(ctx)) return '/hr';
    if (/per\s*month|monthly|\/\s*mo|\/\s*month|p\.m\./i.test(ctx)) return '/mo';
    if (/per\s*day|\bday\b|daily|\/\s*day|IR35/i.test(ctx)) return '/day';
    if (/per\s*week|weekly|\/\s*week/i.test(ctx)) return '/wk';
    if (/per\s*year|per\s*annum|annual|yearly|\/\s*yr|\/\s*year|p\.a\./i.test(ctx)) return '/yr';
    return null;
  }
  // Pattern: "$90-97hr" or "$90-$97hr" (no slash before hr)
  var m0 = d.match(/\$\s*([\d,.]+)\s*[\-\u2013to]+\s*\$?\s*([\d,.]+)\s*(hr|hour)\b/i);
  if (m0) return '$'+m0[1]+'-$'+m0[2]+'/hr';
  // Pattern: "$180k-$230k" or "$180K - $230K" (k = thousand)
  var mK = d.match(/\$\s*([\d,.]+)\s*k\s*[\-\u2013to]+\s*\$?\s*([\d,.]+)\s*k/i);
  if (mK) {
    var kLow = Math.round(parseFloat(mK[1].replace(/,/g,'')) * 1000);
    var kHigh = Math.round(parseFloat(mK[2].replace(/,/g,'')) * 1000);
    var kPeriod = detectPeriod(d, mK[0]) || '/yr';
    return '$'+kLow.toLocaleString()+'-$'+kHigh.toLocaleString()+kPeriod;
  }
  // Single "$180k"
  var mKs = d.match(/(?:salary|compensation|pay|base|rate)\s*:?\s*\$\s*([\d,.]+)\s*k\b/i);
  if (mKs) {
    var kVal = Math.round(parseFloat(mKs[1].replace(/,/g,'')) * 1000);
    return '$'+kVal.toLocaleString()+'/yr';
  }
  // Pattern: $XX.XX/hr - $YY.YY/hr
  var m1 = d.match(/\$\s*([\d,.]+)\s*\/\s*(hr|hour)\s*(?:and|to|[\-\u2013])\s*\$?\s*([\d,.]+)\s*\/?\s*(?:hr|hour)?/i);
  if (m1) return '$'+m1[1]+'/hr - $'+m1[3]+'/hr';
  // Pattern: "$X to $Y/hr" or "$X - $Y/hr" (explicit /hr at end)
  var m1b = d.match(/\$\s*([\d,.]+)\s*(?:to|[\-\u2013])\s*\$?\s*([\d,.]+)\s*\/(hr|hour|mo|month|day|wk|week|yr|year)/i);
  if (m1b) {
    var sfx1b = {'hr':'/hr','hour':'/hr','mo':'/mo','month':'/mo','day':'/day','wk':'/wk','week':'/wk','yr':'/yr','year':'/yr'};
    return '$'+m1b[1]+'-$'+m1b[2]+(sfx1b[m1b[3].toLowerCase()]||'/yr');
  }
  // Pattern: "between $X and $Y"
  var m2 = d.match(/(?:between|from)\s*\$\s*([\d,.]+)\s*(?:\/\s*(?:hr|hour)\s*)?(?:and|to|[\-\u2013])\s*\$?\s*([\d,.]+)\s*(?:\/?\s*(?:hr|hour))?/i);
  if (m2) {
    var p2 = detectPeriod(d, m2[0]) || '/yr';
    return '$'+m2[1]+'-$'+m2[2]+p2;
  }
  // Pattern: "$X,000 - $Y,000" with optional period
  var m3 = d.match(/\$\s*([\d,]+(?:\.\d{1,2})?)\s*[\-\u2013to]+\s*\$?\s*([\d,]+(?:\.\d{1,2})?)\s*\+?\s*(\/hr|\/hour|\/mo|\/month|\/yr|\/year|\/day|\/wk|\/week|per\s*hour|per\s*month|per\s*year|per\s*day|per\s*week|per\s*annum|an\s*hour|an\s*month|an\s*year|hourly|monthly|annually|daily|weekly|p\.a\.|p\.m\.)?/i);
  if (m3) {
    var sfx3 = '/yr';
    if (m3[3]) {
      var s3 = m3[3].toLowerCase();
      if (/hour|hr/.test(s3)) sfx3='/hr';
      else if (/month|mo|p\.m/.test(s3)) sfx3='/mo';
      else if (/day|daily/.test(s3)) sfx3='/day';
      else if (/week|wk/.test(s3)) sfx3='/wk';
    } else { sfx3 = detectPeriod(d, m3[0]) || '/yr'; }
    return '$'+m3[1]+'-$'+m3[2]+sfx3;
  }
  // Pattern: "Pay/Salary: $X" single amount with period context
  var m4 = d.match(/(?:compensation|salary|pay|rate)\s*:?\s*\$\s*([\d,]+(?:\.\d{1,2})?)/i);
  if (m4) {
    var p4 = detectPeriod(d, m4[0]) || '/yr';
    return '$'+m4[1]+p4;
  }
  // Pattern: £ range
  var m5 = d.match(/[£]\s*([\d,]+(?:\.\d{1,2})?)\s*[\-\u2013to]+\s*[£]?\s*([\d,]+(?:\.\d{1,2})?)/i);
  if (m5) {
    var p5 = detectPeriod(d, m5[0]) || '/yr';
    return '£'+m5[1]+'-£'+m5[2]+p5;
  }
  // Pattern: £ IR35 rate (always daily in UK): "£550 - £650 Inside IR35"
  var mIR35 = d.match(/[£]\s*([\d,]+(?:\.\d{1,2})?)\s*[\-\u2013to]+\s*[£]?\s*([\d,]+(?:\.\d{1,2})?)\s*(?:per\s*day\s*)?(?:inside|outside)\s*IR35/i);
  if (mIR35) return '£'+mIR35[1]+'-£'+mIR35[2]+'/day';
  // Single £ IR35: "£600 Inside IR35"
  var mIR35s = d.match(/[£]\s*([\d,]+(?:\.\d{1,2})?)\s*(?:per\s*day\s*)?(?:inside|outside)\s*IR35/i);
  if (mIR35s) return '£'+mIR35s[1]+'/day';
  // Pattern: £ with explicit period: "£600/day" or "£600 day" or "£500 per day"
  var m6a = d.match(/[£]\s*([\d,]+(?:\.\d{1,2})?)\s*(?:\/|\s+)(per\s*day|day|per\s*hour|hour|per\s*week|week|per\s*month|month)/i);
  if (m6a) {
    var s6a = m6a[2].toLowerCase();
    var sfx6a = /day/.test(s6a)?'/day':/hour/.test(s6a)?'/hr':/week/.test(s6a)?'/wk':/month/.test(s6a)?'/mo':'/day';
    return '£'+m6a[1]+sfx6a;
  }
  // Pattern: £ single
  var m6 = d.match(/(?:salary|compensation|pay|package|base|contract\s*rate|rate)\s*:?\s*[£]\s*([\d,]+(?:\.\d{1,2})?)/i);
  if (m6) {
    var p6 = detectPeriod(d, m6[0]) || '/yr';
    return '£'+m6[1]+p6;
  }
  // Pattern: € range
  var m7 = d.match(/[€]\s*([\d,]+(?:\.\d{1,2})?)\s*[\-\u2013to]+\s*[€]?\s*([\d,]+(?:\.\d{1,2})?)/i);
  if (m7) return '€'+m7[1]+'-€'+m7[2]+(detectPeriod(d,m7[0])||'/yr');
  // Pattern: € single
  var m8 = d.match(/(?:salary|compensation)\s*:?\s*[€]\s*([\d,]+)/i);
  if (m8) return '€'+m8[1]+(detectPeriod(d,m8[0])||'/yr');
  // Pattern: single rate "$60/hr" or "Rate: $60/hr"
  var m9 = d.match(/(?:pay\s*rate|rate|hourly\s*rate)\s*:?\s*\$\s*([\d,.]+)\s*(?:\/|\s*per\s*)(hr|hour|day|mo|month|yr|year|week|wk)/i);
  if (m9) {
    var sfx9 = {'hr':'/hr','hour':'/hr','day':'/day','mo':'/mo','month':'/mo','yr':'/yr','year':'/yr','week':'/wk','wk':'/wk'};
    return '$'+m9[1]+(sfx9[m9[2].toLowerCase()]||'/hr');
  }
  // Pattern: standalone "$XX/hr" anywhere
  var m10 = d.match(/\$\s*([\d,.]+)\s*\/(hr|hour)/i);
  if (m10) return '$'+m10[1]+'/hr';
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
// #231: Extract contract duration from description
function extractContractDuration(desc) {
  var d = (desc || '');
  var patterns = [
    // Range patterns FIRST (before single-number patterns)
    /\b(?:duration|length|term|period)\s*(?:[\-–:]\s*)?(\d+)\s*[\-–]\s*(\d+)\s*(?:months?|mos?)/i,
    /\b(\d+)\s*[\-–]\s*(\d+)\s*(?:months?|mos?)\s*(?:contract|engagement|initial|assignment)/i,
    // Single-number patterns
    /\b(?:duration|length|term|period)\s*(?:[\-–:]\s*)?(\d+)\s*(?:months?|mos?)(?:\s*(?:initial|rolling|extendable|minimum|\+\s*extension))?/i,
    /\b(\d+)\s*(?:months?|mos?)\s*(?:contract|engagement|assignment|initial|rolling|duration)/i,
    /\b(?:initial\s*)?(?:contract|engagement)\s*(?:[\-–:]\s*)?(\d+)\s*(?:months?|mos?)/i,
    /\b(?:contract[\s-]*to[\s-]*hire|c2h|temp[\s-]*to[\s-]*perm)\s*(?:after\s*)?(\d+)\s*(?:months?|mos?)/i,
    /\b(\d+)\s*(?:months?|mos?)\s*(?:\+\s*(?:\d+\s*)?(?:months?|extension))/i,
    /\b(?:duration|length|term|period)\s*(?:[\-–:]\s*)?(\d+)\s*(?:weeks?)/i,
    // Year-based patterns
    /\b(\d+)[\s-]*(?:year|yr)\s*(?:renewable|rolling|extendable|fixed[\s-]*term)?\s*(?:contract|engagement|assignment)/i,
    /\b(?:contract|engagement)\s*(?:[\-–:(]\s*)?(\d+)[\s-]*(?:year|yr)(?:\s*(?:renewable|rolling|extendable|initial))?\s*[):]?/i,
  ];
  for (var i = 0; i < patterns.length; i++) {
    var m = d.match(patterns[i]);
    if (m) {
      // Range patterns (indices 0, 1)
      if (i <= 1 && m[2]) {
        var r1=parseInt(m[1]),r2=parseInt(m[2]);
        if(r1>=1&&r1<=36&&r2>=1&&r2<=36&&r2>r1) return r1+'-'+r2+' months';
        continue;
      }
      // Year patterns (indices 7, 8)
      if (i >= 7) {
        var num = parseInt(m[1]);
        if (num >= 1 && num <= 5) {
          var yearLabel = num === 1 ? '1 year' : num + ' years';
          var ctx = d.substring(Math.max(0, (m.index||0) - 10), (m.index||0) + m[0].length + 20);
          if (/renewable|rolling|extendable/i.test(ctx)) yearLabel += ' (renewable)';
          return yearLabel;
        }
        continue;
      }
      var num = parseInt(m[1]);
      if (num >= 1 && num <= 36) {
        if (/weeks/.test(patterns[i].toString())) return num + ' weeks';
        return num + ' months';
      }
    }
  }
  return '';
}

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
  var title = job.job_title || '';
  if (/\bcontract\b/i.test(title)) contractSignals += 4; // "Contract" in job title is strongest signal
  if (/\bcontract\s*(?:position|role|opportunity|assignment|engagement|basis|duration|length)\b/i.test(d)) contractSignals += 3;
  if (/\b(?:W-?2|1099|C2C|Corp[\s-]*to[\s-]*Corp)\b/i.test(d)) contractSignals += 3;
  if (/\b(?:contract[\s-]*to[\s-]*hire|temp[\s-]*to[\s-]*perm)\b/i.test(d)) contractSignals += 3;
  if (/\b\d+\+?\s*(?:month|months|mo)\s*(?:contract|engagement|assignment|duration)\b/i.test(d)) contractSignals += 3;
  if (/\bduration\s*:?\s*\d+\+?\s*(?:month|months|week|weeks)\b/i.test(d)) contractSignals += 3;
  if (/\b(?:contract|engagement)\s*(?:length|duration|period)\s*:?\s*\d+/i.test(d)) contractSignals += 3;
  if (/\binitial\s*contract\s*:?\s*\d+/i.test(d)) contractSignals += 3;
  if (/\b(?:with\s*(?:possible\s*)?extension|likelihood\s*of\s*extension|option\s*to\s*extend)\b/i.test(d)) contractSignals += 2;
  if (/\/\s*(?:hr|hour)\b/i.test(salary)) contractSignals += 2;
  if (/\bcontract\s*(?:only|worker|staff|employee|personnel)\b/i.test(d)) contractSignals += 2;
  if (/\b(?:outside\s*IR35|inside\s*IR35|IR35)\b/i.test(d)) contractSignals += 3; // UK contract term
  // Weak: just "contractor" mentioned in passing (like "manage contractor staff") - not counted

  // Strong full-time indicators
  if (/\bfull[\s-]*time\s*(?:position|role|opportunity|employee|employment)\b/i.test(d)) fulltimeSignals += 3;
  if (/\b(?:position|employment|job)\s*(?:type|status)\s*:?\s*full[\s-]*time\b/i.test(d)) fulltimeSignals += 4;
  if (/\bfull[\s-]*time\b/i.test(title)) fulltimeSignals += 3;
  if (/\b(?:benefits|401k|401\(k\)|PTO|paid\s*time\s*off|medical|dental|vision)\b/i.test(d)) fulltimeSignals += 2;
  if (/\b(?:annual|yearly)\s*(?:salary|compensation|bonus)\b/i.test(d)) fulltimeSignals += 2;
  if (/\btotal\s*compensation\b/i.test(d)) fulltimeSignals += 2;
  if (/\/\s*(?:yr|year)\b/i.test(salary) && !salary.includes('Not disclosed')) fulltimeSignals += 1;
  if (/[£€]\s*\d/.test(salary)) fulltimeSignals += 2; // GBP/EUR salary = likely full-time
  if (/\bsalaried\b/i.test(d)) fulltimeSignals += 3;

  // "Position Type: Contract" in JD
  if (/\b(?:position|employment|job)\s*(?:type|status)\s*:?\s*contract\b/i.test(d)) contractSignals += 4;

  // Part-time indicators
  var partTimeSignals = /\bpart[\s-]*time\b/i.test(d) ? 3 : 0;
  if (/\b(?:position|employment|job)\s*(?:type|status)\s*:?\s*part[\s-]*time\b/i.test(d)) partTimeSignals += 4;
  if (/\bpart[\s-]*time\b/i.test(title)) partTimeSignals += 3;

  // Internship indicators
  var internSignals = /\bintern(?:ship)?\b/i.test(d) ? 3 : 0;
  if (/\bintern(?:ship)?\b/i.test(title)) internSignals += 3;

  // Decision logic: description analysis overrides API type only if strong signals
  if (contractSignals >= 3 && contractSignals > fulltimeSignals) return 'Contract';
  if (fulltimeSignals >= 3 && fulltimeSignals > contractSignals) return 'Full-time';
  if (partTimeSignals >= 3) return 'Part-time';
  if (internSignals >= 3) return 'Internship';
  // Fall back to API type if available
  if (mapped) return mapped;
  // Final fallback: assume Full-time (most cybersecurity jobs are)
  return 'Full-time';
}

// #60: Detect remote from both API field and description
function detectRemote(job) {
  if (job.job_is_remote) return 'Yes';
  var d = (job.job_description || '') + ' ' + (job.job_title || '');
  if (/\b(?:fully\s*remote|100%\s*remote|remote\s*(?:position|role|opportunity|work|only)|work\s*(?:from\s*home|remotely)|telecommute|telework)\b/i.test(d)) return 'Yes';
  if (/\bLocation\s*:\s*Remote\b/i.test(d)) return 'Yes';
  if (/\b(?:Remote\s*[\|\/\-–]\s*(?:Hybrid|Onsite|On-site)|(?:Hybrid|Onsite|On-site)\s*[\|\/\-–]\s*Remote)\b/i.test(d)) return 'Hybrid';
  if (/\bhybrid\b/i.test(d)) return 'Hybrid';
  if (/\b(?:on[\s-]*site|onsite)\s*[\-–]\s*\d+\s*days?\b/i.test(d)) return 'Hybrid';
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
  // Also check 2-letter codes anywhere in location parts
  var locParts = locStr.split(/[,\s]+/);
  for (var lp = 0; lp < locParts.length; lp++) {
    var lcode = locParts[lp].trim().toUpperCase();
    if (lcode.length === 2 && ccMap && ccMap[lcode] && lcode !== 'IN') return ccMap[lcode];
  }

  // Priority 6: Detect non-English text → map by script (don't default to US/UK)
  var descSample = (job.job_description || '').slice(0, 500);
  if (/[\u0600-\u06FF\u0750-\u077F]/.test(descSample)) return 'Unknown'; // Arabic → could be Egypt, UAE, SA - leave Unknown, location code should catch it
  if (/[\u4E00-\u9FFF]/.test(descSample)) return 'Unknown'; // Chinese
  if (/[\u3040-\u309F\u30A0-\u30FF]/.test(descSample)) return 'Japan'; // Japanese hiragana/katakana
  if (/[\uAC00-\uD7AF]/.test(descSample)) return 'South Korea'; // Korean
  if (/[\u0E00-\u0E7F]/.test(descSample)) return 'Thailand'; // Thai
  if (/[\u0400-\u04FF]/.test(descSample)) return 'Unknown'; // Cyrillic → Russia/Ukraine - leave Unknown
  if (/[\u0900-\u097F]/.test(descSample)) return 'India'; // Devanagari (Hindi)

  // Priority 7: Use search country as fallback (only for Latin-script descriptions)
  if (searchCountry) {
    var scMap = {'us':'United States','ca':'Canada','uk':'United Kingdom','gb':'United Kingdom','in':'India','au':'Australia','de':'Germany','fr':'France','jp':'Japan','sg':'Singapore','nl':'Netherlands','ie':'Ireland','ch':'Switzerland','se':'Sweden','ae':'United Arab Emirates','il':'Israel','br':'Brazil','mx':'Mexico','nz':'New Zealand','za':'South Africa'};
    if (scMap[searchCountry.toLowerCase()]) return scMap[searchCountry.toLowerCase()];
  }

  return 'Unknown';
}

// Auto-classify company type from job description and company name
// Known Job Board platforms (not actual employers)
var JOB_BOARDS = /^(?:indeed|glassdoor|ziprecruiter|dice|monster|careerbuilder|simplyhired|talent\.com|bebee|jobrapido|jobilize|jobleads|usajobs|clearancejobs|virtualvocations|teal|adzuna|jobzmall|jora|workday|lever|greenhouse|icims|smartrecruiters|jazz\s*hr|bullhorn|taleo|brassring|linkedin|snagajob|handshake|wayup|hired|ladders|flexjobs|remote\.co|weworkremotely|angel\.co|wellfound|builtinnyc|builtin|ventureloop|startupers|remotive|nodesk|pangian|talent\s*center)$/i;

// Known Staffing/Recruiting agencies
var STAFFING_AGENCIES = /^(?:robert\s*half|hays|hays\s*technology|randstad|tek\s*systems|teksystems|adecco|modis|insight\s*global|kforce(?:\s*(?:federal|government|gov)\s*(?:solutions)?)?|cybercoders|aerotek|manpower(?:group)?|kelly\s*services|softworld.*kelly|beacon\s*hill|apex\s*systems|allegis|staffing\s*technologies|harvey\s*nash|michael\s*page|page\s*group|spencer\s*stuart|egon\s*zehnder|man\s*tech|disys|corestaff|matlen\s*silver|experis|vaco|addison\s*group|solis|motion\s*recruitment|talent\s*(?:solutions|bridge|partners)|brainworks|dunhill|recruiting\s*(?:from\s*scratch|innovation)|private\s*label\s*staff|11th\s*hour\s*service|river\s*hawk|nanosoft\s*consulting)$/i;

function classifyCompany(company, desc) {
  var compName = (company || '').trim();
  var text = (company + ' ' + desc).toLowerCase();

  // Priority 1: Known Job Board — immediate classification
  if (JOB_BOARDS.test(compName)) return 'Job Board';

  // Priority 2: Known Staffing/Recruiting agency
  if (STAFFING_AGENCIES.test(compName)) return 'Staffing/Recruiting';

  // Priority 3: Detect staffing from description patterns
  var staffingSignals = 0;
  if (/\b(?:our\s*client\s*(?:is|,)|on\s*behalf\s*of|recruiting\s*for|working\s*with\s*(?:a|an|our)\s*(?:leading|top|major)|we\s*(?:are\s*)?(?:placing|staffing|recruiting))\b/i.test(desc)) staffingSignals += 3;
  if (/\b(?:staffing\s*(?:agency|firm|company)|recruitment\s*(?:agency|firm)|talent\s*(?:acquisition|agency)|placing\s*candidates|contractor\s*role|contract\s*(?:to\s*hire|position)\s*(?:at|with|for))\b/i.test(desc)) staffingSignals += 3;

  var score = { mssp: 0, enterprise: 0, govt: 0, startup: 0, consulting: 0, staffing: staffingSignals };

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

  // Consulting/Staffing signals
  if (/\b(?:consulting|consultancy|advisory|professional\s*services)\b/.test(text)) score.consulting += 4;
  if (/\b(?:staffing\s*(?:agency|firm|company)|recruitment\s*agency)\b/.test(text)) score.staffing += 4;
  if (/\b(?:on\s*behalf\s*of|our\s*client|client\s*site)\b/.test(text)) score.staffing += 3;

  // Find highest score
  var best = '', bestScore = 0;
  var map = { mssp: 'MSSP/MDR', enterprise: 'Enterprise', govt: 'Government', startup: 'Startup', consulting: 'IT Consulting', staffing: 'Staffing/Recruiting' };
  for (var k in score) {
    if (score[k] > bestScore) { bestScore = score[k]; best = map[k]; }
  }
  return bestScore >= 3 ? best : '';
}

// #175: Extract company size from JD
function extractCompanySize(desc) {
  if (!desc) return 0;
  var m = desc.match(/(\d[\d,]+)\s*\+?\s*(?:employees|team\s*members|associates|staff|people|workers)\b/i)
    || desc.match(/(?:team|company|organization|firm)\s*(?:of|with)\s*(?:over\s*|more\s*than\s*)?(\d[\d,]+)\s*\+?\s*(?:employees|people)?/i)
    || desc.match(/(\d[\d,]+)\s*\+?\s*(?:global|worldwide)\s*(?:employees|team)/i);
  if (m) { return parseInt(m[1].replace(/,/g,'')) || 0; }
  return 0;
}

// #153: Extract contract duration from JD
function extractDuration(desc) {
  if (!desc) return '';
  var patterns = [
    // "6-Month Contract" or "6-month initial contract" (hyphenated, optional words between)
    /(\d+)[\s-]+(?:months?|mos?)[\s-]+(?:contract|engagement|assignment|mandate|placement)/i,
    /(\d+)[\s-]+(?:months?|mos?)[\s\w-]{0,20}(?:contract|engagement|assignment|mandate|placement)/i,
    // "(6-Month Contract)" in parentheses
    /\((\d+)[\s-]+(?:months?|mos?)[\s-]*(?:contract|engagement|mandate)?\)/i,
    // "contract of 12 months" or "contract: 6 months"
    /(?:initial\s*)?(?:contract|engagement|assignment|duration|period|length|mandate)\s*(?:of|:)?\s*(\d+)[\s-]*\+?\s*(?:months?|mos?)\b/i,
    // "6 months contract" or "12 month mandate"
    /(\d+)[\s-]*\+?\s*(?:months?|mos?)[\s-]*(?:contract|engagement|assignment|duration|renewable|mandate|placement)\b/i,
    // "onboard a consultant for a 6-month mandate"
    /(?:for\s*a?\s*)(\d+)[\s-]*(?:months?|mos?)[\s-]*(?:contract|mandate|engagement|assignment|period|placement)\b/i,
    // "a 12-month...contract" (month and contract separated by other words)
    /\ba\s+(\d+)[\s-]*(?:months?|mos?)\b[^.]{0,40}\b(?:contract|mandate|engagement)\b/i,
    // Weeks
    /(\d+)[\s-]*\+?\s*(?:weeks?|wks?)[\s-]*(?:contract|engagement|assignment|mandate)\b/i,
    /(?:contract|engagement|mandate)\s*(?:of|:)?\s*(\d+)[\s-]*\+?\s*(?:weeks?|wks?)\b/i,
    // Years
    /(\d+)[\s-]*\+?\s*(?:years?|yrs?)[\s-]*(?:contract|engagement|assignment|mandate)\b/i,
    /(?:contract|engagement|mandate)\s*(?:of|:)?\s*(\d+)[\s-]*\+?\s*(?:years?|yrs?)\b/i,
    // Days
    /(\d+)[\s-]*\+?\s*days?[\s-]*(?:contract|engagement|assignment|mandate)\b/i,
    /(?:contract|engagement|mandate|duration)\s*(?:of|:)?\s*(\d+)[\s-]*\+?\s*days?\b/i,
    // "Duration:\n100 days" or "Duration: 100 days" (multiline)
    /duration\s*:?\s*[\n\r\s]*(\d+)\s*(?:days?|months?|weeks?|years?)\b/i,
  ];
  for (var i = 0; i < patterns.length; i++) {
    var m = desc.match(patterns[i]);
    if (m) {
      var num = m[1];
      if (/week/i.test(m[0])) return num + ' Weeks';
      if (/year/i.test(m[0])) return num + ' Years';
      if (/day/i.test(m[0])) return num + ' Days';
      return num + ' Months';
    }
  }
  return '';
}

// #123: Enrich location with city from JD when API location is sparse
function enrichLocation(job) {
  var loc = [job.job_city, job.job_state, job.job_country].filter(Boolean).join(', ');
  var d = (job.job_description || '').slice(0, 3000);

  // #228: For staffing/recruiting companies, try to extract actual client location from description
  var descLoc = null;
  var clientLocPatterns = [
    /\bclient\s+(?:is\s+)?(?:located\s+)?in\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?\s*,\s*[A-Z]{2})\b/,
    /\bseeking\s+[\w\s]+?\s+in\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?\s*,\s*[A-Z]{2})\b/,
    /\b(?:position|role|opportunity|job|work)\s+(?:is\s+)?(?:located\s+)?in\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?\s*,\s*[A-Z]{2})\b/,
    /\b(?:based|located|working)\s+(?:out\s+of\s+)?(?:in\s+)?([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?\s*,\s*[A-Z]{2})\b/,
    /\b(?:On[\s-]?site|Hybrid)\s+(?:in\s+)?([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?\s*,\s*[A-Z]{2})\b/,
    /\bPlace\s+of\s+Performance\s*:?\s*([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?\s*,\s*[A-Z]{2})\b/i,
    /\bContract\s+position\s+(?:based\s+)?(?:out\s+of\s+)?(?:in\s+)?([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?\s*,\s*[A-Z]{2})\b/,
    /\bLocation\s*[\-–:]\s*([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?\s*,?\s*[A-Z]{2})\b/,
    /\b(?:Sterling|Lake\s+Mary|Huntsville|Manassas|Fort\s+\w+|San\s+\w+|Los\s+\w+|New\s+\w+)\s*,?\s*([A-Z]{2})\b/
  ];
  for (var pi = 0; pi < clientLocPatterns.length; pi++) {
    var pm = d.match(clientLocPatterns[pi]);
    if (pm && pm[1] && pm[1].length > 3 && pm[1].length < 40) {
      var cLoc = pm[1].trim();
      if (!/^(?:Remote|Hybrid|The|This|Our)$/i.test(cLoc)) { descLoc = cLoc; break; }
    }
  }

  // If description location found and differs from JSearch location, prefer description
  if (descLoc) {
    var descCity = descLoc.split(',')[0].trim().toLowerCase();
    var jsCity = (job.job_city || '').toLowerCase();
    if (descCity !== jsCity) {
      // Description location is different — use it (likely the actual work site)
      if (job.job_country) return descLoc + ', ' + job.job_country;
      return descLoc;
    }
  }

  // If we already have a good location (has city), return it
  if (job.job_city && job.job_city.length > 2) return loc || 'Remote';
  // Try to extract city from description
  var cityPatterns = [
    /(?:Location|Office|Based\s*in|Work\s*Location|Job\s*Location|Position\s*Location)\s*:?\s*([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?(?:\s*,\s*[A-Z][a-z]+)?)/,
    /(?:Location|Office)\s*:?\s*([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)\s*\(/,
    /(?:Onsite|On-site|Hybrid)\s*(?:[\-–]\s*)?([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)/,
  ];
  for (var i = 0; i < cityPatterns.length; i++) {
    var m = d.match(cityPatterns[i]);
    if (m && m[1] && m[1].length > 2 && m[1].length < 40) {
      var city = m[1].trim();
      if (/^(?:Remote|Hybrid|The|This|Our|Full|Part|Any|Not|See|TBD)$/i.test(city)) continue;
      if (job.job_country) return city + ', ' + job.job_country;
      return city;
    }
  }
  return loc || 'Remote';
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
      var fullText = (job.job_title || '') + ' ' + desc + ' ' + (job.job_highlights?.Qualifications || []).join(' ') + ' ' + (job.job_highlights?.Responsibilities || []).join(' ');
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
      // #63: Build company URL - use employer_website if available
      var companyWebUrl = job.employer_website || '';
      // #221: If no website or it's clearly wrong, try to extract domain from emails in description
      if (!companyWebUrl || companyWebUrl.indexOf('google.com/search') > -1) {
        var emailMatch = desc.match(/[\w.+-]+@([\w-]+\.[\w.]+)/gi);
        if (emailMatch) {
          var companyNameLower = actualCompany.toLowerCase().replace(/[^a-z0-9]/g, '');
          for (var ei = 0; ei < emailMatch.length; ei++) {
            var emailDomain = emailMatch[ei].split('@')[1].toLowerCase();
            // Skip generic email providers
            if (/^(?:gmail|yahoo|hotmail|outlook|aol|icloud|protonmail|mail|live|msn)\./.test(emailDomain)) continue;
            // Check if domain looks related to company name (at least 3 chars match)
            var domainBase = emailDomain.split('.')[0].replace(/[^a-z0-9]/g, '');
            if (companyNameLower.indexOf(domainBase) > -1 || domainBase.indexOf(companyNameLower.slice(0, Math.max(4, companyNameLower.length * 0.4))) > -1) {
              companyWebUrl = 'https://' + emailDomain;
              break;
            }
          }
        }
      }
      if (!companyWebUrl) {
        companyWebUrl = 'https://www.google.com/search?q=' + encodeURIComponent(actualCompany + ' official website');
      }
      return {
        idx: i + 1, id: job.job_id,
        date: job.job_posted_at_datetime_utc ? new Date(job.job_posted_at_datetime_utc).toLocaleDateString('en-US') : 'N/A',
        dateRaw: job.job_posted_at_datetime_utc || '',
        title: job.job_title || 'N/A', titleClean: (function(){ var tc=cleanTitle(job.job_title); var dur=extractDuration((job.job_title||'')+' '+desc); return (dur&&!/\d+\s*(?:month|week|year)/i.test(tc))?tc+' - '+dur:tc; })(), company: actualCompany,
        companyType: classifyCompany(actualCompany, desc),
        companySize: extractCompanySize(desc),
        companyUrl: companyWebUrl,
        location: enrichLocation(job),
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
        contractDuration: extractContractDuration(desc),
        remote: detectRemote(job),
        applyLink: job.job_apply_link || '', description: desc,
        qualifications: job.job_highlights?.Qualifications || [],
        responsibilities: job.job_highlights?.Responsibilities || [],
        benefits: job.job_highlights?.Benefits || []
      };
    });

    // #167: Filter out non-cybersecurity jobs (e.g., mental health "Incident Responder")
    jobs = jobs.filter(function(j) {
      var text = (j.title + ' ' + j.description).toLowerCase();
      var titleOnly = (j.title || '').toLowerCase().replace(/\bwith\s+security\s+clearance\b/gi, '').replace(/\bsecurity\s+clearance\b/gi, '').trim();
      // Non-IT job title indicators (including military/defense/clearance roles)
      var nonITTitle = /\b(?:compensation\s*analyst|benefits\s*analyst|payroll|human\s*resources|hr\s*(?:analyst|manager|coordinator|generalist|specialist|director|assistant)|recruiter|talent\s*acquisition|staffing\s*(?:coordinator|specialist)|financial\s*analyst|accountant|bookkeeper|tax\s*(?:analyst|specialist)|auditor(?!\s*(?:security|IT|cyber))|marketing\s*(?:analyst|manager|coordinator|specialist)|sales\s*(?:rep|representative|executive|manager)|real\s*estate|property\s*manager|teacher|professor|instructor|librarian|janitor|custodian|mechanic|plumber|electrician|carpenter|welder|driver|truck\s*driver|warehouse|forklift|cashier|barista|waiter|waitress|chef|cook|bartender|humint|sigint|geoint|masint|imint|all\s*source\s*analyst|program\s*analyst|budget\s*analyst|operations?\s*(?:concept\s*)?analyst|concept\s*analyst|space\s*(?:threat|analyst|operations)|operational\s*concept|weapons?\s*analyst|mission\s*analyst|battle|combat|acquisition\s*analyst|contracts?\s*(?:specialist|analyst)|procurement|customer\s*success|optimizer|maintenance(?!\s*(?:security|cyber))|personnel\s*security|physical\s*security(?:\s*(?:operations|officer|specialist|manager|analyst))?|sap\s*(?:fiori|security|consultant|basis)|supply\s*chain|business\s*operations|action\s*officer|case\s*management|service\s*desk|data\s*entry|administrative|executive\s*assistant|office\s*manager|workday\s*(?:hcm|consultant|architect|developer)|hcm\s*(?:solutions|architect|consultant|analyst)|peoplesoft|oracle\s*(?:hcm|erp|financials)|salesforce\s*(?:admin|developer|consultant)|full[\s-]*stack(?:\s*(?:engineer|developer))?|front[\s-]*end(?:\s*(?:engineer|developer))?|back[\s-]*end(?:\s*(?:engineer|developer))?|software\s*(?:engineer|developer)(?!\s*(?:security|cyber|soc|siem))|web\s*developer|mobile\s*developer|ui[\s\/]*ux\s*(?:designer|developer)|data\s*(?:engineer|scientist)(?!\s*(?:security|cyber))|machine\s*learning\s*engineer|ml\s*engineer|database\s*(?:admin|developer)|devops\s*engineer(?!\s*(?:security|sec)))\b/i;
      if (nonITTitle.test(titleOnly)) return false;
      // #258 #267: Filter physical/personnel security roles (title may say SOC/Security Analyst but description is not cybersecurity)
      if (/\b(?:physical\s*security\s*(?:operations|center|monitoring)|personnel\s*security\s*(?:and|operations|clearance|processing)|clearance\s*(?:processing|adjudication|investigations))\b/i.test(text)) {
        if (!/\b(?:SIEM|EDR|endpoint|malware|intrusion|cyber|threat\s*hunt|vulnerability|penetration|firewall|SOC\s*(?:analyst|engineer))\b/i.test(text)) return false;
      }
      if (/\bphysical\s*security\s*(?:operations|center|monitoring)\b/i.test(text) && /\b(?:alarm\s*monitoring|cctv|access\s*control\s*badge|guard\s*force|patrol|visitor\s*management)\b/i.test(text)) {
        if (!/\b(?:SIEM|EDR|endpoint|malware|intrusion|cyber|threat\s*hunt)\b/i.test(text)) return false;
      }
      // Non-IT description indicators (medical, social work, etc.)
      var nonIT = /\b(?:mental\s*health|licensed\s*(?:therapist|counselor|psychologist|social\s*worker|clinical)|clinical\s*(?:psychologist|therapist|counselor)|marriage\s*and\s*family|behavioral\s*health|psychiatric|therapy\s*session|suicide\s*prevention|substance\s*abuse|addiction\s*treatment|patient\s*care|nursing|registered\s*nurse|medical\s*doctor|physician|pharmacy|paramedic|physical\s*therapy|occupational\s*therapy|speech\s*therapy|dental\s*hygien|veterinar|social\s*work(?:er)?|case\s*manager\s*(?:social|child)|child\s*welfare)\b/i;
      if (!nonIT.test(text)) return true;
      // If has non-IT description signals, check if it also has strong IT/cyber signals
      var cyberSignals = /\b(?:SIEM|SOC\s*(?:analyst|engineer|manager)|cybersecurity|cyber\s*security|information\s*security|infosec|malware|threat\s*(?:hunt|intel|detect)|vulnerability|penetration\s*test|firewall|endpoint\s*(?:detect|protect)|encryption|MITRE|NIST|splunk|sentinel|crowdstrike|EDR|XDR|phishing|ransomware|zero\s*trust|IAM|DLP)\b/i;
      return cyberSignals.test(text); // Keep only if also has cyber keywords
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

      // Query DB for existing company data (type, size, LinkedIn, URL)
      if (uniqueCompanies.length > 0) {
        var existingData = await col.aggregate([
          { $match: { company: { $in: uniqueCompanies } } },
          { $group: {
            _id: '$company',
            companyType: { $first: { $cond: [{ $and: [{ $ne: ['$companyType', ''] }, { $ne: ['$companyType', null] }] }, '$companyType', null] } },
            companySize: { $max: '$companySize' },
            companyLinkedin: { $first: { $cond: [{ $and: [{ $ne: ['$companyLinkedin', ''] }, { $ne: ['$companyLinkedin', null] }] }, '$companyLinkedin', null] } },
            companyUrl: { $first: { $cond: [{ $and: [{ $ne: ['$companyUrl', ''] }, { $ne: ['$companyUrl', null] }, { $not: { $regexMatch: { input: { $ifNull: ['$companyUrl', ''] }, regex: /google\.com\/search/ } } }] }, '$companyUrl', null] } }
          } }
        ]).toArray();

        var companyDataMap = {};
        existingData.forEach(function(e) { companyDataMap[e._id] = e; });

        // Apply existing DB data to new jobs (DB takes priority = manual overrides preserved)
        jobs.forEach(function(j) {
          var cd = companyDataMap[j.company];
          if (!cd) return;
          if (cd.companyType) j.companyType = cd.companyType;
          if (cd.companySize && (!j.companySize || j.companySize === 0)) j.companySize = cd.companySize;
          if (cd.companyLinkedin && !j.companyLinkedin) j.companyLinkedin = cd.companyLinkedin;
          if (cd.companyUrl && (!j.companyUrl || j.companyUrl.indexOf('google.com/search') > -1)) j.companyUrl = cd.companyUrl;
        });
      }

      // #247: Clean non-cybersecurity certs from all jobs before save
      var BAD_CERTS = /^(?:cka|ckad|cks)$/i;
      jobs.forEach(function(j) {
        if (j.certifications && j.certifications !== 'See details') {
          var cleaned = j.certifications.split(/[,\n]+/).map(function(c){return c.trim()}).filter(function(c){return c && !BAD_CERTS.test(c)});
          j.certifications = cleaned.length ? cleaned.join(', ') : 'See details';
        }
      });

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
              source: j.source, jobType: j.jobType, contractDuration: j.contractDuration || '', remote: j.remote, applyLink: j.applyLink,
              companyType: j.companyType || '',
              description: j.description, qualifications: j.qualifications,
              responsibilities: j.responsibilities, benefits: j.benefits
            }, $max: { companySize: j.companySize || 0 },
            $setOnInsert: { status: 'new', companyLinkedin: j.companyLinkedin || '', notes: '', searchedBy: userEmail,
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
