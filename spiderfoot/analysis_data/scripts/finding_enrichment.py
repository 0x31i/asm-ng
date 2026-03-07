"""
finding_enrichment.py — Shared enrichment library for ASM-NG report prompts.

Usage in GROUP prompts:
    import sys
    sys.path.insert(0, './scripts')
    from finding_enrichment import enrich_finding

    lead = f"{vuln_name} was identified on {instance_count} instances across {asset_count} assets: {asset_list}."
    description, recommendation = enrich_finding(vuln_type, lead)

enrich_finding(tab, lead_sentence) returns a (description, recommendation) tuple.
- description  = lead_sentence + ' ' + specific technical context from the library
- recommendation = specific actionable remediation steps for this finding type
If the finding type is not in the library, the originals are returned unchanged.
"""

# ─────────────────────────────────────────────────────────────────────────────
# FINDING SPECIFICATIONS
# Each key is the Tab / Vuln_Type / event type string from the ASM-NG CSV.
# Each value has:
#   'desc_context'  — appended after the auto-generated lead sentence
#   'rec'           — full replacement recommendation (actionable, specific)
# ─────────────────────────────────────────────────────────────────────────────
FINDING_SPECS = {

    # ── CRITICAL ──────────────────────────────────────────────────────────────

    'VULNERABILITY_DISCLOSURE': {
        'desc_context': (
            'Public vulnerability disclosures signal that attackers are explicitly aware of '
            'specific weaknesses in the organization\'s infrastructure. Disclosed vulnerabilities '
            'on bug-bounty platforms (e.g., OpenBugBounty) are frequently targeted by automated '
            'exploitation tools within hours of publication. This finding requires immediate '
            'triage, patch assessment, and remediation prioritization.'
        ),
        'rec': (
            'Immediately retrieve and read the full disclosure report at the listed URL. '
            'Assess whether the organization is currently impacted by the disclosed vulnerability. '
            'If impacted: apply available vendor patches or deploy compensating controls (WAF '
            'virtual patching rule, input validation, authentication strengthening) as an interim '
            'measure. Acknowledge the disclosure to the researcher via the platform within 72 hours '
            '— unacknowledged public disclosures may escalate to full exploit publication. Monitor '
            'threat intelligence feeds for active exploitation of the disclosed issue. Once '
            'remediated, retest the fix and request the researcher verify the closure. Update your '
            'vulnerability disclosure policy (security.txt / responsible disclosure program) to '
            'encourage direct private reporting before public posting.'
        ),
    },

    'BLACKLISTED_IPADDR': {
        'desc_context': (
            'IP addresses appearing on public threat intelligence blacklists have been observed '
            'in spam distribution, botnet command-and-control activity, port scanning, or '
            'brute-force campaigns. Blacklisted IPs trigger automatic rejection by email servers '
            'running DNSBL checks, blocks from enterprise security gateways, and reputational '
            'damage that affects legitimate business traffic and email deliverability.'
        ),
        'rec': (
            'For each affected IP, perform a full blacklist check using MXToolbox '
            '(mxtoolbox.com/blacklists.aspx) and AbuseIPDB (abuseipdb.com) to identify every '
            'active listing and the stated reason. Investigate the root cause before requesting '
            'delisting: check whether the host is infected with malware, acting as an open relay, '
            'serving spam, or part of a botnet (review outbound SMTP logs, firewall egress logs, '
            'and process listings on the host). Remediate the underlying issue first — delist '
            'requests without a fix are reversed quickly. Submit delisting requests to each '
            'applicable list (Spamhaus SBL/XBL/PBL removal page, SORBS delisting form, UCEPROTECT '
            'removal). For email-sending IPs, confirm SPF, DKIM, and DMARC alignment. Implement '
            'automated blacklist monitoring with alerting so future listings are detected within '
            'hours. Estimated delist time: 24–72 hours after root-cause remediation.'
        ),
    },

    'MALICIOUS_IPADDR': {
        'desc_context': (
            'Threat intelligence feeds have flagged these IP addresses as associated with confirmed '
            'malicious activity — including malware command-and-control (C2) infrastructure, botnet '
            'participation, active exploitation campaigns, or prior high-confidence abuse reports. '
            'This is a higher-severity indicator than a standard blacklist listing and warrants '
            'immediate forensic investigation of the affected hosts.'
        ),
        'rec': (
            'Treat each flagged IP as a potential indicator of compromise (IOC). Query VirusTotal '
            '(virustotal.com/gui/ip-address/), Shodan (shodan.io), AbuseIPDB, and Cisco Talos '
            '(talosintelligence.com) for the full threat history and reported indicators. For IPs '
            'you control directly: isolate the host from the network and conduct forensic triage — '
            'check for unauthorized processes, unusual outbound connections (netstat -an), modified '
            'system files, and scheduled tasks or cron jobs. If the IP is shared infrastructure '
            '(CDN edge node, cloud NAT, shared hosting): contact your provider to investigate '
            'co-tenant activity and request a new IP allocation, then update DNS records. Block '
            'flagged IPs at the WAF and perimeter firewall for inbound traffic. File an abuse report '
            'with the hosting provider if activity is confirmed malicious. Implement continuous IP '
            'reputation monitoring via your SIEM or threat intelligence platform.'
        ),
    },

    'LEAKSITE_URL': {
        'desc_context': (
            'Appearances on paste sites, leak forums, or data broker platforms indicate that '
            'organizational data has been collected and published by third parties, often following '
            'a data breach, credential theft, or insider exfiltration event. Leaked data is indexed '
            'and actively queried by threat actors for credential stuffing, targeted phishing, and '
            'extortion campaigns within hours of publication.'
        ),
        'rec': (
            'Immediately access and preserve each leak site URL for forensic review — many '
            'paste/leak posts are deleted or expire quickly. Classify the leaked content by type '
            'and sensitivity: credentials, PII, source code, internal documents, API keys, or '
            'configuration files. For confirmed credential leaks: initiate mandatory password resets '
            'for all affected accounts and enforce MFA. For source code or config file leaks: rotate '
            'every secret, API key, and certificate that may appear in the leaked material — assume '
            'all exposed values are compromised. Engage your legal and compliance teams to assess '
            'breach notification obligations (GDPR Article 33, CCPA, HIPAA Breach Rule). Submit '
            'DMCA/abuse takedown requests to each paste/leak platform. Launch a full incident '
            'response investigation: establish a timeline, identify the exfiltration vector, and '
            'scope the total data exposure. Implement DLP controls and CASB policies to detect '
            'future exfiltration attempts.'
        ),
    },

    # ── HIGH ──────────────────────────────────────────────────────────────────

    'DNS_SPF': {
        'desc_context': (
            'Sender Policy Framework (SPF) DNS records are missing or incorrectly configured '
            'for the identified domains, allowing unauthorized parties to send email that appears '
            'to originate from these domains. Without SPF, phishing and Business Email Compromise '
            '(BEC) emails that spoof your domain bypass basic SMTP authentication checks, damaging '
            'email reputation and enabling targeted attacks against customers, partners, and staff.'
        ),
        'rec': (
            'Create or correct the SPF TXT record in public DNS for each affected domain. '
            'Step-by-step: (1) Enumerate every legitimate mail-sending source: your on-premise '
            'mail server IP(s), cloud email provider (Google Workspace: include:_spf.google.com, '
            'Microsoft 365: include:spf.protection.outlook.com), marketing platforms (Mailchimp, '
            'Salesforce Marketing Cloud, HubSpot — each has a documented SPF include). '
            '(2) Construct the record: "v=spf1 include:provider.com ip4:x.x.x.x -all" — use -all '
            '(hard fail), not ~all (soft fail), once all senders are validated. (3) Keep DNS lookup '
            'count ≤ 10 (RFC 7208 limit) — use SPF flattening tools if needed. (4) Publish the '
            'record and test with: dig TXT yourdomain.com @8.8.8.8 and mxtoolbox.com/spf.aspx. '
            '(5) Complement SPF with DKIM signing (2048-bit RSA minimum) and a DMARC policy '
            '(v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@yourdomain.com). Target DMARC '
            'enforcement: p=reject within 90 days of initial deployment.'
        ),
    },

    'SSL_CERTIFICATE_EXPIRED': {
        'desc_context': (
            'The expired certificate causes browsers to display a blocking security warning '
            '(NET::ERR_CERT_DATE_INVALID), preventing users from accessing the service without '
            'clicking through an explicit security exception. Automated clients, APIs, and mobile '
            'applications that enforce certificate validity will fail outright with TLS handshake '
            'errors. Search engines may also penalize or de-index pages served over an expired '
            'certificate.'
        ),
        'rec': (
            'Renew the expired certificate on the affected host immediately — this is an active '
            'service degradation. For public-facing web services, use an ACME client to automate '
            'renewal going forward. Certbot (certbot.eff.org) with Let\'s Encrypt provides free, '
            'auto-renewing DV certificates: "certbot renew --nginx" or "--apache". For certificates '
            'managed through a commercial CA (DigiCert, Sectigo, GlobalSign): generate a new CSR, '
            'submit for validation, and deploy to all servers, load balancers, and CDN edges in the '
            'chain. Verify the new certificate with: "openssl s_client -connect hostname:443 | '
            'openssl x509 -noout -dates". Implement certificate expiration monitoring with alert '
            'thresholds at 60, 30, and 7 days before expiry. Maintain a certificate inventory to '
            'track all certificates, their owners, and renewal dates.'
        ),
    },

    'SSL_CERTIFICATE_EXPIRING': {
        'desc_context': (
            'Certificates approaching expiration will cause browser security warnings and broken '
            'API connections if not renewed before the deadline. A high count of expiring '
            'certificates suggests that certificate lifecycle management is either manual or absent, '
            'creating a recurring operational risk that will repeat unless automated renewal is '
            'implemented.'
        ),
        'rec': (
            'Prioritize renewal by days-to-expiry — treat any certificate expiring within 14 days '
            'as critical. For each expiring certificate: (1) Run "echo | openssl s_client -connect '
            'hostname:443 -servername hostname 2>/dev/null | openssl x509 -noout -enddate" to '
            'confirm the exact expiry date. (2) For Let\'s Encrypt / ACME certificates: verify '
            'certbot is installed and the renewal cron/systemd timer is active ("certbot renew '
            '--dry-run"). (3) For CA-managed certificates: initiate renewal via your CA portal, '
            'validate domain control, generate a new CSR with 2048-bit RSA or ECDSA P-256, and '
            'deploy to all serving endpoints. (4) After deployment, confirm: "curl -vI '
            'https://hostname 2>&1 | grep -E \'expire|issuer\'". Going forward: implement automated '
            'ACME renewal and set monitoring alerts at 60-day, 30-day, and 7-day pre-expiry '
            'thresholds. Conduct quarterly certificate inventory audits.'
        ),
    },

    'SSL_CERTIFICATE_MISMATCH': {
        'desc_context': (
            'SSL/TLS certificate hostname mismatches cause browsers to block access with '
            'NET::ERR_CERT_COMMON_NAME_INVALID errors. Common causes include a wildcard certificate '
            'not matching a third-level subdomain, a SAN certificate missing a newly added '
            'hostname, or incorrect virtual host / SNI configuration presenting the wrong '
            'certificate to incoming connections.'
        ),
        'rec': (
            'Diagnose each mismatch with: "openssl s_client -connect hostname:443 -servername '
            'hostname 2>/dev/null | openssl x509 -noout -subject -ext subjectAltName". Compare the '
            'CN and SAN list against the requested hostname. Common fixes: (1) If the certificate '
            'lacks the hostname as a SAN: request a new certificate from your CA that includes the '
            'hostname in the SAN field (never use CN-only certificates). (2) If using a wildcard: '
            'wildcards only cover one subdomain level — obtain a SAN or additional wildcard as '
            'needed. (3) If the server presents the wrong certificate despite correct installation: '
            'verify SNI configuration (Nginx: server_name directive; Apache: ServerName + '
            'SSLCertificateFile in the correct VirtualHost; IIS: SNI binding in site bindings). '
            '(4) After deploying the corrected certificate, validate with: "curl -v '
            'https://hostname 2>&1 | grep -E \'subject|SAN|error\'". Set up external SSL monitoring '
            'on all hostnames to alert on future certificate errors immediately.'
        ),
    },

    'PUBLIC_CODE_REPO': {
        'desc_context': (
            'Public code repositories expose organizational source code, configuration, and '
            'potentially hardcoded secrets to anyone with internet access. Threat actors routinely '
            'run automated secret-scanning tools against GitHub organization pages to harvest '
            'credentials within minutes of a public commit. Even "private" logic embedded in '
            'frontend bundles is accessible and can be deobfuscated.'
        ),
        'rec': (
            'Immediately audit all identified public repositories for sensitive data using automated '
            'secret-scanning tools: run truffleHog ("trufflehog github --org=<orgname>"), gitleaks '
            '("gitleaks detect --source=<repo_path> --report-format=json"), or enable GitHub\'s '
            'own secret scanning (Settings → Security → Secret scanning). For any secrets found — '
            'including in git history: rotate the credential immediately (assume it is compromised), '
            'then purge from git history using BFG Repo Cleaner or "git filter-repo '
            '--invert-paths --path <secret_file>". Evaluate each public repository\'s necessity '
            'for public access: convert any repo containing internal tooling, proprietary '
            'algorithms, or org-specific configuration to private. Implement pre-commit hooks with '
            'secret detection in all developer environments. Enable GitHub Advanced Security or '
            'equivalent org-level secret scanning with push protection. Establish a written policy '
            'defining repository visibility classification.'
        ),
    },

    'BLACKLISTED_INTERNET_NAME': {
        'desc_context': (
            'Domain names appearing on DNS-based blacklists (DBLs), URL reputation lists, or '
            'web-filtering blocklists have typically been flagged for malware distribution, phishing '
            'page hosting, spam sending, or past compromise. A blacklisted domain causes browser '
            'security interstitials (Google Safe Browsing warning), email delivery failures, and '
            'blocks from enterprise security gateways using web-filtering products.'
        ),
        'rec': (
            'Look up each blacklisted domain on: Google Safe Browsing Transparency Report '
            '(transparencyreport.google.com/safe-browsing/search), Cisco Talos '
            '(talosintelligence.com), Spamhaus DBL (spamhaus.org), and Sucuri SiteCheck '
            '(sitecheck.sucuri.net). Identify the listing reason and date. Investigate whether '
            'the domain was actively compromised: check for injected malicious content, unauthorized '
            'DNS record changes, or abuse by a co-tenant on shared hosting. If compromised: restore '
            'from a clean backup, patch the vulnerability that enabled access (CMS/plugin update, '
            'credential reset), and run a server-side malware scan (ClamAV, Maldet). Submit '
            'delisting requests: Google Safe Browsing review takes 1–3 business days after cleanup; '
            'Spamhaus DBL removal requires completing the hosted removal form. Implement domain '
            'reputation monitoring via Google Search Console alerts going forward.'
        ),
    },

    'MALICIOUS_COHOST': {
        'desc_context': (
            'The organization\'s domains share IP address space with hosts flagged as malicious by '
            'threat intelligence feeds. In shared hosting environments, malicious activity '
            'originating from co-hosted sites can cause IP-level blocks that affect all tenants on '
            'the shared IP. It may also indicate that the hosting provider has weak abuse '
            'enforcement policies, increasing the risk of future contamination.'
        ),
        'rec': (
            'Determine the nature of the shared IP relationship: (1) Check whether the affected '
            'assets are on shared hosting, a CDN edge node, a cloud NAT gateway, or a VPN exit '
            'node — use "dig -x <IP>" and Shodan to enumerate all hostnames on the IP. (2) For '
            'shared hosting: request a dedicated IP allocation from your provider, or migrate to a '
            'VPS, dedicated server, or cloud instance with a dedicated IP. (3) For CDN providers: '
            'CDN providers generally isolate tenant reputations — verify the malicious flag is '
            'against the origin IP, not the CDN IP. If the CDN IP is flagged, contact the '
            'provider\'s abuse team. (4) Contact your hosting provider and report the malicious '
            'co-tenants — request investigation and suspension of offending accounts. (5) Monitor '
            'IP reputation proactively: set up AbuseIPDB and Spamhaus monitoring for your hosting '
            'IPs with alerts on new listings.'
        ),
    },

    'EMAILADDR_COMPROMISED': {
        'desc_context': (
            'Email addresses associated with the organization have appeared in publicly known data '
            'breach datasets, meaning the corresponding account credentials have been exposed to '
            'threat actors. Compromised credentials are the #1 initial access vector in enterprise '
            'breaches: attackers use automated credential-stuffing tools to test breach data against '
            'corporate VPN, email, SSO, and cloud services within hours of a breach disclosure.'
        ),
        'rec': (
            'Initiate mandatory password resets for all identified compromised accounts immediately '
            '— do not wait for users to self-service. Steps: (1) Cross-reference each compromised '
            'email with the HaveIBeenPwned API (haveibeenpwned.com/API/v3) or your identity '
            'provider\'s breach detection (Entra ID Identity Protection, Okta ThreatInsight) to '
            'identify which specific breaches apply and what data was included. (2) Force password '
            'reset via your identity provider admin console and require MFA enrollment before the '
            'reset is accepted. Enforce FIDO2/WebAuthn hardware keys or authenticator apps — not '
            'SMS OTP. (3) Audit login activity for each account over the past 90 days: look for '
            'anomalous sign-in locations, unusual times, or new device enrollments. (4) Identify '
            'any compromised accounts with privileged roles (admin, finance, HR, IT) and treat '
            'those as incident response priority — suspend and investigate before reactivating. '
            '(5) Deploy a ban-password list containing known breach passwords and enforce it in '
            'your identity provider. (6) Run periodic HIBP API checks integrated into your '
            'identity governance process for ongoing monitoring.'
        ),
    },

    'MALICIOUS_EMAILADDR': {
        'desc_context': (
            'Email addresses associated with the organization\'s domain have been flagged on threat '
            'intelligence platforms as connected to malicious activity — potentially spam campaigns, '
            'phishing distribution, or confirmed abuse reports. This can result from account '
            'compromise and weaponization, a misconfigured mail relay being used without '
            'authorization, or false-positive listings from aggregator feeds.'
        ),
        'rec': (
            'For each flagged email address: (1) Query the specific threat intelligence source to '
            'determine the listing reason, severity, and date range of reported activity '
            '(AbuseIPDB, Spamhaus, emailrep.io). (2) Investigate the associated mail account for '
            'compromise indicators: review sent-mail logs for high volume, unusual recipients, '
            'after-hours sending patterns, or auto-forwarding rules to external addresses. '
            '(3) If the account appears compromised: reset credentials immediately, revoke all '
            'active sessions, remove suspicious mail rules or forwarding configurations, and enable '
            'MFA. (4) Check your mail server for open relay configuration: run "telnet '
            'yourmail.domain.com 25" and attempt to relay to an external address — if it succeeds, '
            'immediately restrict relay to authenticated users only. (5) If the listing is a false '
            'positive: document the evidence and submit a dispute to each listing service. '
            '(6) Implement DMARC with p=quarantine or p=reject to prevent domain spoofing from '
            'contributing to future malicious-sender listings for your domain.'
        ),
    },

    'MALICIOUS_PHONE_NUMBER': {
        'desc_context': (
            'Phone numbers associated with the organization are flagged in spam, fraud, or threat '
            'intelligence databases. Flagged numbers are leveraged in vishing (voice phishing) and '
            'smishing (SMS phishing) campaigns impersonating the organization, and phone numbers '
            'used as MFA factors are targets for SIM-swapping attacks where attackers socially '
            'engineer carriers to transfer the number to attacker-controlled SIM cards.'
        ),
        'rec': (
            'Verify ownership and investigate each flagged number: (1) Check on Truecaller '
            '(truecaller.com) and SpamCalls (spamcalls.net) to identify the nature and source of '
            'the reports. (2) Confirm the number is legitimately under organizational control — '
            'contact your telecom carrier if you suspect unauthorized porting or spoofing. '
            '(3) If the number is being spoofed in outbound scam calls: report to the FTC '
            '(reportfraud.ftc.gov) and your carrier\'s abuse/fraud team; request STIR/SHAKEN '
            'attestation enforcement from your carrier. (4) If the number is used as an SMS MFA '
            'factor: transition those accounts to authenticator app or FIDO2 hardware key MFA '
            'immediately — phone-based MFA is vulnerable to SIM-swapping. (5) Alert '
            'customer-facing staff (support lines, reception) that social engineers may reference '
            'organizational phone numbers to build trust — train on call-back verification '
            'procedures.'
        ),
    },

    'INTERESTING_FILE': {
        'desc_context': (
            'A file accessible from the organization\'s web infrastructure has been identified as '
            'potentially sensitive based on its filename, path, or content type. Publicly '
            'accessible sensitive files — such as backup archives, configuration files, exported '
            'data, or administrative scripts — are a frequent and high-impact finding in web '
            'application assessments.'
        ),
        'rec': (
            'Access and review the identified file immediately to determine its content and '
            'sensitivity. If the file contains credentials, API keys, internal data, or '
            'configuration details: rotate any exposed secrets immediately and treat them as fully '
            'compromised. Remove the file from public web accessibility via server configuration '
            '(deny by extension in Apache/Nginx, or delete from the web root). Audit the web '
            'server for similar file types that should not be public: search for *.bak, *.sql, '
            '*.zip, *.tar.gz, *.config, *.env, *.log in web-accessible directories. Disable '
            'directory listing on all web server directories (Apache: "Options -Indexes", '
            'Nginx: "autoindex off"). Review server access logs for prior downloads to assess '
            'who may have accessed the file. Implement a pre-deployment checklist that explicitly '
            'checks for and removes sensitive file types before any web deployment.'
        ),
    },

    'INTERNAL_IP_ADDRESS': {
        'desc_context': (
            'Private (RFC 1918) IP addresses from the internal network have been exposed in '
            'publicly accessible content — such as DNS records, SSL certificate SANs, HTTP '
            'response headers (X-Forwarded-For, X-Real-IP), JavaScript source files, or '
            'application error messages. Internal IP disclosure gives attackers actionable network '
            'topology intelligence useful for lateral movement planning and circumventing network '
            'segmentation assumptions.'
        ),
        'rec': (
            'Identify the specific disclosure vector for each internal IP. Remediation by vector: '
            '(1) HTTP headers: configure your load balancer or reverse proxy to strip internal '
            'addressing headers before they reach clients (Nginx: "proxy_hide_header X-Real-IP;", '
            'Apache: "Header unset X-Forwarded-For"). (2) SSL certificate SANs: regenerate '
            'certificates using only publicly reachable FQDNs as SANs — internal IPs and RFC 1918 '
            'addresses must not appear in public-facing certificates. (3) DNS records: ensure '
            'split-horizon DNS is configured so internal zone records are not resolvable from the '
            'public internet. (4) Application error pages: configure custom error handlers that '
            'return generic messages without stack traces or internal addressing. '
            '(5) JavaScript/HTML source: review client-side code for hardcoded internal endpoints '
            'and remove them in the build pipeline.'
        ),
    },

    'URL_PASSWORD': {
        'desc_context': (
            'Authentication credentials or tokens have been detected embedded in URL query string '
            'parameters. Passwords and session tokens in URLs are written to web server access '
            'logs, browser history, bookmark stores, proxy access logs, and transmitted in HTTP '
            'Referer headers to any third-party resource loaded on the subsequent page — making '
            'them accessible to anyone with log access, browser sharing, or proxy visibility.'
        ),
        'rec': (
            'Immediately rotate all passwords and tokens found in URLs — assume they are fully '
            'compromised due to log exposure. Audit server access logs, proxy logs, and SIEM log '
            'sources for the affected URL patterns to determine the scope of exposure. Refactor '
            'the affected authentication flows: credentials must be transmitted via POST request '
            'body parameters or HTTP Authorization header (Bearer token per RFC 6750), never in '
            'URL query strings. For API authentication: enforce "Authorization: Bearer <token>" '
            'header and explicitly reject token query parameters in your API gateway. Implement a '
            'WAF rule to detect and alert when common credential parameter names appear in query '
            'strings (password=, passwd=, pwd=, token=, secret=). Configure your web server to '
            'redact sensitive query parameters from access logs going forward.'
        ),
    },

    'WEBSERVER_TECHNOLOGY': {
        'desc_context': (
            'Web server banners and HTTP response headers are disclosing detailed technology '
            'information, including server type and version numbers. Technology version disclosure '
            'enables automated vulnerability targeting: attackers can cross-reference the disclosed '
            'version against CVE databases and public exploit repositories to identify applicable '
            'exploits without any further active probing.'
        ),
        'rec': (
            'Suppress technology disclosure across all web servers and application frameworks. '
            '(1) Apache httpd: set "ServerTokens Prod" and "ServerSignature Off" in httpd.conf — '
            'reduces the Server header to just "Apache" with no version. (2) Nginx: set '
            '"server_tokens off" in the http{} block of nginx.conf. (3) IIS: remove the Server '
            'header via URL Rewrite outbound rule and use IIS Crypto to configure cipher suites. '
            '(4) ASP.NET: remove X-Powered-By, X-AspNet-Version, X-AspNetMvc-Version in '
            'web.config: "<httpRuntime enableVersionHeader=\\"false\\"/>". (5) PHP: set '
            '"expose_php = Off" in php.ini. After configuration changes, verify with: '
            '"curl -sI https://hostname | grep -iE \'server|x-powered|x-aspnet\'" — the Server '
            'header should return only a generic value or be absent. Place a WAF or CDN in front '
            'of origin servers to mask backend technology details at the edge. Conduct quarterly '
            'header audits to catch regressions from application updates.'
        ),
    },

    # ── MEDIUM ────────────────────────────────────────────────────────────────

    'DOMAIN_NAME': {
        'desc_context': (
            'Domain names associated with the organization have been enumerated through DNS '
            'resolution, certificate transparency logs, and passive DNS databases. The full domain '
            'inventory may include forgotten subdomains, legacy development environments, shadow IT, '
            'and third-party-managed domains that are not under active security oversight or '
            'included in the vulnerability management program.'
        ),
        'rec': (
            'Maintain a living domain asset inventory: (1) Validate every discovered domain against '
            'your official domain registry — flag any unknown domains for investigation (potential '
            'shadow IT, forgotten acquisitions, or unauthorized registrations). (2) Check all '
            'domains for DNSSEC enablement — enable DNSSEC signing on authoritative zones to '
            'prevent DNS cache poisoning. (3) Identify domains with dangling CNAME records pointing '
            'to deprovisioned cloud services (Azure, AWS, Heroku, GitHub Pages) — these are '
            'subdomain takeover vulnerabilities that must be removed immediately. Use '
            '"can-i-take-over-xyz" (github.com/EdOverflow/can-i-take-over-xyz) as a reference. '
            '(4) Ensure all domains have auto-renew enabled and current registrant contact '
            'information. (5) Incorporate all discovered domains into your vulnerability scanning '
            'and monitoring program. (6) Schedule quarterly domain discovery scans.'
        ),
    },

    'DOMAIN_REGISTRAR': {
        'desc_context': (
            'Domain registrar information for organizational domains has been collected. The '
            'registrar holds authority to modify DNS records, transfer domain ownership, and manage '
            'contact information — making registrar account compromise one of the highest-impact '
            'attacks an organization can face. Social engineering targeting registrar support staff '
            '(citing WHOIS contact data as "proof of ownership") is a documented and successful '
            'attack vector for domain hijacking.'
        ),
        'rec': (
            'Harden all registrar accounts immediately: (1) Enable Registrar Lock (transfer lock) '
            'on every domain — this prevents unauthorized transfers even if the registrar account '
            'is compromised. (2) Request Registry Lock (EPP clientTransferProhibited + '
            'serverTransferProhibited status codes) from your registrar for critical domains — '
            'Registry Lock requires out-of-band phone verification to unlock. (3) Enable '
            'two-factor authentication on all registrar accounts using an authenticator app (not '
            'SMS). (4) Use a dedicated monitored mailbox (domains@yourcompany.com) for registrar '
            'account notifications — never a personal address. (5) Review and update authorized '
            'contacts for each domain; remove any former employees. (6) Consider consolidating all '
            'domains to an enterprise registrar (CSC, MarkMonitor, Corporate Domains) that offers '
            'enhanced security controls including domain monitoring and change alerting.'
        ),
    },

    'ACCOUNT_EXTERNAL_OWNED': {
        'desc_context': (
            'External accounts and digital profiles associated with the organization\'s domain have '
            'been identified across third-party platforms. The high count suggests a broad and '
            'potentially unmanaged external presence spanning SaaS tools, social platforms, '
            'developer services, and business directories. Unmanaged external accounts can be '
            'hijacked after employee departure, used to host malicious content, or may store '
            'organizational data in platforms that have not been reviewed for security or '
            'compliance.'
        ),
        'rec': (
            'Conduct an external account audit: (1) Classify each account as: Official (actively '
            'managed by IT/Marketing), Dormant (previously used, now inactive), Shadow IT '
            '(employee-created without IT oversight), or Potential impersonation. (2) For dormant '
            'accounts: formally deactivate or delete them — dormant accounts with organizational '
            'email credentials are prime hijacking targets if passwords have not been rotated since '
            'the employee left. (3) For shadow IT accounts: bring under IT governance or '
            'decommission. (4) For all active accounts: enable MFA, store credentials in a shared '
            'organizational password vault (not personal accounts), and establish account ownership '
            'by role. (5) Review each platform\'s terms of service regarding data ownership and '
            'export options. (6) Implement an offboarding checklist that explicitly transfers or '
            'deactivates all external accounts when an employee leaves.'
        ),
    },

    'APPSTORE_ENTRY': {
        'desc_context': (
            'Mobile application entries in public app stores (Apple App Store, Google Play) have '
            'been identified for the organization. App store presence expands the attack surface '
            'to include mobile-specific vulnerabilities: insecure data storage, insufficient '
            'transport layer security, weak authentication, and reverse engineering of compiled '
            'app code to extract API keys or business logic. Fake or cloned apps impersonating '
            'the organization can also be used for credential harvesting against customers.'
        ),
        'rec': (
            'Conduct a mobile application security audit: (1) Verify all identified app store '
            'listings are officially published by the organization — report any unauthorized or '
            'counterfeit apps via Apple\'s Report a Problem or Google Play\'s policy violation '
            'report form. (2) Perform mobile application security testing (MAST) per OWASP Mobile '
            'Security Testing Guide on the current production release: focus on M1 (improper '
            'credential usage), M3 (insecure authentication), and M5 (insecure communication). '
            '(3) Implement certificate pinning to prevent MITM attacks. (4) Ensure app binaries '
            'do not contain hardcoded API keys, passwords, or internal endpoint URLs — use device '
            'keychain/keystore and server-side token issuance instead. (5) Enable Google Play '
            'Protect scanning and subscribe to Apple Developer security advisories.'
        ),
    },

    'EMAILADDR': {
        'desc_context': (
            'A large volume of organizational email addresses has been enumerated from public web '
            'content, LinkedIn, GitHub repositories, and other publicly indexed sources. A '
            'comprehensive email directory enables precisely targeted phishing campaigns, password '
            'spray attacks against known usernames, and credential stuffing. The breadth of '
            'exposure indicates that threat actors can readily construct a near-complete staff '
            'email list without any active probing.'
        ),
        'rec': (
            'Reduce email enumeration exposure and harden defenses: (1) Replace mailto: links on '
            'public-facing web pages with contact forms. Where email display is required, encode '
            'addresses in JavaScript. (2) Review LinkedIn org page settings: limit member '
            'directory visibility to logged-in LinkedIn users only if not required for recruiting. '
            '(3) Cross-reference exposed addresses with breach data (EMAILADDR_COMPROMISED finding) '
            'and initiate resets for any overlap. (4) Deploy advanced anti-phishing controls: '
            'Microsoft Defender for Office 365 P2 (or equivalent) with impersonation detection, '
            'lookalike domain protection, and SafeLinks URL detonation. (5) Run quarterly phishing '
            'simulation exercises targeting the exposed address pool using KnowBe4, Proofpoint '
            'Security Awareness, or GoPhish. (6) Implement a consistent offboarding process: '
            'immediately disable email accounts upon termination.'
        ),
    },

    'HASH': {
        'desc_context': (
            'Cryptographic hash values associated with the organization have been identified in '
            'public sources. These may represent software file hashes (version fingerprinting), '
            'password hashes from a database breach, or API/session token digests. Password hash '
            'exposure is the most critical scenario: modern GPU-based cracking hardware can '
            'recover common passwords from MD5 or SHA-1 hashes in seconds to minutes.'
        ),
        'rec': (
            'Determine the type and origin of each hash: (1) If password hashes: immediately force '
            'password resets for all potentially affected accounts, audit the source of the hash '
            'exposure (database dump in git history, public S3 bucket, log file), and verify your '
            'password storage implementation uses a memory-hard hashing algorithm (bcrypt cost '
            'factor ≥ 12, Argon2id, or PBKDF2 with ≥ 600,000 SHA-256 iterations per NIST '
            'SP 800-132). MD5 and SHA-1 password hashes must be considered plaintext-equivalent. '
            '(2) If file integrity hashes or software fingerprints: assess whether they reveal '
            'version information useful for CVE targeting and strip version hashes from public '
            'responses. (3) If API or session tokens expressed as hashes: rotate all affected '
            'tokens immediately. Audit git history for any committed hash values using gitleaks '
            'or truffleHog.'
        ),
    },

    'HUMAN_NAME': {
        'desc_context': (
            'Employee names have been publicly enumerated from LinkedIn, GitHub, domain WHOIS '
            'records, and indexed web content. A staff directory combined with organizational '
            'roles enables highly targeted spear-phishing, BEC (Business Email Compromise) attacks '
            'impersonating executives, and social engineering campaigns against finance, HR, and IT '
            'personnel — the highest-value targets for wire fraud and privilege escalation.'
        ),
        'rec': (
            'Implement layered defenses against social engineering enabled by name exposure: '
            '(1) Conduct targeted security awareness training focused on spear-phishing and BEC '
            'for employees whose names are highly visible — especially executives, finance '
            'controllers, HR, and IT admins. Train users to recognize "urgent wire transfer" and '
            '"change of bank account" BEC patterns. (2) Implement a strict callback verification '
            'policy: all wire transfers, payment instruction changes, and sensitive data disclosures '
            'must be confirmed via a pre-established phone number from the internal directory, not '
            'from a number in the requesting email. (3) Deploy executive impersonation detection '
            'in your email gateway (Defender for Office 365, Proofpoint TAP) to flag emails '
            'mimicking C-suite display names. (4) Enable WHOIS privacy on all domain registrations. '
            '(5) Audit your public website and documents for unnecessary name disclosure and remove '
            'or generalize where not needed. (6) Update incident response procedures to include a '
            'BEC/wire fraud playbook with clear escalation paths.'
        ),
    },

    'USERNAME': {
        'desc_context': (
            'Usernames associated with organizational accounts have been identified from public '
            'sources including social media profiles, GitHub commits, forum posts, and breach '
            'databases. Known usernames dramatically reduce the effort required for credential '
            'attacks: automated credential-stuffing tools can test a known username against '
            'thousands of password candidates per second using breach-derived wordlists.'
        ),
        'rec': (
            'Neutralize the credential attack risk from username enumeration: (1) Enforce MFA on '
            'all external-facing services — a known username is useless to an attacker if MFA is '
            'required. Prioritize VPN, webmail, SSO portal, and admin interfaces. (2) Implement '
            'account lockout and rate limiting on all authentication endpoints: minimum 5-attempt '
            'lockout window with progressive delay, plus CAPTCHA after 3 failed attempts. '
            '(3) Deploy a credential-stuffing-aware WAF rule matching high-frequency login attempts '
            'from diverse IP ranges. (4) Enable identity provider threat intelligence: Entra ID '
            'Identity Protection or Okta ThreatInsight to automatically block sign-ins matching '
            'known attack patterns. (5) Audit login pages for username enumeration vulnerabilities: '
            'responses for valid vs. invalid usernames must be identical ("Invalid credentials" — '
            'not "User not found" vs. "Wrong password"). (6) Review all discovered usernames '
            'against your Active Directory/Okta user list — deactivate any accounts for departed '
            'employees immediately.'
        ),
    },

    'PGP_KEY': {
        'desc_context': (
            'PGP public keys linked to organizational email addresses have been found on public '
            'keyservers (keys.openpgp.org, pgp.mit.edu, keyserver.ubuntu.com). While public keys '
            'are designed for distribution, their presence confirms email addresses, reveals key '
            'creation dates, and may expose organizational structure through key signing '
            'relationships. Expired or abandoned keys on keyservers can cause encryption failures '
            'for senders trying to securely communicate with the organization.'
        ),
        'rec': (
            'Audit all discovered PGP keys: (1) Classify each key as current (active, valid, in '
            'use), stale (valid but unused), expired (past expiry), or orphaned (associated with '
            'a former employee or retired system). (2) For expired or abandoned keys: publish '
            'revocation certificates to all major keyservers — generate with "gpg --gen-revoke '
            '<key-id>" and upload. (3) For keys linked to former employee email addresses: ensure '
            'the corresponding email accounts are deactivated and the keys are revoked. '
            '(4) Establish a PGP key management policy: minimum key size (RSA 4096-bit or '
            'Ed25519), mandatory expiration (2-3 year maximum), and a key escrow process for '
            'organizational continuity. (5) Store organizational PGP private keys in a hardware '
            'security module (HSM) or encrypted key vault — never on individual developer '
            'workstations without passphrase protection.'
        ),
    },

    'PHONE_NUMBER': {
        'desc_context': (
            'Business phone numbers have been collected from website listings, WHOIS records, and '
            'business directories. Publicly listed phone numbers enable vishing (voice phishing) '
            'attacks against staff, caller ID spoofing for organizational impersonation, and '
            'smishing (SMS phishing) campaigns. Phone numbers used as MFA factors are also targets '
            'for SIM-swapping attacks.'
        ),
        'rec': (
            'Audit all exposed phone numbers and implement protective controls: (1) Classify each '
            'number: main business line (intentionally public), support/helpdesk line (appropriate '
            'for public), individual employee number (should typically not be public). (2) Remove '
            'personal/mobile employee numbers from public websites, LinkedIn, and WHOIS records — '
            'replace with role-based contact forms or generic department numbers. (3) For any '
            'phone numbers used as MFA factors (SMS OTP or voice call): transition affected '
            'accounts to authenticator apps or FIDO2 hardware keys — notify your mobile carrier '
            'to add SIM swap alerts on organizational numbers. (4) Train customer-facing staff '
            '(reception, helpdesk) to verify caller identity before taking action: implement a '
            'callback procedure for any request involving system access, data disclosure, or '
            'financial transactions.'
        ),
    },

    'PHYSICAL_ADDRESS': {
        'desc_context': (
            'Physical office and facility addresses have been gathered from WHOIS records, website '
            'content, and business directories. While primary business addresses are often '
            'intentionally public, data center and server room addresses should never appear in '
            'public records. Physical address disclosure also supports social engineering attacks: '
            'knowing office layout and locations assists tailgating attacks, package-delivery '
            'pretexting, and physical access attempts.'
        ),
        'rec': (
            'Review each disclosed physical address for appropriateness: (1) For data center or '
            'server room addresses: immediately remove from all public registrations (WHOIS, '
            'LinkedIn company page, website "Contact Us" pages) — use a legal/registered agent '
            'address or postal box instead. (2) For WHOIS registrant addresses: enable registrar '
            'privacy service or use your legal entity\'s registered office address. (3) For '
            'publicly disclosed office locations: conduct a physical security review — verify '
            'access control systems (badge readers, mantrap for high-security zones), visitor '
            'management procedures (sign-in, escort requirement), security cameras at entry/exit '
            'points, and secure document disposal. (4) Brief reception and facilities staff on '
            'tailgating prevention: no "piggybacking" through secure doors.'
        ),
    },

    'TCP_PORT_OPEN': {
        'desc_context': (
            'Open network ports have been detected across external infrastructure, defining the '
            'full network perimeter exposure profile. Each open port represents a potential attack '
            'entry point: unnecessary services should be closed at the firewall, exposed management '
            'interfaces are high-value targets for exploitation, and any services running outdated '
            'software with known CVEs require immediate patching priority.'
        ),
        'rec': (
            'Conduct a firewall rule review against the discovered port list. Priority tiers: '
            'CRITICAL — close immediately: database ports exposed to internet (MSSQL 1433, '
            'MySQL 3306, PostgreSQL 5432, MongoDB 27017, Redis 6379, Elasticsearch 9200); these '
            'must never be internet-facing. HIGH — restrict to IP allowlist (VPN/jump host only): '
            'SSH (22), RDP (3389), WinRM (5985/5986), SNMP (161/162), Kubernetes API (6443). '
            'MEDIUM — review and document: non-standard high ports (>1024) that are not recognized '
            'services. For all ports deemed necessary: verify the running service is current on '
            'patches, enforce TLS/mTLS where applicable, and ensure authentication is required. '
            'For cloud environments (AWS/Azure/GCP): audit Security Groups and NSGs for '
            '0.0.0.0/0 or ::/0 inbound rules and remediate. Implement quarterly firewall rule '
            'reviews to retire stale access.'
        ),
    },

    'URL_FORM': {
        'desc_context': (
            'Web forms have been identified across public-facing web applications. Web forms are '
            'primary attack vectors for CSRF, injection attacks (SQL, XSS, SSRF, command '
            'injection), automated abuse (account creation, spam, credential stuffing), and '
            'information harvesting. Each form that accepts and processes user input represents a '
            'trust boundary that requires explicit security validation.'
        ),
        'rec': (
            'Conduct a security review of each identified form: (1) CSRF protection: verify every '
            'state-changing form implements the synchronizer token pattern or uses the '
            'SameSite=Strict or SameSite=Lax cookie attribute as a defense-in-depth measure. '
            '(2) Input validation: implement server-side validation for every form field — define '
            'an allowlist of acceptable input and reject anything that does not match. Client-side '
            'validation is not a security control. (3) Output encoding: all form input redisplayed '
            'to users must be HTML-encoded to prevent reflected XSS. (4) Rate limiting and '
            'CAPTCHA: apply rate limiting to all public forms (login, registration, contact, '
            'password reset) and add hCaptcha or reCAPTCHA v3 to forms targeted for automated '
            'abuse. (5) File uploads: if any form accepts file uploads, restrict accepted MIME '
            'types to an allowlist, scan uploads with ClamAV, and store outside the web root with '
            'randomized filenames. (6) Test all forms for SQL injection using SQLMap or Burp Suite.'
        ),
    },

    'URL_PASSWORD_HISTORIC': {
        'desc_context': (
            'Passwords or authentication tokens embedded in URLs have been found in archived '
            'historical versions of the web application. Web archives such as the Wayback Machine '
            'preserve these URLs indefinitely and are regularly crawled by threat actor tooling '
            'specifically seeking exposed credentials. The pattern of multiple historic instances '
            'suggests this was a systemic design choice rather than an isolated incident — meaning '
            'current versions of the application should also be audited.'
        ),
        'rec': (
            'Treat all historically exposed credentials as compromised regardless of apparent age '
            '— assume they have been harvested. (1) Query the Wayback Machine for each identified '
            'URL pattern to confirm the full scope and duration of historical exposure. '
            '(2) Cross-reference every exposed credential against currently active accounts in '
            'your identity provider — force-reset any matches immediately. (3) Audit your current '
            'application code for the same credential-in-URL pattern: search for "password=", '
            '"passwd=", "pwd=", "token=", "key=" in URL construction code. Refactor to POST body '
            'or Authorization header delivery. (4) Review web server access logs from the '
            'historical exposure period for evidence of credential harvesting. (5) Submit a '
            'request to the Internet Archive to remove specific archived URLs containing '
            'credentials (help@archive.org).'
        ),
    },

    'WEBSERVER_STRANGEHEADER': {
        'desc_context': (
            'Non-standard or anomalous HTTP response headers have been identified across multiple '
            'web assets. Unusual headers can reveal internal infrastructure details (private '
            'hostnames, backend server identifiers, internal IP addresses, software version '
            'strings, debug flags), indicate improperly configured security headers, or expose '
            'sensitive session-related data. Header analysis is a standard first-pass '
            'reconnaissance technique in web application assessments.'
        ),
        'rec': (
            'Audit all identified headers using securityheaders.com and Burp Suite Repeater: '
            '(1) Remove information-leaking headers containing internal hostnames, private IPs, '
            'software version strings, or internal path structures. Common culprits: X-Served-By, '
            'X-Backend-Server, X-Upstream, X-Internal-IP, X-Cluster-Client-IP. (2) Remove '
            'debugging headers: X-Debug, X-Debug-Token, X-Runtime, X-Powered-By, '
            'X-AspNet-Version. (3) Add missing security headers to all responses: '
            'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload, '
            'X-Content-Type-Options: nosniff, X-Frame-Options: DENY, '
            'Referrer-Policy: strict-origin-when-cross-origin, and Permissions-Policy. '
            '(4) Configure your load balancer or reverse proxy to strip outbound '
            'internal-detail headers before they reach clients — defense-in-depth even if '
            'application headers are misconfigured. (5) Validate the header policy after changes '
            'with "curl -sI https://hostname | sort" and recheck monthly after deployments.'
        ),
    },

    'TARGET_WEB_CONTENT': {
        'desc_context': (
            'Public-facing web content has been collected and indexed as part of attack surface '
            'enumeration. Content analysis can reveal internal application structure, API endpoint '
            'patterns, technology stack details embedded in comments or meta tags, error handling '
            'behavior, and sensitive information that should not be publicly accessible (internal '
            'documentation, draft pages, configuration snippets in page source).'
        ),
        'rec': (
            'Review the captured web content for unintentional data exposure: (1) Audit HTML '
            'comments across all pages for internal notes, TODO items, developer debug output, or '
            'infrastructure references — strip all HTML comments from production deployments as '
            'part of your build/minification process. (2) Review JavaScript files for hardcoded '
            'API keys, internal endpoint URLs, or business logic that should be server-side only. '
            '(3) Verify that error pages (404, 403, 500) return generic messages without stack '
            'traces, internal file paths, or database error strings. (4) Check for directory '
            'listing: attempt to access directories without a filename — if a file list is '
            'returned, disable directory browsing immediately. (5) Confirm that content requiring '
            'authentication is enforced server-side: do not rely on navigation restrictions to '
            'hide sensitive pages. (6) Implement a Content Security Policy (CSP) to restrict '
            'script, style, and media sources to approved origins.'
        ),
    },

    'TARGET_WEB_CONTENT_TYPE': {
        'desc_context': (
            'MIME content types served by organizational web applications have been inventoried. '
            'Content type analysis identifies the variety of file formats being served and can '
            'highlight endpoints serving executable content (JavaScript, XML with active content, '
            'SVG) that may be exploitable via MIME type confusion attacks, or responses missing '
            'correct Content-Type headers that enable MIME sniffing by browsers.'
        ),
        'rec': (
            'Review content type security configuration: (1) Set "X-Content-Type-Options: nosniff" '
            'on all HTTP responses to prevent browsers from MIME-sniffing content away from the '
            'declared Content-Type. (2) Ensure every response has an explicit Content-Type header '
            'including character encoding: text/html; charset=UTF-8. (3) For file download '
            'endpoints: add "Content-Disposition: attachment; filename=\\"file.ext\\"" for binary '
            'files to force download rather than browser rendering. (4) For API endpoints: '
            'strictly validate that responses return application/json and that clients verify '
            'the Content-Type before parsing — JSON endpoints returning text/html are a frequent '
            'CSRF and XSS vulnerability source. (5) Implement a Content Security Policy (CSP) '
            'with "default-src \'self\'" to restrict what content types the browser will load '
            'from which origins.'
        ),
    },

    # ── LOW ───────────────────────────────────────────────────────────────────

    'DNS_TEXT': {
        'desc_context': (
            'DNS TXT records across the organization\'s domains have been enumerated. TXT records '
            'serve legitimate authentication purposes (SPF, DKIM, DMARC, domain verification '
            'tokens) but frequently accumulate stale entries over time: verification tokens for '
            'SaaS services no longer in use, test records left by developers, and in rare cases '
            'API keys or internal documentation inadvertently published in DNS.'
        ),
        'rec': (
            'Audit all TXT records across every zone: (1) Identify and remove records that are '
            'no longer needed — a stale domain verification token (google-site-verification, '
            'MS=msXXXXXXXX) for a service you no longer use is unnecessary noise and indicates '
            'shadow IT. (2) Verify SPF records: use MXToolbox\'s SPF checker to confirm the '
            'record is valid, under the 10 DNS lookup limit, and uses -all (hard fail). '
            '(3) Verify DKIM: confirm key records exist for every mail selector in use and that '
            '1024-bit keys are upgraded to 2048-bit minimum. (4) Verify DMARC: confirm a DMARC '
            'record exists, is at minimum p=quarantine, and has rua/ruf reporting addresses '
            'configured. (5) Remove any TXT records containing credentials, API keys, or network '
            'addresses. (6) Document the purpose of every TXT record and schedule quarterly '
            'cleanup reviews.'
        ),
    },

    'DOMAIN_NAME_PARENT': {
        'desc_context': (
            'Parent domain relationships for the organization\'s DNS hierarchy have been mapped. '
            'Parent domain visibility reveals the organizational naming structure and can identify '
            'registrable domain levels that should be owned by the organization but may not be — '
            'leaving them open to squatting or takeover by a third party.'
        ),
        'rec': (
            'Verify all parent domain levels are under organizational control: (1) Check '
            'registration status for each parent domain — ensure the organization owns the correct '
            'TLD combinations for active brands. (2) Enable DNSSEC on all parent zones to prevent '
            'DNS cache poisoning that could redirect traffic for all child subdomains. (3) Check '
            'for domain squatting on adjacent or typo variants of parent domains using dnstwist '
            '(github.com/elceef/dnstwist) — register high-risk typosquats defensively. '
            '(4) Ensure delegation records (NS records) in parent zones point to the correct '
            'authoritative nameservers and have not been tampered with. (5) Confirm auto-renew '
            'is enabled at the registrar for all parent domains — losing a parent domain due to '
            'registration lapse would take down all child subdomains under it.'
        ),
    },

    'DOMAIN_WHOIS': {
        'desc_context': (
            'WHOIS registration records for organizational domains have been collected. WHOIS data '
            'exposes registrant contact details that can include personal names, email addresses, '
            'phone numbers, and physical addresses of domain administrators. This information '
            'enables social engineering attacks targeting registrar accounts and reveals the '
            'identity of individuals who control critical domain infrastructure.'
        ),
        'rec': (
            'Harden WHOIS data across all domains: (1) Enable RDAP/WHOIS privacy protection with '
            'your registrar on all domains where applicable — ICANN mandates privacy options since '
            '2018 GDPR implementation. Most major registrars offer free privacy proxy services. '
            '(2) Replace personal registrant details with organizational contact information: use '
            'a corporate abuse contact email (abuse@yourcompany.com) and your legal registered '
            'business address. (3) Enable change notification alerts via your registrar for all '
            'domains — you should receive an email immediately if any domain contact, nameserver, '
            'or registration detail is modified. (4) Verify all WHOIS data is accurate — outdated '
            'WHOIS data can complicate domain dispute resolution. (5) Review the WHOIS tech '
            'contact and admin contact emails — ensure they map to active monitored mailboxes, '
            'not personal accounts or departed employee addresses.'
        ),
    },

    'SIMILAR_ACCOUNT_EXTERNAL': {
        'desc_context': (
            'External accounts with usernames or handles similar to organizational identities have '
            'been identified across multiple platforms. At scale, a subset will be deliberate brand '
            'squatters or impersonation accounts used to deceive customers, recruit victims for '
            'fraud, or conduct targeted social engineering against employees who follow/connect '
            'with lookalike accounts.'
        ),
        'rec': (
            'Implement a scalable brand impersonation monitoring and response program: (1) '
            'Prioritize by similarity and platform: high-similarity accounts on LinkedIn, '
            'Twitter/X, GitHub, and Facebook warrant immediate manual review — assess profile '
            'photos, bio text, activity, and follower overlap with legitimate accounts. (2) File '
            'trademark/impersonation reports for confirmed impersonators via each platform\'s '
            'abuse mechanism (LinkedIn, Twitter/X, GitHub each have reporting forms). (3) At high '
            'volume, engage a commercial brand protection service (Recorded Future Brand '
            'Intelligence, ZeroFOX, or BrandShield) to automate detection, prioritization, and '
            'takedown workflows. (4) Register your primary organizational handles across all '
            'major platforms defensively — even for services you don\'t use actively — to prevent '
            'future squatting. (5) Publish a "follow the official accounts" page on your website '
            'linking to verified/official profiles to help stakeholders identify legitimate '
            'channels.'
        ),
    },

    'SOCIAL_MEDIA': {
        'desc_context': (
            'Social media accounts linked to the organization\'s domain or brand have been '
            'identified. Social media accounts are a meaningful attack surface: account takeover '
            'through weak credentials or phishing of account managers can enable brand reputation '
            'attacks, misinformation distribution, or customer-targeting fraud campaigns that '
            'appear to originate from a trusted organizational source.'
        ),
        'rec': (
            'Establish social media account security governance: (1) Audit all identified accounts '
            '— verify each is officially controlled by the organization and has a documented owner '
            'and backup access procedure. (2) Enable MFA on every account: use an authenticator '
            'app (not SMS) and store backup codes in a shared organizational vault. (3) Move '
            'account credentials to a shared organizational credential vault (1Password Teams, '
            'Bitwarden Organizations) with role-based access so account access survives employee '
            'turnover. (4) Revoke access for departed employees immediately — make account '
            'offboarding part of the HR departure checklist. (5) Conduct regular (quarterly) '
            'audits of connected third-party applications and integrations — remove any apps that '
            'are no longer needed or have excessive permissions.'
        ),
    },

    'COUNTRY_NAME': {
        'desc_context': (
            'Geographic country data has been resolved for infrastructure assets, providing a map '
            'of the organization\'s global infrastructure distribution. Country attribution is '
            'relevant for identifying infrastructure in unexpected jurisdictions, verifying data '
            'residency compliance, and informing geographic-based threat intelligence policies.'
        ),
        'rec': (
            'Use the country distribution data for defensive purposes: (1) Identify any '
            'infrastructure located in countries outside your expected operational footprint and '
            'investigate: are these authorized CDN nodes, cloud regions, or third-party vendor '
            'infrastructure? Or unexpected assets suggesting shadow IT? (2) For organizations with '
            'data residency requirements (GDPR Article 44, HIPAA, sovereign data laws, FedRAMP): '
            'verify no customer data is processed or stored in unauthorized geographic regions — '
            'cloud providers log data region in the console. (3) Implement geographic-based access '
            'policies in your WAF/firewall: consider geo-blocking inbound traffic from countries '
            'where you have no customers, employees, or operations. (4) Configure your SIEM '
            'geographic anomaly detection rules: flag authentication attempts from high-risk or '
            'unexpected countries for step-up MFA or automatic block.'
        ),
    },

    'GEOINFO': {
        'desc_context': (
            'Detailed geolocation data (city, region, ASN, ISP) has been collected for '
            'infrastructure assets, mapping the organizational infrastructure footprint to hosting '
            'providers and geographic regions. This data is directly usable for infrastructure '
            'correlation and ISP relationship enumeration by threat actors conducting '
            'pre-attack reconnaissance.'
        ),
        'rec': (
            'Leverage geolocation data operationally for defense: (1) Review the ISP and ASN '
            'distribution — investigate any hosting providers or ASNs not in your official '
            'infrastructure inventory. (2) For internet-facing authentication endpoints: configure '
            'geolocation-based anomaly detection in your identity provider (Entra ID Conditional '
            'Access with Named Locations and Sign-in Risk Policy, or Okta Adaptive MFA with '
            'network zone policies) to trigger step-up authentication for logins from unexpected '
            'countries or regions. (3) Use ASN/ISP data to verify all cloud infrastructure is '
            'deployed via your approved accounts and regions — unexpected hosting ASNs may '
            'indicate unauthorized or forgotten cloud deployments. (4) Provide city-level location '
            'data to your SOC team as context for alert enrichment.'
        ),
    },

    'PHYSICAL_COORDINATES': {
        'desc_context': (
            'Approximate GPS coordinates have been derived from IP geolocation databases for '
            'infrastructure assets. While IP geolocation accuracy varies (typically city-level '
            'precision), this data provides approximate physical locations for data centers and '
            'office infrastructure. It is most useful for verifying infrastructure is placed in '
            'expected physical locations and for data residency compliance verification.'
        ),
        'rec': (
            'Use coordinate data to validate infrastructure placement: (1) Cross-reference each '
            'set of coordinates against your approved data center and office locations — '
            'significant mismatches (wrong city or country) may indicate unauthorized '
            'infrastructure. (2) For compliance-sensitive workloads with hard geographic '
            'constraints (GDPR, HIPAA, FedRAMP, ITAR): verify boundary compliance with actual '
            'cloud region data from your provider console, not solely IP geolocation — use '
            'authoritative cloud region documentation for legal compliance. (3) Ensure all data '
            'centers processing sensitive data have appropriate physical security certifications '
            '(SOC 2 Type II, ISO 27001, Tier III/IV ANSI/TIA-942 data center standards).'
        ),
    },

    'SSL_CERTIFICATE_ISSUED': {
        'desc_context': (
            'SSL/TLS certificate issuance history has been compiled from certificate transparency '
            '(CT) logs. CT logs provide a public, tamper-evident audit trail of every certificate '
            'issued by trusted CAs. CT log monitoring is one of the most effective methods for '
            'detecting unauthorized certificate issuance, which can occur after domain compromise '
            'or CA misissuance errors.'
        ),
        'rec': (
            'Conduct a certificate transparency audit and establish ongoing CT monitoring: '
            '(1) Review all identified certificates against your expected certificate inventory — '
            'any unrecognized certificates should be investigated as potential unauthorized '
            'issuance. Query crt.sh (crt.sh/?q=%25.yourdomain.com&output=json) for a complete '
            'picture. (2) Set up real-time CT monitoring alerts (Facebook CT Monitor, Sectigo CT '
            'Watch, or cert-manager\'s certificate monitoring) to alert you within minutes of a '
            'new certificate being issued for your domain. (3) Implement CAA (Certification '
            'Authority Authorization) DNS records to restrict which CAs are authorized to issue '
            'certificates for your domains: "yourdomain.com. IN CAA 0 issue \\"letsencrypt.org\\"". '
            '(4) Revoke any unrecognized or unused certificates via your CA\'s revocation portal. '
            '(5) Identify any certificates using deprecated algorithms (SHA-1 signatures, '
            'RSA < 2048-bit) and plan replacement.'
        ),
    },

    'SSL_CERTIFICATE_ISSUER': {
        'desc_context': (
            'The certification authorities (CAs) responsible for issuing SSL/TLS certificates '
            'to organizational domains have been inventoried. CA diversity reveals whether '
            'certificate management is centrally governed or fragmented — fragmented procurement '
            'across multiple CAs complicates renewal tracking, incident response, and enforcement '
            'of organizational PKI standards.'
        ),
        'rec': (
            'Standardize and harden certificate authority management: (1) Implement CAA DNS '
            'records to restrict certificate issuance to your approved CA(s) for every domain — '
            'this prevents unauthorized certificate issuance from other CAs even during a '
            'temporary DNS compromise. (2) Consolidate certificate procurement: reduce to the '
            'smallest set of CAs that meets your business requirements — fewer CAs means simpler '
            'renewal tracking and a smaller incident response scope. (3) For Let\'s Encrypt / '
            'free CA certificates: ensure automated ACME renewal is configured — manual renewal '
            'of 90-day certificates leads to expiration incidents. (4) Verify all CAs in use '
            'issue certificates meeting your minimum cryptographic standards: RSA 2048-bit or '
            'ECDSA P-256 key, SHA-256 signature algorithm, maximum 1-year validity.'
        ),
    },

    'INTERESTING_FILE_HISTORIC': {
        'desc_context': (
            'A historic file of potential security interest has been found in web archive databases '
            'associated with the organization\'s web presence. Web archives commonly capture files '
            'during the brief window between accidental publication and removal — a scenario common '
            'in development incidents, CMS misconfigurations, or rushed deployments. The content '
            'may include configuration files, backup archives, exported data, or administrative '
            'scripts.'
        ),
        'rec': (
            'Access the archived URL and review its content to determine sensitivity: (1) If the '
            'archived file contains credentials, API keys, connection strings, or sensitive data: '
            'rotate the affected secrets immediately — archive services are indexed by automated '
            'scanners and should be treated as fully public. (2) Determine how the file became '
            'publicly accessible: common causes include deploying backup files to the web root '
            '(*.bak, *.old, *.zip), a developer committing sensitive files to a branch that '
            'gets deployed, or a CMS plugin creating temp files in accessible directories. Fix '
            'the root cause. (3) Submit a takedown request to the Internet Archive '
            '(help@archive.org) referencing the exact archived URL. (4) Audit your current web '
            'root for similar file types: use "find /var/www -name \'*.bak\' -o -name \'*.sql\' '
            '-o -name \'*.zip\' -o -name \'*.env\'" and remove any found.'
        ),
    },

    'SOFTWARE_USED': {
        'desc_context': (
            'Software packages, CMS platforms, and web frameworks have been fingerprinted on the '
            'organization\'s web infrastructure. Software version disclosure reduces attacker '
            'reconnaissance effort to near zero: a disclosed version is immediately '
            'cross-referenceable against NVD/CVE databases and public exploit repositories. Any '
            'identified software with outstanding CVEs should be treated as a prioritized patching '
            'item.'
        ),
        'rec': (
            'Implement a software asset inventory and patch management process: (1) Map each '
            'identified software component to its current version and query the NVD '
            '(nvd.nist.gov) or a vulnerability feed (Tenable, Qualys, Snyk) for outstanding '
            'CVEs. Prioritize: Critical and High CVEs with public exploits must be patched within '
            '72 hours of release. (2) Suppress software version disclosure: see WEBSERVER_TECHNOLOGY '
            'finding for specific header suppression steps. Remove version numbers from HTML meta '
            'generator tags, comments, and error pages. (3) Establish a monthly patch cycle for '
            'all web-facing software. (4) Integrate Software Composition Analysis (SCA) into your '
            'CI/CD pipeline: Dependabot (GitHub), Snyk, or OWASP Dependency-Check will '
            'automatically flag vulnerable dependencies and open PRs/alerts when new CVEs are '
            'published. (5) Where software cannot be immediately patched: implement WAF virtual '
            'patching rules for the specific CVE as a compensating control.'
        ),
    },

    'IP_ADDRESS': {
        'desc_context': (
            'IPv4 addresses associated with the organization have been enumerated, constituting '
            'the complete IPv4 network perimeter. This inventory defines every IP that is '
            'reachable from the internet — each representing a potential entry point. Unrecognized '
            'IPs in the inventory may indicate shadow IT, forgotten cloud instances, or '
            'unauthorized hosting that falls outside the security monitoring and patching program.'
        ),
        'rec': (
            'Use the IP inventory as the basis for perimeter security review: (1) Validate every '
            'identified IP against your official infrastructure inventory (CMDB, cloud console, '
            'network diagram) — flag and investigate any IPs not recognized. (2) For all '
            'internet-facing IPs: ensure each is covered by your vulnerability scanning program '
            'with at least monthly unauthenticated scans and quarterly authenticated scans. '
            '(3) For cloud environments (AWS/Azure/GCP): audit all Elastic IP, Public IP, and NAT '
            'Gateway allocations and release any unattached or unneeded IPs. (4) Cross-reference '
            'all IPs against blacklist and threat intel feeds (see BLACKLISTED_IPADDR and '
            'MALICIOUS_IPADDR findings). (5) Implement a cloud asset discovery tool (AWS Config, '
            'Microsoft Defender for Cloud, GCP Security Command Center) to automatically inventory '
            'new IP allocations and alert on unexpected internet-facing resources.'
        ),
    },

    'IPV6_ADDRESS': {
        'desc_context': (
            'IPv6 addresses have been identified, indicating the organization operates dual-stack '
            '(IPv4 + IPv6) infrastructure. Many organizations have IPv6-enabled infrastructure '
            'without fully extending their IPv4 security controls to IPv6 — firewall rules, '
            'monitoring, and vulnerability scanning that cover IPv4 frequently miss the IPv6 '
            'attack surface entirely, creating security blind spots.'
        ),
        'rec': (
            'Apply equivalent security controls to IPv6 as to IPv4: (1) Audit all firewall, '
            'security group, and WAF rules for IPv6 coverage — in cloud environments, security '
            'groups and NSGs often have IPv4 rules but allow all IPv6 (::/0) by default. Review '
            'and restrict IPv6 inbound rules to match your IPv4 policy. (2) Ensure your '
            'vulnerability scanning program covers IPv6 addresses. (3) Audit DNS AAAA records to '
            'confirm all published IPv6 addresses are intentional — remove AAAA records for '
            'services that do not need to be publicly reachable via IPv6. (4) Verify operating '
            'system and network device IPv6 configurations: disable IPv6 on interfaces where it '
            'is not required. (5) Configure IPv6 DHCPv6 Snooping and Router Advertisement Guard '
            '(RA Guard) on switches to prevent rogue IPv6 router advertisement attacks.'
        ),
    },

    'HTTP_CODE': {
        'desc_context': (
            'HTTP response codes have been collected for web resources across the organization\'s '
            'assets. Response code analysis reveals the behavioral state of web endpoints: 5xx '
            'errors may be leaking internal details, unexpected 200 responses on supposedly '
            'restricted paths may indicate authentication bypass, and unusual redirect chains can '
            'indicate misconfigurations that expose sensitive paths or redirect to unintended '
            'destinations.'
        ),
        'rec': (
            'Review the response code distribution for security implications: (1) For 500-series '
            'errors: test whether error responses include stack traces, exception messages, or '
            'internal path information — if so, configure custom error pages returning generic '
            'messages. (2) For resources returning 200 that should require authentication: conduct '
            'manual verification — test without authentication headers and with manipulated cookies '
            'to confirm server-side enforcement. (3) For redirect chains (301/302): trace each '
            'redirect to its final destination using "curl -L -v https://hostname" — verify no '
            'redirect crosses to unexpected external domains (open redirect risk). (4) For 401/403 '
            'responses: verify that the same generic error is returned for both non-existent '
            'resources and authenticated-only resources to prevent resource enumeration. '
            '(5) Add all identified endpoints to your synthetic monitoring platform to alert on '
            'unexpected response code changes.'
        ),
    },

    'INTERNET_NAME': {
        'desc_context': (
            'A comprehensive enumeration of internet hostnames and subdomains associated with the '
            'organization has been completed. At scale, the inventory likely includes production '
            'services alongside staging and development environments, forgotten legacy hosts, '
            'third-party service verification records, and subdomain takeover candidates (dangling '
            'CNAMEs pointing to deprovisioned cloud resources).'
        ),
        'rec': (
            'Triage the subdomain inventory systematically: (1) Identify all subdomains not in '
            'your official asset inventory — these are the highest-priority items. Investigate '
            'each: determine the business purpose, verify the owner, and decide to document, '
            'harden, or decommission. (2) Check for subdomain takeover vulnerabilities across all '
            'CNAMEs: run each subdomain through subjack or subzy to detect CNAMEs pointing to '
            'unclaimed cloud resources (GitHub Pages, Azure App Service, Heroku, AWS S3, Fastly). '
            'Unclaimed resources must be claimed or the DNS record removed. (3) Identify and '
            'disable/restrict development and staging subdomains that are publicly reachable '
            'without authentication. (4) Implement ongoing subdomain monitoring: certificate '
            'transparency monitoring will alert you to new subdomains within hours of creation. '
            '(5) Review DNS wildcard configurations — wildcard A/CNAME records that resolve to a '
            'single IP can create takeover opportunities for non-existent subdomains.'
        ),
    },

    'URL_JAVASCRIPT': {
        'desc_context': (
            'JavaScript files served by organizational web applications have been identified. '
            'JavaScript files are a primary target for security review: they may contain hardcoded '
            'API keys, internal backend endpoint URLs, access tokens embedded in source code, '
            'debug logic left in production builds, and sensitive business logic that was intended '
            'to be server-side only. Modern bundled JavaScript, while minified, is fully readable '
            'after running through a formatter or source map.'
        ),
        'rec': (
            'Audit JavaScript files for sensitive exposure: (1) Run truffleHog or gitleaks against '
            'your JavaScript build outputs to detect hardcoded API keys, tokens, and credentials. '
            '(2) Review bundled JavaScript for: internal API endpoint paths, environment-specific '
            'configuration that may have been inlined at build time, and hardcoded credentials '
            '(search for "password", "secret", "apikey", "Bearer"). (3) Implement Subresource '
            'Integrity (SRI) for any JavaScript loaded from third-party CDNs: <script src="..." '
            'integrity="sha384-..." crossorigin="anonymous">. SRI ensures CDN-served scripts have '
            'not been tampered with. (4) Configure your JavaScript build pipeline to strip '
            'comments, console.log statements, and debug code from production builds. (5) '
            'Implement a Content Security Policy (CSP) restricting script execution to approved '
            'sources. (6) Never implement authorization logic in client-side JavaScript — always '
            'enforce access controls server-side.'
        ),
    },

    'URL_STATIC': {
        'desc_context': (
            'Static resource URLs (CSS, images, fonts, static downloads) served from '
            'organizational infrastructure have been enumerated. While most static resources are '
            'intentionally public, their enumeration reveals CDN and storage backend configuration '
            'and may include inadvertently deployed sensitive documents, configuration files, or '
            'backup archives left in web-accessible directories.'
        ),
        'rec': (
            'Review the enumerated static content for security concerns: (1) Scan web-accessible '
            'directories for files that should not be public: backup files (*.bak, *.old, *.sql, '
            '*.tar.gz, *.zip), configuration files (*.env, *.config, *.ini, *.yml with secrets), '
            'and editor files (*.swp). Remove any found immediately. (2) Disable directory listing '
            'on all web server directories: Apache: "Options -Indexes" in .htaccess, '
            'Nginx: "autoindex off". (3) For cloud storage (S3, Azure Blob, GCS): verify buckets '
            'are not publicly listable even if individual files are public — the s3:ListBucket '
            'permission is separate from s3:GetObject. (4) Implement SRI hashes for any CSS or '
            'JavaScript loaded from external CDNs. (5) Review CDN cache headers to ensure '
            'sensitive static resources are not cached by shared CDN nodes.'
        ),
    },

    'URL_WEB_FRAMEWORK': {
        'desc_context': (
            'Web application framework fingerprints have been identified across the organization\'s '
            'web applications. Detected frameworks have version-specific CVE histories: older jQuery '
            'versions are commonly targeted for prototype pollution and XSS vulnerabilities; older '
            'Bootstrap versions have XSS issues in data-* attribute handling. Framework '
            'identification gives attackers a targeted vulnerability shortlist without further '
            'probing.'
        ),
        'rec': (
            'Conduct a web framework security review: (1) Identify the specific installed versions '
            'of all detected frameworks and cross-reference against NVD/CVE database or Snyk '
            '(snyk.io/vuln) — prioritize updating any frameworks with Critical or High CVEs, '
            'particularly jQuery < 3.5.0 (multiple XSS/prototype pollution) and Bootstrap < 4.3.1 '
            '(XSS via data-template attribute). (2) Remove or suppress framework version '
            'disclosure: strip version numbers from HTML meta generator tags, script src filenames '
            '(jquery-1.x.y.min.js → jquery.min.js), and HTTP headers. (3) Integrate SCA '
            '(Software Composition Analysis) scanning in CI/CD to automatically detect outdated '
            'framework versions on every deployment. (4) Remove default framework artifacts from '
            'production: admin panels, default error pages, and framework-specific diagnostic '
            'endpoints (e.g., /elmah.axd, /trace.axd in ASP.NET should be disabled).'
        ),
    },

    'URL_JAVASCRIPT_HISTORIC': {
        'desc_context': (
            'Historic JavaScript files associated with the organization\'s web applications have '
            'been found in web archive databases. These archived scripts may contain API keys, '
            'credentials, or internal endpoint references that were removed from current '
            'deployments but remain permanently accessible via archive services — which are '
            'actively queried by automated reconnaissance tools.'
        ),
        'rec': (
            'Investigate each archived JavaScript file for sensitive content: (1) Access the '
            'Wayback Machine URLs and search the archived JavaScript for credentials, API keys, '
            'hardcoded tokens, and internal endpoint URLs — download and scan with truffleHog '
            'offline. (2) For any secrets found: rotate them immediately (treat as fully '
            'compromised). (3) Check whether internal API endpoints referenced in historic scripts '
            'still exist and respond — deprecated endpoints sometimes remain active in the backend '
            'even after removal from client-side code. (4) Submit takedown requests to the '
            'Internet Archive for specific URLs containing sensitive data (help@archive.org). '
            '(5) Add the response header "X-Robots-Tag: noarchive" to JavaScript file requests '
            'to prevent future archiving (note: this does not remove existing archives).'
        ),
    },

    'URL_WEB_FRAMEWORK_HISTORIC': {
        'desc_context': (
            'Historic web frameworks have been identified in archived versions of the '
            'organization\'s web applications. These historic entries document the technology '
            'evolution of the platform and may reveal older framework versions that contained '
            'known vulnerabilities at the time of their deployment.'
        ),
        'rec': (
            'Use historic framework data to verify and improve current posture: (1) Confirm that '
            'current production deployments have migrated away from identified historic framework '
            'versions — pay particular attention to jQuery (check for any remaining 1.x or 2.x '
            'instances with known XSS/prototype pollution CVEs) and YUI (deprecated since 2014, '
            'no security patches). Verify current versions using browser DevTools. (2) Review '
            'historic archived pages for sensitive content and submit takedown requests to the '
            'Internet Archive for any pages containing sensitive material. (3) Use the historic '
            'technology inventory to build a technology debt register: document legacy components, '
            'their last known versions, associated CVE risk, and target modernization dates.'
        ),
    },

    'URL_STATIC_HISTORIC': {
        'desc_context': (
            'Historic static content associated with the organization\'s web applications has '
            'been captured in web archive databases. While most static assets carry low individual '
            'risk, archived versions may have been captured at a time when sensitive documents, '
            'configuration files, or exported data were briefly accessible before removal.'
        ),
        'rec': (
            'Review the archived static content for security implications: (1) Access the archived '
            'URL and evaluate the file type and content — prioritize review of archived documents '
            '(PDF, DOCX, XLSX), configuration files, and compressed archives. (2) If sensitive '
            'content is found: rotate any exposed credentials or secrets immediately and submit a '
            'takedown request to the Internet Archive. (3) Investigate how the file became '
            'temporarily accessible and implement controls to prevent recurrence. (4) Implement a '
            'content inventory review as part of your deployment checklist to verify that only '
            'intended assets are published to web-accessible directories. (5) Add archive '
            'exclusion headers to static file responses where archiving is undesirable: '
            '"Cache-Control: no-store" combined with "X-Robots-Tag: noarchive".'
        ),
    },
}


def enrich_finding(tab, lead_sentence):
    """
    Return (description, recommendation) for a given finding type.

    tab           — the Tab / Vuln_Type / event type string (e.g. 'BLACKLISTED_IPADDR')
    lead_sentence — the auto-generated first sentence containing asset/count info

    If the tab is in the library, description = lead + context and recommendation
    is the specific library content.  If not found, returns the lead unmodified
    and an empty string so the caller can fall back to its own template.
    """
    spec = FINDING_SPECS.get(tab)
    if not spec:
        return lead_sentence, ''

    # Ensure lead sentence ends with a period + space
    lead = lead_sentence.strip()
    if lead and not lead.endswith('.'):
        lead += '.'

    description = lead + ' ' + spec['desc_context']
    recommendation = spec['rec']
    return description, recommendation


def enrich_or_default(tab, lead_sentence, default_desc, default_rec):
    """
    Like enrich_finding() but falls back to provided defaults when the tab
    is not in the library.  Drop-in replacement for the catchall block in
    each GROUP prompt.
    """
    description, recommendation = enrich_finding(tab, lead_sentence)
    if not recommendation:
        return default_desc, default_rec
    return description, recommendation
