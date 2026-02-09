# Positive Findings Review Instructions 
- For each item, there are specific target areas to review.  Overall, a review of any internal processes that impact the target area needs to be done.  Are there changes that can prevent issues or unintentional exposure of data?
  
```
EXTERNAL_VULNERABILITIES
•	Confirm all targeted assets are valid and in scope.
•	Review past vulnerability tickets for recurring themes (ex: unpatched third-party libraries).
•	Ensure patching and remediation processes are timely and consistently applied.
•	Track metrics to identify systemic issues requiring process changes.
INTERNAL_IP_ADDRESS
•	Validate that internal IP addresses listed are accurate and currently in use.
•	Remove or update obsolete or invalid addresses.
•	Investigate any exposures of internal IPs to the public and close unnecessary paths.
•	Implement controls to reduce accidental external exposure of internal networks.
IP_ADDRESS
•	Confirm listed IP addresses are valid and required for business operations.
•	Remove or decommission unused or invalid IP addresses.
•	Review whether all public IPs are necessary, consolidating where possible.
•	Document ownership and purpose for each exposed IP to support ongoing management.
TCP_PORT_OPEN
•	Validate that the listed open ports are accurate and required.
•	Close or block unused or unauthorized ports.
•	Confirm that exposed services are hardened and updated.
•	Monitor regularly for unexpected changes in open ports.
IPV6_ADDRESS
•	Confirm listed IPv6 addresses are valid and assigned to correct assets.
•	Remove or update unused or invalid IPv6 addresses.
•	Review exposure of IPv6 services to ensure they are intentional.
•	Apply consistent firewall and monitoring policies across IPv4 and IPv6.
WEBAPP_VULNERABILITIES
•	Confirm that all targeted web applications are valid and monitored.
•	Review recent tickets for repeated issues pointing to process gaps (ex: outdated libraries).
•	Ensure vulnerability patching processes are applied consistently and promptly.
•	Track recurring web application issues to drive long-term remediation improvements.
INTERNET_NAME
•	Validate listed internet names are correct and active.
•	Remove or update unused or incorrect entries.
•	Verify that naming conventions follow company policy.
•	Document ownership for accountability and lifecycle management.
WEBSERVER_TECHNOLOGY
•	Confirm that the listed web server technologies are accurate.
•	Remove or update outdated or incorrect entries.
•	Verify that web server versions are supported and patched.
•	Standardize server technologies to simplify management.
URL_PASSWORD
•	Validate listed URLs are correct and necessary.
•	Confirm that password utilities are still required for function.
•	Remove outdated or unused password-related endpoints.
•	Ensure strong authentication and access control are enforced.
URL_UPLOAD
•	Validate listed URLs are correct and in use.
•	Confirm file upload utilities are still required for functionality.
•	Remove or disable unused upload functions.
•	Apply security controls (file type restrictions, malware scanning, access validation).
HTTP_CODE
•	Validate that listed sources and return codes are correct.
•	Identify and remove incorrect or unnecessary codes.
•	Investigate unexpected error codes for misconfiguration.
•	Monitor for changes that could indicate unauthorized behavior.
TARGET_WEB_CONTENT
•	Confirm that sources and return content are correct.
•	Remove or correct any invalid or outdated content.
•	Ensure sensitive information is not unintentionally exposed.
•	Monitor content changes for anomalies or defacement attempts.
TARGET_WEB_CONTENT_TYPE
•	Validate that content types match expected application use.
•	Remove or correct unnecessary or incorrect entries.
•	Ensure content types do not expose vulnerabilities (ex: MIME misconfigurations).
•	Standardize content type usage across applications.
URL_FORM
•	Validate listed URLs are correct and active.
•	Identify and remove unnecessary or outdated forms.
•	Confirm forms use secure transmission (HTTPS, CSRF protections).
•	Monitor forms for misuse or injection attempts.
URL_PASSWORD_HISTORIC
•	Validate that listed URLs are correct and relevant.
•	Remove obsolete or unnecessary entries.
•	Confirm no legacy password utilities are exposed.
•	Enforce secure handling of password-related functionality.
URL_STATIC
•	Validate listed URLs are correct and relevant.
•	Remove outdated or unnecessary static content.
•	Ensure static content does not expose sensitive data.
•	Apply caching and integrity controls where appropriate.
WEBSERVER_STRANGEHEADER
•	Validate whether the unusual or unexpected HTTP headers are intentional.
•	Remove or sanitize headers that disclose unnecessary system details (ex: internal software versions, debug info).
•	If required by application logic, document the purpose of the header and ensure it is safe to expose externally.
URL_JAVASCRIPT
•	Validate listed URLs are correct and required.
•	Remove outdated or unused JavaScript files.
•	Ensure scripts are loaded securely (HTTPS, integrity checks).
•	Monitor for injection or unauthorized modifications.
URL_WEB_FRAMEWORK
•	Confirm the detected web framework is correct and in active use.
•	Review versioning — if outdated, plan to upgrade or patch to supported releases.
•	Ensure the framework’s admin/debug utilities are not exposed externally.
BREACHED_CREDENTIALS
•	Monitor for new breached credentials regularly.
•	Investigate if affected accounts are still active.
•	Reset passwords and enforce MFA where necessary.
•	Provide employee security awareness training.
EMAILADDR
•	Validate that email addresses are accurate and active.
•	Remove or update incorrect or inactive addresses.
•	Confirm addresses follow organizational naming conventions.
•	Review for unnecessary public exposure.
EMAILADDR_COMPROMISED
•	Validate compromised email addresses are correct.
•	Investigate affected accounts for unauthorized activity.
•	Reset passwords and enforce MFA.
•	Provide targeted training for compromised users.
INTERESTING_FILE
•	Review files flagged as “interesting” for sensitive data.
•	Remove or secure files not intended for public access.
•	Confirm file permissions are correctly applied.
•	Monitor for recurrence of exposed sensitive files.
MALICIOUS_EMAILADDR
•	Verify whether the email addresses listed have been targeted in phishing, spam, or malicious campaigns.
•	Block or flag malicious sender addresses at the email gateway.
•	Educate employees to recognize and report emails originating from flagged addresses.
PGP_KEY
•	Confirm the PGP key is valid and intended for public use.
•	Retire any old or unused keys, and ensure all active keys are properly managed.
•	Document ownership and rotation practices for cryptographic keys.
HASH
•	Determine whether the hash corresponds to a leaked password, file, or artifact.
•	If sensitive, rotate the underlying credential and investigate possible compromise.
•	Avoid exposing cryptographic hashes in public sources unless necessary (ex: software integrity checks).
HUMAN_NAME
•	Validate whether exposure of personal names is appropriate (ex: public employees vs. sensitive staff).
•	Redact or limit unnecessary personal identifiers in public assets.
•	Review data leakage sources (documents, code commits, metadata).
INTERESTING_FILE_HISTORIC
•	Review previously exposed files for sensitive information that may still be cached or archived externally.
•	Request takedowns where possible and ensure the files are no longer accessible.
•	Monitor for reappearance in future scans.
PHONE_NUMBER
•	Confirm listed phone numbers are still valid and intended to be public-facing.
•	Remove or obfuscate any internal, private, or employee personal numbers that should not be published.
•	Route all public-facing phone numbers through approved contact centers.
PHYSICAL_ADDRESS
•	Validate whether physical addresses are legitimate company assets.
•	Ensure sensitive or non-public office/employee addresses are not disclosed externally.
•	For public addresses, confirm accuracy and remove duplicates.
SOFTWARE_USED
•	Verify all detected software packages are valid and currently supported.
•	Remove unused or outdated software from public systems.
•	Track versions to ensure timely patching and upgrades.
USERNAME
•	Confirm whether exposed usernames are active.
•	Remove or disable unnecessary accounts.
•	Ensure multi-factor authentication (MFA) is required for all valid organization-related accounts and monitor for brute-force attempts against exposed accounts.
VULNERABILITY_DISCLOSURE
Confirm all applicable vulnerability disclosures have been accounted for, and the vulnerabilities disclosed are remediated. Are there new or updated assets these disclosures could be relevant to?
PUBLIC_CODE_REPO
•	Review repositories for exposed credentials, API keys, or sensitive configurations.
•	Remove sensitive data and rotate any leaked secrets.
•	Apply .gitignore and secret-scanning tools (ex: GitGuardian, Trufflehog) to prevent recurrence.
SSL_CERTIFICATE_EXPIRING
•	Validate all certificate expiration dates.
•	Ensure timely renewal of certificates before expiry.
•	Review certificate renewal processes for improvements.
•	Automate monitoring to prevent lapses.
SSL_CERTIFICATE_MISMATCH
•	Confirm certificates match the domains they protect.
•	Replace or reissue mismatched certificates.
•	Review certificate creation and deployment process.
•	Automate certificate management to reduce errors.
APPSTORE_ENTRY
•	Confirm all app store entries are official and accurate.
•	Remove or report fraudulent or outdated entries.
•	Ensure apps are signed and are up to date.
•	Monitor for impersonation or malicious clones.
GEOINFO
•	Validate geographic information accuracy.
•	Remove or correct outdated or irrelevant entries.
•	Confirm no unnecessary location data is exposed.
•	Monitor for misuse of geolocation information.
PHYSICAL_COORDINATES
•	Confirm listed coordinates are valid and relevant.
•	Remove or update obsolete entries.
•	Ensure no sensitive site locations are exposed.
•	Monitor for unauthorized use of location data.
SSL_CERTIFICATE_ISSUED
•	Confirm that certificates are issued by a trusted CA and properly bound to the intended hostname(s).
•	Replace any certificates issued by untrusted or test CAs.
•	Standardize issuance from a central certificate authority to prevent inconsistencies.
SSL_CERTIFICATE_ISSUER
•	Confirm that certificates are issued by a trusted CA and properly bound to the intended hostname(s).
•	Replace any certificates issued by untrusted or test CAs.
•	Standardize issuance from a central certificate authority to prevent inconsistencies.
ACCOUNT_EXTERNAL_OWNED
•	Confirm external accounts (ex: SaaS, cloud, social logins) are authorized and managed.
•	Decommission unused accounts.
•	Enforce MFA and strong password policies on all accounts.
SOCIAL_MEDIA
•	Validate that identified social media accounts are official and managed by the company.
•	Report and remove fake or impersonating accounts.
•	Ensure corporate accounts have secure logins and account recovery processes.
TARGET_ACCOUNTS
•	Validate that identified social media accounts are official and managed by the company.
•	Report and remove fake or impersonating accounts.
•	Ensure corporate accounts have secure logins and account recovery processes.
DNS_SPF
•	Confirm SPF and other DNS TXT records are correctly configured for the organization’s mail domain(s).
•	Remove obsolete records and ensure policies align with DMARC/DKIM requirements.
•	Monitor DNS for unauthorized or malicious record changes.
DNS_TEXT
•	Confirm SPF and other DNS TXT records are correctly configured for the organization’s mail domain(s).
•	Remove obsolete records and ensure policies align with DMARC/DKIM requirements.
•	Monitor DNS for unauthorized or malicious record changes.
DOMAIN_NAME
•	Ensure domains are registered under the correct registrar and ownership is current.
•	Renew domains before expiration to prevent hijacking.
•	Apply registrar lock where possible and limit WHOIS exposure of sensitive contact info.
DOMAIN_REGISTRAR
•	Ensure domains are registered under the correct registrar and ownership is current.
•	Renew domains before expiration to prevent hijacking.
•	Apply registrar lock where possible and limit WHOIS exposure of sensitive contact info.
DOMAIN_NAME_PARENT
•	Ensure domains are registered under the correct registrar and ownership is current.
•	Renew domains before expiration to prevent hijacking.
•	Apply registrar lock where possible and limit WHOIS exposure of sensitive contact info.
DOMAIN_WHOIS
•	Ensure domains are registered under the correct registrar and ownership is current.
•	Renew domains before expiration to prevent hijacking.
•	Apply registrar lock where possible and limit WHOIS exposure of sensitive contact info.
BLACKLISTED_IPADDR
•	Investigate why company IPs or subnets are blacklisted.
•	Remediate any underlying compromise (ex: spam relay, malware infection).
•	Submit delisting requests once issues are resolved.
•	Monitor continuously for reappearance.
MALICIOUS_IPADDR
•	Investigate why company IPs or subnets are blacklisted.
•	Remediate any underlying compromise (ex: spam relay, malware infection).
•	Submit delisting requests once issues are resolved.
•	Monitor continuously for reappearance.
BLACKLISTED_SUBNET
•	Investigate why company IPs or subnets are blacklisted.
•	Remediate any underlying compromise (ex: spam relay, malware infection).
•	Submit delisting requests once issues are resolved.
•	Monitor continuously for reappearance.
MALICIOUS_SUBNET
•	Investigate why company IPs or subnets are blacklisted.
•	Remediate any underlying compromise (ex: spam relay, malware infection).
•	Submit delisting requests once issues are resolved.
•	Monitor continuously for reappearance.
```
