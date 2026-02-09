# Positive Findings Review Instructions

For each item, there are specific target areas to review. Overall, a review of any internal processes that impact the target area needs to be done. Are there changes that can prevent issues or unintentional exposure of data?

## EXTERNAL_VULNERABILITIES
*Maps to: VULNERABILITY_CVE_CRITICAL, VULNERABILITY_CVE_HIGH, VULNERABILITY_CVE_MEDIUM, VULNERABILITY_CVE_LOW, VULNERABILITY_GENERAL, VULNERABILITY_DISCLOSURE*

- Confirm all targeted assets are valid and in scope.
- Review past vulnerability tickets for recurring themes (ex: unpatched third-party libraries).
- Ensure patching and remediation processes are timely and consistently applied.
- Track metrics to identify systemic issues requiring process changes.

## INTERNAL_IP_ADDRESS
*Maps to: INTERNAL_IP_ADDRESS*

- Validate that internal IP addresses listed are accurate and currently in use.
- Remove or update obsolete or invalid addresses.
- Investigate any exposures of internal IPs to the public and close unnecessary paths.
- Implement controls to reduce accidental external exposure of internal networks.

## IP_ADDRESS
*Maps to: IP_ADDRESS*

- Confirm listed IP addresses are valid and required for business operations.
- Remove or decommission unused or invalid IP addresses.
- Review whether all public IPs are necessary, consolidating where possible.
- Document ownership and purpose for each exposed IP to support ongoing management.

## TCP_PORT_OPEN
*Maps to: TCP_PORT_OPEN, TCP_PORT_OPEN_BANNER*

- Validate that the listed open ports are accurate and required.
- Close or block unused or unauthorized ports.
- Confirm that exposed services are hardened and updated.
- Monitor regularly for unexpected changes in open ports.

## IPV6_ADDRESS
*Maps to: IPV6_ADDRESS*

- Confirm listed IPv6 addresses are valid and assigned to correct assets.
- Remove or update unused or invalid IPv6 addresses.
- Review exposure of IPv6 services to ensure they are intentional.
- Apply consistent firewall and monitoring policies across IPv4 and IPv6.

---

## MISSING INSTRUCTIONS (not yet mapped)

The following data types do NOT have review instructions yet. Add instructions above and update the JavaScript mapping in `scaninfo.tmpl` when ready:

### Network/Infrastructure
- AFFILIATE_IPADDR
- AFFILIATE_IPV6_ADDRESS
- AFFILIATE_INTERNET_NAME
- AFFILIATE_INTERNET_NAME_UNRESOLVED
- AFFILIATE_DOMAIN_NAME
- BGP_AS_MEMBER
- BGP_AS_OWNER
- CO_HOSTED_SITE
- CO_HOSTED_SITE_DOMAIN
- DOMAIN_NAME
- DOMAIN_NAME_PARENT
- DOMAIN_REGISTRAR
- DOMAIN_WHOIS
- DNS_SPF
- DNS_TEXT
- GEOINFO
- INTERNET_NAME
- INTERNET_NAME_UNRESOLVED
- NETBLOCK_MEMBER
- NETBLOCK_OWNER
- NETBLOCK_WHOIS
- NETBLOCKV6_MEMBER
- NETBLOCKV6_OWNER
- PROVIDER_DNS
- PROVIDER_HOSTING
- PROVIDER_MAIL
- RAW_DNS_RECORDS
- RAW_RIR_DATA
- UDP_PORT_OPEN
- UDP_PORT_OPEN_INFO

### Security/Threats
- BLACKLISTED_IPADDR
- BLACKLISTED_INTERNET_NAME
- BLACKLISTED_AFFILIATE_IPADDR
- BLACKLISTED_AFFILIATE_INTERNET_NAME
- BLACKLISTED_COHOST
- BLACKLISTED_NETBLOCK
- BLACKLISTED_SUBNET
- MALICIOUS_IPADDR
- MALICIOUS_INTERNET_NAME
- MALICIOUS_AFFILIATE_IPADDR
- MALICIOUS_AFFILIATE_INTERNET_NAME
- MALICIOUS_COHOST
- MALICIOUS_NETBLOCK
- MALICIOUS_SUBNET
- MALICIOUS_ASN
- MALICIOUS_EMAILADDR
- MALICIOUS_PHONE_NUMBER
- MALICIOUS_BITCOIN_ADDRESS
- DEFACED_IPADDR
- DEFACED_INTERNET_NAME
- DEFACED_AFFILIATE_IPADDR
- DEFACED_AFFILIATE_INTERNET_NAME
- DEFACED_COHOST
- PROXY_HOST
- TOR_EXIT_NODE
- VPN_HOST
- THREAT_INTELLIGENCE

### Identity/Credentials
- EMAILADDR
- EMAILADDR_COMPROMISED
- EMAILADDR_GENERIC
- EMAILADDR_DELIVERABLE
- EMAILADDR_UNDELIVERABLE
- EMAILADDR_DISPOSABLE
- HUMAN_NAME
- PASSWORD_COMPROMISED
- PGP_KEY
- PHONE_NUMBER
- PHONE_NUMBER_COMPROMISED
- USERNAME
- ACCOUNT_EXTERNAL_OWNED
- ACCOUNT_EXTERNAL_OWNED_COMPROMISED

### Web/Content
- HTTP_CODE
- INTERESTING_FILE
- LINKED_URL_EXTERNAL
- LINKED_URL_INTERNAL
- SOFTWARE_USED
- SSL_CERTIFICATE_EXPIRED
- SSL_CERTIFICATE_EXPIRING
- SSL_CERTIFICATE_ISSUED
- SSL_CERTIFICATE_ISSUER
- SSL_CERTIFICATE_MISMATCH
- SSL_CERTIFICATE_RAW
- TARGET_WEB_CONTENT
- TARGET_WEB_COOKIE
- WEBSERVER_BANNER
- WEBSERVER_HTTPHEADERS
- WEBSERVER_STRANGEHEADER
- WEBSERVER_TECHNOLOGY
- WEB_ANALYTICS_ID

### Other
- BITCOIN_ADDRESS
- BITCOIN_BALANCE
- CLOUD_STORAGE_BUCKET
- CLOUD_STORAGE_BUCKET_OPEN
- COMPANY_NAME
- COUNTRY_NAME
- DARKNET_MENTION_CONTENT
- DARKNET_MENTION_URL
- LEAKSITE_CONTENT
- LEAKSITE_URL
- OPERATING_SYSTEM
- PHYSICAL_ADDRESS
- PHYSICAL_COORDINATES
- PUBLIC_CODE_REPO
- SIMILARDOMAIN
- SOCIAL_MEDIA
