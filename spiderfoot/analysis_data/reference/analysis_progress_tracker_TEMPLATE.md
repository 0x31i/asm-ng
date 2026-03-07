# Security Analysis Progress Tracker
**Analysis Date:** [AUTO-FILLED]
**CSV File:** [AUTO-DETECTED from ./obfuscated/]
**CSV Format:** [AUTO-DETECTED: 10-col (full_scored with CVR) or 7-col (standard)]
**Total Event Types:** 130+ (excluding Information / Reference category)
**Status:** IN PROGRESS

---

## Analysis Configuration
- **Input Format:** ASM-NG CSV export (auto-detect 7-col or 10-col format)
- **Filtering:** Exclude F/P = 1 (false positives)
- **Include:** F/P = 0 (unverified) and F/P = 2 (verified true positives)
- **CVR Scoring:** Extract Confidence/Visibility/Risk when available (10-col format)
- **Tracking Status:** Annotate OPEN/CLOSED/TICKETED per finding
- **Special Logic:**
  * ACCOUNT_EXTERNAL_OWNED: Only analyze FP = 2 (validated), note FP = 0 counts for validation needed
  * WEBAPP_VULNERABILITIES & EXTERNAL_VULNERABILITIES: Exclude "Info" severity, analyze only Critical/High/Medium/Low
  * Informational findings: Analyze for patterns that could indicate Low-Medium vulnerabilities
  * DNS_SPF & DNS_TEXT: zero_entries_fail logic (missing records = Critical)
- **Scope:** Security-relevant event types only (excluding "Information / Reference" category, weight=0.0)
- **Groups:** Aligned 1:1 with ASM-NG grade categories, ordered by weight

---

## ASM-NG Grade Summary

| Category | Weight | Score | Grade | Findings |
|----------|--------|-------|-------|----------|
| Network Security | 1.0 | -- | -- | 0 |
| Web App Security | 1.0 | -- | -- | 0 |
| Information Leakage | 0.8 | -- | -- | 0 |
| General Health | 0.8 | -- | -- | 0 |
| External Account Exposure | 0.7 | -- | -- | 0 |
| DNS Health | 0.7 | -- | -- | 0 |
| IP Reputation | 0.6 | -- | -- | 0 |
| **Overall** | **weighted** | **--** | **--** | **0** |

*Grade thresholds: A=90+, B=80+, C=70+, D=60+, F=<60*
*Score = max(0, 100 + (raw_score * weight))*

---

## Group Analysis Status

### GROUP 1: Network Security (Weight 1.0, Priority P1)
**Status:** NOT STARTED | IN PROGRESS | COMPLETED

#### Event Types in This Group (23):
- [ ] EXTERNAL_VULNERABILITIES (Nessus enrichment, exclude Info severity)
- [ ] VULNERABILITY_CVE_CRITICAL
- [ ] VULNERABILITY_CVE_HIGH
- [ ] VULNERABILITY_CVE_MEDIUM
- [ ] VULNERABILITY_CVE_LOW
- [ ] VULNERABILITY_GENERAL
- [ ] INTERNAL_IP_ADDRESS
- [ ] IP_ADDRESS
- [ ] IPV6_ADDRESS
- [ ] TCP_PORT_OPEN
- [ ] TCP_PORT_OPEN_BANNER (informational)
- [ ] UDP_PORT_OPEN
- [ ] UDP_PORT_OPEN_INFO (informational)
- [ ] DEFACED_INTERNET_NAME
- [ ] DEFACED_IPADDR
- [ ] DEFACED_AFFILIATE_INTERNET_NAME
- [ ] DEFACED_COHOST
- [ ] DEFACED_AFFILIATE_IPADDR
- [ ] PROXY_HOST
- [ ] VPN_HOST
- [ ] TOR_EXIT_NODE
- [ ] AI_ENDPOINT_UNAUTHENTICATED
- [ ] AI_MODEL_EXPOSED

#### Findings Summary:
- **Total Rows Analyzed:** 0
- **False Positives Excluded (FP=1):** 0
- **Info Severity Excluded:** 0
- **Critical Findings:** 0
- **High Findings:** 0
- **Medium Findings:** 0
- **Low Findings:** 0

#### Nessus Enrichment:
- Findings enriched from .nessus file: 0
- Findings using generic fallback: 0
- Enrichment success rate: 0%

#### Tracking Status:
- OPEN: 0
- CLOSED: 0
- TICKETED: 0

#### CVR Score Averages:
- Avg Confidence: -- (or N/A if 7-col format)
- Avg Visibility: --
- Avg Risk: --

#### Key Discoveries:
*[Auto-populated during analysis]*

---

### GROUP 2: Web App Security (Weight 1.0, Priority P1)
**Status:** NOT STARTED

#### Event Types in This Group (34):
- [ ] WEBAPP_VULNERABILITIES (Burp enrichment, exclude Info severity)
- [ ] HTTP_CODE
- [ ] INTERNET_NAME
- [ ] INTERNET_NAME_UNRESOLVED (informational)
- [ ] TARGET_WEB_CONTENT
- [ ] TARGET_WEB_CONTENT_TYPE
- [ ] TARGET_WEB_COOKIE
- [ ] URL_FORM
- [ ] URL_JAVASCRIPT
- [ ] URL_FLASH
- [ ] URL_JAVA_APPLET
- [ ] URL_PASSWORD
- [ ] URL_PASSWORD_HISTORIC
- [ ] URL_STATIC
- [ ] URL_UPLOAD
- [ ] URL_WEB_FRAMEWORK
- [ ] URL_ADBLOCKED_EXTERNAL
- [ ] URL_ADBLOCKED_INTERNAL
- [ ] URL_FORM_HISTORIC
- [ ] URL_FLASH_HISTORIC
- [ ] URL_JAVASCRIPT_HISTORIC
- [ ] URL_WEB_FRAMEWORK_HISTORIC
- [ ] URL_JAVA_APPLET_HISTORIC
- [ ] URL_STATIC_HISTORIC
- [ ] URL_UPLOAD_HISTORIC
- [ ] WEBSERVER_BANNER (informational)
- [ ] WEBSERVER_HTTPHEADERS (informational)
- [ ] WEBSERVER_STRANGEHEADER
- [ ] WEBSERVER_TECHNOLOGY
- [ ] WEB_ANALYTICS_ID (informational)
- [ ] LINKED_URL_EXTERNAL (informational)
- [ ] LINKED_URL_INTERNAL (informational)
- [ ] WAYBACK_FOOTPRINTING (informational)
- [ ] LEAKSITE_URL_WEBAPP (informational)

#### Findings Summary:
- **Total Rows Analyzed:** 0
- **False Positives Excluded:** 0
- **Web Vulnerabilities:** 0
- **Exposed Forms/Uploads:** 0
- **Suspicious Headers:** 0

#### Burp Enrichment:
- Findings enriched from .html file: 0
- Findings using generic fallback: 0

#### Tracking Status:
- OPEN: 0
- CLOSED: 0
- TICKETED: 0

#### CVR Score Averages:
- Avg Confidence: --
- Avg Visibility: --
- Avg Risk: --

#### Key Discoveries:
*[Auto-populated during analysis]*

---

### GROUP 3: Information Leakage (Weight 0.8, Priority P2)
**Status:** NOT STARTED

#### Event Types in This Group (31):
- [ ] BREACHED_CREDENTIALS
- [ ] PASSWORD_COMPROMISED
- [ ] HASH_COMPROMISED
- [ ] CREDIT_CARD_NUMBER
- [ ] AI_API_KEY_LEAKED
- [ ] LEAKSITE_URL
- [ ] LEAKSITE_CONTENT
- [ ] EMAILADDR
- [ ] EMAILADDR_COMPROMISED
- [ ] EMAILADDR_DELIVERABLE
- [ ] EMAILADDR_DISPOSABLE
- [ ] EMAILADDR_GENERIC (informational)
- [ ] EMAILADDR_UNDELIVERABLE (informational)
- [ ] MALICIOUS_EMAILADDR
- [ ] HASH
- [ ] HUMAN_NAME
- [ ] PERSON_NAME
- [ ] DATE_HUMAN_DOB
- [ ] JOB_TITLE
- [ ] PHONE_NUMBER
- [ ] PHONE_NUMBER_COMPROMISED
- [ ] PHONE_NUMBER_TYPE (informational)
- [ ] MALICIOUS_PHONE_NUMBER
- [ ] PHYSICAL_ADDRESS
- [ ] INTERESTING_FILE
- [ ] INTERESTING_FILE_HISTORIC
- [ ] PGP_KEY
- [ ] RAW_FILE_META_DATA (informational)
- [ ] SOFTWARE_USED
- [ ] USERNAME
- [ ] IBAN_NUMBER (informational)

#### Findings Summary:
- **Total Rows Analyzed:** 0
- **False Positives Excluded:** 0
- **Compromised Credentials:** 0
- **Exposed Emails:** 0
- **Exposed PII:** 0
- **Leaked Credentials:** 0

#### Tracking Status:
- OPEN: 0
- CLOSED: 0
- TICKETED: 0

#### CVR Score Averages:
- Avg Confidence: --
- Avg Visibility: --
- Avg Risk: --

#### Key Discoveries:
*[Auto-populated during analysis]*

---

### GROUP 4: General Health (Weight 0.8, Priority P2)
**Status:** NOT STARTED

#### Event Types in This Group (14):
- [ ] VULNERABILITY_DISCLOSURE
- [ ] SSL_CERTIFICATE_EXPIRED
- [ ] SSL_CERTIFICATE_EXPIRING
- [ ] SSL_CERTIFICATE_MISMATCH
- [ ] SSL_CERTIFICATE_ISSUED
- [ ] SSL_CERTIFICATE_ISSUER
- [ ] SSL_CERTIFICATE_RAW (informational)
- [ ] PUBLIC_CODE_REPO
- [ ] APPSTORE_ENTRY
- [ ] COUNTRY_NAME
- [ ] GEOINFO
- [ ] PHYSICAL_COORDINATES
- [ ] BLACKLISTED_AFFILIATE_INTERNET_NAME (informational)
- [ ] BLACKLISTED_AFFILIATE_IPADDR (informational)

#### Findings Summary:
- **Total Rows Analyzed:** 0
- **False Positives Excluded:** 0
- **Certificate Issues:** 0
- **Public Repos:** 0
- **Geographic Exposure:** 0

#### Tracking Status:
- OPEN: 0
- CLOSED: 0
- TICKETED: 0

#### CVR Score Averages:
- Avg Confidence: --
- Avg Visibility: --
- Avg Risk: --

#### Key Discoveries:
*[Auto-populated during analysis]*

---

### GROUP 5: External Account Exposure (Weight 0.7, Priority P3)
**Status:** NOT STARTED

#### Event Types in This Group (6):
- [ ] ACCOUNT_EXTERNAL_OWNED (special: only report FP=2, note FP=0 for validation)
- [ ] ACCOUNT_EXTERNAL_OWNED_COMPROMISED
- [ ] ACCOUNT_EXTERNAL_USER_SHARED_COMPROMISED
- [ ] SIMILAR_ACCOUNT_EXTERNAL
- [ ] SOCIAL_MEDIA
- [ ] TARGET_ACCOUNTS

#### Findings Summary:
- **Total Rows Analyzed:** 0
- **False Positives Excluded:** 0
- **Validation Needed (ACCOUNT_EXTERNAL_OWNED FP=0):** 0
- **Compromised Accounts:** 0
- **Exposed Accounts:** 0

#### Tracking Status:
- OPEN: 0
- CLOSED: 0
- TICKETED: 0

#### CVR Score Averages:
- Avg Confidence: --
- Avg Visibility: --
- Avg Risk: --

#### Key Discoveries:
*[Auto-populated during analysis]*

---

### GROUP 6: DNS Health (Weight 0.7, Priority P3)
**Status:** NOT STARTED

#### Event Types in This Group (10):
- [ ] DNS_SPF (zero_entries_fail: missing = Critical)
- [ ] DNS_TEXT (zero_entries_fail: missing = Critical)
- [ ] DNS_SRV (informational)
- [ ] DOMAIN_IMPERSONATION
- [ ] DOMAIN_NAME
- [ ] DOMAIN_NAME_PARENT
- [ ] DOMAIN_REGISTRAR
- [ ] DOMAIN_WHOIS
- [ ] RAW_DNS_RECORDS (informational)
- [ ] NETBLOCK_WHOIS

#### Findings Summary:
- **Total Rows Analyzed:** 0
- **False Positives Excluded:** 0
- **DNS Misconfigurations:** 0
- **Domain Issues:** 0
- **Impersonation Risks:** 0

#### Tracking Status:
- OPEN: 0
- CLOSED: 0
- TICKETED: 0

#### CVR Score Averages:
- Avg Confidence: --
- Avg Visibility: --
- Avg Risk: --

#### Key Discoveries:
*[Auto-populated during analysis]*

---

### GROUP 7: IP Reputation (Weight 0.6, Priority P3)
**Status:** NOT STARTED

#### Event Types in This Group (11):
- [ ] BLACKLISTED_IPADDR
- [ ] BLACKLISTED_SUBNET (informational)
- [ ] BLACKLISTED_COHOST
- [ ] BLACKLISTED_INTERNET_NAME
- [ ] BLACKLISTED_NETBLOCK
- [ ] MALICIOUS_IPADDR
- [ ] MALICIOUS_SUBNET (informational)
- [ ] MALICIOUS_ASN
- [ ] MALICIOUS_INTERNET_NAME
- [ ] MALICIOUS_NETBLOCK
- [ ] MALICIOUS_BITCOIN_ADDRESS

#### Findings Summary:
- **Total Rows Analyzed:** 0
- **False Positives Excluded:** 0
- **Blacklisted Assets:** 0
- **Malicious IPs:** 0
- **Reputation Issues:** 0

#### Tracking Status:
- OPEN: 0
- CLOSED: 0
- TICKETED: 0

#### CVR Score Averages:
- Avg Confidence: --
- Avg Visibility: --
- Avg Risk: --

#### Key Discoveries:
*[Auto-populated during analysis]*

---

**NOTE:** Event types categorized as "Information / Reference" (weight=0.0) -- including AFFILIATE_*, COMPANY_NAME, DESCRIPTION_*, PROVIDER_*, CO_HOSTED_SITE_*, NETBLOCK_MEMBER/OWNER, BGP_AS_*, BITCOIN_*, ETHEREUM_*, SIMILARDOMAIN*, CLOUD_STORAGE_BUCKET, DARKNET_MENTION_*, etc. -- are excluded from security analysis as they contain contextual/reference data only.

---

## Informational Findings Pattern Analysis

### Patterns Identified Across Groups:
*[Aggregated informational-level findings that together suggest vulnerabilities]*

### Pattern-Based Vulnerabilities Discovered:
- [ ] *[Low/Medium findings derived from informational data patterns]*
- [ ]
- [ ]

### Examples:
- "Multiple outdated software versions (Info) + exposed admin panels (Info) = Medium: Attack surface with known exploits"
- "Internal IPs in headers (Info) + DNS records (Info) + public services (Info) = Low: Architecture disclosure"

---

## Cross-Group Correlations & Insights

### Asset Correlation Matrix
*[Updated as groups are analyzed]*

**High-Risk Asset Patterns:**
- Assets appearing in multiple groups with critical findings
- Correlation between breached credentials and exposed services
- Blacklisted IPs with open high-risk ports
- Compromised emails associated with exposed accounts

### Notable Cross-References:
1. *[Auto-populated as patterns emerge]*
2.
3.

### Interesting Findings Requiring Further Investigation:
- [ ] *[Auto-populated]*
- [ ]
- [ ]

---

## Running Statistics

### Overall Progress:
- **Groups Completed:** 0/7
- **Event Types Analyzed:** 0/130+
- **Informational Event Types Excluded:** ~50+ (weight=0.0)
- **Total Rows Processed:** 0
- **False Positives Excluded:** 0
- **Info Severity Excluded:** 0
- **Accounts Needing Validation (ACCOUNT_EXTERNAL_OWNED FP=0):** 0
- **Total Findings:** 0
  - Critical: 0
  - High: 0
  - Medium: 0
  - Low: 0
- **Pattern-Based Findings from Info Data:** 0

### Tracking Status Summary:
- **OPEN:** 0
- **CLOSED:** 0
- **TICKETED:** 0

### CVR Score Summary (when available):
- **Avg Confidence:** --
- **Avg Visibility:** --
- **Avg Risk:** --
- **Findings with CVR scores:** 0

### Findings by Category:
- Network Security: 0
- Web App Security: 0
- Information Leakage: 0
- General Health: 0
- External Account Exposure: 0
- DNS Health: 0
- IP Reputation: 0
- Pattern-Derived Vulnerabilities: 0

---

## Next Steps
*[Updated at end of each group analysis]*

**Current Focus:** GROUP 1 - Network Security
**Next Group:** GROUP 2 - Web App Security

---

## Notes & Observations
*[Free-form notes added during analysis]*

---

**Last Updated:** [TIMESTAMP]
**Session ID:** [SESSION-ID]
