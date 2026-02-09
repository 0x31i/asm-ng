"""Overall Grade Configuration for Scan Results.

Defines the grading system that evaluates scan results across security
categories. Each event type is mapped to a category with scoring rules.
Categories are weighted and combined into an overall grade.

The grading logic:
1. Each event type maps to a category (Network Security, Web App Security, etc.)
2. Each event type has a scoring rule (points deducted for findings)
3. Points are summed per category -> Raw Score
4. Adjusted Score = Raw Score * Category Weight
5. Score out of 100 = max(0, 100 + Adjusted Score)
6. Letter grade from score thresholds
7. Overall = weighted average of category scores (excluding weight=0 categories)
"""

import json
import logging

log = logging.getLogger(f"spiderfoot.{__name__}")

# ============================================================================
# GRADE CATEGORIES & WEIGHTS
# ============================================================================
# Each category groups related event types and has a weight that determines
# how much it contributes to the overall grade.
# Weight 0 means the category is informational only (not counted in overall).

DEFAULT_GRADE_CATEGORIES = {
    'Network Security': {
        'weight': 1.0,
        'color': '#dc2626',
        'description': 'Open ports, vulnerabilities, internal IP exposure',
    },
    'Web App Security': {
        'weight': 1.0,
        'color': '#ea580c',
        'description': 'Web application vulnerabilities, forms, uploads, frameworks',
    },
    'Information Leakage': {
        'weight': 0.8,
        'color': '#eab308',
        'description': 'Exposed credentials, emails, personal data, files',
    },
    'General Health': {
        'weight': 0.8,
        'color': '#eab308',
        'description': 'SSL certificates, code repos, coordinates, app stores',
    },
    'External Account Exposure': {
        'weight': 0.7,
        'color': '#22c55e',
        'description': 'External accounts, social media, target accounts',
    },
    'DNS Health': {
        'weight': 0.7,
        'color': '#22c55e',
        'description': 'DNS records, SPF, domain registration, WHOIS',
    },
    'IP Reputation': {
        'weight': 0.6,
        'color': '#d946ef',
        'description': 'Blacklisted IPs, malicious IPs, malicious subnets',
    },
    'Information / Reference': {
        'weight': 0.0,
        'color': '#6b7280',
        'description': 'Informational findings that do not affect the grade',
    },
}

# ============================================================================
# GRADE THRESHOLDS
# ============================================================================
# Score ranges for each letter grade. Evaluated top-down, first match wins.

DEFAULT_GRADE_THRESHOLDS = [
    {'min': 90, 'grade': 'A', 'color': '#16a34a', 'bg': '#dcfce7'},
    {'min': 80, 'grade': 'B', 'color': '#2563eb', 'bg': '#dbeafe'},
    {'min': 70, 'grade': 'C', 'color': '#d97706', 'bg': '#fef3c7'},
    {'min': 60, 'grade': 'D', 'color': '#ea580c', 'bg': '#ffedd5'},
    {'min': 0, 'grade': 'F', 'color': '#dc2626', 'bg': '#fee2e2'},
]

# ============================================================================
# SCORING LOGIC TYPES
# ============================================================================
# Each event type uses one of these logic types to calculate its score:
#
# 'unverified_exists'  - If any results found, apply 'points' once
# 'zero_entries_fail'  - If count=0 AND type expected, apply 'fail_points';
#                        if count>0, apply 'points'
# 'crit_high_med'      - For vulnerability types: check severity sub-types
#                        and apply tiered points (crit/high/med)
# 'informational'      - No penalty (0 points, purely informational)
# 'count_scaled'       - Points multiplied by unique count (capped)

# ============================================================================
# EVENT TYPE -> GRADING RULES
# ============================================================================
# Maps each known event type to its grading category and scoring parameters.
#
# Fields:
#   category  - Which grade category this type belongs to
#   rank      - Importance 1-5 (1=most important, 5=least)
#   points    - Base negative points when findings exist
#   logic     - Scoring logic type (see above)
#   fail_points - (optional) Points when zero_entries_fail and count=0
#   crit_points - (optional) Points for critical findings
#   high_points - (optional) Points for high findings
#   med_points  - (optional) Points for medium findings

DEFAULT_EVENT_TYPE_GRADING = {
    # =========================================================================
    # DNS Health
    # =========================================================================
    'DNS_SPF': {
        'category': 'DNS Health', 'rank': 2, 'points': -10,
        'logic': 'zero_entries_fail', 'fail_points': -50,
    },
    'DNS_TEXT': {
        'category': 'DNS Health', 'rank': 2, 'points': -10,
        'logic': 'zero_entries_fail', 'fail_points': -50,
    },
    'DNS_SRV': {
        'category': 'DNS Health', 'rank': 3, 'points': 0,
        'logic': 'informational',
    },
    'DOMAIN_IMPERSONATION': {
        'category': 'DNS Health', 'rank': 5, 'points': 0,
        'logic': 'informational',
    },
    'DOMAIN_NAME': {
        'category': 'DNS Health', 'rank': 3, 'points': -5,
        'logic': 'unverified_exists',
    },
    'DOMAIN_NAME_PARENT': {
        'category': 'DNS Health', 'rank': 4, 'points': -1,
        'logic': 'unverified_exists',
    },
    'DOMAIN_REGISTRAR': {
        'category': 'DNS Health', 'rank': 3, 'points': -5,
        'logic': 'unverified_exists',
    },
    'DOMAIN_WHOIS': {
        'category': 'DNS Health', 'rank': 4, 'points': -1,
        'logic': 'unverified_exists',
    },
    'RAW_DNS_RECORDS': {
        'category': 'DNS Health', 'rank': 5, 'points': 0,
        'logic': 'informational',
    },
    'NETBLOCK_WHOIS': {
        'category': 'DNS Health', 'rank': 4, 'points': -1,
        'logic': 'unverified_exists',
    },

    # =========================================================================
    # General Health
    # =========================================================================
    'APPSTORE_ENTRY': {
        'category': 'General Health', 'rank': 3, 'points': -5,
        'logic': 'unverified_exists',
    },
    'BLACKLISTED_AFFILIATE_INTERNET_NAME': {
        'category': 'General Health', 'rank': 5, 'points': 0,
        'logic': 'informational',
    },
    'BLACKLISTED_AFFILIATE_IPADDR': {
        'category': 'General Health', 'rank': 5, 'points': 0,
        'logic': 'informational',
    },
    'COUNTRY_NAME': {
        'category': 'General Health', 'rank': 3, 'points': -5,
        'logic': 'unverified_exists',
    },
    'GEOINFO': {
        'category': 'General Health', 'rank': 3, 'points': -5,
        'logic': 'unverified_exists',
    },
    'PHYSICAL_COORDINATES': {
        'category': 'General Health', 'rank': 3, 'points': -5,
        'logic': 'unverified_exists',
    },
    'PUBLIC_CODE_REPO': {
        'category': 'General Health', 'rank': 2, 'points': -10,
        'logic': 'unverified_exists',
    },
    'SSL_CERTIFICATE_EXPIRING': {
        'category': 'General Health', 'rank': 2, 'points': -10,
        'logic': 'unverified_exists',
    },
    'SSL_CERTIFICATE_EXPIRED': {
        'category': 'General Health', 'rank': 2, 'points': -10,
        'logic': 'unverified_exists',
    },
    'SSL_CERTIFICATE_ISSUED': {
        'category': 'General Health', 'rank': 4, 'points': -1,
        'logic': 'unverified_exists',
    },
    'SSL_CERTIFICATE_ISSUER': {
        'category': 'General Health', 'rank': 4, 'points': -1,
        'logic': 'unverified_exists',
    },
    'SSL_CERTIFICATE_MISMATCH': {
        'category': 'General Health', 'rank': 2, 'points': -10,
        'logic': 'unverified_exists',
    },
    'SSL_CERTIFICATE_RAW': {
        'category': 'General Health', 'rank': 5, 'points': 0,
        'logic': 'informational',
    },
    'VULNERABILITY_DISCLOSURE': {
        'category': 'General Health', 'rank': 1, 'points': -20,
        'logic': 'unverified_exists',
    },

    # =========================================================================
    # Information / Reference
    # =========================================================================
    'AFFILIATE_COMPANY_NAME': {
        'category': 'Information / Reference', 'rank': 5, 'points': 0,
        'logic': 'informational',
    },
    'AFFILIATE_DESCRIPTION_ABSTRACT': {
        'category': 'Information / Reference', 'rank': 5, 'points': 0,
        'logic': 'informational',
    },
    'AFFILIATE_DESCRIPTION_CATEGORY': {
        'category': 'Information / Reference', 'rank': 5, 'points': 0,
        'logic': 'informational',
    },
    'AFFILIATE_DOMAIN_NAME': {
        'category': 'Information / Reference', 'rank': 5, 'points': 0,
        'logic': 'informational',
    },
    'AFFILIATE_DOMAIN_UNREGISTERED': {
        'category': 'Information / Reference', 'rank': 5, 'points': 0,
        'logic': 'informational',
    },
    'AFFILIATE_DOMAIN_WHOIS': {
        'category': 'Information / Reference', 'rank': 5, 'points': 0,
        'logic': 'informational',
    },
    'AFFILIATE_EMAILADDR': {
        'category': 'Information / Reference', 'rank': 5, 'points': 0,
        'logic': 'informational',
    },
    'AFFILIATE_INTERNET_NAME': {
        'category': 'Information / Reference', 'rank': 5, 'points': 0,
        'logic': 'informational',
    },
    'AFFILIATE_INTERNET_NAME_HIJACKABLE': {
        'category': 'Information / Reference', 'rank': 5, 'points': 0,
        'logic': 'informational',
    },
    'AFFILIATE_INTERNET_NAME_UNRESOLVED': {
        'category': 'Information / Reference', 'rank': 5, 'points': 0,
        'logic': 'informational',
    },
    'AFFILIATE_IPADDR': {
        'category': 'Information / Reference', 'rank': 5, 'points': 0,
        'logic': 'informational',
    },
    'AFFILIATE_IPV6_ADDRESS': {
        'category': 'Information / Reference', 'rank': 5, 'points': 0,
        'logic': 'informational',
    },
    'AFFILIATE_WEB_CONTENT': {
        'category': 'Information / Reference', 'rank': 5, 'points': 0,
        'logic': 'informational',
    },
    'BGP_AS_MEMBER': {
        'category': 'Information / Reference', 'rank': 5, 'points': 0,
        'logic': 'informational',
    },
    'BGP_AS_OWNER': {
        'category': 'Information / Reference', 'rank': 5, 'points': 0,
        'logic': 'informational',
    },
    'BITCOIN_ADDRESS': {
        'category': 'Information / Reference', 'rank': 5, 'points': 0,
        'logic': 'informational',
    },
    'BITCOIN_BALANCE': {
        'category': 'Information / Reference', 'rank': 5, 'points': 0,
        'logic': 'informational',
    },
    'CLOUD_STORAGE_BUCKET': {
        'category': 'Information / Reference', 'rank': 5, 'points': 0,
        'logic': 'informational',
    },
    'CLOUD_STORAGE_BUCKET_OPEN': {
        'category': 'Information / Reference', 'rank': 3, 'points': -10,
        'logic': 'unverified_exists',
    },
    'CO_HOSTED_SITE': {
        'category': 'Information / Reference', 'rank': 5, 'points': 0,
        'logic': 'informational',
    },
    'CO_HOSTED_SITE_DOMAIN': {
        'category': 'Information / Reference', 'rank': 5, 'points': 0,
        'logic': 'informational',
    },
    'CO_HOSTED_SITE_DOMAIN_WHOIS': {
        'category': 'Information / Reference', 'rank': 5, 'points': 0,
        'logic': 'informational',
    },
    'COMPANY_NAME': {
        'category': 'Information / Reference', 'rank': 5, 'points': 0,
        'logic': 'informational',
    },
    'DESCRIPTION_ABSTRACT': {
        'category': 'Information / Reference', 'rank': 5, 'points': 0,
        'logic': 'informational',
    },
    'DESCRIPTION_CATEGORY': {
        'category': 'Information / Reference', 'rank': 5, 'points': 0,
        'logic': 'informational',
    },
    'LEI': {
        'category': 'Information / Reference', 'rank': 5, 'points': 0,
        'logic': 'informational',
    },
    'MALICIOUS_AFFILIATE_INTERNET_NAME': {
        'category': 'Information / Reference', 'rank': 5, 'points': 0,
        'logic': 'informational',
    },
    'MALICIOUS_AFFILIATE_IPADDR': {
        'category': 'Information / Reference', 'rank': 5, 'points': 0,
        'logic': 'informational',
    },
    'MALICIOUS_COHOST': {
        'category': 'Information / Reference', 'rank': 5, 'points': 0,
        'logic': 'informational',
    },
    'NETBLOCK_MEMBER': {
        'category': 'Information / Reference', 'rank': 5, 'points': 0,
        'logic': 'informational',
    },
    'NETBLOCK_OWNER': {
        'category': 'Information / Reference', 'rank': 5, 'points': 0,
        'logic': 'informational',
    },
    'NETBLOCKV6_MEMBER': {
        'category': 'Information / Reference', 'rank': 5, 'points': 0,
        'logic': 'informational',
    },
    'NETBLOCKV6_OWNER': {
        'category': 'Information / Reference', 'rank': 5, 'points': 0,
        'logic': 'informational',
    },
    'PROVIDER_DNS': {
        'category': 'Information / Reference', 'rank': 5, 'points': 0,
        'logic': 'informational',
    },
    'PROVIDER_HOSTING': {
        'category': 'Information / Reference', 'rank': 5, 'points': 0,
        'logic': 'informational',
    },
    'PROVIDER_JAVASCRIPT': {
        'category': 'Information / Reference', 'rank': 5, 'points': 0,
        'logic': 'informational',
    },
    'PROVIDER_MAIL': {
        'category': 'Information / Reference', 'rank': 5, 'points': 0,
        'logic': 'informational',
    },
    'PROVIDER_TELCO': {
        'category': 'Information / Reference', 'rank': 5, 'points': 0,
        'logic': 'informational',
    },
    'SIMILARDOMAIN': {
        'category': 'Information / Reference', 'rank': 5, 'points': 0,
        'logic': 'informational',
    },
    'SIMILARDOMAIN_WHOIS': {
        'category': 'Information / Reference', 'rank': 5, 'points': 0,
        'logic': 'informational',
    },
    'ETHEREUM_ADDRESS': {
        'category': 'Information / Reference', 'rank': 5, 'points': 0,
        'logic': 'informational',
    },
    'ETHEREUM_BALANCE': {
        'category': 'Information / Reference', 'rank': 5, 'points': 0,
        'logic': 'informational',
    },
    'BASE64_DATA': {
        'category': 'Information / Reference', 'rank': 5, 'points': 0,
        'logic': 'informational',
    },
    'DEVICE_TYPE': {
        'category': 'Information / Reference', 'rank': 5, 'points': 0,
        'logic': 'informational',
    },
    'OPERATING_SYSTEM': {
        'category': 'Information / Reference', 'rank': 5, 'points': 0,
        'logic': 'informational',
    },
    'ERROR_MESSAGE': {
        'category': 'Information / Reference', 'rank': 5, 'points': 0,
        'logic': 'informational',
    },
    'JUNK_FILE': {
        'category': 'Information / Reference', 'rank': 5, 'points': 0,
        'logic': 'informational',
    },
    'SEARCH_ENGINE_WEB_CONTENT': {
        'category': 'Information / Reference', 'rank': 5, 'points': 0,
        'logic': 'informational',
    },
    'WIKIPEDIA_PAGE_EDIT': {
        'category': 'Information / Reference', 'rank': 5, 'points': 0,
        'logic': 'informational',
    },
    'WIFI_ACCESS_POINT': {
        'category': 'Information / Reference', 'rank': 5, 'points': 0,
        'logic': 'informational',
    },
    'DARKNET_MENTION_URL': {
        'category': 'Information / Reference', 'rank': 3, 'points': -10,
        'logic': 'unverified_exists',
    },
    'DARKNET_MENTION_CONTENT': {
        'category': 'Information / Reference', 'rank': 3, 'points': 0,
        'logic': 'informational',
    },
    'RAW_RIR_DATA': {
        'category': 'Information / Reference', 'rank': 5, 'points': 0,
        'logic': 'informational',
    },

    # =========================================================================
    # Information Leakage
    # =========================================================================
    'BREACHED_CREDENTIALS': {
        'category': 'Information Leakage', 'rank': 1, 'points': -20,
        'logic': 'unverified_exists',
    },
    'EMAILADDR': {
        'category': 'Information Leakage', 'rank': 2, 'points': -10,
        'logic': 'unverified_exists',
    },
    'EMAILADDR_COMPROMISED': {
        'category': 'Information Leakage', 'rank': 2, 'points': -10,
        'logic': 'unverified_exists',
    },
    'EMAILADDR_DELIVERABLE': {
        'category': 'Information Leakage', 'rank': 3, 'points': -5,
        'logic': 'unverified_exists',
    },
    'EMAILADDR_DISPOSABLE': {
        'category': 'Information Leakage', 'rank': 3, 'points': -5,
        'logic': 'unverified_exists',
    },
    'EMAILADDR_GENERIC': {
        'category': 'Information Leakage', 'rank': 4, 'points': 0,
        'logic': 'informational',
    },
    'EMAILADDR_UNDELIVERABLE': {
        'category': 'Information Leakage', 'rank': 4, 'points': 0,
        'logic': 'informational',
    },
    'HASH': {
        'category': 'Information Leakage', 'rank': 3, 'points': -5,
        'logic': 'unverified_exists',
    },
    'HASH_COMPROMISED': {
        'category': 'Information Leakage', 'rank': 1, 'points': -20,
        'logic': 'unverified_exists',
    },
    'HUMAN_NAME': {
        'category': 'Information Leakage', 'rank': 3, 'points': -5,
        'logic': 'unverified_exists',
    },
    'PERSON_NAME': {
        'category': 'Information Leakage', 'rank': 3, 'points': -5,
        'logic': 'unverified_exists',
    },
    'DATE_HUMAN_DOB': {
        'category': 'Information Leakage', 'rank': 2, 'points': -10,
        'logic': 'unverified_exists',
    },
    'JOB_TITLE': {
        'category': 'Information Leakage', 'rank': 4, 'points': -5,
        'logic': 'unverified_exists',
    },
    'IBAN_NUMBER': {
        'category': 'Information Leakage', 'rank': 5, 'points': 0,
        'logic': 'informational',
    },
    'CREDIT_CARD_NUMBER': {
        'category': 'Information Leakage', 'rank': 1, 'points': -20,
        'logic': 'unverified_exists',
    },
    'INTERESTING_FILE': {
        'category': 'Information Leakage', 'rank': 2, 'points': -10,
        'logic': 'unverified_exists',
    },
    'INTERESTING_FILE_HISTORIC': {
        'category': 'Information Leakage', 'rank': 3, 'points': -5,
        'logic': 'unverified_exists',
    },
    'MALICIOUS_EMAILADDR': {
        'category': 'Information Leakage', 'rank': 2, 'points': -10,
        'logic': 'unverified_exists',
    },
    'PGP_KEY': {
        'category': 'Information Leakage', 'rank': 2, 'points': -10,
        'logic': 'unverified_exists',
    },
    'PHONE_NUMBER': {
        'category': 'Information Leakage', 'rank': 3, 'points': -5,
        'logic': 'unverified_exists',
    },
    'PHONE_NUMBER_COMPROMISED': {
        'category': 'Information Leakage', 'rank': 2, 'points': -10,
        'logic': 'unverified_exists',
    },
    'PHONE_NUMBER_TYPE': {
        'category': 'Information Leakage', 'rank': 4, 'points': 0,
        'logic': 'informational',
    },
    'MALICIOUS_PHONE_NUMBER': {
        'category': 'Information Leakage', 'rank': 2, 'points': -10,
        'logic': 'unverified_exists',
    },
    'PHYSICAL_ADDRESS': {
        'category': 'Information Leakage', 'rank': 3, 'points': -5,
        'logic': 'unverified_exists',
    },
    'RAW_FILE_META_DATA': {
        'category': 'Information Leakage', 'rank': 5, 'points': 0,
        'logic': 'informational',
    },
    'SOFTWARE_USED': {
        'category': 'Information Leakage', 'rank': 3, 'points': -5,
        'logic': 'unverified_exists',
    },
    'USERNAME': {
        'category': 'Information Leakage', 'rank': 3, 'points': -5,
        'logic': 'unverified_exists',
    },
    'PASSWORD_COMPROMISED': {
        'category': 'Information Leakage', 'rank': 1, 'points': -20,
        'logic': 'unverified_exists',
    },
    'LEAKSITE_URL': {
        'category': 'Information Leakage', 'rank': 1, 'points': -20,
        'logic': 'unverified_exists',
    },
    'LEAKSITE_CONTENT': {
        'category': 'Information Leakage', 'rank': 1, 'points': -20,
        'logic': 'unverified_exists',
    },

    # =========================================================================
    # IP Reputation
    # =========================================================================
    'BLACKLISTED_IPADDR': {
        'category': 'IP Reputation', 'rank': 1, 'points': -20,
        'logic': 'unverified_exists',
    },
    'BLACKLISTED_SUBNET': {
        'category': 'IP Reputation', 'rank': 5, 'points': 0,
        'logic': 'informational',
    },
    'BLACKLISTED_COHOST': {
        'category': 'IP Reputation', 'rank': 2, 'points': -10,
        'logic': 'unverified_exists',
    },
    'BLACKLISTED_INTERNET_NAME': {
        'category': 'IP Reputation', 'rank': 2, 'points': -10,
        'logic': 'unverified_exists',
    },
    'BLACKLISTED_NETBLOCK': {
        'category': 'IP Reputation', 'rank': 3, 'points': -5,
        'logic': 'unverified_exists',
    },
    'MALICIOUS_IPADDR': {
        'category': 'IP Reputation', 'rank': 1, 'points': -20,
        'logic': 'unverified_exists',
    },
    'MALICIOUS_SUBNET': {
        'category': 'IP Reputation', 'rank': 5, 'points': 0,
        'logic': 'informational',
    },
    'MALICIOUS_ASN': {
        'category': 'IP Reputation', 'rank': 2, 'points': -10,
        'logic': 'unverified_exists',
    },
    'MALICIOUS_INTERNET_NAME': {
        'category': 'IP Reputation', 'rank': 2, 'points': -10,
        'logic': 'unverified_exists',
    },
    'MALICIOUS_NETBLOCK': {
        'category': 'IP Reputation', 'rank': 3, 'points': -5,
        'logic': 'unverified_exists',
    },
    'MALICIOUS_BITCOIN_ADDRESS': {
        'category': 'IP Reputation', 'rank': 2, 'points': -10,
        'logic': 'unverified_exists',
    },

    # =========================================================================
    # Network Security
    # =========================================================================
    'EXTERNAL_VULNERABILITIES': {
        'category': 'Network Security', 'rank': 1, 'points': 0,
        'logic': 'crit_high_med',
        'crit_points': -20, 'high_points': -10, 'med_points': -5,
    },
    'VULNERABILITY_CVE_CRITICAL': {
        'category': 'Network Security', 'rank': 1, 'points': -20,
        'logic': 'unverified_exists',
    },
    'VULNERABILITY_CVE_HIGH': {
        'category': 'Network Security', 'rank': 1, 'points': -15,
        'logic': 'unverified_exists',
    },
    'VULNERABILITY_CVE_MEDIUM': {
        'category': 'Network Security', 'rank': 2, 'points': -10,
        'logic': 'unverified_exists',
    },
    'VULNERABILITY_CVE_LOW': {
        'category': 'Network Security', 'rank': 3, 'points': -5,
        'logic': 'unverified_exists',
    },
    'VULNERABILITY_GENERAL': {
        'category': 'Network Security', 'rank': 2, 'points': -10,
        'logic': 'unverified_exists',
    },
    'INTERNAL_IP_ADDRESS': {
        'category': 'Network Security', 'rank': 1, 'points': -20,
        'logic': 'unverified_exists',
    },
    'IP_ADDRESS': {
        'category': 'Network Security', 'rank': 3, 'points': -5,
        'logic': 'unverified_exists',
    },
    'IPV6_ADDRESS': {
        'category': 'Network Security', 'rank': 3, 'points': -5,
        'logic': 'unverified_exists',
    },
    'TCP_PORT_OPEN': {
        'category': 'Network Security', 'rank': 2, 'points': -10,
        'logic': 'unverified_exists',
    },
    'TCP_PORT_OPEN_BANNER': {
        'category': 'Network Security', 'rank': 5, 'points': 0,
        'logic': 'informational',
    },
    'UDP_PORT_OPEN': {
        'category': 'Network Security', 'rank': 2, 'points': -10,
        'logic': 'unverified_exists',
    },
    'UDP_PORT_OPEN_INFO': {
        'category': 'Network Security', 'rank': 5, 'points': 0,
        'logic': 'informational',
    },
    'DEFACED_INTERNET_NAME': {
        'category': 'Network Security', 'rank': 1, 'points': -20,
        'logic': 'unverified_exists',
    },
    'DEFACED_IPADDR': {
        'category': 'Network Security', 'rank': 1, 'points': -20,
        'logic': 'unverified_exists',
    },
    'DEFACED_AFFILIATE_INTERNET_NAME': {
        'category': 'Network Security', 'rank': 2, 'points': -10,
        'logic': 'unverified_exists',
    },
    'DEFACED_COHOST': {
        'category': 'Network Security', 'rank': 2, 'points': -10,
        'logic': 'unverified_exists',
    },
    'DEFACED_AFFILIATE_IPADDR': {
        'category': 'Network Security', 'rank': 2, 'points': -10,
        'logic': 'unverified_exists',
    },
    'PROXY_HOST': {
        'category': 'Network Security', 'rank': 3, 'points': -5,
        'logic': 'unverified_exists',
    },
    'VPN_HOST': {
        'category': 'Network Security', 'rank': 3, 'points': -5,
        'logic': 'unverified_exists',
    },
    'TOR_EXIT_NODE': {
        'category': 'Network Security', 'rank': 3, 'points': -5,
        'logic': 'unverified_exists',
    },

    # =========================================================================
    # External Account Exposure
    # =========================================================================
    'ACCOUNT_EXTERNAL_OWNED': {
        'category': 'External Account Exposure', 'rank': 3, 'points': -5,
        'logic': 'unverified_exists',
    },
    'ACCOUNT_EXTERNAL_OWNED_COMPROMISED': {
        'category': 'External Account Exposure', 'rank': 1, 'points': -20,
        'logic': 'unverified_exists',
    },
    'ACCOUNT_EXTERNAL_USER_SHARED_COMPROMISED': {
        'category': 'External Account Exposure', 'rank': 1, 'points': -20,
        'logic': 'unverified_exists',
    },
    'SIMILAR_ACCOUNT_EXTERNAL': {
        'category': 'External Account Exposure', 'rank': 3, 'points': -5,
        'logic': 'unverified_exists',
    },
    'SOCIAL_MEDIA': {
        'category': 'External Account Exposure', 'rank': 3, 'points': -5,
        'logic': 'unverified_exists',
    },
    'TARGET_ACCOUNTS': {
        'category': 'External Account Exposure', 'rank': 2, 'points': -10,
        'logic': 'unverified_exists',
    },

    # =========================================================================
    # Web App Security
    # =========================================================================
    'HTTP_CODE': {
        'category': 'Web App Security', 'rank': 3, 'points': -5,
        'logic': 'unverified_exists',
    },
    'INTERNET_NAME': {
        'category': 'Web App Security', 'rank': 2, 'points': -10,
        'logic': 'unverified_exists',
    },
    'INTERNET_NAME_UNRESOLVED': {
        'category': 'Web App Security', 'rank': 5, 'points': 0,
        'logic': 'informational',
    },
    'LEAKSITE_URL_WEBAPP': {
        'category': 'Web App Security', 'rank': 5, 'points': 0,
        'logic': 'informational',
    },
    'LINKED_URL_EXTERNAL': {
        'category': 'Web App Security', 'rank': 5, 'points': 0,
        'logic': 'informational',
    },
    'LINKED_URL_INTERNAL': {
        'category': 'Web App Security', 'rank': 5, 'points': 0,
        'logic': 'informational',
    },
    'TARGET_WEB_CONTENT': {
        'category': 'Web App Security', 'rank': 3, 'points': -5,
        'logic': 'unverified_exists',
    },
    'TARGET_WEB_CONTENT_TYPE': {
        'category': 'Web App Security', 'rank': 3, 'points': -5,
        'logic': 'unverified_exists',
    },
    'TARGET_WEB_COOKIE': {
        'category': 'Web App Security', 'rank': 3, 'points': -5,
        'logic': 'unverified_exists',
    },
    'URL_FORM': {
        'category': 'Web App Security', 'rank': 3, 'points': -5,
        'logic': 'unverified_exists',
    },
    'URL_JAVASCRIPT': {
        'category': 'Web App Security', 'rank': 4, 'points': -1,
        'logic': 'unverified_exists',
    },
    'URL_FLASH': {
        'category': 'Web App Security', 'rank': 3, 'points': -5,
        'logic': 'unverified_exists',
    },
    'URL_JAVA_APPLET': {
        'category': 'Web App Security', 'rank': 3, 'points': -5,
        'logic': 'unverified_exists',
    },
    'URL_PASSWORD': {
        'category': 'Web App Security', 'rank': 2, 'points': -10,
        'logic': 'unverified_exists',
    },
    'URL_PASSWORD_HISTORIC': {
        'category': 'Web App Security', 'rank': 3, 'points': -5,
        'logic': 'unverified_exists',
    },
    'URL_STATIC': {
        'category': 'Web App Security', 'rank': 3, 'points': -5,
        'logic': 'unverified_exists',
    },
    'URL_UPLOAD': {
        'category': 'Web App Security', 'rank': 2, 'points': -10,
        'logic': 'unverified_exists',
    },
    'URL_WEB_FRAMEWORK': {
        'category': 'Web App Security', 'rank': 4, 'points': -5,
        'logic': 'unverified_exists',
    },
    'URL_ADBLOCKED_EXTERNAL': {
        'category': 'Web App Security', 'rank': 4, 'points': -1,
        'logic': 'unverified_exists',
    },
    'URL_ADBLOCKED_INTERNAL': {
        'category': 'Web App Security', 'rank': 4, 'points': -1,
        'logic': 'unverified_exists',
    },
    'URL_FORM_HISTORIC': {
        'category': 'Web App Security', 'rank': 4, 'points': -1,
        'logic': 'unverified_exists',
    },
    'URL_FLASH_HISTORIC': {
        'category': 'Web App Security', 'rank': 4, 'points': -1,
        'logic': 'unverified_exists',
    },
    'URL_JAVASCRIPT_HISTORIC': {
        'category': 'Web App Security', 'rank': 4, 'points': -1,
        'logic': 'unverified_exists',
    },
    'URL_WEB_FRAMEWORK_HISTORIC': {
        'category': 'Web App Security', 'rank': 4, 'points': -1,
        'logic': 'unverified_exists',
    },
    'URL_JAVA_APPLET_HISTORIC': {
        'category': 'Web App Security', 'rank': 4, 'points': -1,
        'logic': 'unverified_exists',
    },
    'URL_STATIC_HISTORIC': {
        'category': 'Web App Security', 'rank': 4, 'points': -1,
        'logic': 'unverified_exists',
    },
    'URL_UPLOAD_HISTORIC': {
        'category': 'Web App Security', 'rank': 4, 'points': -1,
        'logic': 'unverified_exists',
    },
    'WAYBACK_FOOTPRINTING': {
        'category': 'Web App Security', 'rank': 5, 'points': 0,
        'logic': 'informational',
    },
    'WEB_ANALYTICS_ID': {
        'category': 'Web App Security', 'rank': 5, 'points': 0,
        'logic': 'informational',
    },
    'WEBAPP_VULNERABILITIES': {
        'category': 'Web App Security', 'rank': 1, 'points': 0,
        'logic': 'crit_high_med',
        'crit_points': -20, 'high_points': -10, 'med_points': -5,
    },
    'WEBSERVER_BANNER': {
        'category': 'Web App Security', 'rank': 5, 'points': 0,
        'logic': 'informational',
    },
    'WEBSERVER_HTTPHEADERS': {
        'category': 'Web App Security', 'rank': 5, 'points': 0,
        'logic': 'informational',
    },
    'WEBSERVER_STRANGEHEADER': {
        'category': 'Web App Security', 'rank': 3, 'points': -5,
        'logic': 'unverified_exists',
    },
    'WEBSERVER_TECHNOLOGY': {
        'category': 'Web App Security', 'rank': 2, 'points': -10,
        'logic': 'unverified_exists',
    },

    # =========================================================================
    # Internal / excluded from grading
    # =========================================================================
    'ROOT': {
        'category': 'Information / Reference', 'rank': 5, 'points': 0,
        'logic': 'informational',
    },
    'AI_SINGLE_SCAN_CORRELATION': {
        'category': 'Information / Reference', 'rank': 5, 'points': 0,
        'logic': 'informational',
    },
    'AI_CROSS_SCAN_CORRELATION': {
        'category': 'Information / Reference', 'rank': 5, 'points': 0,
        'logic': 'informational',
    },
}


# ============================================================================
# AUTO-CATEGORIZATION
# ============================================================================
# For event types not explicitly mapped above, guess category by name patterns.

_AUTO_CATEGORY_PATTERNS = [
    # Order matters: more specific patterns first
    ('MALICIOUS_', 'IP Reputation'),
    ('BLACKLISTED_', 'IP Reputation'),
    ('DEFACED_', 'Network Security'),
    ('VULNERABILITY_', 'Network Security'),
    ('SSL_CERTIFICATE_', 'General Health'),
    ('DNS_', 'DNS Health'),
    ('DOMAIN_', 'DNS Health'),
    ('TCP_PORT_', 'Network Security'),
    ('UDP_PORT_', 'Network Security'),
    ('INTERNAL_IP_', 'Network Security'),
    ('URL_PASSWORD', 'Web App Security'),
    ('URL_UPLOAD', 'Web App Security'),
    ('URL_FORM', 'Web App Security'),
    ('URL_', 'Web App Security'),
    ('WEBSERVER_', 'Web App Security'),
    ('WEB_', 'Web App Security'),
    ('HTTP_', 'Web App Security'),
    ('INTERNET_NAME', 'Web App Security'),
    ('TARGET_WEB_', 'Web App Security'),
    ('LINKED_URL_', 'Web App Security'),
    ('EMAILADDR', 'Information Leakage'),
    ('HASH', 'Information Leakage'),
    ('PASSWORD_', 'Information Leakage'),
    ('PHONE_NUMBER', 'Information Leakage'),
    ('HUMAN_NAME', 'Information Leakage'),
    ('PERSON_NAME', 'Information Leakage'),
    ('USERNAME', 'Information Leakage'),
    ('PHYSICAL_', 'Information Leakage'),
    ('INTERESTING_FILE', 'Information Leakage'),
    ('LEAKSITE_', 'Information Leakage'),
    ('DARKNET_', 'Information Leakage'),
    ('CREDIT_CARD_', 'Information Leakage'),
    ('IBAN_', 'Information Leakage'),
    ('BREACHED_', 'Information Leakage'),
    ('ACCOUNT_EXTERNAL', 'External Account Exposure'),
    ('SOCIAL_MEDIA', 'External Account Exposure'),
    ('SIMILAR_ACCOUNT', 'External Account Exposure'),
    ('APPSTORE_', 'General Health'),
    ('PUBLIC_CODE_', 'General Health'),
    ('COUNTRY_NAME', 'General Health'),
    ('GEOINFO', 'General Health'),
    ('AFFILIATE_', 'Information / Reference'),
    ('NETBLOCK_', 'Information / Reference'),
    ('BGP_AS_', 'Information / Reference'),
    ('CO_HOSTED_', 'Information / Reference'),
    ('COMPANY_NAME', 'Information / Reference'),
    ('DESCRIPTION_', 'Information / Reference'),
    ('PROVIDER_', 'Information / Reference'),
    ('SIMILARDOMAIN', 'Information / Reference'),
    ('RAW_', 'Information / Reference'),
    ('BITCOIN_', 'Information / Reference'),
    ('ETHEREUM_', 'Information / Reference'),
]


def auto_categorize_event_type(event_type_code: str) -> str:
    """Guess the grade category for an unknown event type based on naming patterns.

    Args:
        event_type_code: The event type code (e.g., 'MALICIOUS_IPADDR')

    Returns:
        Category name string.
    """
    code = event_type_code.upper()
    for prefix, category in _AUTO_CATEGORY_PATTERNS:
        if code.startswith(prefix) or prefix in code:
            return category
    return 'Information / Reference'


def get_event_grading(event_type_code: str, overrides: dict = None) -> dict:
    """Get the grading rule for an event type.

    Checks explicit mapping first, then user overrides, then auto-categorizes.

    Args:
        event_type_code: Event type code
        overrides: Optional dict of user-supplied overrides

    Returns:
        Dict with category, rank, points, logic, etc.
    """
    # Check user overrides first
    if overrides and event_type_code in overrides:
        return overrides[event_type_code]

    # Check default mapping
    if event_type_code in DEFAULT_EVENT_TYPE_GRADING:
        return DEFAULT_EVENT_TYPE_GRADING[event_type_code]

    # Auto-categorize unknown types
    category = auto_categorize_event_type(event_type_code)
    return {
        'category': category,
        'rank': 5,
        'points': 0,
        'logic': 'informational',
    }


def get_grade_for_score(score: float, thresholds: list = None) -> dict:
    """Convert a numeric score (0-100) to a letter grade.

    Args:
        score: Numeric score 0-100
        thresholds: Optional custom thresholds list

    Returns:
        Dict with grade letter, color, and background color.
    """
    if thresholds is None:
        thresholds = DEFAULT_GRADE_THRESHOLDS

    for t in thresholds:
        if score >= t['min']:
            return {
                'grade': t['grade'],
                'color': t['color'],
                'bg': t.get('bg', '#ffffff'),
            }

    # Fallback
    last = thresholds[-1] if thresholds else {'grade': 'F', 'color': '#dc2626', 'bg': '#fee2e2'}
    return {'grade': last['grade'], 'color': last['color'], 'bg': last.get('bg', '#ffffff')}


def calculate_category_score(event_type_counts: dict, grading_rules: dict,
                             category_name: str) -> dict:
    """Calculate the score for a single grade category.

    Args:
        event_type_counts: Dict of {event_type: {'total': N, 'unique': N}}
        grading_rules: Dict of grading rules per event type
        category_name: The category being calculated

    Returns:
        Dict with raw_score, details list, etc.
    """
    raw_score = 0
    details = []

    for event_type, rule in grading_rules.items():
        if rule.get('category') != category_name:
            continue

        counts = event_type_counts.get(event_type, {'total': 0, 'unique': 0})
        total = counts['total']
        unique = counts['unique']
        logic = rule.get('logic', 'informational')
        points_applied = 0

        if logic == 'informational':
            points_applied = 0

        elif logic == 'unverified_exists':
            if unique > 0:
                points_applied = rule.get('points', 0)

        elif logic == 'zero_entries_fail':
            if unique == 0:
                points_applied = rule.get('fail_points', -50)
            else:
                points_applied = rule.get('points', 0)

        elif logic == 'crit_high_med':
            # For aggregate vulnerability types, we need severity sub-counts.
            # These are passed in via the counts dict with extra keys.
            crit = counts.get('crit', 0)
            high = counts.get('high', 0)
            med = counts.get('med', 0)
            if crit > 0:
                points_applied += rule.get('crit_points', -20)
            if high > 0:
                points_applied += rule.get('high_points', -10)
            if med > 0:
                points_applied += rule.get('med_points', -5)

        elif logic == 'count_scaled':
            max_penalty = rule.get('max_penalty', -50)
            per_item = rule.get('points', -1)
            points_applied = max(max_penalty, per_item * unique)

        raw_score += points_applied

        if points_applied != 0 or unique > 0:
            details.append({
                'type': event_type,
                'count': unique,
                'total': total,
                'points': points_applied,
                'logic': logic,
                'rank': rule.get('rank', 5),
            })

    # Sort details by points (worst first), then by rank
    details.sort(key=lambda d: (d['points'], d['rank']))

    return {
        'raw_score': raw_score,
        'details': details,
    }


def calculate_full_grade(event_type_counts: dict, config_overrides: dict = None) -> dict:
    """Calculate the full grade for a scan.

    This is the main entry point for grade calculation.

    Args:
        event_type_counts: Dict of {event_type: {'total': N, 'unique': N}}
                          May include 'crit', 'high', 'med' keys for vuln types.
        config_overrides: Optional dict with keys:
            'categories': override category weights
            'event_types': override event type grading rules
            'thresholds': override grade thresholds

    Returns:
        Dict with categories, overall_score, overall_grade, etc.
    """
    overrides = config_overrides or {}

    # Merge category config
    categories = dict(DEFAULT_GRADE_CATEGORIES)
    if 'categories' in overrides:
        for cat_name, cat_override in overrides['categories'].items():
            if cat_name in categories:
                categories[cat_name].update(cat_override)
            else:
                categories[cat_name] = cat_override

    # Merge event type grading rules
    grading_rules = dict(DEFAULT_EVENT_TYPE_GRADING)
    if 'event_types' in overrides:
        grading_rules.update(overrides['event_types'])

    # Also add auto-categorized rules for any event types in the scan
    # that aren't in the grading rules
    for event_type in event_type_counts:
        if event_type not in grading_rules:
            grading_rules[event_type] = get_event_grading(event_type)

    # Thresholds
    thresholds = overrides.get('thresholds', DEFAULT_GRADE_THRESHOLDS)

    # Calculate per-category scores
    category_results = {}
    weighted_sum = 0.0
    weight_total = 0.0
    unmapped_types = []

    for cat_name, cat_config in categories.items():
        result = calculate_category_score(event_type_counts, grading_rules, cat_name)
        weight = cat_config.get('weight', 0.0)

        adj_score = result['raw_score'] * weight
        score = max(0.0, min(100.0, 100.0 + adj_score))
        grade_info = get_grade_for_score(score, thresholds)

        category_results[cat_name] = {
            'raw_score': result['raw_score'],
            'adj_score': round(adj_score, 1),
            'score': round(score, 1),
            'grade': grade_info['grade'],
            'grade_color': grade_info['color'],
            'grade_bg': grade_info['bg'],
            'weight': weight,
            'color': cat_config.get('color', '#6b7280'),
            'description': cat_config.get('description', ''),
            'details': result['details'],
        }

        if weight > 0:
            weighted_sum += score * weight
            weight_total += weight

    # Overall score = weighted average
    overall_score = round(weighted_sum / weight_total, 1) if weight_total > 0 else 100.0
    overall_grade_info = get_grade_for_score(overall_score, thresholds)

    # Check for unmapped types
    for event_type in event_type_counts:
        if event_type not in DEFAULT_EVENT_TYPE_GRADING:
            if not (overrides.get('event_types') and event_type in overrides['event_types']):
                unmapped_types.append(event_type)

    return {
        'categories': category_results,
        'overall_score': overall_score,
        'overall_grade': overall_grade_info['grade'],
        'overall_grade_color': overall_grade_info['color'],
        'overall_grade_bg': overall_grade_info['bg'],
        'unmapped_types': unmapped_types,
        'enabled': True,
    }


def load_grade_config_overrides(config: dict) -> dict:
    """Load grade configuration overrides from the global config dict.

    Reads the _grade_* settings and parses their JSON values.

    Args:
        config: The global SpiderFoot config dict

    Returns:
        Dict suitable for passing as config_overrides to calculate_full_grade()
    """
    overrides = {}

    # Category weight overrides
    cat_weights_str = config.get('_grade_category_weights', '')
    if cat_weights_str and isinstance(cat_weights_str, str) and cat_weights_str.strip():
        try:
            overrides['categories'] = json.loads(cat_weights_str)
        except (json.JSONDecodeError, ValueError) as e:
            log.warning(f"Invalid _grade_category_weights JSON: {e}")

    # Event type overrides
    event_overrides_str = config.get('_grade_event_overrides', '')
    if event_overrides_str and isinstance(event_overrides_str, str) and event_overrides_str.strip():
        try:
            overrides['event_types'] = json.loads(event_overrides_str)
        except (json.JSONDecodeError, ValueError) as e:
            log.warning(f"Invalid _grade_event_overrides JSON: {e}")

    # Threshold overrides
    thresholds_str = config.get('_grade_thresholds', '')
    if thresholds_str and isinstance(thresholds_str, str) and thresholds_str.strip():
        try:
            overrides['thresholds'] = json.loads(thresholds_str)
        except (json.JSONDecodeError, ValueError) as e:
            log.warning(f"Invalid _grade_thresholds JSON: {e}")

    return overrides
