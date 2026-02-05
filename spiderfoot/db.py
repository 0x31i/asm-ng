# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfdb
# Purpose:      Common functions for working with the database back-end.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     15/05/2012
# Copyright:   (c) Steve Micallef 2012
# Licence:     MIT
# -------------------------------------------------------------------------------

from pathlib import Path
import hashlib
import os
import random
import re
import secrets
import sqlite3
import threading
import time
import psycopg2
import psycopg2.extras


class SpiderFootDb:
    """SpiderFoot database.

    Attributes:
        conn: Database connection
        dbh: Database cursor
        dbhLock (_thread.RLock): thread lock on database handle
    """

    dbh = None
    conn = None

    # Prevent multithread access to database
    dbhLock = threading.RLock()

    # Queries for creating the SpiderFoot database
    createSchemaQueries = [
        "PRAGMA journal_mode=WAL",
        "CREATE TABLE tbl_event_types ( \
            event       VARCHAR NOT NULL PRIMARY KEY, \
            event_descr VARCHAR NOT NULL, \
            event_raw   INT NOT NULL DEFAULT 0, \
            event_type  VARCHAR NOT NULL \
        )",
        "CREATE TABLE tbl_config ( \
            scope   VARCHAR NOT NULL, \
            opt     VARCHAR NOT NULL, \
            val     VARCHAR NOT NULL, \
            PRIMARY KEY (scope, opt) \
        )",
        "CREATE TABLE tbl_scan_instance ( \
            guid        VARCHAR NOT NULL PRIMARY KEY, \
            name        VARCHAR NOT NULL, \
            seed_target VARCHAR NOT NULL, \
            created     INT DEFAULT 0, \
            started     INT DEFAULT 0, \
            ended       INT DEFAULT 0, \
            status      VARCHAR NOT NULL \
        )",
        "CREATE TABLE tbl_scan_log ( \
            scan_instance_id    VARCHAR NOT NULL REFERENCES tbl_scan_instance(guid), \
            generated           INT NOT NULL, \
            component           VARCHAR, \
            type                VARCHAR NOT NULL, \
            message             VARCHAR \
        )",
        "CREATE TABLE tbl_scan_config ( \
            scan_instance_id    VARCHAR NOT NULL REFERENCES tbl_scan_instance(guid), \
            component           VARCHAR NOT NULL, \
            opt                 VARCHAR NOT NULL, \
            val                 VARCHAR NOT NULL \
        )",
        "CREATE TABLE tbl_scan_results ( \
            scan_instance_id    VARCHAR NOT NULL REFERENCES tbl_scan_instance(guid), \
            hash                VARCHAR NOT NULL, \
            type                VARCHAR NOT NULL REFERENCES tbl_event_types(event), \
            generated           INT NOT NULL, \
            confidence          INT NOT NULL DEFAULT 100, \
            visibility          INT NOT NULL DEFAULT 100, \
            risk                INT NOT NULL DEFAULT 0, \
            module              VARCHAR NOT NULL, \
            data                VARCHAR, \
            false_positive      INT NOT NULL DEFAULT 0, \
            source_event_hash  VARCHAR DEFAULT 'ROOT', \
            imported_from_scan  VARCHAR DEFAULT NULL \
        )",
        "CREATE TABLE tbl_scan_correlation_results ( \
            id                  VARCHAR NOT NULL PRIMARY KEY, \
            scan_instance_id    VARCHAR NOT NULL REFERENCES tbl_scan_instance(guid), \
            title               VARCHAR NOT NULL, \
            rule_risk           VARCHAR NOT NULL, \
            rule_id             VARCHAR NOT NULL, \
            rule_name           VARCHAR NOT NULL, \
            rule_descr          VARCHAR NOT NULL, \
            rule_logic          VARCHAR NOT NULL \
        )",
        "CREATE TABLE tbl_scan_correlation_results_events ( \
            correlation_id      VARCHAR NOT NULL REFERENCES tbl_scan_correlation_results(id), \
            event_hash          VARCHAR NOT NULL REFERENCES tbl_scan_results(hash) \
        )",
        "CREATE INDEX idx_scan_results_id ON tbl_scan_results (scan_instance_id)",
        "CREATE INDEX idx_scan_results_type ON tbl_scan_results (scan_instance_id, type)",
        "CREATE INDEX idx_scan_results_hash ON tbl_scan_results (scan_instance_id, hash)",
        "CREATE INDEX idx_scan_results_module ON tbl_scan_results(scan_instance_id, module)",
        "CREATE INDEX idx_scan_results_srchash ON tbl_scan_results (scan_instance_id, source_event_hash)",
        "CREATE INDEX idx_scan_logs ON tbl_scan_log (scan_instance_id)",
        "CREATE INDEX idx_scan_correlation ON tbl_scan_correlation_results (scan_instance_id, id)",
        "CREATE INDEX idx_scan_correlation_events ON tbl_scan_correlation_results_events (correlation_id)",
        "CREATE TABLE tbl_target_false_positives ( \
            id              INTEGER PRIMARY KEY AUTOINCREMENT, \
            target          VARCHAR NOT NULL, \
            event_type      VARCHAR NOT NULL, \
            event_data      VARCHAR NOT NULL, \
            source_data     VARCHAR, \
            date_added      INT NOT NULL, \
            notes           VARCHAR, \
            UNIQUE(target, event_type, event_data, source_data) \
        )",
        "CREATE INDEX idx_target_fp_target ON tbl_target_false_positives (target)",
        "CREATE INDEX idx_target_fp_lookup ON tbl_target_false_positives (target, event_type, event_data, source_data)",
        "CREATE TABLE tbl_target_validated ( \
            id              INTEGER PRIMARY KEY AUTOINCREMENT, \
            target          VARCHAR NOT NULL, \
            event_type      VARCHAR NOT NULL, \
            event_data      VARCHAR NOT NULL, \
            source_data     VARCHAR, \
            date_added      INT NOT NULL, \
            notes           VARCHAR, \
            UNIQUE(target, event_type, event_data, source_data) \
        )",
        "CREATE INDEX idx_target_val_target ON tbl_target_validated (target)",
        "CREATE INDEX idx_target_val_lookup ON tbl_target_validated (target, event_type, event_data, source_data)",
        "CREATE TABLE tbl_users ( \
            id              INTEGER PRIMARY KEY AUTOINCREMENT, \
            username        VARCHAR NOT NULL UNIQUE, \
            password_hash   VARCHAR NOT NULL, \
            salt            VARCHAR NOT NULL, \
            display_name    VARCHAR, \
            active          INT NOT NULL DEFAULT 1, \
            created         INT NOT NULL, \
            last_login      INT DEFAULT 0 \
        )",
        "CREATE TABLE tbl_audit_log ( \
            id              INTEGER PRIMARY KEY AUTOINCREMENT, \
            username        VARCHAR NOT NULL, \
            action          VARCHAR NOT NULL, \
            detail          VARCHAR, \
            ip_address      VARCHAR, \
            created         INT NOT NULL \
        )",
        "CREATE INDEX idx_audit_log_username ON tbl_audit_log (username)",
        "CREATE INDEX idx_audit_log_created ON tbl_audit_log (created)",
        "CREATE INDEX idx_audit_log_action ON tbl_audit_log (action)"
    ]

    # PostgreSQL-specific schema queries
    createPostgreSQLSchemaQueries = [
        "CREATE TABLE IF NOT EXISTS tbl_event_types ( \
            event       VARCHAR NOT NULL PRIMARY KEY, \
            event_descr VARCHAR NOT NULL, \
            event_raw   INT NOT NULL DEFAULT 0, \
            event_type  VARCHAR NOT NULL \
        )",
        "CREATE TABLE IF NOT EXISTS tbl_config ( \
            scope   VARCHAR NOT NULL, \
            opt     VARCHAR NOT NULL, \
            val     VARCHAR NOT NULL, \
            PRIMARY KEY (scope, opt) \
        )",
        "CREATE TABLE IF NOT EXISTS tbl_scan_instance ( \
            guid        VARCHAR NOT NULL PRIMARY KEY, \
            name        VARCHAR NOT NULL, \
            seed_target VARCHAR NOT NULL, \
            created     BIGINT DEFAULT 0, \
            started     BIGINT DEFAULT 0, \
            ended       BIGINT DEFAULT 0, \
            status      VARCHAR NOT NULL \
        )",
        "CREATE TABLE IF NOT EXISTS tbl_scan_log ( \
            scan_instance_id    VARCHAR NOT NULL REFERENCES tbl_scan_instance(guid), \
            generated           BIGINT NOT NULL, \
            component           VARCHAR, \
            type                VARCHAR NOT NULL, \
            message             VARCHAR \
        )",
        "CREATE TABLE IF NOT EXISTS tbl_scan_config ( \
            scan_instance_id    VARCHAR NOT NULL REFERENCES tbl_scan_instance(guid), \
            component           VARCHAR NOT NULL, \
            opt                 VARCHAR NOT NULL, \
            val                 VARCHAR NOT NULL \
        )",
        "CREATE TABLE IF NOT EXISTS tbl_scan_results ( \
            scan_instance_id    VARCHAR NOT NULL REFERENCES tbl_scan_instance(guid), \
            hash                VARCHAR NOT NULL, \
            type                VARCHAR NOT NULL REFERENCES tbl_event_types(event), \
            generated           BIGINT NOT NULL, \
            confidence          INT NOT NULL DEFAULT 100, \
            visibility          INT NOT NULL DEFAULT 100, \
            risk                INT NOT NULL DEFAULT 0, \
            module              VARCHAR NOT NULL, \
            data                TEXT, \
            false_positive      INT NOT NULL DEFAULT 0, \
            source_event_hash  VARCHAR DEFAULT 'ROOT', \
            imported_from_scan  VARCHAR DEFAULT NULL \
        )",
        "CREATE TABLE IF NOT EXISTS tbl_scan_correlation_results ( \
            id                  VARCHAR NOT NULL PRIMARY KEY, \
            scan_instance_id    VARCHAR NOT NULL REFERENCES tbl_scan_instance(guid), \
            title               VARCHAR NOT NULL, \
            rule_risk           VARCHAR NOT NULL, \
            rule_id             VARCHAR NOT NULL, \
            rule_name           VARCHAR NOT NULL, \
            rule_descr          VARCHAR NOT NULL, \
            rule_logic          VARCHAR NOT NULL \
        )",
        "CREATE TABLE IF NOT EXISTS tbl_scan_correlation_results_events ( \
            correlation_id      VARCHAR NOT NULL REFERENCES tbl_scan_correlation_results(id), \
            event_hash          VARCHAR NOT NULL REFERENCES tbl_scan_results(hash) \
        )",
        "CREATE INDEX IF NOT EXISTS idx_scan_results_id ON tbl_scan_results (scan_instance_id)",
        "CREATE INDEX IF NOT EXISTS idx_scan_results_type ON tbl_scan_results (scan_instance_id, type)",
        "CREATE INDEX IF NOT EXISTS idx_scan_results_hash ON tbl_scan_results (scan_instance_id, hash)",
        "CREATE INDEX IF NOT EXISTS idx_scan_results_module ON tbl_scan_results(scan_instance_id, module)",
        "CREATE INDEX IF NOT EXISTS idx_scan_results_srchash ON tbl_scan_results (scan_instance_id, source_event_hash)",
        "CREATE INDEX IF NOT EXISTS idx_scan_logs ON tbl_scan_log (scan_instance_id)",
        "CREATE INDEX IF NOT EXISTS idx_scan_correlation ON tbl_scan_correlation_results (scan_instance_id, id)",
        "CREATE INDEX IF NOT EXISTS idx_scan_correlation_events ON tbl_scan_correlation_results_events (correlation_id)",
        "CREATE TABLE IF NOT EXISTS tbl_target_false_positives ( \
            id              SERIAL PRIMARY KEY, \
            target          VARCHAR NOT NULL, \
            event_type      VARCHAR NOT NULL, \
            event_data      TEXT NOT NULL, \
            source_data     TEXT, \
            date_added      BIGINT NOT NULL, \
            notes           TEXT, \
            UNIQUE(target, event_type, event_data, source_data) \
        )",
        "CREATE INDEX IF NOT EXISTS idx_target_fp_target ON tbl_target_false_positives (target)",
        "CREATE INDEX IF NOT EXISTS idx_target_fp_lookup ON tbl_target_false_positives (target, event_type, event_data, source_data)",
        "CREATE TABLE IF NOT EXISTS tbl_target_validated ( \
            id              SERIAL PRIMARY KEY, \
            target          VARCHAR NOT NULL, \
            event_type      VARCHAR NOT NULL, \
            event_data      TEXT NOT NULL, \
            source_data     TEXT, \
            date_added      BIGINT NOT NULL, \
            notes           TEXT, \
            UNIQUE(target, event_type, event_data, source_data) \
        )",
        "CREATE INDEX IF NOT EXISTS idx_target_val_target ON tbl_target_validated (target)",
        "CREATE INDEX IF NOT EXISTS idx_target_val_lookup ON tbl_target_validated (target, event_type, event_data, source_data)",
        "CREATE TABLE IF NOT EXISTS tbl_users ( \
            id              SERIAL PRIMARY KEY, \
            username        VARCHAR NOT NULL UNIQUE, \
            password_hash   VARCHAR NOT NULL, \
            salt            VARCHAR NOT NULL, \
            display_name    VARCHAR, \
            active          INT NOT NULL DEFAULT 1, \
            created         BIGINT NOT NULL, \
            last_login      BIGINT DEFAULT 0 \
        )",
        "CREATE TABLE IF NOT EXISTS tbl_audit_log ( \
            id              SERIAL PRIMARY KEY, \
            username        VARCHAR NOT NULL, \
            action          VARCHAR NOT NULL, \
            detail          TEXT, \
            ip_address      VARCHAR, \
            created         BIGINT NOT NULL \
        )",
        "CREATE INDEX IF NOT EXISTS idx_audit_log_username ON tbl_audit_log (username)",
        "CREATE INDEX IF NOT EXISTS idx_audit_log_created ON tbl_audit_log (created)",
        "CREATE INDEX IF NOT EXISTS idx_audit_log_action ON tbl_audit_log (action)"
    ]

    eventDetails = [
        ['ROOT', 'Internal SpiderFoot Root event', 1, 'INTERNAL'],
        ['ACCOUNT_EXTERNAL_OWNED', 'Account on External Site', 0, 'ENTITY'],
        ['ACCOUNT_EXTERNAL_OWNED_COMPROMISED',
            'Hacked Account on External Site', 0, 'DESCRIPTOR'],
        ['ACCOUNT_EXTERNAL_USER_SHARED_COMPROMISED',
            'Hacked User Account on External Site', 0, 'DESCRIPTOR'],
        ['AFFILIATE_EMAILADDR', 'Affiliate - Email Address', 0, 'ENTITY'],
        ['AFFILIATE_INTERNET_NAME', 'Affiliate - Internet Name', 0, 'ENTITY'],
        ['AFFILIATE_INTERNET_NAME_HIJACKABLE',
            'Affiliate - Internet Name Hijackable', 0, 'ENTITY'],
        ['AFFILIATE_INTERNET_NAME_UNRESOLVED',
            'Affiliate - Internet Name - Unresolved', 0, 'ENTITY'],
        ['AFFILIATE_IPADDR', 'Affiliate - IP Address', 0, 'ENTITY'],
        ['AFFILIATE_IPV6_ADDRESS', 'Affiliate - IPv6 Address', 0, 'ENTITY'],
        ['AFFILIATE_WEB_CONTENT', 'Affiliate - Web Content', 1, 'DATA'],
        ['AFFILIATE_DOMAIN_NAME', 'Affiliate - Domain Name', 0, 'ENTITY'],
        ['AFFILIATE_DOMAIN_UNREGISTERED',
            'Affiliate - Domain Name Unregistered', 0, 'ENTITY'],
        ['AFFILIATE_COMPANY_NAME', 'Affiliate - Company Name', 0, 'ENTITY'],
        ['AFFILIATE_DOMAIN_WHOIS', 'Affiliate - Domain Whois', 1, 'DATA'],
        ['AFFILIATE_DESCRIPTION_CATEGORY',
            'Affiliate Description - Category', 0, 'DESCRIPTOR'],
        ['AFFILIATE_DESCRIPTION_ABSTRACT',
            'Affiliate Description - Abstract', 0, 'DESCRIPTOR'],
        ['APPSTORE_ENTRY', 'App Store Entry', 0, 'ENTITY'],
        ['CLOUD_STORAGE_BUCKET', 'Cloud Storage Bucket', 0, 'ENTITY'],
        ['CLOUD_STORAGE_BUCKET_OPEN', 'Cloud Storage Bucket Open', 0, 'DESCRIPTOR'],
        ['COMPANY_NAME', 'Company Name', 0, 'ENTITY'],
        ['CREDIT_CARD_NUMBER', 'Credit Card Number', 0, 'ENTITY'],
        ['BASE64_DATA', 'Base64-encoded Data', 1, 'DATA'],
        ['BITCOIN_ADDRESS', 'Bitcoin Address', 0, 'ENTITY'],
        ['BITCOIN_BALANCE', 'Bitcoin Balance', 0, 'DESCRIPTOR'],
        ['BGP_AS_OWNER', 'BGP AS Ownership', 0, 'ENTITY'],
        ['BGP_AS_MEMBER', 'BGP AS Membership', 0, 'ENTITY'],
        ['BLACKLISTED_COHOST', 'Blacklisted Co-Hosted Site', 0, 'DESCRIPTOR'],
        ['BLACKLISTED_INTERNET_NAME', 'Blacklisted Internet Name', 0, 'DESCRIPTOR'],
        ['BLACKLISTED_AFFILIATE_INTERNET_NAME',
            'Blacklisted Affiliate Internet Name', 0, 'DESCRIPTOR'],
        ['BLACKLISTED_IPADDR', 'Blacklisted IP Address', 0, 'DESCRIPTOR'],
        ['BLACKLISTED_AFFILIATE_IPADDR',
            'Blacklisted Affiliate IP Address', 0, 'DESCRIPTOR'],
        ['BLACKLISTED_SUBNET', 'Blacklisted IP on Same Subnet', 0, 'DESCRIPTOR'],
        ['BLACKLISTED_NETBLOCK', 'Blacklisted IP on Owned Netblock', 0, 'DESCRIPTOR'],
        ['COUNTRY_NAME', 'Country Name', 0, 'ENTITY'],
        ['CO_HOSTED_SITE', 'Co-Hosted Site', 0, 'ENTITY'],
        ['CO_HOSTED_SITE_DOMAIN', 'Co-Hosted Site - Domain Name', 0, 'ENTITY'],
        ['CO_HOSTED_SITE_DOMAIN_WHOIS', 'Co-Hosted Site - Domain Whois', 1, 'DATA'],
        ['DARKNET_MENTION_URL', 'Darknet Mention URL', 0, 'DESCRIPTOR'],
        ['DARKNET_MENTION_CONTENT', 'Darknet Mention Web Content', 1, 'DATA'],
        ['DATE_HUMAN_DOB', 'Date of Birth', 0, 'ENTITY'],
        ['DEFACED_INTERNET_NAME', 'Defaced', 0, 'DESCRIPTOR'],
        ['DEFACED_IPADDR', 'Defaced IP Address', 0, 'DESCRIPTOR'],
        ['DEFACED_AFFILIATE_INTERNET_NAME', 'Defaced Affiliate', 0, 'DESCRIPTOR'],
        ['DEFACED_COHOST', 'Defaced Co-Hosted Site', 0, 'DESCRIPTOR'],
        ['DEFACED_AFFILIATE_IPADDR', 'Defaced Affiliate IP Address', 0, 'DESCRIPTOR'],
        ['DESCRIPTION_CATEGORY', 'Description - Category', 0, 'DESCRIPTOR'],
        ['DESCRIPTION_ABSTRACT', 'Description - Abstract', 0, 'DESCRIPTOR'],
        ['DEVICE_TYPE', 'Device Type', 0, 'DESCRIPTOR'],
        ['DNS_TEXT', 'DNS TXT Record', 0, 'DATA'],
        ['DNS_SRV', 'DNS SRV Record', 0, 'DATA'],
        ['DNS_SPF', 'DNS SPF Record', 0, 'DATA'],
        ['DOMAIN_NAME', 'Domain Name', 0, 'ENTITY'],
        ['DOMAIN_NAME_PARENT', 'Domain Name (Parent)', 0, 'ENTITY'],
        ['DOMAIN_REGISTRAR', 'Domain Registrar', 0, 'ENTITY'],
        ['DOMAIN_WHOIS', 'Domain Whois', 1, 'DATA'],
        ['EMAILADDR', 'Email Address', 0, 'ENTITY'],
        ['EMAILADDR_COMPROMISED', 'Hacked Email Address', 0, 'DESCRIPTOR'],
        ['EMAILADDR_DELIVERABLE', 'Deliverable Email Address', 0, 'DESCRIPTOR'],
        ['EMAILADDR_DISPOSABLE', 'Disposable Email Address', 0, 'DESCRIPTOR'],
        ['EMAILADDR_GENERIC', 'Email Address - Generic', 0, 'ENTITY'],
        ['EMAILADDR_UNDELIVERABLE', 'Undeliverable Email Address', 0, 'DESCRIPTOR'],
        ['ERROR_MESSAGE', 'Error Message', 0, 'DATA'],
        ['ETHEREUM_ADDRESS', 'Ethereum Address', 0, 'ENTITY'],
        ['ETHEREUM_BALANCE', 'Ethereum Balance', 0, 'DESCRIPTOR'],
        ['GEOINFO', 'Physical Location', 0, 'DESCRIPTOR'],
        ['HASH', 'Hash', 0, 'DATA'],
        ['HASH_COMPROMISED', 'Compromised Password Hash', 0, 'DATA'],
        ['HTTP_CODE', 'HTTP Status Code', 0, 'DATA'],
        ['HUMAN_NAME', 'Human Name', 0, 'ENTITY'],
        ['IBAN_NUMBER', 'IBAN Number', 0, 'ENTITY'],
        ['INTERESTING_FILE', 'Interesting File', 0, 'DESCRIPTOR'],
        ['INTERESTING_FILE_HISTORIC', 'Historic Interesting File', 0, 'DESCRIPTOR'],
        ['JUNK_FILE', 'Junk File', 0, 'DESCRIPTOR'],
        ['INTERNAL_IP_ADDRESS', 'IP Address - Internal Network', 0, 'ENTITY'],
        ['INTERNET_NAME', 'Internet Name', 0, 'ENTITY'],
        ['INTERNET_NAME_UNRESOLVED', 'Internet Name - Unresolved', 0, 'ENTITY'],
        ['IP_ADDRESS', 'IP Address', 0, 'ENTITY'],
        ['IPV6_ADDRESS', 'IPv6 Address', 0, 'ENTITY'],
        ['LEI', 'Legal Entity Identifier', 0, 'ENTITY'],
        ['JOB_TITLE', 'Job Title', 0, 'DESCRIPTOR'],
        ['LINKED_URL_INTERNAL', 'Linked URL - Internal', 0, 'SUBENTITY'],
        ['LINKED_URL_EXTERNAL', 'Linked URL - External', 0, 'SUBENTITY'],
        ['MALICIOUS_ASN', 'Malicious AS', 0, 'DESCRIPTOR'],
        ['MALICIOUS_BITCOIN_ADDRESS', 'Malicious Bitcoin Address', 0, 'DESCRIPTOR'],
        ['MALICIOUS_IPADDR', 'Malicious IP Address', 0, 'DESCRIPTOR'],
        ['MALICIOUS_COHOST', 'Malicious Co-Hosted Site', 0, 'DESCRIPTOR'],
        ['MALICIOUS_EMAILADDR', 'Malicious E-mail Address', 0, 'DESCRIPTOR'],
        ['MALICIOUS_INTERNET_NAME', 'Malicious Internet Name', 0, 'DESCRIPTOR'],
        ['MALICIOUS_AFFILIATE_INTERNET_NAME',
            'Malicious Affiliate', 0, 'DESCRIPTOR'],
        ['MALICIOUS_AFFILIATE_IPADDR',
            'Malicious Affiliate IP Address', 0, 'DESCRIPTOR'],
        ['MALICIOUS_NETBLOCK', 'Malicious IP on Owned Netblock', 0, 'DESCRIPTOR'],
        ['MALICIOUS_PHONE_NUMBER', 'Malicious Phone Number', 0, 'DESCRIPTOR'],
        ['MALICIOUS_SUBNET', 'Malicious IP on Same Subnet', 0, 'DESCRIPTOR'],
        ['NETBLOCK_OWNER', 'Netblock Ownership', 0, 'ENTITY'],
        ['NETBLOCKV6_OWNER', 'Netblock IPv6 Ownership', 0, 'ENTITY'],
        ['NETBLOCK_MEMBER', 'Netblock Membership', 0, 'ENTITY'],
        ['NETBLOCKV6_MEMBER', 'Netblock IPv6 Membership', 0, 'ENTITY'],
        ['NETBLOCK_WHOIS', 'Netblock Whois', 1, 'DATA'],
        ['OPERATING_SYSTEM', 'Operating System', 0, 'DESCRIPTOR'],
        ['LEAKSITE_URL', 'Leak Site URL', 0, 'ENTITY'],
        ['LEAKSITE_CONTENT', 'Leak Site Content', 1, 'DATA'],
        ['PASSWORD_COMPROMISED', 'Compromised Password', 0, 'DATA'],
        ['PERSON_NAME', 'Person Name', 0, 'ENTITY'],
        ['PHONE_NUMBER', 'Phone Number', 0, 'ENTITY'],
        ['PHONE_NUMBER_COMPROMISED', 'Phone Number Compromised', 0, 'DESCRIPTOR'],
        ['PHONE_NUMBER_TYPE', 'Phone Number Type', 0, 'DESCRIPTOR'],
        ['PHYSICAL_ADDRESS', 'Physical Address', 0, 'ENTITY'],
        ['PHYSICAL_COORDINATES', 'Physical Coordinates', 0, 'ENTITY'],
        ['PGP_KEY', 'PGP Public Key', 0, 'DATA'],
        ['PROXY_HOST', 'Proxy Host', 0, 'DESCRIPTOR'],
        ['PROVIDER_DNS', 'Name Server (DNS ''NS'' Records)', 0, 'ENTITY'],
        ['PROVIDER_JAVASCRIPT', 'Externally Hosted Javascript', 0, 'ENTITY'],
        ['PROVIDER_MAIL', 'Email Gateway (DNS ''MX'' Records)', 0, 'ENTITY'],
        ['PROVIDER_HOSTING', 'Hosting Provider', 0, 'ENTITY'],
        ['PROVIDER_TELCO', 'Telecommunications Provider', 0, 'ENTITY'],
        ['PUBLIC_CODE_REPO', 'Public Code Repository', 0, 'ENTITY'],
        ['RAW_RIR_DATA', 'Raw Data from RIRs/APIs', 1, 'DATA'],
        ['RAW_DNS_RECORDS', 'Raw DNS Records', 1, 'DATA'],
        ['RAW_FILE_META_DATA', 'Raw File Meta Data', 1, 'DATA'],
        ['SEARCH_ENGINE_WEB_CONTENT', 'Search Engine Web Content', 1, 'DATA'],
        ['SOCIAL_MEDIA', 'Social Media Presence', 0, 'ENTITY'],
        ['SIMILAR_ACCOUNT_EXTERNAL', 'Similar Account on External Site', 0, 'ENTITY'],
        ['SIMILARDOMAIN', 'Similar Domain', 0, 'ENTITY'],
        ['SIMILARDOMAIN_WHOIS', 'Similar Domain - Whois', 1, 'DATA'],
        ['SOFTWARE_USED', 'Software Used', 0, 'SUBENTITY'],
        ['SSL_CERTIFICATE_RAW', 'SSL Certificate - Raw Data', 1, 'DATA'],
        ['SSL_CERTIFICATE_ISSUED', 'SSL Certificate - Issued to', 0, 'ENTITY'],
        ['SSL_CERTIFICATE_ISSUER', 'SSL Certificate - Issued by', 0, 'ENTITY'],
        ['SSL_CERTIFICATE_MISMATCH', 'SSL Certificate Host Mismatch', 0, 'DESCRIPTOR'],
        ['SSL_CERTIFICATE_EXPIRED', 'SSL Certificate Expired', 0, 'DESCRIPTOR'],
        ['SSL_CERTIFICATE_EXPIRING', 'SSL Certificate Expiring', 0, 'DESCRIPTOR'],
        ['TARGET_WEB_CONTENT', 'Web Content', 1, 'DATA'],
        ['TARGET_WEB_CONTENT_TYPE', 'Web Content Type', 0, 'DESCRIPTOR'],
        ['TARGET_WEB_COOKIE', 'Cookies', 0, 'DATA'],
        ['TCP_PORT_OPEN', 'Open TCP Port', 0, 'SUBENTITY'],
        ['TCP_PORT_OPEN_BANNER', 'Open TCP Port Banner', 0, 'DATA'],
        ['TOR_EXIT_NODE', 'TOR Exit Node', 0, 'DESCRIPTOR'],
        ['UDP_PORT_OPEN', 'Open UDP Port', 0, 'SUBENTITY'],
        ['UDP_PORT_OPEN_INFO', 'Open UDP Port Information', 0, 'DATA'],
        ['URL_ADBLOCKED_EXTERNAL',
            'URL (AdBlocked External)', 0, 'DESCRIPTOR'],
        ['URL_ADBLOCKED_INTERNAL',
            'URL (AdBlocked Internal)', 0, 'DESCRIPTOR'],
        ['URL_FORM', 'URL (Form)', 0, 'DESCRIPTOR'],
        ['URL_FLASH', 'URL (Uses Flash)', 0, 'DESCRIPTOR'],
        ['URL_JAVASCRIPT', 'URL (Uses Javascript)', 0, 'DESCRIPTOR'],
        ['URL_WEB_FRAMEWORK', 'URL (Uses a Web Framework)', 0, 'DESCRIPTOR'],
        ['URL_JAVA_APPLET', 'URL (Uses Java Applet)', 0, 'DESCRIPTOR'],
        ['URL_STATIC', 'URL (Purely Static)', 0, 'DESCRIPTOR'],
        ['URL_PASSWORD', 'URL (Accepts Passwords)', 0, 'DESCRIPTOR'],
        ['URL_UPLOAD', 'URL (Accepts Uploads)', 0, 'DESCRIPTOR'],
        ['URL_FORM_HISTORIC', 'Historic URL (Form)', 0, 'DESCRIPTOR'],
        ['URL_FLASH_HISTORIC', 'Historic URL (Uses Flash)', 0, 'DESCRIPTOR'],
        ['URL_JAVASCRIPT_HISTORIC',
            'Historic URL (Uses Javascript)', 0, 'DESCRIPTOR'],
        ['URL_WEB_FRAMEWORK_HISTORIC',
            'Historic URL (Uses a Web Framework)', 0, 'DESCRIPTOR'],
        ['URL_JAVA_APPLET_HISTORIC',
            'Historic URL (Uses Java Applet)', 0, 'DESCRIPTOR'],
        ['URL_STATIC_HISTORIC',
            'Historic URL (Purely Static)', 0, 'DESCRIPTOR'],
        ['URL_PASSWORD_HISTORIC',
            'Historic URL (Accepts Passwords)', 0, 'DESCRIPTOR'],
        ['URL_UPLOAD_HISTORIC',
            'Historic URL (Accepts Uploads)', 0, 'DESCRIPTOR'],
        ['USERNAME', 'Username', 0, 'ENTITY'],
        ['VPN_HOST', 'VPN Host', 0, 'DESCRIPTOR'],
        ['VULNERABILITY_DISCLOSURE',
            'Vulnerability - Third Party Disclosure', 0, 'DESCRIPTOR'],
        ['VULNERABILITY_CVE_CRITICAL', 'Vulnerability - CVE Critical', 0, 'DESCRIPTOR'],
        ['VULNERABILITY_CVE_HIGH', 'Vulnerability - CVE High', 0, 'DESCRIPTOR'],
        ['VULNERABILITY_CVE_MEDIUM', 'Vulnerability - CVE Medium', 0, 'DESCRIPTOR'],
        ['VULNERABILITY_CVE_LOW', 'Vulnerability - CVE Low', 0, 'DESCRIPTOR'],
        ['VULNERABILITY_GENERAL', 'Vulnerability - General', 0, 'DESCRIPTOR'],
        ['WEB_ANALYTICS_ID', 'Web Analytics', 0, 'ENTITY'],
        ['WEBSERVER_BANNER', 'Web Server', 0, 'DATA'],
        ['WEBSERVER_HTTPHEADERS', 'HTTP Headers', 1, 'DATA'],
        ['WEBSERVER_STRANGEHEADER', 'Non-Standard HTTP Header', 0, 'DATA'],
        ['WEBSERVER_TECHNOLOGY', 'Web Technology', 0, 'DESCRIPTOR'],
        ['WIFI_ACCESS_POINT', 'WiFi Access Point Nearby', 0, 'ENTITY'],
        ['WIKIPEDIA_PAGE_EDIT', 'Wikipedia Page Edit', 0, 'DESCRIPTOR'],
    ]

    def __init__(self, opts: dict, init: bool = False) -> None:
        """Initialize database and create handle to the database file. Creates
        the database file if it does not exist. Creates database schema if it
        does not exist.

        Args:
            opts (dict): must specify the database file path in the '__database' key
            init (bool): initialise the database schema.
                         if the database file does not exist this option will be ignored.

        Raises:
            TypeError: arg type was invalid
            ValueError: arg value was invalid
            IOError: database I/O failed
        """

        if not isinstance(opts, dict):
            raise TypeError(f"opts is {type(opts)}; expected dict()") from None
        if not opts:
            raise ValueError("opts is empty") from None
        if not opts.get('__database'):
            raise ValueError("opts['__database'] is empty") from None

        self.db_type = opts.get('__dbtype', 'sqlite')

        if self.db_type == 'sqlite':
            database_path = opts['__database']

            # create database directory
            Path(database_path).parent.mkdir(exist_ok=True, parents=True)

            # connect() will create the database file if it doesn't exist, but
            # at least we can use this opportunity to ensure we have permissions to
            # read and write to such a file.
            try:
                dbh = sqlite3.connect(database_path)
            except Exception as e:
                raise IOError(
                    f"Error connecting to internal database {database_path}") from e

            if dbh is None:
                raise IOError(
                    f"Could not connect to internal database, and could not create {database_path}") from None

            dbh.text_factory = str

            self.conn = dbh
            self.dbh = dbh.cursor()

            def __dbregex__(qry: str, data: str) -> bool:
                """SQLite doesn't support regex queries, so we create a custom
                function to do so.

                Args:
                    qry (str): TBD
                    data (str): TBD

                Returns:
                    bool: matches
                """

                try:
                    rx = re.compile(qry, re.IGNORECASE | re.DOTALL)
                    ret = rx.match(data)
                except Exception:
                    return False
                return ret is not None

            # Now we actually check to ensure the database file has the schema set
            # up correctly.
            with self.dbhLock:
                try:
                    self.dbh.execute('SELECT COUNT(*) FROM tbl_scan_config')
                    self.conn.create_function("REGEXP", 2, __dbregex__)
                except sqlite3.Error:
                    init = True
                    try:
                        self.create()
                    except Exception as e:
                        raise IOError(
                            "Tried to set up the SpiderFoot database schema, but failed") from e

                # For users with pre 4.0 databases, add the correlation
                # tables + indexes if they don't exist.
                try:
                    self.dbh.execute(
                        "SELECT COUNT(*) FROM tbl_scan_correlation_results")
                except sqlite3.Error:
                    try:
                        for query in self.createSchemaQueries:
                            if "correlation" in query:
                                self.dbh.execute(query)
                        self.conn.commit()
                    except sqlite3.Error:
                        raise IOError("Looks like you are running a pre-4.0 database. Unfortunately "
                                      "SpiderFoot wasn't able to migrate you, so you'll need to delete "
                                      "your SpiderFoot database in order to proceed.") from None

                # Add target false positives table if it doesn't exist (migration)
                try:
                    self.dbh.execute(
                        "SELECT COUNT(*) FROM tbl_target_false_positives")
                except sqlite3.Error:
                    try:
                        for query in self.createSchemaQueries:
                            if "target_false_positives" in query or "target_fp" in query:
                                self.dbh.execute(query)
                        self.conn.commit()
                    except sqlite3.Error:
                        pass  # Table creation failed, but this is not critical

                # Migration: Add source_data column and update UNIQUE constraint
                # SQLite doesn't support modifying constraints, so we need to recreate the table
                try:
                    self.dbh.execute("SELECT source_data FROM tbl_target_false_positives LIMIT 1")
                    # Column exists, but check if we need to fix the UNIQUE constraint
                    # by checking if we can insert two entries with same (target, type, data) but different source
                    self.dbh.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='tbl_target_false_positives'")
                    table_sql = self.dbh.fetchone()
                    if table_sql and 'source_data' not in str(table_sql[0]).split('UNIQUE')[1] if 'UNIQUE' in str(table_sql[0]) else True:
                        # Need to recreate table with updated UNIQUE constraint
                        raise sqlite3.Error("Need to update UNIQUE constraint")
                except sqlite3.Error:
                    try:
                        # Recreate table with source_data in UNIQUE constraint
                        self.dbh.execute("CREATE TABLE IF NOT EXISTS tbl_target_false_positives_new ( \
                            id INTEGER PRIMARY KEY AUTOINCREMENT, \
                            target VARCHAR NOT NULL, \
                            event_type VARCHAR NOT NULL, \
                            event_data VARCHAR NOT NULL, \
                            source_data VARCHAR, \
                            date_added INT NOT NULL, \
                            notes VARCHAR, \
                            UNIQUE(target, event_type, event_data, source_data) \
                        )")
                        # Copy existing data
                        self.dbh.execute("INSERT OR IGNORE INTO tbl_target_false_positives_new \
                            (id, target, event_type, event_data, source_data, date_added, notes) \
                            SELECT id, target, event_type, event_data, \
                            CASE WHEN source_data IS NULL THEN NULL ELSE source_data END, \
                            date_added, notes FROM tbl_target_false_positives")
                        # Drop old table and rename new one
                        self.dbh.execute("DROP TABLE tbl_target_false_positives")
                        self.dbh.execute("ALTER TABLE tbl_target_false_positives_new RENAME TO tbl_target_false_positives")
                        # Recreate indexes
                        self.dbh.execute("CREATE INDEX IF NOT EXISTS idx_target_fp_target ON tbl_target_false_positives (target)")
                        self.dbh.execute("CREATE INDEX IF NOT EXISTS idx_target_fp_lookup ON tbl_target_false_positives (target, event_type, event_data, source_data)")
                        self.conn.commit()
                    except sqlite3.Error:
                        pass  # Migration failed, but continue

                # Add target validated table if it doesn't exist (migration for validated status feature)
                try:
                    self.dbh.execute(
                        "SELECT COUNT(*) FROM tbl_target_validated")
                except sqlite3.Error:
                    try:
                        for query in self.createSchemaQueries:
                            if "target_validated" in query or "target_val" in query:
                                self.dbh.execute(query)
                        self.conn.commit()
                    except sqlite3.Error:
                        pass  # Table creation failed, but this is not critical

                # Migration: Add imported_from_scan column to tbl_scan_results if it doesn't exist
                try:
                    self.dbh.execute("SELECT imported_from_scan FROM tbl_scan_results LIMIT 1")
                except sqlite3.Error:
                    try:
                        self.dbh.execute("ALTER TABLE tbl_scan_results ADD COLUMN imported_from_scan VARCHAR DEFAULT NULL")
                        self.conn.commit()
                    except sqlite3.Error:
                        pass  # Column addition failed, but continue

                # Migration: Add tbl_users table if it doesn't exist
                try:
                    self.dbh.execute("SELECT COUNT(*) FROM tbl_users")
                except sqlite3.Error:
                    try:
                        for query in self.createSchemaQueries:
                            if "tbl_users" in query:
                                self.dbh.execute(query)
                        self.conn.commit()
                    except sqlite3.Error:
                        pass

                # Migration: Add tbl_audit_log table if it doesn't exist
                try:
                    self.dbh.execute("SELECT COUNT(*) FROM tbl_audit_log")
                except sqlite3.Error:
                    try:
                        for query in self.createSchemaQueries:
                            if "audit_log" in query:
                                self.dbh.execute(query)
                        self.conn.commit()
                    except sqlite3.Error:
                        pass

                if init:
                    for row in self.eventDetails:
                        event = row[0]
                        event_descr = row[1]
                        event_raw = row[2]
                        event_type = row[3]
                        qry = "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES (?, ?, ?, ?)"

                        try:
                            self.dbh.execute(qry, (
                                event, event_descr, event_raw, event_type
                            ))
                            self.conn.commit()
                        except Exception:
                            continue
                    self.conn.commit()

        elif self.db_type == 'postgresql':
            try:
                self.conn = psycopg2.connect(opts['__database'])
                self.dbh = self.conn.cursor(
                    cursor_factory=psycopg2.extras.DictCursor)
            except Exception as e:
                raise IOError(
                    f"Error connecting to PostgreSQL database {opts['__database']}") from e

            with self.dbhLock:
                try:
                    self.dbh.execute('SELECT COUNT(*) FROM tbl_scan_config')
                except psycopg2.Error:
                    init = True
                    try:
                        self.create()
                    except Exception as e:
                        raise IOError(
                            "Tried to set up the SpiderFoot database schema, but failed") from e

                if init:
                    for row in self.eventDetails:
                        event = row[0]
                        event_descr = row[1]
                        event_raw = row[2]
                        event_type = row[3]
                        qry = "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES (%s, %s, %s, %s)"

                        try:
                            self.dbh.execute(qry, (
                                event, event_descr, event_raw, event_type
                            ))
                            self.conn.commit()
                        except Exception:
                            continue
                    self.conn.commit()

                # Migration: Add source_data column and update UNIQUE constraint
                try:
                    self.dbh.execute("SELECT source_data FROM tbl_target_false_positives LIMIT 1")
                except psycopg2.Error:
                    self.conn.rollback()
                    try:
                        self.dbh.execute("ALTER TABLE tbl_target_false_positives ADD COLUMN source_data TEXT")
                        self.conn.commit()
                    except psycopg2.Error:
                        self.conn.rollback()

                # Update UNIQUE constraint to include source_data (PostgreSQL)
                try:
                    # Check if old constraint exists and drop it
                    self.dbh.execute("ALTER TABLE tbl_target_false_positives DROP CONSTRAINT IF EXISTS tbl_target_false_positives_target_event_type_event_data_key")
                    self.conn.commit()
                except psycopg2.Error:
                    self.conn.rollback()

                try:
                    # Add new constraint with source_data
                    self.dbh.execute("ALTER TABLE tbl_target_false_positives ADD CONSTRAINT tbl_target_false_positives_target_event_type_event_data_source_key UNIQUE (target, event_type, event_data, source_data)")
                    self.conn.commit()
                except psycopg2.Error:
                    self.conn.rollback()  # Constraint may already exist

                # Migration: Add imported_from_scan column to tbl_scan_results if it doesn't exist
                try:
                    self.dbh.execute("SELECT imported_from_scan FROM tbl_scan_results LIMIT 1")
                except psycopg2.Error:
                    self.conn.rollback()
                    try:
                        self.dbh.execute("ALTER TABLE tbl_scan_results ADD COLUMN imported_from_scan VARCHAR DEFAULT NULL")
                        self.conn.commit()
                    except psycopg2.Error:
                        self.conn.rollback()  # Column addition failed, but continue

                # Migration: Add tbl_users table if it doesn't exist
                try:
                    self.dbh.execute("SELECT COUNT(*) FROM tbl_users")
                except psycopg2.Error:
                    self.conn.rollback()
                    try:
                        for query in self.createPostgreSQLSchemaQueries:
                            if "tbl_users" in query:
                                self.dbh.execute(query)
                        self.conn.commit()
                    except psycopg2.Error:
                        self.conn.rollback()

                # Migration: Add tbl_audit_log table if it doesn't exist
                try:
                    self.dbh.execute("SELECT COUNT(*) FROM tbl_audit_log")
                except psycopg2.Error:
                    self.conn.rollback()
                    try:
                        for query in self.createPostgreSQLSchemaQueries:
                            if "audit_log" in query:
                                self.dbh.execute(query)
                        self.conn.commit()
                    except psycopg2.Error:
                        self.conn.rollback()
        else:
            raise ValueError(f"Unsupported database type: {self.db_type}")

    #
    # Back-end database operations
    #

    def create(self) -> None:
        """Create the database schema.

        Raises:
            IOError: database I/O failed
        """

        with self.dbhLock:
            try:
                if self.db_type == 'sqlite':
                    for qry in self.createSchemaQueries:
                        self.dbh.execute(qry)
                elif self.db_type == 'postgresql':
                    for qry in self.createPostgreSQLSchemaQueries:
                        self.dbh.execute(qry)
                
                self.conn.commit()
                
                # Insert event types
                for row in self.eventDetails:
                    event = row[0]
                    event_descr = row[1]
                    event_raw = row[2]
                    event_type = row[3]
                    
                    if self.db_type == 'sqlite':
                        qry = "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES (?, ?, ?, ?)"
                        params = (event, event_descr, event_raw, event_type)
                    else:  # postgresql
                        qry = "INSERT INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES (%s, %s, %s, %s) ON CONFLICT (event) DO NOTHING"
                        params = (event, event_descr, event_raw, event_type)

                    self.dbh.execute(qry, params)
                self.conn.commit()
            except (sqlite3.Error, psycopg2.Error) as e:
                raise IOError(
                    "SQL error encountered when setting up database") from e

    def close(self) -> None:
        """Close the database handle and connection."""

        with self.dbhLock:
            if self.dbh:
                self.dbh.close()
                self.dbh = None
            if self.conn:
                self.conn.close()
                self.conn = None

    def vacuumDB(self) -> None:
        """Vacuum the database. Clears unused database file pages.

        Returns:
            bool: success

        Raises:
            IOError: database I/O failed
        """
        with self.dbhLock:
            try:
                if ((self.db_type == 'sqlite') or (self.db_type == 'postgresql')):
                    self.dbh.execute("VACUUM")
                self.conn.commit()
                return True
            except (sqlite3.Error, psycopg2.Error) as e:
                raise IOError(
                    "SQL error encountered when vacuuming the database") from e
        return False

    def search(self, criteria: dict, filterFp: bool = False) -> list:
        """Search database.

        Args:
            criteria (dict): search criteria such as:
                - scan_id (search within a scan, if omitted search all)
                - type (search a specific type, if omitted search all)
                - value (search values for a specific string, if omitted search all)
                - regex (search values for a regular expression)
                ** at least two criteria must be set **
            filterFp (bool): filter out false positives

        Returns:
            list: search results

        Raises:
            TypeError: arg type was invalid
            ValueError: arg value was invalid
            IOError: database I/O failed
        """
        if not isinstance(criteria, dict):
            raise TypeError(
                f"criteria is {type(criteria)}; expected dict()") from None

        valid_criteria = ['scan_id', 'type', 'value', 'regex']

        for key in list(criteria.keys()):
            if key not in valid_criteria:
                criteria.pop(key, None)
                continue

            if not isinstance(criteria.get(key), str):
                raise TypeError(
                    f"criteria[{key}] is {type(criteria.get(key))}; expected str()") from None

            if not criteria[key]:
                criteria.pop(key, None)
                continue

        if len(criteria) == 0:
            raise ValueError(
                f"No valid search criteria provided; expected: {', '.join(valid_criteria)}") from None

        if len(criteria) == 1:
            raise ValueError(
                "Only one search criteria provided; expected at least two")

        qvars = list()
        qry = "SELECT ROUND(c.generated) AS generated, c.data, \
            s.data as 'source_data', \
            c.module, c.type, c.confidence, c.visibility, c.risk, c.hash, \
            c.source_event_hash, t.event_descr, t.event_type, c.scan_instance_id, \
            c.false_positive as 'fp', s.false_positive as 'parent_fp' \
            FROM tbl_scan_results c, tbl_scan_results s, tbl_event_types t \
            WHERE s.scan_instance_id = c.scan_instance_id AND \
            t.event = c.type AND c.source_event_hash = s.hash "

        if filterFp:
            qry += " AND c.false_positive <> 1 "

        if criteria.get('scan_id') is not None:
            qry += "AND c.scan_instance_id = ? "
            qvars.append(criteria['scan_id'])

        if criteria.get('type') is not None:
            qry += " AND c.type = ? "
            qvars.append(criteria['type'])

        if criteria.get('value') is not None:
            qry += " AND (c.data LIKE ? OR s.data LIKE ?) "
            qvars.append(criteria['value'])
            qvars.append(criteria['value'])

        if criteria.get('regex') is not None:
            qry += " AND (c.data REGEXP ? OR s.data REGEXP ?) "
            qvars.append(criteria['regex'])
            qvars.append(criteria['regex'])

        qry += " ORDER BY c.data"

        with self.dbhLock:
            try:
                self.dbh.execute(qry, qvars)
                return self.dbh.fetchall()
            except (sqlite3.Error, psycopg2.Error) as e:
                raise IOError(
                    "SQL error encountered when fetching search results") from e

    def eventTypes(self) -> list:
        """Get event types.

        Returns:
            list: event types

        Raises:
            IOError: database I/O failed
        """

        qry = "SELECT event_descr, event, event_raw, event_type FROM tbl_event_types"
        with self.dbhLock:
            try:
                self.dbh.execute(qry)
                return self.dbh.fetchall()
            except (sqlite3.Error, psycopg2.Error) as e:
                raise IOError(
                    "SQL error encountered when retrieving event types") from e

    def scanLogEvents(self, batch: list) -> bool:
        """Logs a batch of events to the database.

        Args:
            batch (list): tuples containing: instanceId, classification, message, component, logTime

        Raises:
            TypeError: arg type was invalid
            IOError: database I/O failed

        Returns:
            bool: Whether the logging operation succeeded
        """
        if not batch:
            return True

        inserts = []

        for item in batch:
            if len(item) != 5:
                continue
                
            instanceId, classification, message, component, logTime = item
            
            if not isinstance(instanceId, str):
                continue

            if not isinstance(classification, str):
                continue

            if not isinstance(message, str):
                continue

            if not component:
                component = "SpiderFoot"

            # Convert logTime to proper format if needed
            if isinstance(logTime, float):
                logTime = int(logTime * 1000)
            elif isinstance(logTime, int) and logTime < 1000000000000:  # Assume seconds if too small
                logTime = logTime * 1000

            inserts.append((instanceId, logTime,
                           component, classification, message))

        if not inserts:
            return True

        if self.db_type == 'sqlite':
            qry = "INSERT INTO tbl_scan_log \
                (scan_instance_id, generated, component, type, message) \
                VALUES (?, ?, ?, ?, ?)"
        else:  # postgresql
            qry = "INSERT INTO tbl_scan_log \
                (scan_instance_id, generated, component, type, message) \
                VALUES (%s, %s, %s, %s, %s)"

        with self.dbhLock:
            try:
                # Ensure connection is alive
                if not self.conn:
                    return False
                    
                self.dbh.executemany(qry, inserts)
                self.conn.commit()
                return True
            except (sqlite3.Error, psycopg2.Error) as e:
                # More specific error handling
                if "locked" in str(e).lower() or "thread" in str(e).lower():
                    return False
                # Try to reconnect on other errors
                try:
                    self.conn.rollback()
                except:
                    pass
                return False
            except Exception as e:
                return False

    def scanLogEvent(self, instanceId: str, classification: str, message: str, component: str = None) -> None:
        """Log an event to the database.

        Args:
            instanceId (str): scan instance ID
            classification (str): TBD
            message (str): TBD
            component (str): TBD

        Raises:
            TypeError: arg type was invalid
            IOError: database I/O failed

        Todo:
            Do something smarter to handle database locks
        """

        if not isinstance(instanceId, str):
            raise TypeError(
                f"instanceId is {type(instanceId)}; expected str()") from None

        if not isinstance(classification, str):
            raise TypeError(
                f"classification is {type(classification)}; expected str()") from None

        if not isinstance(message, str):
            raise TypeError(
                f"message is {type(message)}; expected str()") from None

        if not component:
            component = "SpiderFoot"

        qry = "INSERT INTO tbl_scan_log \
            (scan_instance_id, generated, component, type, message) \
            VALUES (?, ?, ?, ?, ?)"

        with self.dbhLock:
            try:
                self.dbh.execute(qry, (
                    instanceId, time.time() * 1000, component, classification, message
                ))
                self.conn.commit()
            except (sqlite3.Error, psycopg2.Error) as e:
                if "locked" not in e.args[0] and "thread" not in e.args[0]:
                    raise IOError(
                        "Unable to log scan event in database") from e
                # print("[warning] Couldn't log due to SQLite limitations. You can probably ignore this.")
                # log.critical(f"Unable to log event in DB due to lock: {e.args[0]}")
                pass

    def scanInstanceCreate(self, instanceId: str, scanName: str, scanTarget: str) -> None:
        """Store a scan instance in the database.

        Args:
            instanceId (str): scan instance ID
            scanName(str): scan name
            scanTarget (str): scan target

        Raises:
            TypeError: arg type was invalid
            IOError: database I/O failed
        """

        if not isinstance(instanceId, str):
            raise TypeError(
                f"instanceId is {type(instanceId)}; expected str()") from None

        if not isinstance(scanName, str):
            raise TypeError(
                f"scanName is {type(scanName)}; expected str()") from None

        if not isinstance(scanTarget, str):
            raise TypeError(
                f"scanTarget is {type(scanTarget)}; expected str()") from None

        qry = "INSERT INTO tbl_scan_instance \
            (guid, name, seed_target, created, status) \
            VALUES (?, ?, ?, ?, ?)"

        with self.dbhLock:
            try:
                self.dbh.execute(qry, (
                    instanceId, scanName, scanTarget, time.time() * 1000, 'CREATED'
                ))
                self.conn.commit()
            except (sqlite3.Error, psycopg2.Error) as e:
                raise IOError(
                    "Unable to create scan instance in database") from e

    def scanInstanceSet(self, instanceId: str, started: str = None, ended: str = None, status: str = None) -> None:
        """Update the start time, end time or status (or all 3) of a scan
        instance.

        Args:
            instanceId (str): scan instance ID
            started (str): scan start time
            ended (str): scan end time
            status (str): scan status

        Raises:
            TypeError: arg type was invalid
            IOError: database I/O failed
        """

        if not isinstance(instanceId, str):
            raise TypeError(
                f"instanceId is {type(instanceId)}; expected str()") from None

        qvars = list()
        qry = "UPDATE tbl_scan_instance SET "

        if started is not None:
            qry += " started = ?,"
            qvars.append(started)

        if ended is not None:
            qry += " ended = ?,"
            qvars.append(ended)

        if status is not None:
            qry += " status = ?,"
            qvars.append(status)

        # guid = guid is a little hack to avoid messing with , placement above
        qry += " guid = guid WHERE guid = ?"
        qvars.append(instanceId)

        with self.dbhLock:
            try:
                self.dbh.execute(qry, qvars)
                self.conn.commit()
            except (sqlite3.Error, psycopg2.Error):
                raise IOError(
                    "Unable to set information for the scan instance.") from None

    def scanInstanceGet(self, instanceId: str) -> list:
        """Return info about a scan instance (name, target, created, started,
        ended, status)

        Args:
            instanceId (str): scan instance ID

        Returns:
            list: scan instance info

        Raises:
            TypeError: arg type was invalid
            IOError: database I/O failed
        """

        if not isinstance(instanceId, str):
            raise TypeError(
                f"instanceId is {type(instanceId)}; expected str()") from None

        qry = "SELECT name, seed_target, ROUND(created/1000) AS created, \
            ROUND(started/1000) AS started, ROUND(ended/1000) AS ended, status \
            FROM tbl_scan_instance WHERE guid = ?"
        qvars = [instanceId]

        with self.dbhLock:
            try:
                self.dbh.execute(qry, qvars)
                return self.dbh.fetchone()
            except (sqlite3.Error, psycopg2.Error) as e:
                raise IOError(
                    "SQL error encountered when retrieving scan instance") from e

    def scanCountForTarget(self, target: str) -> int:
        """Count the number of scans for a given target.

        Args:
            target (str): the target (seed_target value)

        Returns:
            int: number of scans for the target

        Raises:
            TypeError: arg type was invalid
            IOError: database I/O failed
        """
        if not isinstance(target, str):
            raise TypeError(f"target is {type(target)}; expected str()") from None

        qry = "SELECT COUNT(*) FROM tbl_scan_instance WHERE seed_target = ?"

        with self.dbhLock:
            try:
                self.dbh.execute(qry, [target])
                row = self.dbh.fetchone()
                return row[0] if row else 0
            except (sqlite3.Error, psycopg2.Error) as e:
                raise IOError("SQL error encountered when counting scans for target") from e

    def scanResultSummary(self, instanceId: str, by: str = "type") -> list:
        """Obtain a summary of the results, filtered by event type, module or
        entity.

        Args:
            instanceId (str): scan instance ID
            by (str): filter by type

        Returns:
            list: scan instance info

        Raises:
            TypeError: arg type was invalid
            ValueError: arg value was invalid
            IOError: database I/O failed
        """

        if not isinstance(instanceId, str):
            raise TypeError(
                f"instanceId is {type(instanceId)}; expected str()") from None

        if not isinstance(by, str):
            raise TypeError(f"by is {type(by)}; expected str()") from None

        if by not in ["type", "module", "entity"]:
            raise ValueError(f"Invalid filter by value: {by}") from None

        if by == "type":
            qry = "SELECT r.type, e.event_descr, MAX(ROUND(generated)) AS last_in, \
                count(*) AS total, count(DISTINCT r.data) as utotal FROM \
                tbl_scan_results r, tbl_event_types e WHERE e.event = r.type \
                AND r.scan_instance_id = ? GROUP BY r.type ORDER BY e.event_descr"

        if by == "module":
            qry = "SELECT r.module, '', MAX(ROUND(generated)) AS last_in, \
                count(*) AS total, count(DISTINCT r.data) as utotal FROM \
                tbl_scan_results r, tbl_event_types e WHERE e.event = r.type \
                AND r.scan_instance_id = ? GROUP BY r.module ORDER BY r.module DESC"

        if by == "entity":
            qry = "SELECT r.data, e.event_descr, MAX(ROUND(generated)) AS last_in, \
                count(*) AS total, count(DISTINCT r.data) as utotal FROM \
                tbl_scan_results r, tbl_event_types e WHERE e.event = r.type \
                AND r.scan_instance_id = ? \
                AND e.event_type in ('ENTITY') \
                GROUP BY r.data, e.event_descr ORDER BY total DESC limit 50"

        qvars = [instanceId]

        with self.dbhLock:
            try:
                self.dbh.execute(qry, qvars)
                return self.dbh.fetchall()
            except (sqlite3.Error, psycopg2.Error) as e:
                raise IOError(
                    "SQL error encountered when fetching result summary") from e

    def scanCorrelationSummary(self, instanceId: str, by: str = "rule") -> list:
        """Obtain a summary of the correlations, filtered by rule or risk.

        Args:
            instanceId (str): scan instance ID
            by (str): filter by rule or risk

        Returns:
            list: scan correlation summary

        Raises:
            TypeError: arg type was invalid
            ValueError: arg value was invalid
            IOError: database I/O failed
        """

        if not isinstance(instanceId, str):
            raise TypeError(
                f"instanceId is {type(instanceId)}; expected str()") from None

        if not isinstance(by, str):
            raise TypeError(f"by is {type(by)}; expected str()") from None

        if by not in ["rule", "risk"]:
            raise ValueError(f"Invalid filter by value: {by}") from None

        if by == "risk":
            qry = "SELECT rule_risk, count(*) AS total FROM \
                tbl_scan_correlation_results \
                WHERE scan_instance_id = ? GROUP BY rule_risk ORDER BY rule_id"

        if by == "rule":
            qry = "SELECT rule_id, rule_name, rule_risk, rule_descr, \
                count(*) AS total FROM \
                tbl_scan_correlation_results \
                WHERE scan_instance_id = ? GROUP BY rule_id ORDER BY rule_id"

        qvars = [instanceId]

        with self.dbhLock:
            try:
                self.dbh.execute(qry, qvars)
                return self.dbh.fetchall()
            except (sqlite3.Error, psycopg2.Error) as e:
                raise IOError(
                    "SQL error encountered when fetching correlation summary") from e

    def scanCorrelationList(self, instanceId: str) -> list:
        """Obtain a list of the correlations from a scan.

        Args:
            instanceId (str): scan instance ID

        Returns:
            list: scan correlation list

        Raises:
            TypeError: arg type was invalid
            IOError: database I/O failed
        """

        if not isinstance(instanceId, str):
            raise TypeError(
                f"instanceId is {type(instanceId)}; expected str()") from None

        qry = "SELECT c.id, c.title, c.rule_id, c.rule_risk, c.rule_name, \
            c.rule_descr, c.rule_logic, count(e.event_hash) AS event_count FROM \
            tbl_scan_correlation_results c, tbl_scan_correlation_results_events e \
            WHERE scan_instance_id = ? AND c.id = e.correlation_id \
            GROUP BY c.id ORDER BY c.title, c.rule_risk"

        qvars = [instanceId]

        with self.dbhLock:
            try:
                self.dbh.execute(qry, qvars)
                return self.dbh.fetchall()
            except (sqlite3.Error, psycopg2.Error) as e:
                raise IOError(
                    "SQL error encountered when fetching correlation list") from e

    def scanResultEvent(
        self,
        instanceId: str,
        eventType: str = 'ALL',
        srcModule: str = None,
        data: list = None,
        sourceId: list = None,
        correlationId: str = None,
        filterFp: bool = False
    ) -> list:
        """Obtain the data for a scan and event type.

        Args:
            instanceId (str): scan instance ID
            eventType (str): filter by event type
            srcModule (str): filter by the generating module
            data (list): filter by the data
            sourceId (list): filter by the ID of the source event
            correlationId (str): filter by the ID of a correlation result
            filterFp (bool): filter false positives

        Returns:
            list: scan results

        Raises:
            TypeError: arg type was invalid
            IOError: database I/O failed
        """

        if not isinstance(instanceId, str):
            raise TypeError(
                f"instanceId is {type(instanceId)}; expected str()") from None

        if not isinstance(eventType, str) and not isinstance(eventType, list):
            raise TypeError(
                f"eventType is {type(eventType)}; expected str() or list()") from None

        qry = "SELECT ROUND(c.generated) AS generated, c.data, \
            s.data as 'source_data', \
            c.module, c.type, c.confidence, c.visibility, c.risk, c.hash, \
            c.source_event_hash, t.event_descr, t.event_type, s.scan_instance_id, \
            c.false_positive as 'fp', s.false_positive as 'parent_fp', \
            c.imported_from_scan \
            FROM tbl_scan_results c, tbl_scan_results s, tbl_event_types t "

        if correlationId:
            qry += ", tbl_scan_correlation_results_events ce "

        qry += "WHERE c.scan_instance_id = ? AND c.source_event_hash = s.hash AND \
            s.scan_instance_id = c.scan_instance_id AND t.event = c.type"

        qvars = [instanceId]

        if correlationId:
            qry += " AND ce.event_hash = c.hash AND ce.correlation_id = ?"
            qvars.append(correlationId)

        if eventType != "ALL":
            if isinstance(eventType, list):
                qry += " AND c.type in (" + \
                    ','.join(['?'] * len(eventType)) + ")"
                qvars.extend(eventType)
            else:
                qry += " AND c.type = ?"
                qvars.append(eventType)

        if filterFp:
            qry += " AND c.false_positive <> 1"

        if srcModule:
            if isinstance(srcModule, list):
                qry += " AND c.module in (" + \
                    ','.join(['?'] * len(srcModule)) + ")"
                qvars.extend(srcModule)
            else:
                qry += " AND c.module = ?"
                qvars.append(srcModule)

        if data:
            if isinstance(data, list):
                qry += " AND c.data in (" + ','.join(['?'] * len(data)) + ")"
                qvars.extend(data)
            else:
                qry += " AND c.data = ?"
                qvars.append(data)

        if sourceId:
            if isinstance(sourceId, list):
                qry += " AND c.source_event_hash in (" + \
                    ','.join(['?'] * len(sourceId)) + ")"
                qvars.extend(sourceId)
            else:
                qry += " AND c.source_event_hash = ?"
                qvars.append(sourceId)

        qry += " ORDER BY c.data"

        with self.dbhLock:
            try:
                self.dbh.execute(qry, qvars)
                return self.dbh.fetchall()
            except (sqlite3.Error, psycopg2.Error) as e:
                raise IOError(
                    "SQL error encountered when fetching result events") from e

    def scanResultEventUnique(self, instanceId: str, eventType: str = 'ALL', filterFp: bool = False) -> list:
        """Obtain a unique list of elements.

        Args:
            instanceId (str): scan instance ID
            eventType (str): filter by event type
            filterFp (bool): filter false positives

        Returns:
            list: unique scan results

        Raises:
            TypeError: arg type was invalid
            IOError: database I/O failed
        """

        if not isinstance(instanceId, str):
            raise TypeError(
                f"instanceId is {type(instanceId)}; expected str()") from None

        if not isinstance(eventType, str):
            raise TypeError(
                f"eventType is {type(eventType)}; expected str()") from None

        qry = "SELECT DISTINCT data, type, COUNT(*) FROM tbl_scan_results \
            WHERE scan_instance_id = ?"
        qvars = [instanceId]

        if eventType != "ALL":
            qry += " AND type = ?"
            qvars.append(eventType)

        if filterFp:
            qry += " AND false_positive <> 1"

        qry += " GROUP BY type, data ORDER BY COUNT(*)"

        with self.dbhLock:
            try:
                self.dbh.execute(qry, qvars)
                return self.dbh.fetchall()
            except (sqlite3.Error, psycopg2.Error) as e:
                raise IOError(
                    "SQL error encountered when fetching unique result events") from e

    def scanLogs(self, instanceId: str, limit: int = None, fromRowId: int = 0, reverse: bool = False) -> list:
        """Get scan logs.

        Args:
            instanceId (str): scan instance ID
            limit (int): limit number of results
            fromRowId (int): retrieve logs starting from row ID
            reverse (bool): search result order

        Returns:
            list: scan logs

        Raises:
            TypeError: arg type was invalid
            IOError: database I/O failed
        """

        if not isinstance(instanceId, str):
            raise TypeError(
                f"instanceId is {type(instanceId)}; expected str()") from None

        qry = "SELECT generated AS generated, component, \
            type, message, rowid FROM tbl_scan_log WHERE scan_instance_id = ?"
        if fromRowId:
            qry += " and rowid > ?"

        qry += " ORDER BY generated "
        if reverse:
            qry += "ASC"
        else:
            qry += "DESC"
        qvars = [instanceId]

        if fromRowId:
            qvars.append(str(fromRowId))

        if limit is not None:
            qry += " LIMIT ?"
            qvars.append(str(limit))

        with self.dbhLock:
            try:
                self.dbh.execute(qry, qvars)
                return self.dbh.fetchall()
            except (sqlite3.Error, psycopg2.Error) as e:
                raise IOError(
                    "SQL error encountered when fetching scan logs") from e

    def scanErrors(self, instanceId: str, limit: int = 0) -> list:
        """Get scan errors.

        Args:
            instanceId (str): scan instance ID
            limit (int): limit number of results

        Returns:
            list: scan errors

        Raises:
            TypeError: arg type was invalid
            IOError: database I/O failed
        """

        if not isinstance(instanceId, str):
            raise TypeError(
                f"instanceId is {type(instanceId)}; expected str()") from None

        if not isinstance(limit, int):
            raise TypeError(
                f"limit is {type(limit)}; expected int()") from None

        qry = "SELECT generated AS generated, component, \
            message FROM tbl_scan_log WHERE scan_instance_id = ? \
            AND type = 'ERROR' ORDER BY generated DESC"
        qvars = [instanceId]

        if limit:
            qry += " LIMIT ?"
            qvars.append(str(limit))

        with self.dbhLock:
            try:
                self.dbh.execute(qry, qvars)
                return self.dbh.fetchall()
            except (sqlite3.Error, psycopg2.Error) as e:
                raise IOError(
                    "SQL error encountered when fetching scan errors") from e

    def scanInstanceDelete(self, instanceId: str) -> bool:
        """Delete a scan instance.

        Args:
            instanceId (str): scan instance ID

        Returns:
            bool: success

        Raises:
            TypeError: arg type was invalid
            IOError: database I/O failed
        """

        if not isinstance(instanceId, str):
            raise TypeError(
                f"instanceId is {type(instanceId)}; expected str()") from None

        qry1 = "DELETE FROM tbl_scan_instance WHERE guid = ?"
        qry2 = "DELETE FROM tbl_scan_config WHERE scan_instance_id = ?"
        qry3 = "DELETE FROM tbl_scan_results WHERE scan_instance_id = ?"
        qry4 = "DELETE FROM tbl_scan_log WHERE scan_instance_id = ?"
        qvars = [instanceId]

        with self.dbhLock:
            try:
                self.dbh.execute(qry1, qvars)
                self.dbh.execute(qry2, qvars)
                self.dbh.execute(qry3, qvars)
                self.dbh.execute(qry4, qvars)
                self.conn.commit()
            except (sqlite3.Error, psycopg2.Error) as e:
                raise IOError(
                    "SQL error encountered when deleting scan") from e

        return True

    def scanResultsUpdateFP(self, instanceId: str, resultHashes: list, fpFlag: int) -> bool:
        """Set the false positive flag for a result.

        Args:
            instanceId (str): scan instance ID
            resultHashes (list): list of event hashes
            fpFlag (int): false positive

        Returns:
            bool: success

        Raises:
            TypeError: arg type was invalid
            IOError: database I/O failed
        """

        if not isinstance(instanceId, str):
            raise TypeError(
                f"instanceId is {type(instanceId)}; expected str()") from None

        if not isinstance(resultHashes, list):
            raise TypeError(
                f"resultHashes is {type(resultHashes)}; expected list()") from None

        with self.dbhLock:
            for resultHash in resultHashes:
                qry = "UPDATE tbl_scan_results SET false_positive = ? WHERE \
                    scan_instance_id = ? AND hash = ?"
                qvars = [fpFlag, instanceId, resultHash]
                try:
                    self.dbh.execute(qry, qvars)
                except (sqlite3.Error, psycopg2.Error) as e:
                    raise IOError(
                        "SQL error encountered when updating false-positive") from e

            try:
                self.conn.commit()
            except (sqlite3.Error, psycopg2.Error) as e:
                raise IOError(
                    "SQL error encountered when updating false-positive") from e

        return True

    def syncFalsePositiveAcrossScans(self, target: str, eventType: str, eventData: str, sourceData: str, fpFlag: int) -> int:
        """Sync the false positive flag across all scans of the same target for matching entries.

        This updates the scan-level FP flag in tbl_scan_results for all entries across
        all scans of the same target that match the given (event_type, event_data, source_data).

        Args:
            target (str): the target (seed_target value)
            eventType (str): the event type
            eventData (str): the event data
            sourceData (str): the source data of the event (data from the source event)
            fpFlag (int): false positive flag (0=unvalidated, 1=FP, 2=validated)

        Returns:
            int: number of rows updated

        Raises:
            TypeError: arg type was invalid
            IOError: database I/O failed
        """
        if not isinstance(target, str):
            raise TypeError(f"target is {type(target)}; expected str()") from None
        if not isinstance(eventType, str):
            raise TypeError(f"eventType is {type(eventType)}; expected str()") from None
        if not isinstance(eventData, str):
            raise TypeError(f"eventData is {type(eventData)}; expected str()") from None

        # Update scan results across all scans of the same target where:
        # - type matches eventType
        # - data matches eventData
        # - the source event's data matches sourceData
        # This uses a subquery to find scans with the same target and match source data via self-join
        if sourceData is not None:
            qry = """UPDATE tbl_scan_results
                SET false_positive = ?
                WHERE scan_instance_id IN (SELECT guid FROM tbl_scan_instance WHERE seed_target = ?)
                AND type = ?
                AND data = ?
                AND source_event_hash IN (
                    SELECT hash FROM tbl_scan_results src
                    WHERE src.scan_instance_id = tbl_scan_results.scan_instance_id
                    AND src.data = ?
                )"""
            params = (fpFlag, target, eventType, eventData, sourceData)
        else:
            # If sourceData is None, only match entries where source_event_hash = 'ROOT'
            qry = """UPDATE tbl_scan_results
                SET false_positive = ?
                WHERE scan_instance_id IN (SELECT guid FROM tbl_scan_instance WHERE seed_target = ?)
                AND type = ?
                AND data = ?
                AND source_event_hash = 'ROOT'"""
            params = (fpFlag, target, eventType, eventData)

        with self.dbhLock:
            try:
                self.dbh.execute(qry, params)
                rowcount = self.dbh.rowcount
                self.conn.commit()
                return rowcount
            except (sqlite3.Error, psycopg2.Error) as e:
                raise IOError("SQL error encountered when syncing false positive across scans") from e

    def targetFalsePositiveAdd(self, target: str, eventType: str, eventData: str, sourceData: str = None, notes: str = None) -> bool:
        """Add a target-level false positive entry.

        This allows false positives to persist across scans for the same target.

        Args:
            target (str): the target (seed_target value)
            eventType (str): the event type
            eventData (str): the event data
            sourceData (str): the source data element (for more granular matching)
            notes (str): optional notes about why this is a false positive

        Returns:
            bool: success

        Raises:
            TypeError: arg type was invalid
            IOError: database I/O failed
        """
        if not isinstance(target, str):
            raise TypeError(f"target is {type(target)}; expected str()") from None
        if not isinstance(eventType, str):
            raise TypeError(f"eventType is {type(eventType)}; expected str()") from None
        if not isinstance(eventData, str):
            raise TypeError(f"eventData is {type(eventData)}; expected str()") from None

        if self.db_type == 'sqlite':
            qry = "INSERT OR IGNORE INTO tbl_target_false_positives \
                (target, event_type, event_data, source_data, date_added, notes) \
                VALUES (?, ?, ?, ?, ?, ?)"
        else:  # postgresql
            qry = "INSERT INTO tbl_target_false_positives \
                (target, event_type, event_data, source_data, date_added, notes) \
                VALUES (%s, %s, %s, %s, %s, %s) ON CONFLICT DO NOTHING"

        with self.dbhLock:
            try:
                self.dbh.execute(qry, (target, eventType, eventData, sourceData, int(time.time() * 1000), notes))
                self.conn.commit()
            except (sqlite3.Error, psycopg2.Error) as e:
                raise IOError("SQL error encountered when adding target false positive") from e

        return True

    def targetFalsePositiveRemove(self, target: str, eventType: str, eventData: str, sourceData: str = None) -> bool:
        """Remove a target-level false positive entry.

        When removing with a specific source_data, also removes entries with NULL source_data
        to handle legacy imports that didn't include source_data.

        Args:
            target (str): the target (seed_target value)
            eventType (str): the event type
            eventData (str): the event data
            sourceData (str): the source data element

        Returns:
            bool: success

        Raises:
            TypeError: arg type was invalid
            IOError: database I/O failed
        """
        if not isinstance(target, str):
            raise TypeError(f"target is {type(target)}; expected str()") from None
        if not isinstance(eventType, str):
            raise TypeError(f"eventType is {type(eventType)}; expected str()") from None
        if not isinstance(eventData, str):
            raise TypeError(f"eventData is {type(eventData)}; expected str()") from None

        with self.dbhLock:
            try:
                if sourceData is None:
                    # Only delete entries with NULL source_data
                    qry = "DELETE FROM tbl_target_false_positives WHERE target = ? AND event_type = ? AND event_data = ? AND source_data IS NULL"
                    self.dbh.execute(qry, (target, eventType, eventData))
                else:
                    # Delete the specific entry with matching source_data
                    qry = "DELETE FROM tbl_target_false_positives WHERE target = ? AND event_type = ? AND event_data = ? AND source_data = ?"
                    self.dbh.execute(qry, (target, eventType, eventData, sourceData))
                    # Also delete legacy entries with NULL source_data for the same (event_type, event_data)
                    # This handles old legacy imports that didn't include source_data
                    qry_null = "DELETE FROM tbl_target_false_positives WHERE target = ? AND event_type = ? AND event_data = ? AND source_data IS NULL"
                    self.dbh.execute(qry_null, (target, eventType, eventData))
                self.conn.commit()
            except (sqlite3.Error, psycopg2.Error) as e:
                raise IOError("SQL error encountered when removing target false positive") from e

        return True

    def targetFalsePositiveRemoveById(self, fpId: int) -> bool:
        """Remove a target-level false positive entry by its ID.

        Args:
            fpId (int): the false positive entry ID

        Returns:
            bool: success

        Raises:
            TypeError: arg type was invalid
            IOError: database I/O failed
        """
        if not isinstance(fpId, int):
            raise TypeError(f"fpId is {type(fpId)}; expected int()") from None

        qry = "DELETE FROM tbl_target_false_positives WHERE id = ?"

        with self.dbhLock:
            try:
                self.dbh.execute(qry, (fpId,))
                self.conn.commit()
            except (sqlite3.Error, psycopg2.Error) as e:
                raise IOError("SQL error encountered when removing target false positive") from e

        return True

    def targetFalsePositiveList(self, target: str = None) -> list:
        """Get target-level false positives.

        Args:
            target (str): optional target to filter by (if None, returns all)

        Returns:
            list: list of target false positive entries

        Raises:
            IOError: database I/O failed
        """
        if target is not None:
            qry = "SELECT id, target, event_type, event_data, ROUND(date_added/1000) as date_added, notes \
                FROM tbl_target_false_positives WHERE target = ? ORDER BY date_added DESC"
            qvars = [target]
        else:
            qry = "SELECT id, target, event_type, event_data, ROUND(date_added/1000) as date_added, notes \
                FROM tbl_target_false_positives ORDER BY target, date_added DESC"
            qvars = []

        with self.dbhLock:
            try:
                self.dbh.execute(qry, qvars)
                return self.dbh.fetchall()
            except (sqlite3.Error, psycopg2.Error) as e:
                raise IOError("SQL error encountered when fetching target false positives") from e

    def targetFalsePositiveCheck(self, target: str, eventType: str, eventData: str) -> bool:
        """Check if a specific event is marked as a target-level false positive.

        Args:
            target (str): the target (seed_target value)
            eventType (str): the event type
            eventData (str): the event data

        Returns:
            bool: True if it's marked as a target-level false positive

        Raises:
            TypeError: arg type was invalid
            IOError: database I/O failed
        """
        if not isinstance(target, str):
            raise TypeError(f"target is {type(target)}; expected str()") from None
        if not isinstance(eventType, str):
            raise TypeError(f"eventType is {type(eventType)}; expected str()") from None
        if not isinstance(eventData, str):
            raise TypeError(f"eventData is {type(eventData)}; expected str()") from None

        qry = "SELECT COUNT(*) FROM tbl_target_false_positives \
            WHERE target = ? AND event_type = ? AND event_data = ?"

        with self.dbhLock:
            try:
                self.dbh.execute(qry, (target, eventType, eventData))
                row = self.dbh.fetchone()
                return row[0] > 0
            except (sqlite3.Error, psycopg2.Error) as e:
                raise IOError("SQL error encountered when checking target false positive") from e

    def targetFalsePositivesForTarget(self, target: str) -> set:
        """Get all false positive (type, data, source) tuples for a target as a set for fast lookups.

        Args:
            target (str): the target (seed_target value)

        Returns:
            set: set of (event_type, event_data, source_data) tuples

        Raises:
            TypeError: arg type was invalid
            IOError: database I/O failed
        """
        if not isinstance(target, str):
            raise TypeError(f"target is {type(target)}; expected str()") from None

        qry = "SELECT event_type, event_data, source_data FROM tbl_target_false_positives WHERE target = ?"

        with self.dbhLock:
            try:
                self.dbh.execute(qry, (target,))
                return {(row[0], row[1], row[2]) for row in self.dbh.fetchall()}
            except (sqlite3.Error, psycopg2.Error) as e:
                raise IOError("SQL error encountered when fetching target false positives") from e

    def targetValidatedAdd(self, target: str, eventType: str, eventData: str, sourceData: str = None, notes: str = None) -> bool:
        """Add a target-level validated entry.

        This allows validated status to persist across scans for the same target.
        Validated means the data/asset has been confirmed to belong to the organization.

        Args:
            target (str): the target (seed_target value)
            eventType (str): the event type
            eventData (str): the event data
            sourceData (str): the source data element (for more granular matching)
            notes (str): optional notes about why this is validated

        Returns:
            bool: success

        Raises:
            TypeError: arg type was invalid
            IOError: database I/O failed
        """
        if not isinstance(target, str):
            raise TypeError(f"target is {type(target)}; expected str()") from None
        if not isinstance(eventType, str):
            raise TypeError(f"eventType is {type(eventType)}; expected str()") from None
        if not isinstance(eventData, str):
            raise TypeError(f"eventData is {type(eventData)}; expected str()") from None

        if self.db_type == 'sqlite':
            qry = "INSERT OR IGNORE INTO tbl_target_validated \
                (target, event_type, event_data, source_data, date_added, notes) \
                VALUES (?, ?, ?, ?, ?, ?)"
        else:  # postgresql
            qry = "INSERT INTO tbl_target_validated \
                (target, event_type, event_data, source_data, date_added, notes) \
                VALUES (%s, %s, %s, %s, %s, %s) ON CONFLICT DO NOTHING"

        with self.dbhLock:
            try:
                self.dbh.execute(qry, (target, eventType, eventData, sourceData, int(time.time() * 1000), notes))
                self.conn.commit()
            except (sqlite3.Error, psycopg2.Error) as e:
                raise IOError("SQL error encountered when adding target validated entry") from e

        return True

    def targetValidatedRemove(self, target: str, eventType: str, eventData: str, sourceData: str = None) -> bool:
        """Remove a target-level validated entry.

        When removing with a specific source_data, also removes entries with NULL source_data
        to handle legacy imports that didn't include source_data.

        Args:
            target (str): the target (seed_target value)
            eventType (str): the event type
            eventData (str): the event data
            sourceData (str): the source data element

        Returns:
            bool: success

        Raises:
            TypeError: arg type was invalid
            IOError: database I/O failed
        """
        if not isinstance(target, str):
            raise TypeError(f"target is {type(target)}; expected str()") from None
        if not isinstance(eventType, str):
            raise TypeError(f"eventType is {type(eventType)}; expected str()") from None
        if not isinstance(eventData, str):
            raise TypeError(f"eventData is {type(eventData)}; expected str()") from None

        with self.dbhLock:
            try:
                if sourceData is None:
                    # Only delete entries with NULL source_data
                    qry = "DELETE FROM tbl_target_validated WHERE target = ? AND event_type = ? AND event_data = ? AND source_data IS NULL"
                    self.dbh.execute(qry, (target, eventType, eventData))
                else:
                    # Delete the specific entry with matching source_data
                    qry = "DELETE FROM tbl_target_validated WHERE target = ? AND event_type = ? AND event_data = ? AND source_data = ?"
                    self.dbh.execute(qry, (target, eventType, eventData, sourceData))
                    # Also delete legacy entries with NULL source_data for the same (event_type, event_data)
                    # This handles old legacy imports that didn't include source_data
                    qry_null = "DELETE FROM tbl_target_validated WHERE target = ? AND event_type = ? AND event_data = ? AND source_data IS NULL"
                    self.dbh.execute(qry_null, (target, eventType, eventData))
                self.conn.commit()
            except (sqlite3.Error, psycopg2.Error) as e:
                raise IOError("SQL error encountered when removing target validated entry") from e

        return True

    def targetValidatedRemoveById(self, valId: int) -> bool:
        """Remove a target-level validated entry by its ID.

        Args:
            valId (int): the validated entry ID

        Returns:
            bool: success

        Raises:
            TypeError: arg type was invalid
            IOError: database I/O failed
        """
        if not isinstance(valId, int):
            raise TypeError(f"valId is {type(valId)}; expected int()") from None

        qry = "DELETE FROM tbl_target_validated WHERE id = ?"

        with self.dbhLock:
            try:
                self.dbh.execute(qry, (valId,))
                self.conn.commit()
            except (sqlite3.Error, psycopg2.Error) as e:
                raise IOError("SQL error encountered when removing target validated entry") from e

        return True

    def targetValidatedList(self, target: str = None) -> list:
        """Get target-level validated entries.

        Args:
            target (str): optional target to filter by (if None, returns all)

        Returns:
            list: list of target validated entries

        Raises:
            IOError: database I/O failed
        """
        if target is not None:
            qry = "SELECT id, target, event_type, event_data, ROUND(date_added/1000) as date_added, notes \
                FROM tbl_target_validated WHERE target = ? ORDER BY date_added DESC"
            qvars = [target]
        else:
            qry = "SELECT id, target, event_type, event_data, ROUND(date_added/1000) as date_added, notes \
                FROM tbl_target_validated ORDER BY target, date_added DESC"
            qvars = []

        with self.dbhLock:
            try:
                self.dbh.execute(qry, qvars)
                return self.dbh.fetchall()
            except (sqlite3.Error, psycopg2.Error) as e:
                raise IOError("SQL error encountered when fetching target validated entries") from e

    def targetValidatedCheck(self, target: str, eventType: str, eventData: str) -> bool:
        """Check if a specific event is marked as target-level validated.

        Args:
            target (str): the target (seed_target value)
            eventType (str): the event type
            eventData (str): the event data

        Returns:
            bool: True if it's marked as target-level validated

        Raises:
            TypeError: arg type was invalid
            IOError: database I/O failed
        """
        if not isinstance(target, str):
            raise TypeError(f"target is {type(target)}; expected str()") from None
        if not isinstance(eventType, str):
            raise TypeError(f"eventType is {type(eventType)}; expected str()") from None
        if not isinstance(eventData, str):
            raise TypeError(f"eventData is {type(eventData)}; expected str()") from None

        qry = "SELECT COUNT(*) FROM tbl_target_validated \
            WHERE target = ? AND event_type = ? AND event_data = ?"

        with self.dbhLock:
            try:
                self.dbh.execute(qry, (target, eventType, eventData))
                row = self.dbh.fetchone()
                return row[0] > 0
            except (sqlite3.Error, psycopg2.Error) as e:
                raise IOError("SQL error encountered when checking target validated status") from e

    def targetValidatedForTarget(self, target: str) -> set:
        """Get all validated (type, data, source) tuples for a target as a set for fast lookups.

        Args:
            target (str): the target (seed_target value)

        Returns:
            set: set of (event_type, event_data, source_data) tuples

        Raises:
            TypeError: arg type was invalid
            IOError: database I/O failed
        """
        if not isinstance(target, str):
            raise TypeError(f"target is {type(target)}; expected str()") from None

        qry = "SELECT event_type, event_data, source_data FROM tbl_target_validated WHERE target = ?"

        with self.dbhLock:
            try:
                self.dbh.execute(qry, (target,))
                return {(row[0], row[1], row[2]) for row in self.dbh.fetchall()}
            except (sqlite3.Error, psycopg2.Error) as e:
                raise IOError("SQL error encountered when fetching target validated entries") from e

    def configSet(self, optMap: dict = {}) -> bool:
        """Store the default configuration in the database.

        Args:
            optMap (dict): config options

        Returns:
            bool: success

        Raises:
            TypeError: arg type was invalid
            ValueError: arg value was invalid
            IOError: database I/O failed
        """

        if not isinstance(optMap, dict):
            raise TypeError(
                f"optMap is {type(optMap)}; expected dict()") from None
        if not optMap:
            raise ValueError("optMap is empty") from None

        qry = "REPLACE INTO tbl_config (scope, opt, val) VALUES (?, ?, ?)"

        with self.dbhLock:
            for opt in list(optMap.keys()):
                # Module option
                if ":" in opt:
                    parts = opt.split(':')
                    qvals = [parts[0], parts[1], optMap[opt]]
                else:
                    # Global option
                    qvals = ["GLOBAL", opt, optMap[opt]]

                try:
                    self.dbh.execute(qry, qvals)
                except (sqlite3.Error, psycopg2.Error) as e:
                    raise IOError(
                        "SQL error encountered when storing config, aborting") from e

            try:
                self.conn.commit()
            except (sqlite3.Error, psycopg2.Error) as e:
                raise IOError(
                    "SQL error encountered when storing config, aborting") from e

        return True

    def configGet(self) -> dict:
        """Retreive the config from the database.

        Returns:
            dict: config

        Raises:
            IOError: database I/O failed
        """

        qry = "SELECT scope, opt, val FROM tbl_config"

        retval = dict()

        with self.dbhLock:
            try:
                self.dbh.execute(qry)
                for [scope, opt, val] in self.dbh.fetchall():
                    if scope == "GLOBAL":
                        retval[opt] = val
                    else:
                        retval[f"{scope}:{opt}"] = val

                return retval
            except (sqlite3.Error, psycopg2.Error) as e:
                raise IOError(
                    "SQL error encountered when fetching configuration") from e

    def configClear(self) -> None:
        """Reset the config to default.

        Clears the config from the database and lets the hard-coded settings in the code take effect.

        Raises:
            IOError: database I/O failed
        """

        qry = "DELETE from tbl_config"
        with self.dbhLock:
            try:
                self.dbh.execute(qry)
                self.conn.commit()
            except (sqlite3.Error, psycopg2.Error) as e:
                raise IOError(
                    "Unable to clear configuration from the database") from e

    def scanConfigSet(self, scan_id, optMap=dict()) -> None:
        """Store a configuration value for a scan.

        Args:
            scan_id (int): scan instance ID
            optMap (dict): config options

        Raises:
            TypeError: arg type was invalid
            ValueError: arg value was invalid
            IOError: database I/O failed
        """

        if not isinstance(optMap, dict):
            raise TypeError(
                f"optMap is {type(optMap)}; expected dict()") from None
        if not optMap:
            raise ValueError("optMap is empty") from None

        qry = "REPLACE INTO tbl_scan_config \
                (scan_instance_id, component, opt, val) VALUES (?, ?, ?, ?)"

        with self.dbhLock:
            for opt in list(optMap.keys()):
                # Module option
                if ":" in opt:
                    parts = opt.split(':')
                    qvals = [scan_id, parts[0], parts[1], optMap[opt]]
                else:
                    # Global option
                    qvals = [scan_id, "GLOBAL", opt, optMap[opt]]

                try:
                    self.dbh.execute(qry, qvals)
                except (sqlite3.Error, psycopg2.Error) as e:
                    raise IOError(
                        "SQL error encountered when storing config, aborting") from e

            try:
                self.conn.commit()
            except (sqlite3.Error, psycopg2.Error) as e:
                raise IOError(
                    "SQL error encountered when storing config, aborting") from e

    def scanConfigGet(self, instanceId: str) -> dict:
        """Retrieve configuration data for a scan component.

        Args:
            instanceId (str): scan instance ID

        Returns:
            dict: configuration data

        Raises:
            TypeError: arg type was invalid
            IOError: database I/O failed
        """

        if not isinstance(instanceId, str):
            raise TypeError(
                f"instanceId is {type(instanceId)}; expected str()") from None

        qry = "SELECT component, opt, val FROM tbl_scan_config \
                WHERE scan_instance_id = ? ORDER BY component, opt"
        qvars = [instanceId]

        retval = dict()

        with self.dbhLock:
            try:
                self.dbh.execute(qry, qvars)
                for [component, opt, val] in self.dbh.fetchall():
                    if component == "GLOBAL":
                        retval[opt] = val
                    else:
                        retval[f"{component}:{opt}"] = val
                return retval
            except (sqlite3.Error, psycopg2.Error) as e:
                raise IOError(
                    "SQL error encountered when fetching configuration") from e

    def scanEventStore(self, instanceId: str, sfEvent, truncateSize: int = 0) -> None:
        """Store an event in the database.

        Args:
            instanceId (str): scan instance ID
            sfEvent (SpiderFootEvent): event to be stored in the database
            truncateSize (int): truncate size for event data

        Raises:
            TypeError: arg type was invalid
            ValueError: arg value was invalid
            IOError: database I/O failed
        """
        from spiderfoot import SpiderFootEvent

        if not isinstance(instanceId, str):
            raise TypeError(
                f"instanceId is {type(instanceId)}; expected str()") from None

        if not instanceId:
            raise ValueError("instanceId is empty") from None

        if not isinstance(sfEvent, SpiderFootEvent):
            raise TypeError(
                f"sfEvent is {type(sfEvent)}; expected SpiderFootEvent()") from None

        if not isinstance(sfEvent.generated, float):
            raise TypeError(
                f"sfEvent.generated is {type(sfEvent.generated)}; expected float()") from None

        if not sfEvent.generated:
            raise ValueError("sfEvent.generated is empty") from None

        if not isinstance(sfEvent.eventType, str):
            raise TypeError(
                f"sfEvent.eventType is {type(sfEvent.eventType,)}; expected str()") from None

        if not sfEvent.eventType:
            raise ValueError("sfEvent.eventType is empty") from None

        if not isinstance(sfEvent.data, str):
            raise TypeError(
                f"sfEvent.data is {type(sfEvent.data)}; expected str()") from None

        if not sfEvent.data:
            raise ValueError("sfEvent.data is empty") from None

        if not isinstance(sfEvent.module, str):
            raise TypeError(
                f"sfEvent.module is {type(sfEvent.module)}; expected str()") from None

        if not sfEvent.module and sfEvent.eventType != "ROOT":
            raise ValueError("sfEvent.module is empty") from None

        if not isinstance(sfEvent.confidence, int):
            raise TypeError(
                f"sfEvent.confidence is {type(sfEvent.confidence)}; expected int()") from None

        if not 0 <= sfEvent.confidence <= 100:
            raise ValueError(
                f"sfEvent.confidence value is {type(sfEvent.confidence)}; expected 0 - 100") from None

        if not isinstance(sfEvent.visibility, int):
            raise TypeError(
                f"sfEvent.visibility is {type(sfEvent.visibility)}; expected int()") from None

        if not 0 <= sfEvent.visibility <= 100:
            raise ValueError(
                f"sfEvent.visibility value is {type(sfEvent.visibility)}; expected 0 - 100") from None

        if not isinstance(sfEvent.risk, int):
            raise TypeError(
                f"sfEvent.risk is {type(sfEvent.risk)}; expected int()") from None

        if not 0 <= sfEvent.risk <= 100:
            raise ValueError(
                f"sfEvent.risk value is {type(sfEvent.risk)}; expected 0 - 100") from None

        if not isinstance(sfEvent.sourceEvent, SpiderFootEvent) and sfEvent.eventType != "ROOT":
            raise TypeError(
                f"sfEvent.sourceEvent is {type(sfEvent.sourceEvent)}; expected str()") from None

        if not isinstance(sfEvent.sourceEventHash, str):
            raise TypeError(
                f"sfEvent.sourceEventHash is {type(sfEvent.sourceEventHash)}; expected str()") from None

        if not sfEvent.sourceEventHash:
            raise ValueError("sfEvent.sourceEventHash is empty") from None

        storeData = sfEvent.data

        # truncate if required
        if isinstance(truncateSize, int) and truncateSize > 0:
            storeData = storeData[0:truncateSize]

        # retrieve scan results
        qry = "INSERT INTO tbl_scan_results \
            (scan_instance_id, hash, type, generated, confidence, \
            visibility, risk, module, data, source_event_hash) \
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"

        qvals = [instanceId, sfEvent.hash, sfEvent.eventType, sfEvent.generated,
                 sfEvent.confidence, sfEvent.visibility, sfEvent.risk,
                 sfEvent.module, storeData, sfEvent.sourceEventHash]

        with self.dbhLock:
            try:
                self.dbh.execute(qry, qvals)
                self.conn.commit()
            except (sqlite3.Error, psycopg2.Error) as e:
                raise IOError(
                    f"SQL error encountered when storing event data ({self.dbh})") from e

    def scanInstanceList(self) -> list:
        """List all previously run scans.

        Returns:
            list: previously run scans

        Raises:
            IOError: database I/O failed
        """

        # SQLite doesn't support OUTER JOINs, so we need a work-around that
        # does a UNION of scans with results and scans without results to
        # get a complete listing.
        qry = "SELECT i.guid, i.name, i.seed_target, ROUND(i.created/1000), \
            ROUND(i.started)/1000 as started, ROUND(i.ended)/1000, i.status, COUNT(r.type) \
            FROM tbl_scan_instance i, tbl_scan_results r WHERE i.guid = r.scan_instance_id \
            AND r.type <> 'ROOT' GROUP BY i.guid \
            UNION ALL \
            SELECT i.guid, i.name, i.seed_target, ROUND(i.created/1000), \
            ROUND(i.started)/1000 as started, ROUND(i.ended)/1000, i.status, '0' \
            FROM tbl_scan_instance i  WHERE i.guid NOT IN ( \
            SELECT distinct scan_instance_id FROM tbl_scan_results WHERE type <> 'ROOT') \
            ORDER BY started DESC"

        with self.dbhLock:
            try:
                self.dbh.execute(qry)
                return self.dbh.fetchall()
            except (sqlite3.Error, psycopg2.Error) as e:
                raise IOError(
                    "SQL error encountered when fetching scan list") from e

    def scanResultHistory(self, instanceId: str) -> list:
        """History of data from the scan.

        Args:
            instanceId (str): scan instance ID

        Returns:
            list: scan data history

        Raises:
            TypeError: arg type was invalid
            IOError: database I/O failed
        """

        if not isinstance(instanceId, str):
            raise TypeError(
                f"instanceId is {type(instanceId)}; expected str()") from None

        qry = "SELECT STRFTIME('%H:%M %w', generated, 'unixepoch') AS hourmin, \
                type, COUNT(*) FROM tbl_scan_results \
                WHERE scan_instance_id = ? GROUP BY hourmin, type"
        qvars = [instanceId]

        with self.dbhLock:
            try:
                self.dbh.execute(qry, qvars)
                return self.dbh.fetchall()
            except (sqlite3.Error, psycopg2.Error) as e:
                raise IOError(
                    f"SQL error encountered when fetching history for scan {instanceId}") from e

    def scanElementSourcesDirect(self, instanceId: str, elementIdList: list) -> list:
        """Get the source IDs, types and data for a set of IDs.

        Args:
            instanceId (str): scan instance ID
            elementIdList (list): TBD

        Returns:
            list: TBD

        Raises:
            TypeError: arg type was invalid
            IOError: database I/O failed
        """

        if not isinstance(instanceId, str):
            raise TypeError(
                f"instanceId is {type(instanceId)}; expected str()") from None

        if not isinstance(elementIdList, list):
            raise TypeError(
                f"elementIdList is {type(elementIdList)}; expected list()") from None

        hashIds = []
        for hashId in elementIdList:
            if not hashId:
                continue
            if not hashId.isalnum():
                continue
            hashIds.append(hashId)

        # the output of this needs to be aligned with scanResultEvent,
        # as other functions call both expecting the same output.
        qry = "SELECT ROUND(c.generated) AS generated, c.data, \
            s.data as 'source_data', \
            c.module, c.type, c.confidence, c.visibility, c.risk, c.hash, \
            c.source_event_hash, t.event_descr, t.event_type, s.scan_instance_id, \
            c.false_positive as 'fp', s.false_positive as 'parent_fp', \
            s.type, s.module, st.event_type as 'source_entity_type' \
            FROM tbl_scan_results c, tbl_scan_results s, tbl_event_types t, \
            tbl_event_types st \
            WHERE c.scan_instance_id = ? AND c.source_event_hash = s.hash AND \
            s.scan_instance_id = c.scan_instance_id AND st.event = s.type AND \
            t.event = c.type AND c.hash in ('%s')" % "','".join(hashIds)
        qvars = [instanceId]

        with self.dbhLock:
            try:
                self.dbh.execute(qry, qvars)
                return self.dbh.fetchall()
            except (sqlite3.Error, psycopg2.Error) as e:
                raise IOError(
                    "SQL error encountered when getting source element IDs") from e

    def scanElementChildrenDirect(self, instanceId: str, elementIdList: list) -> list:
        """Get the child IDs, types and data for a set of IDs.

        Args:
            instanceId (str): scan instance ID
            elementIdList (list): TBD

        Returns:
            list: TBD

        Raises:
            TypeError: arg type was invalid
            IOError: database I/O failed
        """

        if not isinstance(instanceId, str):
            raise TypeError(
                f"instanceId is {type(instanceId)}; expected str()") from None

        if not isinstance(elementIdList, list):
            raise TypeError(
                f"elementIdList is {type(elementIdList)}; expected list()") from None

        hashIds = []
        for hashId in elementIdList:
            if not hashId:
                continue
            if not hashId.isalnum():
                continue
            hashIds.append(hashId)

        # the output of this needs to be aligned with scanResultEvent,
        # as other functions call both expecting the same output.
        qry = "SELECT ROUND(c.generated) AS generated, c.data, \
            s.data as 'source_data', \
            c.module, c.type, c.confidence, c.visibility, c.risk, c.hash, \
            c.source_event_hash, t.event_descr, t.event_type, s.scan_instance_id, \
            c.false_positive as 'fp', s.false_positive as 'parent_fp' \
            FROM tbl_scan_results c, tbl_scan_results s, tbl_event_types t \
            WHERE c.scan_instance_id = ? AND c.source_event_hash = s.hash AND \
            s.scan_instance_id = c.scan_instance_id AND \
            t.event = c.type AND s.hash in ('%s')" % "','".join(hashIds)
        qvars = [instanceId]

        with self.dbhLock:
            try:
                self.dbh.execute(qry, qvars)
                return self.dbh.fetchall()
            except (sqlite3.Error, psycopg2.Error) as e:
                raise IOError(
                    "SQL error encountered when getting child element IDs") from e

    def scanElementSourcesAll(self, instanceId: str, childData: list) -> list:
        """Get the full set of upstream IDs which are parents to the supplied
        set of IDs.

        Args:
            instanceId (str): scan instance ID
            childData (list): TBD

        Returns:
            list: TBD

        Raises:
            TypeError: arg type was invalid
            ValueError: arg value was invalid
        """

        if not isinstance(instanceId, str):
            raise TypeError(
                f"instanceId is {type(instanceId)}; expected str()")

        if not isinstance(childData, list):
            raise TypeError(f"childData is {type(childData)}; expected list()")

        if not childData:
            raise ValueError("childData is empty")

        # Get the first round of source IDs for the leafs
        keepGoing = True
        nextIds = list()
        datamap = dict()
        pc = dict()

        for row in childData:
            # these must be unique values!
            parentId = row[9]
            childId = row[8]
            datamap[childId] = row

            if parentId in pc:
                if childId not in pc[parentId]:
                    pc[parentId].append(childId)
            else:
                pc[parentId] = [childId]

            # parents of the leaf set
            if parentId not in nextIds:
                nextIds.append(parentId)

        while keepGoing:
            parentSet = self.scanElementSourcesDirect(instanceId, nextIds)
            nextIds = list()
            keepGoing = False

            for row in parentSet:
                parentId = row[9]
                childId = row[8]
                datamap[childId] = row

                if parentId in pc:
                    if childId not in pc[parentId]:
                        pc[parentId].append(childId)
                else:
                    pc[parentId] = [childId]
                if parentId not in nextIds:
                    nextIds.append(parentId)

                # Prevent us from looping at root
                if parentId != "ROOT":
                    keepGoing = True

        datamap[parentId] = row
        return [datamap, pc]

    def scanElementChildrenAll(self, instanceId: str, parentIds: list) -> list:
        """Get the full set of downstream IDs which are children of the
        supplied set of IDs.

        Args:
            instanceId (str): scan instance ID
            parentIds (list): TBD

        Returns:
            list: TBD

        Raises:
            TypeError: arg type was invalid

        Note: This function is not the same as the scanElementParent* functions.
              This function returns only ids.
        """

        if not isinstance(instanceId, str):
            raise TypeError(
                f"instanceId is {type(instanceId)}; expected str()")

        if not isinstance(parentIds, list):
            raise TypeError(f"parentIds is {type(parentIds)}; expected list()")

        datamap = list()
       
        keepGoing = True
        nextIds = list()

        nextSet = self.scanElementChildrenDirect(instanceId, parentIds)
        for row in nextSet:
            datamap.append(row[8])

        for row in nextSet:
            if row[8] not in nextIds:
                nextIds.append(row[8])

        while keepGoing:
            nextSet = self.scanElementChildrenDirect(instanceId, nextIds)
            if nextSet is None or len(nextSet) == 0:
                keepGoing = False
                break

            for row in nextSet:
                datamap.append(row[8])
                nextIds = list()
                nextIds.append(row[8])

        return datamap

    def correlationResultCreate(self, instanceId: str, event_hash: str, ruleId: str,
        ruleName: str,
        ruleDescr: str,
        ruleRisk: str,
        ruleYaml: str,
        correlationTitle: str, eventHashes: list
    ) -> str:
        """Create a correlation result in the database.

        Args:
            instanceId (str): scan instance ID
            event_hash (str): event hash
            ruleId (str): correlation rule ID
            ruleName (str): correlation rule name
            ruleDescr (str): correlation rule description
            ruleRisk (str): correlation rule risk level
            ruleYaml (str): correlation rule raw YAML
            correlationTitle (str): correlation title
            eventHashes (list): events mapped to the correlation result

        Returns:
            str: Correlation ID created

        Raises:
            IOError: database I/O failed
            TypeError: arg type was invalid        """
        import uuid
        correlation_id = str(uuid.uuid4())

        with self.dbhLock:
            qry = "INSERT INTO tbl_scan_correlation_results \
                (id, scan_instance_id, title, rule_id, rule_risk, rule_name, \
                rule_descr, rule_logic) \
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
            qvars = [correlation_id, instanceId, correlationTitle, ruleId, ruleRisk, ruleName, ruleDescr, ruleYaml]

            try:
                self.dbh.execute(qry, qvars)
                self.conn.commit()
            except (sqlite3.Error, psycopg2.Error) as e:
                raise IOError(
                    "Unable to create correlation result in database") from e

            correlationId = correlation_id

            if isinstance(eventHashes, str):
                eventHashes = [eventHashes]

            # Insert event hashes for this correlation
            for eventHash in eventHashes:
                qry = "INSERT INTO tbl_scan_correlation_results_events (correlation_id, event_hash) VALUES (?, ?)"
                qvars = [correlationId, eventHash]
                try:
                    self.dbh.execute(qry, qvars)
                except (sqlite3.Error, psycopg2.Error) as e:
                    raise IOError("Unable to create correlation result events in database") from e

            self.conn.commit()
        
        return str(correlationId)

    def get_sources(self, scan_id: str, event_hash: str) -> list:
        """Return the list of source events for a given event in a scan.

        Args:
            scan_id (str): The scan instance ID
            event_hash (str): The hash of the event whose sources to retrieve

        Returns:
            list: List of dicts with source event details (hash, type, data, module, etc.)
        """
        qry = """
            SELECT s.hash, s.type, s.data, s.module, s.generated, s.source_event_hash
            FROM tbl_scan_results c
            JOIN tbl_scan_results s
              ON c.source_event_hash = s.hash
            WHERE c.scan_instance_id = ?
              AND c.hash = ?
              AND c.source_event_hash != 'ROOT'
        """
        qvars = [scan_id, event_hash]
        with self.dbhLock:
            try:
                self.dbh.execute(qry, qvars)
                rows = self.dbh.fetchall()
                sources = []
                for row in rows:
                    sources.append({
                        'hash': row[0],
                        'type': row[1],
                        'data': row[2],
                        'module': row[3],
                        'generated': row[4],
                        'source_event_hash': row[5]
                    })
                return sources
            except (sqlite3.Error, psycopg2.Error) as e:
                raise IOError("SQL error encountered when fetching event sources") from e

    def get_entities(self, scan_id: str, event_hash: str) -> list:
        """Return the list of entity events that are children of a given event in a scan.

        Args:
            scan_id (str): The scan instance ID
            event_hash (str): The hash of the event whose child entities to retrieve

        Returns:
            list: List of dicts with entity event details (hash, type, data, module, etc.)
        """
        qry = """
            SELECT c.hash, c.type, c.data, c.module, c.generated, c.source_event_hash
            FROM tbl_scan_results c
            WHERE c.scan_instance_id = ?
              AND c.source_event_hash = ?
              AND c.type IN (
                SELECT event FROM tbl_event_types WHERE event_type = 'ENTITY'
              )
        """
        qvars = [scan_id, event_hash]
        with self.dbhLock:
            try:
                self.dbh.execute(qry, qvars)
                rows = self.dbh.fetchall()
                entities = []
                for row in rows:
                    entities.append({
                        'hash': row[0],
                        'type': row[1],
                        'data': row[2],
                        'module': row[3],
                        'generated': row[4],
                        'source_event_hash': row[5]
                    })
                return entities
            except (sqlite3.Error, psycopg2.Error) as e:
                raise IOError("SQL error encountered when fetching entity events") from e

    def getLatestScanForTarget(self, target: str) -> str:
        """Get the GUID of the most recent scan for a target.

        Args:
            target (str): the target (seed_target value)

        Returns:
            str: GUID of the latest scan, or None if no scans exist

        Raises:
            TypeError: arg type was invalid
            IOError: database I/O failed
        """
        if not isinstance(target, str):
            raise TypeError(f"target is {type(target)}; expected str()") from None

        qry = """SELECT guid FROM tbl_scan_instance
            WHERE seed_target = ?
            ORDER BY started DESC LIMIT 1"""

        with self.dbhLock:
            try:
                self.dbh.execute(qry, [target])
                row = self.dbh.fetchone()
                return row[0] if row else None
            except (sqlite3.Error, psycopg2.Error) as e:
                raise IOError("SQL error encountered when getting latest scan for target") from e

    def isLatestScan(self, instanceId: str) -> dict:
        """Check if a scan is the latest scan for its target.

        Args:
            instanceId (str): scan instance ID

        Returns:
            dict: {isLatest: bool, latestScanId: str, scanCount: int, importedCount: int}

        Raises:
            TypeError: arg type was invalid
            IOError: database I/O failed
        """
        if not isinstance(instanceId, str):
            raise TypeError(f"instanceId is {type(instanceId)}; expected str()") from None

        # Get the target for this scan
        scanInfo = self.scanInstanceGet(instanceId)
        if not scanInfo:
            return {'isLatest': False, 'latestScanId': None, 'scanCount': 0, 'importedCount': 0}

        target = scanInfo[1]

        # Get the latest scan ID for this target
        latestScanId = self.getLatestScanForTarget(target)

        # Count scans for this target
        scanCount = self.scanCountForTarget(target)

        # Count imported entries for this scan
        importedCount = self.getImportedEntriesCount(instanceId)

        return {
            'isLatest': instanceId == latestScanId,
            'latestScanId': latestScanId,
            'scanCount': scanCount,
            'importedCount': importedCount
        }

    def getImportedEntriesCount(self, instanceId: str) -> int:
        """Count the number of imported entries in a scan.

        Args:
            instanceId (str): scan instance ID

        Returns:
            int: number of imported entries

        Raises:
            TypeError: arg type was invalid
            IOError: database I/O failed
        """
        if not isinstance(instanceId, str):
            raise TypeError(f"instanceId is {type(instanceId)}; expected str()") from None

        qry = """SELECT COUNT(*) FROM tbl_scan_results
            WHERE scan_instance_id = ? AND imported_from_scan IS NOT NULL"""

        with self.dbhLock:
            try:
                self.dbh.execute(qry, [instanceId])
                row = self.dbh.fetchone()
                return row[0] if row else 0
            except (sqlite3.Error, psycopg2.Error) as e:
                raise IOError("SQL error encountered when counting imported entries") from e

    def deleteImportedEntries(self, instanceId: str) -> int:
        """Delete ALL imported entries from a scan.

        Deletes all entries that have imported_from_scan set, regardless of
        validation status. This ensures a clean slate before re-importing.

        Args:
            instanceId (str): scan instance ID

        Returns:
            int: number of entries deleted

        Raises:
            TypeError: arg type was invalid
            IOError: database I/O failed
        """
        if not isinstance(instanceId, str):
            raise TypeError(f"instanceId is {type(instanceId)}; expected str()") from None

        with self.dbhLock:
            try:
                # First count how many will be deleted (ALL imported entries)
                count_qry = """SELECT COUNT(*) FROM tbl_scan_results
                    WHERE scan_instance_id = ?
                    AND imported_from_scan IS NOT NULL"""
                self.dbh.execute(count_qry, [instanceId])
                row = self.dbh.fetchone()
                count = row[0] if row else 0

                # Delete ALL imported entries regardless of validation status
                delete_qry = """DELETE FROM tbl_scan_results
                    WHERE scan_instance_id = ?
                    AND imported_from_scan IS NOT NULL"""
                self.dbh.execute(delete_qry, [instanceId])
                self.conn.commit()

                return count
            except (sqlite3.Error, psycopg2.Error) as e:
                raise IOError("SQL error encountered when deleting imported entries") from e

    def getImportableEntries(self, instanceId: str) -> list:
        """Get entries from older scans that can be imported into this scan.

        Returns entries from older scans of the same target that:
        - Do not already exist as NATIVE entries in the current scan
          (native = entries where imported_from_scan IS NULL)
        - Are unique across all older scans (no duplicates from multiple old scans)

        Duplicate detection uses a triple check against NATIVE entries only:
        - DATA ELEMENT (data column)
        - SOURCE DATA ELEMENT (parent event's data)
        - SOURCE MODULE (module that produced the entry)

        Args:
            instanceId (str): current scan instance ID

        Returns:
            list: list of importable entries with source scan info

        Raises:
            TypeError: arg type was invalid
            IOError: database I/O failed
        """
        if not isinstance(instanceId, str):
            raise TypeError(f"instanceId is {type(instanceId)}; expected str()") from None

        # Get the target for this scan
        scanInfo = self.scanInstanceGet(instanceId)
        if not scanInfo:
            return []

        target = scanInfo[1]

        with self.dbhLock:
            try:
                # Step 1: Get all (data, source_data, module) combinations in current scan
                # ONLY from NATIVE entries (where imported_from_scan IS NULL)
                # This is the "triple check" for duplicate detection
                current_entries_qry = """
                    SELECT curr.data, COALESCE(src.data, 'ROOT') as source_data, curr.module
                    FROM tbl_scan_results curr
                    LEFT JOIN tbl_scan_results src ON curr.source_event_hash = src.hash
                        AND curr.scan_instance_id = src.scan_instance_id
                    WHERE curr.scan_instance_id = ?
                      AND curr.imported_from_scan IS NULL
                """
                self.dbh.execute(current_entries_qry, [instanceId])
                current_entries = set()
                for row in self.dbh.fetchall():
                    # Normalize: strip whitespace, use consistent case for comparison
                    data = (row[0] or '').strip()
                    source_data = (row[1] or 'ROOT').strip()
                    module = (row[2] or '').strip()
                    current_entries.add((data, source_data, module))

                # Step 2: Get all entries from older scans with their source_data
                # IMPORTANT: Look up source_data in the CURRENT scan (not old scan)
                # This ensures we compare what the entry would look like AFTER import,
                # since the UI displays source_data by joining on current scan_instance_id.
                # If the parent doesn't exist in current scan, COALESCE returns 'ROOT'.
                old_entries_qry = """
                    SELECT old.hash, old.type, old.data, old.module, old.generated,
                           old.confidence, old.visibility, old.risk, old.false_positive,
                           old.source_event_hash, old.scan_instance_id,
                           si.name as source_scan_name, si.started as source_scan_started,
                           COALESCE(curr_src.data, 'ROOT') as source_data
                    FROM tbl_scan_results old
                    JOIN tbl_scan_instance si ON old.scan_instance_id = si.guid
                    LEFT JOIN tbl_scan_results curr_src ON old.source_event_hash = curr_src.hash
                        AND curr_src.scan_instance_id = ?
                    WHERE si.seed_target = ?
                      AND old.scan_instance_id != ?
                      AND old.type != 'ROOT'
                      AND old.imported_from_scan IS NULL
                    ORDER BY si.started DESC, old.generated DESC
                """
                self.dbh.execute(old_entries_qry, [instanceId, target, instanceId])
                old_entries = self.dbh.fetchall()

                # Step 3: Filter and deduplicate in Python using triple check
                seen_combinations = set()
                importable = []

                for entry in old_entries:
                    # Entry format: hash[0], type[1], data[2], module[3], generated[4],
                    #               confidence[5], visibility[6], risk[7], false_positive[8],
                    #               source_event_hash[9], scan_instance_id[10],
                    #               source_scan_name[11], source_scan_started[12], source_data[13]
                    data = (entry[2] or '').strip()
                    source_data = (entry[13] or 'ROOT').strip()
                    module = (entry[3] or '').strip()

                    # Triple check key: DATA ELEMENT + SOURCE DATA ELEMENT + SOURCE MODULE
                    entry_key = (data, source_data, module)

                    # Skip if this combination already exists in current scan
                    if entry_key in current_entries:
                        continue

                    # Skip if we've already seen this combination from another old scan
                    if entry_key in seen_combinations:
                        continue

                    seen_combinations.add(entry_key)
                    importable.append(entry)

                return importable

            except (sqlite3.Error, psycopg2.Error) as e:
                raise IOError("SQL error encountered when getting importable entries") from e

    def importEntriesFromOlderScans(self, instanceId: str) -> dict:
        """Import entries from older scans of the same target into this scan.

        Copies unique entries from older scans, marking them with imported_from_scan.
        Only imports entries that don't already exist in the current scan.
        Duplicate detection uses triple check: DATA + SOURCE DATA + MODULE.

        Args:
            instanceId (str): current scan instance ID

        Returns:
            dict: {imported: int, skipped: int} counts

        Raises:
            TypeError: arg type was invalid
            IOError: database I/O failed
        """
        if not isinstance(instanceId, str):
            raise TypeError(f"instanceId is {type(instanceId)}; expected str()") from None

        # Get importable entries (already filtered by getImportableEntries)
        entries = self.getImportableEntries(instanceId)

        if not entries:
            return {'imported': 0, 'skipped': 0}

        imported = 0
        skipped = 0

        # Track already imported combinations to prevent duplicates within this batch
        imported_combinations = set()

        with self.dbhLock:
            try:
                for entry in entries:
                    # Entry format: hash[0], type[1], data[2], module[3], generated[4],
                    #               confidence[5], visibility[6], risk[7], false_positive[8],
                    #               source_event_hash[9], scan_instance_id[10],
                    #               source_scan_name[11], source_scan_started[12], source_data[13]
                    original_hash = entry[0]
                    event_type = entry[1]
                    data = (entry[2] or '').strip()
                    module = (entry[3] or '').strip()
                    generated = entry[4]
                    confidence = entry[5]
                    visibility = entry[6]
                    risk = entry[7]
                    false_positive = entry[8]
                    source_event_hash = entry[9]
                    source_scan_id = entry[10]
                    source_data = (entry[13] if len(entry) > 13 else 'ROOT').strip()

                    # Triple check key: DATA ELEMENT + SOURCE DATA ELEMENT + SOURCE MODULE
                    entry_key = (data, source_data, module)

                    # Skip if we've already imported this combination in this batch
                    if entry_key in imported_combinations:
                        skipped += 1
                        continue

                    # Double-check: verify this exact combination doesn't exist in current scan
                    # Uses the same triple check: data + source_data + module
                    check_qry = """
                        SELECT 1 FROM tbl_scan_results curr
                        LEFT JOIN tbl_scan_results curr_src ON curr.source_event_hash = curr_src.hash
                            AND curr.scan_instance_id = curr_src.scan_instance_id
                        WHERE curr.scan_instance_id = ?
                          AND curr.data = ?
                          AND COALESCE(curr_src.data, 'ROOT') = ?
                          AND curr.module = ?
                        LIMIT 1
                    """
                    self.dbh.execute(check_qry, [instanceId, data, source_data, module])
                    if self.dbh.fetchone():
                        skipped += 1
                        continue

                    # Generate new hash for this imported entry
                    new_hash = hashlib.sha256(
                        f"{instanceId}{event_type}{data}{module}{source_data}".encode('utf-8')
                    ).hexdigest()

                    # Check if we need to map the source_event_hash
                    # For ROOT events or if the parent doesn't exist, use ROOT
                    if source_event_hash == 'ROOT':
                        mapped_source_hash = 'ROOT'
                    else:
                        # Check if parent exists in current scan
                        parent_qry = """SELECT hash FROM tbl_scan_results
                            WHERE scan_instance_id = ? AND hash = ?"""
                        self.dbh.execute(parent_qry, [instanceId, source_event_hash])
                        if self.dbh.fetchone():
                            mapped_source_hash = source_event_hash
                        else:
                            # Parent doesn't exist - link to ROOT
                            mapped_source_hash = 'ROOT'

                    # Insert the imported entry
                    qry = """INSERT INTO tbl_scan_results
                        (scan_instance_id, hash, type, generated, confidence, visibility,
                         risk, module, data, false_positive, source_event_hash, imported_from_scan)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"""

                    try:
                        self.dbh.execute(qry, [
                            instanceId, new_hash, event_type, generated, confidence, visibility,
                            risk, module, data, false_positive, mapped_source_hash, source_scan_id
                        ])
                        imported += 1
                        # Track this combination as imported
                        imported_combinations.add(entry_key)
                    except (sqlite3.Error, psycopg2.Error):
                        # Entry already exists (race condition or duplicate)
                        skipped += 1
                        continue

                self.conn.commit()
                return {'imported': imported, 'skipped': skipped}

            except (sqlite3.Error, psycopg2.Error) as e:
                raise IOError("SQL error encountered when importing entries") from e

    def getScansByTarget(self, target: str) -> list:
        """Get all scans for a target, ordered by started date (newest first).

        Args:
            target (str): the target (seed_target value)

        Returns:
            list: list of (guid, name, created, started, ended, status) tuples

        Raises:
            TypeError: arg type was invalid
            IOError: database I/O failed
        """
        if not isinstance(target, str):
            raise TypeError(f"target is {type(target)}; expected str()") from None

        qry = """SELECT guid, name, ROUND(created/1000) as created,
            ROUND(started/1000) as started, ROUND(ended/1000) as ended, status
            FROM tbl_scan_instance
            WHERE seed_target = ?
            ORDER BY started DESC"""

        with self.dbhLock:
            try:
                self.dbh.execute(qry, [target])
                return self.dbh.fetchall()
            except (sqlite3.Error, psycopg2.Error) as e:
                raise IOError("SQL error encountered when getting scans for target") from e

    #
    # User management methods
    #

    @staticmethod
    def hashPassword(password: str, salt: str = None) -> tuple:
        """Hash a password with a salt using SHA-256.

        Args:
            password (str): plain text password
            salt (str): optional salt; generated if not provided

        Returns:
            tuple: (password_hash, salt)
        """
        if salt is None:
            salt = secrets.token_hex(32)
        password_hash = hashlib.sha256((salt + password).encode('utf-8')).hexdigest()
        return password_hash, salt

    def userCreate(self, username: str, password: str, display_name: str = None) -> bool:
        """Create a new user.

        Args:
            username (str): username
            password (str): plain text password (will be hashed)
            display_name (str): optional display name

        Returns:
            bool: True if user was created
        """
        password_hash, salt = self.hashPassword(password)
        created = int(time.time() * 1000)

        if self.db_type == 'sqlite':
            qry = "INSERT INTO tbl_users (username, password_hash, salt, display_name, active, created) VALUES (?, ?, ?, ?, 1, ?)"
            params = (username, password_hash, salt, display_name or username, created)
        else:
            qry = "INSERT INTO tbl_users (username, password_hash, salt, display_name, active, created) VALUES (%s, %s, %s, %s, 1, %s)"
            params = (username, password_hash, salt, display_name or username, created)

        with self.dbhLock:
            try:
                self.dbh.execute(qry, params)
                self.conn.commit()
                return True
            except (sqlite3.Error, psycopg2.Error):
                if self.db_type == 'postgresql':
                    self.conn.rollback()
                return False

    def userVerify(self, username: str, password: str) -> bool:
        """Verify a user's password.

        Args:
            username (str): username
            password (str): plain text password

        Returns:
            bool: True if credentials are valid
        """
        if self.db_type == 'sqlite':
            qry = "SELECT password_hash, salt, active FROM tbl_users WHERE username = ?"
        else:
            qry = "SELECT password_hash, salt, active FROM tbl_users WHERE username = %s"

        with self.dbhLock:
            try:
                self.dbh.execute(qry, [username])
                row = self.dbh.fetchone()
                if not row:
                    return False
                stored_hash, salt, active = row[0], row[1], row[2]
                if not active:
                    return False
                check_hash, _ = self.hashPassword(password, salt)
                return check_hash == stored_hash
            except (sqlite3.Error, psycopg2.Error):
                return False

    def userUpdateLastLogin(self, username: str) -> None:
        """Update the last login timestamp for a user.

        Args:
            username (str): username
        """
        now = int(time.time() * 1000)
        if self.db_type == 'sqlite':
            qry = "UPDATE tbl_users SET last_login = ? WHERE username = ?"
        else:
            qry = "UPDATE tbl_users SET last_login = %s WHERE username = %s"

        with self.dbhLock:
            try:
                self.dbh.execute(qry, [now, username])
                self.conn.commit()
            except (sqlite3.Error, psycopg2.Error):
                if self.db_type == 'postgresql':
                    self.conn.rollback()

    def userGet(self, username: str) -> dict:
        """Get user details.

        Args:
            username (str): username

        Returns:
            dict: user details or None
        """
        if self.db_type == 'sqlite':
            qry = "SELECT id, username, display_name, active, created, last_login FROM tbl_users WHERE username = ?"
        else:
            qry = "SELECT id, username, display_name, active, created, last_login FROM tbl_users WHERE username = %s"

        with self.dbhLock:
            try:
                self.dbh.execute(qry, [username])
                row = self.dbh.fetchone()
                if not row:
                    return None
                return {
                    'id': row[0],
                    'username': row[1],
                    'display_name': row[2],
                    'active': row[3],
                    'created': row[4],
                    'last_login': row[5]
                }
            except (sqlite3.Error, psycopg2.Error):
                return None

    def userList(self) -> list:
        """List all users.

        Returns:
            list: list of user dicts
        """
        qry = "SELECT id, username, display_name, active, created, last_login FROM tbl_users ORDER BY username"

        with self.dbhLock:
            try:
                self.dbh.execute(qry)
                rows = self.dbh.fetchall()
                return [
                    {
                        'id': row[0],
                        'username': row[1],
                        'display_name': row[2],
                        'active': row[3],
                        'created': row[4],
                        'last_login': row[5]
                    }
                    for row in rows
                ]
            except (sqlite3.Error, psycopg2.Error):
                return []

    def userCount(self) -> int:
        """Count users in the database.

        Returns:
            int: number of users
        """
        qry = "SELECT COUNT(*) FROM tbl_users"

        with self.dbhLock:
            try:
                self.dbh.execute(qry)
                row = self.dbh.fetchone()
                return row[0] if row else 0
            except (sqlite3.Error, psycopg2.Error):
                return 0

    def userChangePassword(self, username: str, new_password: str) -> bool:
        """Change a user's password.

        Args:
            username (str): username
            new_password (str): new plain text password

        Returns:
            bool: True if password was changed
        """
        password_hash, salt = self.hashPassword(new_password)

        if self.db_type == 'sqlite':
            qry = "UPDATE tbl_users SET password_hash = ?, salt = ? WHERE username = ?"
        else:
            qry = "UPDATE tbl_users SET password_hash = %s, salt = %s WHERE username = %s"

        with self.dbhLock:
            try:
                self.dbh.execute(qry, [password_hash, salt, username])
                self.conn.commit()
                return True
            except (sqlite3.Error, psycopg2.Error):
                if self.db_type == 'postgresql':
                    self.conn.rollback()
                return False

    #
    # Audit log methods
    #

    def auditLog(self, username: str, action: str, detail: str = None, ip_address: str = None) -> None:
        """Record an audit log entry.

        Args:
            username (str): the user who performed the action
            action (str): action type (e.g. LOGIN, SCAN_START, SETTINGS_CHANGE)
            detail (str): optional detail string
            ip_address (str): optional IP address of the user
        """
        created = int(time.time() * 1000)

        if self.db_type == 'sqlite':
            qry = "INSERT INTO tbl_audit_log (username, action, detail, ip_address, created) VALUES (?, ?, ?, ?, ?)"
        else:
            qry = "INSERT INTO tbl_audit_log (username, action, detail, ip_address, created) VALUES (%s, %s, %s, %s, %s)"

        with self.dbhLock:
            try:
                self.dbh.execute(qry, [username, action, detail, ip_address, created])
                self.conn.commit()
            except (sqlite3.Error, psycopg2.Error):
                if self.db_type == 'postgresql':
                    self.conn.rollback()

    def auditLogGet(self, limit: int = 200, username: str = None, action: str = None) -> list:
        """Get audit log entries.

        Args:
            limit (int): max number of entries to return
            username (str): filter by username
            action (str): filter by action type

        Returns:
            list: list of audit log dicts
        """
        conditions = []
        params = []

        if username:
            if self.db_type == 'sqlite':
                conditions.append("username = ?")
            else:
                conditions.append("username = %s")
            params.append(username)

        if action:
            if self.db_type == 'sqlite':
                conditions.append("action = ?")
            else:
                conditions.append("action = %s")
            params.append(action)

        where = ""
        if conditions:
            where = " WHERE " + " AND ".join(conditions)

        if self.db_type == 'sqlite':
            qry = f"SELECT id, username, action, detail, ip_address, created FROM tbl_audit_log{where} ORDER BY created DESC LIMIT ?"
        else:
            qry = f"SELECT id, username, action, detail, ip_address, created FROM tbl_audit_log{where} ORDER BY created DESC LIMIT %s"
        params.append(limit)

        with self.dbhLock:
            try:
                self.dbh.execute(qry, params)
                rows = self.dbh.fetchall()
                return [
                    {
                        'id': row[0],
                        'username': row[1],
                        'action': row[2],
                        'detail': row[3],
                        'ip_address': row[4],
                        'created': row[5]
                    }
                    for row in rows
                ]
            except (sqlite3.Error, psycopg2.Error):
                return []