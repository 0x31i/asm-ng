#!/usr/bin/env python3
"""
ASM-NG Analysis Pipeline - All 7 Groups
Processes obfuscated CSV data and produces per-group findings CSVs.
"""

import csv
import os
import re
import json
import xml.etree.ElementTree as ET
from collections import defaultdict, Counter

# ============================================================================
# CONFIGURATION
# ============================================================================
CSV_FILE = './obfuscated/FHCSD-ASM-2026_02-FULL-SCORED.csv'
NESSUS_FILE = './obfuscated/FHCSD-ASM-NESSUS-2026_02.nessus'
OUTPUT_DIR = './output'
DETAILS_DIR = './output/findings_details'

os.makedirs(OUTPUT_DIR, exist_ok=True)
os.makedirs(DETAILS_DIR, exist_ok=True)

# ============================================================================
# LOAD CSV DATA
# ============================================================================
print("=== Loading CSV Data ===")
ROWS_BY_TYPE = defaultdict(list)
total_rows = 0

with open(CSV_FILE, 'r', errors='replace') as f:
    reader = csv.DictReader(f)
    HEADERS = reader.fieldnames
    for row in reader:
        etype = row.get('Type', '').strip()
        if etype:
            ROWS_BY_TYPE[etype].append(row)
            total_rows += 1

CSV_FORMAT = 'full_scored' if 'Confidence' in HEADERS else 'standard'
print(f"CSV format: {CSV_FORMAT} ({len(HEADERS)} columns)")
print(f"Total rows: {total_rows}")
print(f"Event types: {len(ROWS_BY_TYPE)}")
for etype, rows in sorted(ROWS_BY_TYPE.items(), key=lambda x: -len(x[1]))[:15]:
    print(f"  {etype}: {len(rows)} rows")

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================
def get_fp(row):
    try:
        return int(row.get('F/P', 0) or 0)
    except (ValueError, TypeError):
        return 0

def get_tracking(row):
    return str(row.get('Tracking', 'OPEN')).strip().upper() or 'OPEN'

def get_cvr(row):
    if CSV_FORMAT != 'full_scored':
        return None, None, None
    try:
        c = int(row.get('Confidence', 0) or 0)
        v = int(row.get('Visibility', 0) or 0)
        r = int(row.get('Risk', 0) or 0)
        return c, v, r
    except (ValueError, TypeError):
        return 0, 0, 0

def safe_str(val, max_len=500):
    """Safe string conversion, no 'nan'."""
    s = str(val).strip()
    if s.lower() in ('nan', 'none', ''):
        return ''
    if len(s) > max_len:
        s = s[:max_len] + '...'
    return s

HIGH_RISK_PORTS = {
    '21': ('FTP', 'High'), '22': ('SSH', 'Medium'), '23': ('Telnet', 'Critical'),
    '25': ('SMTP', 'High'), '53': ('DNS', 'Medium'), '110': ('POP3', 'High'),
    '135': ('RPC', 'High'), '137': ('NetBIOS', 'High'), '139': ('NetBIOS/SMB', 'High'),
    '143': ('IMAP', 'Medium'), '161': ('SNMP', 'High'), '389': ('LDAP', 'High'),
    '445': ('SMB', 'Critical'), '1433': ('MSSQL', 'Critical'),
    '1521': ('Oracle', 'Critical'), '2049': ('NFS', 'High'),
    '3306': ('MySQL', 'Critical'), '3389': ('RDP', 'Critical'),
    '5432': ('PostgreSQL', 'Critical'), '5900': ('VNC', 'Critical'),
    '5985': ('WinRM', 'High'), '6379': ('Redis', 'Critical'),
    '8080': ('HTTP-Alt', 'Medium'), '9200': ('Elasticsearch', 'High'),
    '11211': ('Memcached', 'High'), '27017': ('MongoDB', 'Critical'),
}

OUTPUT_FIELDS = ['Category', 'Tab', 'Priority', 'Item', 'Description', 'Recommendation', 'Tracking_Status', 'Avg_Risk']


def process_rows(event_type, default_severity, category):
    """Generic row processor that excludes FP=1 and returns valid rows with metadata."""
    rows = ROWS_BY_TYPE.get(event_type, [])
    results = []
    fp_excluded = 0
    for row in rows:
        fp = get_fp(row)
        if fp == 1:
            fp_excluded += 1
            continue
        data = safe_str(row.get('Data', ''))
        source = safe_str(row.get('Source', ''), 200)
        module = safe_str(row.get('Module', ''), 100)
        tracking = get_tracking(row)
        c, v, r = get_cvr(row)
        results.append({
            'data': data, 'source': source, 'module': module,
            'tracking': tracking, 'fp': fp,
            'confidence': c, 'visibility': v, 'risk': r,
            'row': row
        })
    return results, fp_excluded


def consolidate_and_save(all_findings, group_num, category_name, weight, stats):
    """Consolidate findings and save to CSV."""
    groups = defaultdict(list)
    for f in all_findings:
        key = (f['Category'], f.get('Vuln_Type', f['Tab']), f['Priority'])
        groups[key].append(f)

    consolidated = []
    for key, gf in groups.items():
        cat, vtype, priority = key
        if len(gf) == 1:
            consolidated.append(gf[0])
        else:
            assets = list(set(f.get('Asset', '') for f in gf if f.get('Asset', '') and f.get('Asset', '').lower() not in ('nan', 'none', '')))
            asset_count = len(assets)
            instance_count = len(gf)
            asset_list = ", ".join(f"({i+1}) {assets[i]}" for i in range(min(5, len(assets))))
            if asset_count > 5:
                asset_list += f", and {asset_count - 5} more"

            tracking_counts = Counter(f.get('Tracking_Status', 'OPEN') for f in gf)
            tracking_summary = ", ".join(f"{k}: {v}" for k, v in tracking_counts.items())

            risk_scores = [f['Avg_Risk'] for f in gf if f.get('Avg_Risk') is not None]
            avg_risk = round(sum(risk_scores) / len(risk_scores), 1) if risk_scores else None

            vuln_name = vtype.replace('_', ' ').title()
            desc = (f"{vuln_name} was identified on {instance_count} instances across {asset_count} assets: {asset_list}. "
                    f"This represents a systematic issue affecting multiple systems requiring coordinated remediation. "
                    f"The widespread nature indicates common misconfiguration or consistent security control gaps. "
                    f"Each affected system should be assessed individually for risk and prioritized for remediation. "
                    f"Tracking status: {tracking_summary}.")

            rec = (f"Implement systematic remediation across all {instance_count} affected instances. "
                   f"Deploy consistent security controls and monitoring across all {asset_count} affected assets. "
                   f"Verify remediation on each affected asset through targeted testing after fixes are applied. "
                   f"Priority: {priority} - complete remediation within the appropriate organizational timeline. "
                   f"Implement automated controls to detect and prevent recurrence.")

            entry = {
                'Category': cat, 'Tab': gf[0]['Tab'], 'Priority': priority,
                'Item': f"{vuln_name} - {instance_count} instances across {asset_count} assets",
                'Description': desc, 'Recommendation': rec,
                'Tracking_Status': max(tracking_counts, key=tracking_counts.get),
                'Avg_Risk': avg_risk if avg_risk else '',
                'Vuln_Type': vtype, 'Asset': ", ".join(assets[:5])
            }
            consolidated.append(entry)

            # Detail file
            detail_rows = [{'Instance': i+1, 'Asset': f.get('Asset', ''), 'Details': f['Item'],
                           'Description': f['Description'][:500], 'Tracking_Status': f.get('Tracking_Status', 'OPEN'),
                           'FP_Status': "Verified" if f.get('FP_Status') == 'Verified' else "Unverified"}
                          for i, f in enumerate(gf)]
            detail_file = os.path.join(DETAILS_DIR, f'findings_detail_{vtype}.csv')
            with open(detail_file, 'w', newline='') as csvf:
                w = csv.DictWriter(csvf, fieldnames=detail_rows[0].keys())
                w.writeheader()
                w.writerows(detail_rows)

    # Save consolidated CSV
    out_file = os.path.join(OUTPUT_DIR, f'findings_GROUP{group_num}_FULL_CONSOLIDATED.csv')
    with open(out_file, 'w', newline='') as csvf:
        w = csv.DictWriter(csvf, fieldnames=OUTPUT_FIELDS, extrasaction='ignore')
        w.writeheader()
        w.writerows(consolidated)

    print(f"\n  Saved: {out_file} ({len(consolidated)} consolidated from {len(all_findings)} raw)")
    return consolidated


def make_finding(category, tab, priority, item, desc, rec, source, module, tracking, fp, risk, vuln_type=None):
    """Create a standardized finding dict."""
    return {
        'Category': category, 'Tab': tab, 'Priority': priority,
        'Item': item, 'Description': desc, 'Recommendation': rec,
        'Vuln_Type': vuln_type or tab, 'Asset': source, 'Plugin_Name': module,
        'Tracking_Status': tracking, 'FP_Status': "Verified" if fp == 2 else "Unverified",
        'Avg_Risk': risk if risk is not None else ''
    }


# ============================================================================
# GROUP 1: Network Security (Weight 1.0)
# ============================================================================
def run_group1():
    print("\n" + "=" * 70)
    print("GROUP 1: NETWORK SECURITY (Weight 1.0)")
    print("=" * 70)

    findings = []
    stats = {'rows': 0, 'fp_excluded': 0, 'info_excluded': 0, 'findings': 0,
             'tracking': Counter(), 'cvr': []}

    # VULNERABILITY_CVE_* and VULNERABILITY_GENERAL
    for vtype, sev in [('VULNERABILITY_CVE_CRITICAL', 'Critical'), ('VULNERABILITY_CVE_HIGH', 'High'),
                        ('VULNERABILITY_CVE_MEDIUM', 'Medium'), ('VULNERABILITY_CVE_LOW', 'Low'),
                        ('VULNERABILITY_GENERAL', 'Medium'), ('EXTERNAL_VULNERABILITIES', 'High')]:
        rows, fp_ex = process_rows(vtype, sev, 'Network Security')
        stats['fp_excluded'] += fp_ex
        for r in rows:
            stats['rows'] += 1
            stats['tracking'][r['tracking']] += 1
            if r['risk'] is not None:
                stats['cvr'].append((r['confidence'], r['visibility'], r['risk']))

            # For EXTERNAL_VULNERABILITIES, skip Info severity
            if vtype == 'EXTERNAL_VULNERABILITIES':
                data_lower = r['data'].lower()
                if 'info' in data_lower and 'critical' not in data_lower and 'high' not in data_lower and 'medium' not in data_lower:
                    stats['info_excluded'] += 1
                    continue

            desc = (f"A {sev.lower()} severity vulnerability ({vtype.replace('_', ' ').title()}) was identified on {r['source']}. "
                    f"Details: {r['data'][:400]}. "
                    f"This vulnerability requires assessment and remediation based on its severity and the affected asset's criticality. "
                    f"Exploitation could lead to unauthorized access, data exposure, or service disruption. "
                    f"Immediate remediation planning should be initiated for this finding.")
            rec = (f"Apply vendor patches or configuration changes to address the vulnerability on {r['source']}. "
                   f"Implement compensating controls if patches are not immediately available. "
                   f"Verify remediation through re-scanning after applying fixes. "
                   f"Priority: {sev} - follow organizational SLAs for {sev.lower()} findings. "
                   f"Monitor for active exploitation attempts targeting this vulnerability.")
            findings.append(make_finding('Network Security', vtype, sev,
                f"{vtype.replace('_', ' ').title()} - {r['source']} - {r['data'][:60]}",
                desc, rec, r['source'], r['module'], r['tracking'], r['fp'], r['risk']))
            stats['findings'] += 1

    # TCP_PORT_OPEN, UDP_PORT_OPEN — consolidated by risk tier
    # Instead of one finding per port, group into Critical/High/Medium tiers
    port_tiers = {'Critical': [], 'High': [], 'Medium': []}  # tier -> list of (port, svc, host, protocol, tracking, risk)
    for ptype in ['TCP_PORT_OPEN', 'UDP_PORT_OPEN']:
        proto = ptype.split('_')[0]  # TCP or UDP
        rows, fp_ex = process_rows(ptype, 'Medium', 'Network Security')
        stats['fp_excluded'] += fp_ex
        for r in rows:
            stats['rows'] += 1
            stats['tracking'][r['tracking']] += 1
            if r['risk'] is not None:
                stats['cvr'].append((r['confidence'], r['visibility'], r['risk']))

            port_match = re.search(r'(\d+)', r['data'])
            port_num = port_match.group(1) if port_match else ''
            sev = 'Medium'
            svc = ''
            if port_num in HIGH_RISK_PORTS:
                svc, sev = HIGH_RISK_PORTS[port_num]

            port_tiers[sev].append({
                'port': port_num, 'svc': svc, 'host': r['source'],
                'proto': proto, 'tracking': r['tracking'],
                'risk': r['risk'], 'data': r['data'][:200],
            })

    # Emit one consolidated finding per non-empty risk tier
    for tier_sev in ['Critical', 'High', 'Medium']:
        entries = port_tiers[tier_sev]
        if not entries:
            continue

        # Unique ports and hosts in this tier
        unique_ports = sorted(set(e['port'] for e in entries if e['port']), key=lambda x: int(x) if x.isdigit() else 0)
        unique_hosts = sorted(set(e['host'] for e in entries if e['host']))
        tracking_counts = Counter(e['tracking'] for e in entries)
        tracking_summary = ", ".join(f"{k}: {v}" for k, v in tracking_counts.items())

        # Build port summary with service names
        port_details = []
        for p in unique_ports:
            if p in HIGH_RISK_PORTS:
                svc_name, _ = HIGH_RISK_PORTS[p]
                port_details.append(f"{p}/{svc_name}")
            else:
                port_details.append(p)

        # Truncate port list for description; full list goes in detail CSV
        if len(port_details) <= 20:
            port_list_str = ", ".join(port_details)
        else:
            port_list_str = ", ".join(port_details[:20]) + f", and {len(port_details) - 20} more"

        host_list_str = ", ".join(unique_hosts[:5])
        if len(unique_hosts) > 5:
            host_list_str += f", and {len(unique_hosts) - 5} more"

        tier_label = {'Critical': 'Critical-Risk', 'High': 'High-Risk', 'Medium': 'Standard'}[tier_sev]

        desc = (f"{len(unique_ports)} {tier_label.lower()} open ports detected across {len(unique_hosts)} hosts "
                f"({len(entries)} total port/host instances). "
                f"Ports: {port_list_str}. "
                f"Hosts: {host_list_str}. ")
        if tier_sev == 'Critical':
            desc += ("These include database, remote access, and administrative services that pose severe risk when "
                     "internet-exposed. Exploitation of these services can lead to direct system compromise, data exfiltration, "
                     "or full network takeover. Immediate remediation is required.")
        elif tier_sev == 'High':
            desc += ("These include sensitive services such as file transfer, email, and directory protocols that "
                     "should not be directly accessible from the internet. Unauthorized access to these services "
                     "could enable lateral movement and data compromise.")
        else:
            desc += ("Each exposed port increases the organization's attack surface. While individually lower risk, "
                     "the cumulative exposure across multiple hosts and ports warrants review to ensure only "
                     "necessary services are externally accessible.")

        rec = (f"Review all {len(unique_ports)} exposed ports across {len(unique_hosts)} hosts and close any that are not required for business operations. "
               f"For required services, apply security hardening, enforce strong authentication, and restrict access to authorized IP ranges via firewall rules. "
               f"Place administrative and sensitive services behind VPN or zero-trust access solutions. "
               f"Implement network-level monitoring and IDS rules for all externally exposed services. "
               f"See the detail CSV for the complete port/host inventory to guide remediation prioritization.")

        findings.append(make_finding('Network Security', 'TCP_PORT_OPEN', tier_sev,
            f"{tier_label} Open Ports - {len(unique_ports)} ports across {len(unique_hosts)} hosts",
            desc, rec,
            ", ".join(unique_hosts[:3]),
            entries[0].get('module', '') if entries else '',
            max(tracking_counts, key=tracking_counts.get) if tracking_counts else 'OPEN',
            0, None,
            vuln_type=f"OPEN_PORTS_{tier_sev.upper()}"))
        stats['findings'] += len(entries)

        # Write detail CSV for this tier
        detail_rows = []
        for i, e in enumerate(sorted(entries, key=lambda x: (int(x['port']) if x['port'].isdigit() else 0))):
            svc_label = HIGH_RISK_PORTS[e['port']][0] if e['port'] in HIGH_RISK_PORTS else ''
            detail_rows.append({
                'Instance': i + 1, 'Port': e['port'], 'Protocol': e['proto'],
                'Service': svc_label, 'Host': e['host'],
                'Risk_Tier': tier_sev, 'Tracking_Status': e['tracking'],
                'Raw_Data': e['data'],
            })
        detail_file = os.path.join(DETAILS_DIR, f'findings_detail_OPEN_PORTS_{tier_sev.upper()}.csv')
        with open(detail_file, 'w', newline='') as csvf:
            w = csv.DictWriter(csvf, fieldnames=detail_rows[0].keys())
            w.writeheader()
            w.writerows(detail_rows)

    # Informational port types
    for itype in ['TCP_PORT_OPEN_BANNER', 'UDP_PORT_OPEN_INFO']:
        rows, fp_ex = process_rows(itype, 'Info', 'Network Security')
        stats['fp_excluded'] += fp_ex
        stats['rows'] += len(rows)
        stats['info_excluded'] += len(rows)

    # IP_ADDRESS, IPV6_ADDRESS, INTERNAL_IP_ADDRESS
    for iptype, sev, context in [
        ('INTERNAL_IP_ADDRESS', 'High', 'Internal IP address leaked externally'),
        ('IP_ADDRESS', 'Low', 'External IP address in attack surface'),
        ('IPV6_ADDRESS', 'Low', 'IPv6 address in attack surface'),
    ]:
        rows, fp_ex = process_rows(iptype, sev, 'Network Security')
        stats['fp_excluded'] += fp_ex
        for r in rows:
            stats['rows'] += 1
            stats['tracking'][r['tracking']] += 1
            if r['risk'] is not None:
                stats['cvr'].append((r['confidence'], r['visibility'], r['risk']))

            if iptype == 'INTERNAL_IP_ADDRESS':
                desc = (f"Internal IP address {r['data'][:200]} was discovered via {r['source']} through {r['module']}. "
                        "Leaking internal IP addresses reveals network architecture details to potential attackers. "
                        "This information can be used for reconnaissance, targeted attacks, and network mapping. "
                        "Internal addressing should never be exposed in external-facing content, headers, or DNS records. "
                        "This finding indicates a configuration issue that should be remediated promptly.")
                rec = (f"Identify and remediate the source of internal IP disclosure on {r['source']}. "
                       "Common causes: HTTP headers (X-Forwarded-For, Via), DNS records, error pages, JavaScript, HTML comments. "
                       "Configure reverse proxies and load balancers to strip internal IP headers before external responses. "
                       "Review and sanitize all external-facing content that may contain internal network information. "
                       "Implement egress filtering to prevent internal IP leakage through application responses.")
            else:
                desc = (f"{context}: {r['data'][:300]} discovered via {r['source']}. "
                        f"This address is part of the organization's external attack surface. "
                        "Each discoverable IP address represents a potential entry point for attackers. "
                        "All exposed IP addresses should have appropriate security controls and monitoring in place. "
                        "Regular attack surface inventory helps track and secure all external-facing assets.")
                rec = (f"Ensure {r['data'][:100]} has appropriate security controls including firewall rules, IDS, and regular vulnerability scanning. "
                       "Verify that only necessary services are exposed on this IP address. "
                       "Implement network monitoring and alerting for suspicious activity. "
                       "Include this asset in regular vulnerability scanning and penetration testing scope. "
                       "Review whether this IP needs to be externally accessible.")
            findings.append(make_finding('Network Security', iptype, sev,
                f"{iptype.replace('_', ' ').title()} - {r['data'][:80]} via {r['source']}", desc, rec,
                r['source'], r['module'], r['tracking'], r['fp'], r['risk']))
            stats['findings'] += 1

    # DEFACED_*
    for dtype, sev in [('DEFACED_INTERNET_NAME', 'Critical'), ('DEFACED_IPADDR', 'Critical'),
                        ('DEFACED_AFFILIATE_INTERNET_NAME', 'High'), ('DEFACED_COHOST', 'High'),
                        ('DEFACED_AFFILIATE_IPADDR', 'High')]:
        rows, fp_ex = process_rows(dtype, sev, 'Network Security')
        stats['fp_excluded'] += fp_ex
        for r in rows:
            stats['rows'] += 1
            stats['tracking'][r['tracking']] += 1
            if r['risk'] is not None:
                stats['cvr'].append((r['confidence'], r['visibility'], r['risk']))
            is_direct = 'AFFILIATE' not in dtype and 'COHOST' not in dtype
            desc = (f"{'Direct' if is_direct else 'Affiliate/co-hosted'} website defacement detected on {r['source']}. "
                    f"Details: {r['data'][:400]}. "
                    + ("Website defacement indicates that an attacker has gained unauthorized write access to the web server. " if is_direct else "Defacement of an affiliate/co-hosted site indicates potential shared infrastructure compromise. ")
                    + "This represents a security breach requiring immediate incident response and forensic investigation. "
                    + "The compromised system may have been used as a pivot point for further attacks.")
            rec = (f"Immediately investigate the defacement on {r['source']} and initiate incident response. "
                   "Restore the site from a known-good backup after forensic evidence has been collected. "
                   "Identify and remediate the attack vector (common: CMS vulns, compromised credentials, SQL injection). "
                   "Review and harden web server configurations, update all software, implement file integrity monitoring. "
                   "Conduct a thorough security audit of the affected infrastructure.")
            findings.append(make_finding('Network Security', dtype, sev,
                f"Defacement - {r['source']} - {r['data'][:60]}", desc, rec,
                r['source'], r['module'], r['tracking'], r['fp'], r['risk']))
            stats['findings'] += 1

    # PROXY_HOST, VPN_HOST, TOR_EXIT_NODE
    for atype, label in [('PROXY_HOST', 'Proxy'), ('VPN_HOST', 'VPN'), ('TOR_EXIT_NODE', 'Tor Exit Node')]:
        rows, fp_ex = process_rows(atype, 'Medium', 'Network Security')
        stats['fp_excluded'] += fp_ex
        sev = 'High' if atype == 'TOR_EXIT_NODE' else 'Medium'
        for r in rows:
            stats['rows'] += 1
            stats['tracking'][r['tracking']] += 1
            if r['risk'] is not None:
                stats['cvr'].append((r['confidence'], r['visibility'], r['risk']))
            desc = (f"Asset {r['source']} was identified as a {label.lower()} in the attack surface. "
                    f"Detection details: {r['data'][:400]}. "
                    f"{label} infrastructure can indicate anonymization of malicious traffic or misconfigured equipment. "
                    "Attackers may route traffic through these services to obscure their origin. "
                    "This finding should be investigated to determine if intentional.")
            rec = (f"Investigate whether the {label.lower()} configuration on {r['source']} is intentional and authorized. "
                   "If unauthorized, immediately isolate the system and investigate for compromise. "
                   "Review network architecture to ensure traffic routing is as expected. "
                   f"Implement monitoring for suspicious traffic patterns through {label.lower()} infrastructure. "
                   "Document authorized proxy/VPN/anonymization services in the network inventory.")
            findings.append(make_finding('Network Security', atype, sev,
                f"{label} Detected - {r['source']}", desc, rec,
                r['source'], r['module'], r['tracking'], r['fp'], r['risk']))
            stats['findings'] += 1

    # AI_ENDPOINT_UNAUTHENTICATED, AI_MODEL_EXPOSED
    for aitype, sev, ctx in [('AI_ENDPOINT_UNAUTHENTICATED', 'Critical', 'unauthenticated AI/ML endpoint'),
                              ('AI_MODEL_EXPOSED', 'High', 'exposed AI/ML model')]:
        rows, fp_ex = process_rows(aitype, sev, 'Network Security')
        stats['fp_excluded'] += fp_ex
        for r in rows:
            stats['rows'] += 1
            stats['tracking'][r['tracking']] += 1
            if r['risk'] is not None:
                stats['cvr'].append((r['confidence'], r['visibility'], r['risk']))
            desc = (f"An {ctx} was discovered on {r['source']}. "
                    f"Details: {r['data'][:400]}. "
                    "Exposed AI/ML infrastructure can be exploited for unauthorized inference, model theft, or prompt injection. "
                    "Unauthenticated AI endpoints pose significant risk as they may expose sensitive training data. "
                    "This finding requires immediate security review and access control implementation.")
            rec = (f"Immediately implement authentication and authorization controls on the AI endpoint at {r['source']}. "
                   "Apply rate limiting, input validation, and output filtering to prevent abuse. "
                   "Review whether the AI model or endpoint should be externally accessible at all. "
                   "Implement monitoring for adversarial inputs and unusual query patterns. "
                   "Ensure AI infrastructure follows organizational security policies.")
            findings.append(make_finding('Network Security', aitype, sev,
                f"AI Infrastructure - {r['source']} - {r['data'][:60]}", desc, rec,
                r['source'], r['module'], r['tracking'], r['fp'], r['risk']))
            stats['findings'] += 1

    consolidated = consolidate_and_save(findings, 1, 'Network Security', 1.0, stats)
    print_stats('GROUP 1: Network Security', stats, len(consolidated))
    return stats, len(consolidated)


# ============================================================================
# GROUP 2: Web App Security (Weight 1.0)
# ============================================================================
def run_group2():
    print("\n" + "=" * 70)
    print("GROUP 2: WEB APP SECURITY (Weight 1.0)")
    print("=" * 70)

    findings = []
    stats = {'rows': 0, 'fp_excluded': 0, 'info_excluded': 0, 'findings': 0,
             'tracking': Counter(), 'cvr': []}

    # WEBAPP_VULNERABILITIES (exclude Info)
    rows, fp_ex = process_rows('WEBAPP_VULNERABILITIES', 'High', 'Web App Security')
    stats['fp_excluded'] += fp_ex
    for r in rows:
        stats['rows'] += 1
        stats['tracking'][r['tracking']] += 1
        if r['risk'] is not None:
            stats['cvr'].append((r['confidence'], r['visibility'], r['risk']))
        data_lower = r['data'].lower()
        if 'info' in data_lower and not any(s in data_lower for s in ['critical', 'high', 'medium']):
            stats['info_excluded'] += 1
            continue
        sev = 'Critical' if 'critical' in data_lower else 'High' if 'high' in data_lower else 'Medium'
        desc = (f"A {sev.lower()} web application vulnerability was identified on {r['source']}. "
                f"Details: {r['data'][:400]}. "
                "Web application vulnerabilities can be exploited for data theft, session hijacking, or server compromise. "
                "The specific impact depends on the vulnerability type and the application's role. "
                "Immediate assessment and remediation is recommended.")
        rec = (f"Remediate the web application vulnerability on {r['source']} by applying patches or code fixes. "
               "Implement a web application firewall (WAF) as a defense-in-depth measure. "
               "Conduct application security testing after remediation to verify the fix. "
               f"Priority: {sev} - address within organizational vulnerability management SLAs. "
               "Review application security practices to prevent similar vulnerabilities.")
        findings.append(make_finding('Web App Security', 'WEBAPP_VULNERABILITIES', sev,
            f"Web App Vulnerability - {r['source']} - {r['data'][:60]}", desc, rec,
            r['source'], r['module'], r['tracking'], r['fp'], r['risk']))
        stats['findings'] += 1

    # High-risk URL types
    scored_types = [
        ('URL_PASSWORD', 'High', 'password-protected URL'), ('URL_UPLOAD', 'High', 'file upload endpoint'),
        ('URL_FORM', 'Medium', 'form submission endpoint'), ('URL_FLASH', 'Medium', 'Flash content'),
        ('URL_JAVA_APPLET', 'Medium', 'Java applet'), ('URL_PASSWORD_HISTORIC', 'Medium', 'historic password URL'),
        ('URL_UPLOAD_HISTORIC', 'Medium', 'historic upload endpoint'),
        ('WEBSERVER_TECHNOLOGY', 'High', 'web server technology'), ('WEBSERVER_STRANGEHEADER', 'Medium', 'unusual HTTP header'),
        ('TARGET_WEB_CONTENT', 'Medium', 'web content'), ('TARGET_WEB_CONTENT_TYPE', 'Medium', 'web content type'),
        ('TARGET_WEB_COOKIE', 'Medium', 'web cookie'), ('HTTP_CODE', 'Low', 'HTTP response code'),
        ('INTERNET_NAME', 'Low', 'internet name'), ('URL_JAVASCRIPT', 'Low', 'JavaScript resource'),
        ('URL_STATIC', 'Low', 'static content'), ('URL_WEB_FRAMEWORK', 'Low', 'web framework'),
        ('URL_ADBLOCKED_EXTERNAL', 'Low', 'ad-blocked external resource'),
        ('URL_ADBLOCKED_INTERNAL', 'Low', 'ad-blocked internal resource'),
        ('URL_FORM_HISTORIC', 'Low', 'historic form'), ('URL_FLASH_HISTORIC', 'Low', 'historic Flash'),
        ('URL_JAVASCRIPT_HISTORIC', 'Low', 'historic JavaScript'),
        ('URL_WEB_FRAMEWORK_HISTORIC', 'Low', 'historic web framework'),
        ('URL_JAVA_APPLET_HISTORIC', 'Low', 'historic Java applet'),
        ('URL_STATIC_HISTORIC', 'Low', 'historic static content'),
    ]

    for etype, sev, context in scored_types:
        rows, fp_ex = process_rows(etype, sev, 'Web App Security')
        stats['fp_excluded'] += fp_ex
        for r in rows:
            stats['rows'] += 1
            stats['tracking'][r['tracking']] += 1
            if r['risk'] is not None:
                stats['cvr'].append((r['confidence'], r['visibility'], r['risk']))
            desc = (f"A {context} was identified on {r['source']} via {r['module']}. "
                    f"Details: {r['data'][:400]}. "
                    f"This {context} expands the web application attack surface and may expose functionality to attackers. "
                    "Web application components should be inventoried and assessed for security implications. "
                    "Unnecessary or outdated components should be removed or restricted.")
            rec = (f"Review the {context} on {r['source']} for security implications. "
                   "If not required for business operations, remove or restrict access to the resource. "
                   "Ensure proper access controls and input validation are in place. "
                   "Implement security headers and content security policies. "
                   f"Priority: {sev} - address according to organizational web security standards.")
            findings.append(make_finding('Web App Security', etype, sev,
                f"{etype.replace('_', ' ').title()} - {r['source']} - {r['data'][:60]}", desc, rec,
                r['source'], r['module'], r['tracking'], r['fp'], r['risk']))
            stats['findings'] += 1

    # Informational types
    for itype in ['INTERNET_NAME_UNRESOLVED', 'WEBSERVER_BANNER', 'WEBSERVER_HTTPHEADERS',
                   'WEB_ANALYTICS_ID', 'LINKED_URL_EXTERNAL', 'LINKED_URL_INTERNAL',
                   'WAYBACK_FOOTPRINTING', 'LEAKSITE_URL_WEBAPP']:
        rows, fp_ex = process_rows(itype, 'Info', 'Web App Security')
        stats['fp_excluded'] += fp_ex
        stats['rows'] += len(rows)
        stats['info_excluded'] += len(rows)

    consolidated = consolidate_and_save(findings, 2, 'Web App Security', 1.0, stats)
    print_stats('GROUP 2: Web App Security', stats, len(consolidated))
    return stats, len(consolidated)


# ============================================================================
# GROUP 3: Information Leakage (Weight 0.8)
# ============================================================================
def run_group3():
    print("\n" + "=" * 70)
    print("GROUP 3: INFORMATION LEAKAGE (Weight 0.8)")
    print("=" * 70)

    findings = []
    stats = {'rows': 0, 'fp_excluded': 0, 'info_excluded': 0, 'findings': 0,
             'tracking': Counter(), 'cvr': []}

    # Critical types
    critical_types = [
        ('BREACHED_CREDENTIALS', 'Critical', 'breached credential'),
        ('PASSWORD_COMPROMISED', 'Critical', 'compromised password'),
        ('HASH_COMPROMISED', 'Critical', 'compromised hash'),
        ('CREDIT_CARD_NUMBER', 'Critical', 'exposed credit card number'),
        ('AI_API_KEY_LEAKED', 'Critical', 'leaked AI API key'),
        ('LEAKSITE_URL', 'Critical', 'leak site reference'),
        ('LEAKSITE_CONTENT', 'Critical', 'leak site content'),
    ]
    # High types
    high_types = [
        ('EMAILADDR_COMPROMISED', 'High', 'compromised email address'),
        ('MALICIOUS_EMAILADDR', 'High', 'malicious email address'),
        ('PHONE_NUMBER_COMPROMISED', 'High', 'compromised phone number'),
        ('MALICIOUS_PHONE_NUMBER', 'High', 'malicious phone number'),
        ('INTERESTING_FILE', 'High', 'interesting file'),
        ('DATE_HUMAN_DOB', 'High', 'exposed date of birth'),
    ]
    # Medium types
    medium_types = [
        ('EMAILADDR', 'Medium', 'exposed email address'),
        ('EMAILADDR_DELIVERABLE', 'Medium', 'deliverable email address'),
        ('EMAILADDR_DISPOSABLE', 'Medium', 'disposable email address'),
        ('HASH', 'Medium', 'exposed hash'),
        ('HUMAN_NAME', 'Medium', 'exposed human name'),
        ('PERSON_NAME', 'Medium', 'exposed person name'),
        ('USERNAME', 'Medium', 'exposed username'),
        ('PGP_KEY', 'Medium', 'exposed PGP key'),
        ('PHONE_NUMBER', 'Medium', 'exposed phone number'),
        ('PHYSICAL_ADDRESS', 'Medium', 'exposed physical address'),
        ('JOB_TITLE', 'Medium', 'exposed job title'),
    ]
    # Low types
    low_types = [
        ('INTERESTING_FILE_HISTORIC', 'Low', 'historic interesting file'),
        ('SOFTWARE_USED', 'Low', 'exposed software information'),
    ]

    for type_list in [critical_types, high_types, medium_types, low_types]:
        for etype, sev, context in type_list:
            rows, fp_ex = process_rows(etype, sev, 'Information Leakage')
            stats['fp_excluded'] += fp_ex
            for r in rows:
                stats['rows'] += 1
                stats['tracking'][r['tracking']] += 1
                if r['risk'] is not None:
                    stats['cvr'].append((r['confidence'], r['visibility'], r['risk']))
                desc = (f"A {context} was identified associated with {r['source']} via {r['module']}. "
                        f"Details: {r['data'][:400]}. "
                        f"This {context} represents information leakage that could be exploited by threat actors. "
                        + ("Compromised credentials require immediate password reset and account security review. " if 'compromised' in context or 'breached' in context
                           else "Exposed personal or organizational data increases risk of targeted attacks, phishing, and social engineering. ")
                        + "Organizations should implement data loss prevention controls to mitigate similar exposures.")
                rec = (f"Investigate the source of the {context} exposure involving {r['source']}. "
                       + ("Immediately reset affected passwords and enable multi-factor authentication on all associated accounts. " if 'compromised' in context or 'breached' in context or 'password' in context
                          else "Implement data classification and handling procedures to prevent further exposure. ")
                       + "Review access controls and data protection mechanisms for the affected systems. "
                       + f"Priority: {sev} - address according to organizational data protection policies. "
                       + "Monitor for misuse of the exposed information through threat intelligence feeds.")
                findings.append(make_finding('Information Leakage', etype, sev,
                    f"{etype.replace('_', ' ').title()} - {r['source']} - {r['data'][:60]}", desc, rec,
                    r['source'], r['module'], r['tracking'], r['fp'], r['risk']))
                stats['findings'] += 1

    # Informational types
    for itype in ['EMAILADDR_GENERIC', 'EMAILADDR_UNDELIVERABLE', 'PHONE_NUMBER_TYPE',
                   'RAW_FILE_META_DATA', 'IBAN_NUMBER']:
        rows, fp_ex = process_rows(itype, 'Info', 'Information Leakage')
        stats['fp_excluded'] += fp_ex
        stats['rows'] += len(rows)
        stats['info_excluded'] += len(rows)

    consolidated = consolidate_and_save(findings, 3, 'Information Leakage', 0.8, stats)
    print_stats('GROUP 3: Information Leakage', stats, len(consolidated))
    return stats, len(consolidated)


# ============================================================================
# GROUP 4: General Health (Weight 0.8)
# ============================================================================
def run_group4():
    print("\n" + "=" * 70)
    print("GROUP 4: GENERAL HEALTH (Weight 0.8)")
    print("=" * 70)

    findings = []
    stats = {'rows': 0, 'fp_excluded': 0, 'info_excluded': 0, 'findings': 0,
             'tracking': Counter(), 'cvr': []}

    scored_types = [
        ('VULNERABILITY_DISCLOSURE', 'Critical', 'public vulnerability disclosure'),
        ('SSL_CERTIFICATE_EXPIRED', 'High', 'expired SSL certificate'),
        ('SSL_CERTIFICATE_EXPIRING', 'High', 'expiring SSL certificate'),
        ('SSL_CERTIFICATE_MISMATCH', 'High', 'SSL certificate mismatch'),
        ('PUBLIC_CODE_REPO', 'High', 'public code repository'),
        ('APPSTORE_ENTRY', 'Medium', 'app store entry'),
        ('COUNTRY_NAME', 'Low', 'geographic presence (country)'),
        ('GEOINFO', 'Low', 'geographic information'),
        ('PHYSICAL_COORDINATES', 'Low', 'physical coordinates'),
        ('SSL_CERTIFICATE_ISSUED', 'Low', 'SSL certificate issued'),
        ('SSL_CERTIFICATE_ISSUER', 'Low', 'SSL certificate issuer'),
    ]

    for etype, sev, context in scored_types:
        rows, fp_ex = process_rows(etype, sev, 'General Health')
        stats['fp_excluded'] += fp_ex
        for r in rows:
            stats['rows'] += 1
            stats['tracking'][r['tracking']] += 1
            if r['risk'] is not None:
                stats['cvr'].append((r['confidence'], r['visibility'], r['risk']))

            if 'SSL' in etype:
                desc = (f"A {context} was identified on {r['source']} via {r['module']}. "
                        f"Certificate details: {r['data'][:400]}. "
                        + ("Expired certificates cause browser warnings, break user trust, and may expose encrypted traffic. " if 'EXPIRED' in etype
                           else "Certificate mismatch errors indicate configuration issues that undermine transport security. " if 'MISMATCH' in etype
                           else "Expiring certificates require proactive renewal to avoid service disruption. " if 'EXPIRING' in etype
                           else "Certificate lifecycle tracking helps maintain TLS/SSL health across the infrastructure. ")
                        + "SSL/TLS certificates are foundational to secure communications and must be properly maintained. "
                        + "Certificate issues can lead to man-in-the-middle attacks and data interception.")
                rec = (f"{'Immediately renew' if 'EXPIRED' in etype else 'Plan renewal for' if 'EXPIRING' in etype else 'Investigate and correct'} the SSL certificate on {r['source']}. "
                       "Implement automated certificate management and monitoring for expiration alerts. "
                       "Ensure all certificates use strong cryptographic algorithms (RSA 2048+ or ECDSA P-256+). "
                       "Configure HSTS headers and certificate transparency monitoring. "
                       f"Priority: {sev} - {'immediate action required' if sev in ('Critical', 'High') else 'address within standard maintenance window'}.")
            elif etype == 'PUBLIC_CODE_REPO':
                desc = (f"A public code repository was identified associated with {r['source']} via {r['module']}. "
                        f"Repository details: {r['data'][:400]}. "
                        "Public code repositories may inadvertently expose source code, credentials, API keys, or internal architecture. "
                        "Even without secrets, code exposure provides attackers with detailed knowledge of application logic and potential vulnerabilities. "
                        "All public repositories should be audited for sensitive information.")
                rec = (f"Audit the public code repository associated with {r['source']} for exposed secrets, credentials, and API keys. "
                       "Run automated secret scanning tools (e.g., git-secrets, truffleHog) on all repository history. "
                       "Rotate any credentials found in the repository and implement pre-commit hooks to prevent future leaks. "
                       "Review whether the repository should be public or if it should be made private. "
                       "Priority: High - public code repos are a common source of credential exposure.")
            elif etype == 'VULNERABILITY_DISCLOSURE':
                desc = (f"A public vulnerability disclosure was found referencing {r['source']} via {r['module']}. "
                        f"Disclosure details: {r['data'][:400]}. "
                        "Public vulnerability disclosures signal that attackers are aware of specific weaknesses in the organization's infrastructure. "
                        "Disclosed vulnerabilities are frequently targeted by automated exploitation tools within hours of publication. "
                        "This finding requires immediate assessment and remediation prioritization.")
                rec = (f"Immediately assess the disclosed vulnerability affecting {r['source']} and determine if the organization is impacted. "
                       "Apply available patches or implement compensating controls as an interim measure. "
                       "Monitor threat intelligence for active exploitation of the disclosed vulnerability. "
                       "Coordinate with vendor for remediation guidance if patches are not yet available. "
                       "Priority: Critical - publicly disclosed vulnerabilities are actively targeted by threat actors.")
            else:
                desc = (f"A {context} was identified for {r['source']} via {r['module']}. "
                        f"Details: {r['data'][:400]}. "
                        "Geographic and asset inventory information contributes to the overall security posture assessment. "
                        "Understanding the geographic distribution of assets helps with compliance and risk management. "
                        "This information should be tracked as part of the organizational asset inventory.")
                rec = (f"Document the {context} for {r['source']} in the organizational asset inventory. "
                       "Ensure geographic presence complies with data sovereignty and regulatory requirements. "
                       "Review whether assets in this location require additional security controls. "
                       "Include this asset in regular security assessments and monitoring. "
                       f"Priority: {sev} - include in standard asset management processes.")

            findings.append(make_finding('General Health', etype, sev,
                f"{etype.replace('_', ' ').title()} - {r['source']} - {r['data'][:60]}", desc, rec,
                r['source'], r['module'], r['tracking'], r['fp'], r['risk']))
            stats['findings'] += 1

    # Informational
    for itype in ['SSL_CERTIFICATE_RAW', 'BLACKLISTED_AFFILIATE_INTERNET_NAME', 'BLACKLISTED_AFFILIATE_IPADDR']:
        rows, fp_ex = process_rows(itype, 'Info', 'General Health')
        stats['fp_excluded'] += fp_ex
        stats['rows'] += len(rows)
        stats['info_excluded'] += len(rows)

    consolidated = consolidate_and_save(findings, 4, 'General Health', 0.8, stats)
    print_stats('GROUP 4: General Health', stats, len(consolidated))
    return stats, len(consolidated)


# ============================================================================
# GROUP 5: External Account Exposure (Weight 0.7)
# ============================================================================
def run_group5():
    print("\n" + "=" * 70)
    print("GROUP 5: EXTERNAL ACCOUNT EXPOSURE (Weight 0.7)")
    print("=" * 70)

    findings = []
    stats = {'rows': 0, 'fp_excluded': 0, 'info_excluded': 0, 'findings': 0,
             'tracking': Counter(), 'cvr': [], 'validation_needed': 0}

    # Critical: Compromised accounts
    for etype, sev, ctx in [
        ('ACCOUNT_EXTERNAL_OWNED_COMPROMISED', 'Critical', 'compromised external account'),
        ('ACCOUNT_EXTERNAL_USER_SHARED_COMPROMISED', 'Critical', 'compromised shared user account'),
    ]:
        rows, fp_ex = process_rows(etype, sev, 'External Account Exposure')
        stats['fp_excluded'] += fp_ex
        for r in rows:
            stats['rows'] += 1
            stats['tracking'][r['tracking']] += 1
            if r['risk'] is not None:
                stats['cvr'].append((r['confidence'], r['visibility'], r['risk']))
            desc = (f"A {ctx} was identified for {r['source']} via {r['module']}. "
                    f"Account details: {r['data'][:400]}. "
                    "Compromised external accounts pose immediate risk of unauthorized access and data breach. "
                    "Attackers may use these accounts for credential stuffing, lateral movement, or social engineering. "
                    "Immediate investigation and credential reset is required.")
            rec = (f"Immediately reset credentials for the compromised account associated with {r['source']}. "
                   "Enable multi-factor authentication on all affected accounts and services. "
                   "Investigate for unauthorized access or data exfiltration using the compromised credentials. "
                   "Review and revoke any active sessions associated with the compromised account. "
                   "Priority: Critical - compromised accounts require immediate incident response.")
            findings.append(make_finding('External Account Exposure', etype, sev,
                f"{ctx.title()} - {r['source']} - {r['data'][:60]}", desc, rec,
                r['source'], r['module'], r['tracking'], r['fp'], r['risk']))
            stats['findings'] += 1

    # High: Target accounts
    rows, fp_ex = process_rows('TARGET_ACCOUNTS', 'High', 'External Account Exposure')
    stats['fp_excluded'] += fp_ex
    for r in rows:
        stats['rows'] += 1
        stats['tracking'][r['tracking']] += 1
        if r['risk'] is not None:
            stats['cvr'].append((r['confidence'], r['visibility'], r['risk']))
        desc = (f"A target account was identified for {r['source']} via {r['module']}. "
                f"Account details: {r['data'][:400]}. "
                "Target accounts represent known organizational accounts on external platforms. "
                "These accounts should be monitored for compromise and unauthorized activity. "
                "Account enumeration by attackers can lead to targeted credential attacks.")
        rec = (f"Verify the target account for {r['source']} is authorized and properly secured. "
               "Ensure strong, unique passwords and multi-factor authentication are enabled. "
               "Monitor for suspicious login attempts and unauthorized account changes. "
               "Implement account activity alerts for high-value organizational accounts. "
               "Priority: High - target accounts should be secured and monitored proactively.")
        findings.append(make_finding('External Account Exposure', 'TARGET_ACCOUNTS', 'High',
            f"Target Account - {r['source']} - {r['data'][:60]}", desc, rec,
            r['source'], r['module'], r['tracking'], r['fp'], r['risk']))
        stats['findings'] += 1

    # ACCOUNT_EXTERNAL_OWNED - Special: only FP=2 creates findings, FP=0 counted as validation needed
    all_owned = ROWS_BY_TYPE.get('ACCOUNT_EXTERNAL_OWNED', [])
    owned_fp2 = []
    for row in all_owned:
        fp = get_fp(row)
        if fp == 1:
            stats['fp_excluded'] += 1
            continue
        stats['rows'] += 1
        if fp == 0:
            stats['validation_needed'] += 1
            continue
        if fp == 2:
            owned_fp2.append(row)

    # Group FP=2 owned accounts by platform (from Data field)
    platform_groups = defaultdict(list)
    for row in owned_fp2:
        data = safe_str(row.get('Data', ''))
        platform = data.split('(')[0].strip() if '(' in data else data[:50]
        platform_groups[platform].append(row)

    for platform, prows in platform_groups.items():
        sources = list(set(safe_str(r.get('Source', '')) for r in prows))
        tracking = get_tracking(prows[0])
        stats['tracking'][tracking] += len(prows)
        risk_vals = []
        for pr in prows:
            c, v, r_val = get_cvr(pr)
            if r_val is not None:
                stats['cvr'].append((c, v, r_val))
                risk_vals.append(r_val)
        avg_r = round(sum(risk_vals) / len(risk_vals), 1) if risk_vals else None

        src_list = ", ".join(sources[:5])
        if len(sources) > 5:
            src_list += f" and {len(sources)-5} more"
        desc = (f"Verified external account on {platform} found for {len(prows)} user(s): {src_list}. "
                f"These accounts were validated (FP=2) as belonging to the organization on the {platform} platform. "
                "External accounts expand the organization's digital footprint and may expose employee information. "
                "Accounts on third-party platforms should be inventoried and monitored for unauthorized use. "
                f"Note: {stats['validation_needed']} additional unverified accounts (FP=0) require validation.")
        rec = (f"Review and verify organizational ownership of accounts on {platform}. "
               "Ensure approved accounts follow organizational security policies including strong passwords and MFA. "
               "Deactivate any unauthorized or abandoned accounts on external platforms. "
               "Implement a shadow IT discovery process to track organizational presence on third-party services. "
               "Priority: Medium - maintain inventory and apply security controls to all external accounts.")
        findings.append(make_finding('External Account Exposure', 'ACCOUNT_EXTERNAL_OWNED', 'Medium',
            f"Verified External Account - {platform} - {len(prows)} accounts", desc, rec,
            src_list, 'sfp_accounts', tracking, 2, avg_r))
        stats['findings'] += len(prows)

    # SIMILAR_ACCOUNT_EXTERNAL, SOCIAL_MEDIA
    for etype, sev, ctx in [
        ('SIMILAR_ACCOUNT_EXTERNAL', 'Low', 'similar external account'),
        ('SOCIAL_MEDIA', 'Low', 'social media presence'),
    ]:
        rows, fp_ex = process_rows(etype, sev, 'External Account Exposure')
        stats['fp_excluded'] += fp_ex
        for r in rows:
            stats['rows'] += 1
            stats['tracking'][r['tracking']] += 1
            if r['risk'] is not None:
                stats['cvr'].append((r['confidence'], r['visibility'], r['risk']))
            desc = (f"A {ctx} was identified for {r['source']} via {r['module']}. "
                    f"Account details: {r['data'][:400]}. "
                    f"{'Similar accounts may indicate account impersonation or brand abuse on external platforms.' if 'SIMILAR' in etype else 'Social media presence exposes organizational information and employee details.'} "
                    "External account monitoring helps detect unauthorized use of organizational branding. "
                    "These findings should be reviewed to determine if accounts are legitimate or potentially malicious.")
            rec = (f"Review the {ctx} for {r['source']} to determine if it is authorized. "
                   + ("If impersonation is suspected, report the account to the platform and pursue takedown. " if 'SIMILAR' in etype
                      else "Ensure social media accounts follow organizational security and communication policies. ")
                   + "Monitor external platforms for unauthorized use of organizational branding and employee impersonation. "
                   + "Implement a brand protection program to detect and respond to impersonation threats. "
                   + f"Priority: {sev} - review during routine digital footprint assessment.")
            findings.append(make_finding('External Account Exposure', etype, sev,
                f"{ctx.title()} - {r['source']} - {r['data'][:60]}", desc, rec,
                r['source'], r['module'], r['tracking'], r['fp'], r['risk']))
            stats['findings'] += 1

    consolidated = consolidate_and_save(findings, 5, 'External Account Exposure', 0.7, stats)
    print_stats('GROUP 5: External Account Exposure', stats, len(consolidated))
    print(f"  Validation needed (ACCOUNT_EXTERNAL_OWNED FP=0): {stats['validation_needed']}")
    return stats, len(consolidated)


# ============================================================================
# GROUP 6: DNS Health (Weight 0.7)
# ============================================================================
def run_group6():
    print("\n" + "=" * 70)
    print("GROUP 6: DNS HEALTH (Weight 0.7)")
    print("=" * 70)

    findings = []
    stats = {'rows': 0, 'fp_excluded': 0, 'info_excluded': 0, 'findings': 0,
             'tracking': Counter(), 'cvr': []}

    # DNS_SPF - check for misconfigurations and zero_entries_fail
    spf_rows, fp_ex = process_rows('DNS_SPF', 'High', 'DNS Health')
    stats['fp_excluded'] += fp_ex
    domains_with_spf = set()
    for r in spf_rows:
        stats['rows'] += 1
        stats['tracking'][r['tracking']] += 1
        if r['risk'] is not None:
            stats['cvr'].append((r['confidence'], r['visibility'], r['risk']))
        domains_with_spf.add(r['source'])
        data_lower = r['data'].lower()

        # Check for SPF misconfigurations
        sev = 'Medium'
        issue = 'SPF record found'
        if '+all' in data_lower:
            sev = 'Critical'
            issue = 'SPF record with +all (allows any sender)'
        elif '~all' in data_lower:
            sev = 'High'
            issue = 'SPF record with ~all (soft fail, not enforcing)'
        elif '?all' in data_lower:
            sev = 'High'
            issue = 'SPF record with ?all (neutral, not enforcing)'
        elif data_lower.count('include:') > 10:
            sev = 'Medium'
            issue = f'SPF record with {data_lower.count("include:")} includes (complexity risk)'

        desc = (f"DNS SPF record for {r['source']}: {issue}. "
                f"SPF record content: {r['data'][:400]}. "
                + ("A +all SPF mechanism allows ANY server to send email on behalf of this domain, completely negating email authentication. " if '+all' in data_lower
                   else "A soft-fail (~all) or neutral (?all) SPF mechanism does not prevent email spoofing, only suggests it may be suspicious. " if any(x in data_lower for x in ['~all', '?all'])
                   else "SPF records help prevent email spoofing by specifying authorized mail servers for the domain. ")
                + "Properly configured SPF records are essential for email security and brand protection. "
                + "Email spoofing attacks can lead to phishing, business email compromise, and reputation damage.")
        rec = (f"{'Immediately change +all to -all' if '+all' in data_lower else 'Update SPF to use -all (hard fail)'} in the DNS SPF record for {r['source']}. "
               "Ensure all legitimate mail servers and services are included before enforcing -all. "
               "Implement DMARC in enforcement mode (p=reject or p=quarantine) alongside SPF. "
               "Monitor DMARC aggregate reports to verify email authentication effectiveness. "
               f"Priority: {sev} - email authentication issues enable phishing and BEC attacks.")
        findings.append(make_finding('DNS Health', 'DNS_SPF', sev,
            f"SPF {issue} - {r['source']}", desc, rec,
            r['source'], r['module'], r['tracking'], r['fp'], r['risk']))
        stats['findings'] += 1

    # DNS_TEXT - check for DMARC/DKIM
    text_rows, fp_ex = process_rows('DNS_TEXT', 'Medium', 'DNS Health')
    stats['fp_excluded'] += fp_ex
    domains_with_dmarc = set()
    domains_with_dkim = set()
    for r in text_rows:
        stats['rows'] += 1
        stats['tracking'][r['tracking']] += 1
        if r['risk'] is not None:
            stats['cvr'].append((r['confidence'], r['visibility'], r['risk']))
        data_lower = r['data'].lower()
        if 'dmarc' in data_lower:
            domains_with_dmarc.add(r['source'])
            sev = 'Medium'
            if 'p=none' in data_lower:
                sev = 'High'
                issue = 'DMARC policy set to none (monitoring only, not enforcing)'
            elif 'p=quarantine' in data_lower:
                sev = 'Low'
                issue = 'DMARC policy set to quarantine'
            elif 'p=reject' in data_lower:
                sev = 'Low'
                issue = 'DMARC policy set to reject (properly enforcing)'
            else:
                issue = 'DMARC record found'
            desc = (f"DMARC record for {r['source']}: {issue}. "
                    f"Record content: {r['data'][:400]}. "
                    + ("A DMARC policy of 'none' provides visibility but does not prevent email spoofing attacks. " if 'p=none' in data_lower
                       else "DMARC enforcement helps prevent email spoofing and protects the organization's domain reputation. ")
                    + "DMARC works with SPF and DKIM to authenticate email and prevent domain spoofing. "
                    + "Organizations should progress toward p=reject for maximum protection.")
            rec = (f"{'Upgrade DMARC policy from p=none to p=quarantine or p=reject' if 'p=none' in data_lower else 'Maintain DMARC enforcement'} for {r['source']}. "
                   "Monitor DMARC aggregate and forensic reports for authentication failures. "
                   "Ensure SPF and DKIM are properly aligned with the DMARC policy. "
                   "Gradually tighten DMARC policy (none -> quarantine -> reject) while monitoring legitimate email flow. "
                   f"Priority: {sev} - email authentication is critical for phishing prevention.")
        elif 'dkim' in data_lower:
            domains_with_dkim.add(r['source'])
            sev = 'Low'
            issue = 'DKIM record found'
            desc = (f"DKIM DNS record for {r['source']}: {issue}. "
                    f"Record content: {r['data'][:300]}. "
                    "DKIM provides cryptographic authentication of email messages to prevent tampering in transit. "
                    "Proper DKIM implementation is essential for email deliverability and security. "
                    "DKIM works alongside SPF and DMARC to provide comprehensive email authentication.")
            rec = (f"Maintain DKIM configuration for {r['source']} and ensure signing keys are rotated regularly. "
                   "Verify DKIM alignment with DMARC policy for comprehensive email authentication. "
                   "Monitor for DKIM failures in DMARC reports that may indicate configuration issues. "
                   "Ensure all email-sending services are configured with DKIM signing. "
                   "Priority: Low - DKIM is properly configured, continue monitoring.")
        else:
            sev = 'Low'
            desc = (f"DNS TXT record for {r['source']} via {r['module']}. "
                    f"Record content: {r['data'][:400]}. "
                    "DNS TXT records contain various configuration and verification data for the domain. "
                    "Excessive or outdated TXT records can leak organizational information. "
                    "Regular review of DNS TXT records ensures only necessary records are published.")
            rec = (f"Review DNS TXT records for {r['source']} and remove any outdated or unnecessary entries. "
                   "Ensure verification records (Google, Microsoft, etc.) are still needed. "
                   "Audit TXT records for information that could aid attacker reconnaissance. "
                   "Document the purpose of each TXT record in the domain management system. "
                   "Priority: Low - include in routine DNS hygiene reviews.")

        findings.append(make_finding('DNS Health', 'DNS_TEXT', sev,
            f"DNS TXT - {r['source']} - {r['data'][:60]}", desc, rec,
            r['source'], r['module'], r['tracking'], r['fp'], r['risk']))
        stats['findings'] += 1

    # Scored DNS types
    for etype, sev, ctx in [
        ('DOMAIN_NAME', 'Medium', 'domain name'), ('DOMAIN_NAME_PARENT', 'Low', 'parent domain'),
        ('DOMAIN_REGISTRAR', 'Medium', 'domain registrar'), ('DOMAIN_WHOIS', 'Low', 'domain WHOIS data'),
        ('DOMAIN_IMPERSONATION', 'High', 'domain impersonation'), ('NETBLOCK_WHOIS', 'Low', 'netblock WHOIS'),
    ]:
        rows, fp_ex = process_rows(etype, sev, 'DNS Health')
        stats['fp_excluded'] += fp_ex
        for r in rows:
            stats['rows'] += 1
            stats['tracking'][r['tracking']] += 1
            if r['risk'] is not None:
                stats['cvr'].append((r['confidence'], r['visibility'], r['risk']))
            desc = (f"A {ctx} was identified for {r['source']} via {r['module']}. "
                    f"Details: {r['data'][:400]}. "
                    + ("Domain impersonation attempts can be used for phishing, brand abuse, and social engineering attacks. " if 'IMPERSONATION' in etype
                       else f"This {ctx} is part of the organization's DNS infrastructure and attack surface. ")
                    + "DNS and domain information should be monitored for unauthorized changes and suspicious activity. "
                    + "Proper domain management is essential for maintaining organizational security posture.")
            rec_action = "Immediately investigate the domain impersonation and pursue takedown if confirmed" if 'IMPERSONATION' in etype else f"Review the {ctx} for {r['source']}"
            rec_detail = "Report impersonating domains to the registrar and relevant authorities. " if 'IMPERSONATION' in etype else "Ensure domain registration details are accurate and up to date. "
            rec_priority = "immediate action for impersonation" if 'IMPERSONATION' in etype else "routine domain management"
            rec = (f"{rec_action}. "
                   + rec_detail
                   + "Implement domain monitoring to detect future unauthorized registrations. "
                   + "Enable registrar lock and DNSSEC where supported. "
                   + f"Priority: {sev} - {rec_priority}.")
            findings.append(make_finding('DNS Health', etype, sev,
                f"{ctx.title()} - {r['source']} - {r['data'][:60]}", desc, rec,
                r['source'], r['module'], r['tracking'], r['fp'], r['risk']))
            stats['findings'] += 1

    # Informational
    for itype in ['DNS_SRV', 'RAW_DNS_RECORDS']:
        rows, fp_ex = process_rows(itype, 'Info', 'DNS Health')
        stats['fp_excluded'] += fp_ex
        stats['rows'] += len(rows)
        stats['info_excluded'] += len(rows)

    consolidated = consolidate_and_save(findings, 6, 'DNS Health', 0.7, stats)
    print_stats('GROUP 6: DNS Health', stats, len(consolidated))
    return stats, len(consolidated)


# ============================================================================
# GROUP 7: IP Reputation (Weight 0.6)
# ============================================================================
def run_group7():
    print("\n" + "=" * 70)
    print("GROUP 7: IP REPUTATION (Weight 0.6)")
    print("=" * 70)

    findings = []
    stats = {'rows': 0, 'fp_excluded': 0, 'info_excluded': 0, 'findings': 0,
             'tracking': Counter(), 'cvr': []}

    # Critical reputation
    for etype, sev, ctx in [
        ('BLACKLISTED_IPADDR', 'Critical', 'IP address found on security blacklists'),
        ('MALICIOUS_IPADDR', 'Critical', 'IP address flagged as malicious by threat intelligence'),
    ]:
        rows, fp_ex = process_rows(etype, sev, 'IP Reputation')
        stats['fp_excluded'] += fp_ex
        for r in rows:
            stats['rows'] += 1
            stats['tracking'][r['tracking']] += 1
            if r['risk'] is not None:
                stats['cvr'].append((r['confidence'], r['visibility'], r['risk']))
            desc = (f"IP address {r['source']} was {ctx} via {r['module']}. "
                    f"Blacklist/threat details: {r['data'][:400]}. "
                    + ("Blacklisted IPs can cause email delivery failures, service blocking, and reputation damage. " if 'BLACKLISTED' in etype
                       else "Malicious IP classification indicates active association with cyberattacks such as scanning, exploitation, or C2 communication. ")
                    + "IP reputation issues require investigation to determine if the system is compromised or misconfigured. "
                    + "Unresolved reputation issues can cascade to affect all services hosted on the IP address.")
            rec = (f"Immediately investigate {r['source']} for signs of compromise, misconfiguration, or unauthorized activity. "
                   "Scan the system for malware, unauthorized services, and suspicious processes. "
                   + ("After resolving the root cause, submit delisting requests to each blacklist provider. " if 'BLACKLISTED' in etype
                      else "Implement network monitoring and threat detection for the affected IP address. ")
                   + "Review firewall logs for suspicious inbound and outbound traffic patterns. "
                   + "Priority: Critical - IP reputation issues require investigation within 24 hours.")
            findings.append(make_finding('IP Reputation', etype, sev,
                f"{etype.replace('_', ' ').title()} - {r['source']} - {r['data'][:60]}", desc, rec,
                r['source'], r['module'], r['tracking'], r['fp'], r['risk']))
            stats['findings'] += 1

    # High reputation
    for etype, sev, ctx in [
        ('BLACKLISTED_INTERNET_NAME', 'High', 'domain/hostname found on blacklists'),
        ('MALICIOUS_INTERNET_NAME', 'High', 'domain flagged as malicious'),
        ('BLACKLISTED_COHOST', 'High', 'co-hosted site on blacklists'),
        ('MALICIOUS_COHOST', 'High', 'co-hosted site flagged as malicious'),
        ('MALICIOUS_ASN', 'High', 'ASN flagged for malicious activity'),
        ('MALICIOUS_BITCOIN_ADDRESS', 'High', 'Bitcoin address flagged as malicious'),
    ]:
        rows, fp_ex = process_rows(etype, sev, 'IP Reputation')
        stats['fp_excluded'] += fp_ex
        for r in rows:
            stats['rows'] += 1
            stats['tracking'][r['tracking']] += 1
            if r['risk'] is not None:
                stats['cvr'].append((r['confidence'], r['visibility'], r['risk']))
            desc = (f"A {ctx} was identified for {r['source']} via {r['module']}. "
                    f"Reputation details: {r['data'][:400]}. "
                    "Reputation issues on organizational assets can disrupt services and damage trust. "
                    "The root cause should be identified and resolved to restore clean reputation status. "
                    "Ongoing monitoring is required to detect future reputation degradation.")
            rec = (f"Investigate the reputation issue for {r['source']} and identify the root cause. "
                   "Scan affected systems for compromise indicators and unauthorized activity. "
                   "After remediation, submit delisting requests to relevant blacklist providers. "
                   "Implement continuous reputation monitoring and automated alerting. "
                   f"Priority: {sev} - address within 48 hours to prevent service disruption.")
            findings.append(make_finding('IP Reputation', etype, sev,
                f"{ctx.title()} - {r['source']} - {r['data'][:60]}", desc, rec,
                r['source'], r['module'], r['tracking'], r['fp'], r['risk']))
            stats['findings'] += 1

    # Medium reputation
    for etype, sev in [('BLACKLISTED_NETBLOCK', 'Medium'), ('MALICIOUS_NETBLOCK', 'Medium')]:
        rows, fp_ex = process_rows(etype, sev, 'IP Reputation')
        stats['fp_excluded'] += fp_ex
        for r in rows:
            stats['rows'] += 1
            stats['tracking'][r['tracking']] += 1
            if r['risk'] is not None:
                stats['cvr'].append((r['confidence'], r['visibility'], r['risk']))
            desc = (f"Network block associated with {r['source']} was flagged via {r['module']}. "
                    f"Details: {r['data'][:400]}. "
                    "Netblock-level reputation issues affect all IP addresses within the range. "
                    "This may result from compromised systems, shared hosting, or provider reputation problems. "
                    "All assets within the affected netblock should be assessed for security posture.")
            rec = (f"Identify all organizational assets within the affected netblock and assess their security. "
                   "Work with the network provider to address the reputation issue. "
                   "Monitor all IPs within the netblock for individual blacklisting. "
                   "Consider dedicated IP allocation if shared hosting reputation is a persistent issue. "
                   "Priority: Medium - investigate within 30 days and monitor for escalation.")
            findings.append(make_finding('IP Reputation', etype, sev,
                f"{etype.replace('_', ' ').title()} - {r['source']} - {r['data'][:60]}", desc, rec,
                r['source'], r['module'], r['tracking'], r['fp'], r['risk']))
            stats['findings'] += 1

    # Informational
    for itype in ['BLACKLISTED_SUBNET', 'MALICIOUS_SUBNET']:
        rows, fp_ex = process_rows(itype, 'Info', 'IP Reputation')
        stats['fp_excluded'] += fp_ex
        stats['rows'] += len(rows)
        stats['info_excluded'] += len(rows)

    consolidated = consolidate_and_save(findings, 7, 'IP Reputation', 0.6, stats)
    print_stats('GROUP 7: IP Reputation', stats, len(consolidated))
    return stats, len(consolidated)


# ============================================================================
# UTILITIES
# ============================================================================
def print_stats(name, stats, consolidated_count):
    print(f"\n  {name} STATISTICS:")
    print(f"  Total rows: {stats['rows']}")
    print(f"  FP excluded: {stats['fp_excluded']}")
    print(f"  Info excluded: {stats['info_excluded']}")
    print(f"  Raw findings: {stats['findings']}")
    print(f"  Consolidated: {consolidated_count}")
    print(f"  Tracking: {dict(stats['tracking'])}")
    if stats['cvr']:
        avg_c = sum(s[0] for s in stats['cvr']) / len(stats['cvr'])
        avg_v = sum(s[1] for s in stats['cvr']) / len(stats['cvr'])
        avg_r = sum(s[2] for s in stats['cvr']) / len(stats['cvr'])
        print(f"  CVR Averages: C={avg_c:.1f}, V={avg_v:.1f}, R={avg_r:.1f}")


# ============================================================================
# MAIN EXECUTION
# ============================================================================
if __name__ == '__main__':
    print("\n" + "=" * 70)
    print("ASM-NG ANALYSIS PIPELINE - ALL 7 GROUPS")
    print("=" * 70)

    all_stats = {}
    all_counts = {}

    all_stats[1], all_counts[1] = run_group1()
    all_stats[2], all_counts[2] = run_group2()
    all_stats[3], all_counts[3] = run_group3()
    all_stats[4], all_counts[4] = run_group4()
    all_stats[5], all_counts[5] = run_group5()
    all_stats[6], all_counts[6] = run_group6()
    all_stats[7], all_counts[7] = run_group7()

    # ============================================================================
    # SUMMARY
    # ============================================================================
    print("\n" + "=" * 70)
    print("PIPELINE SUMMARY")
    print("=" * 70)

    categories = {
        1: ('Network Security', 1.0),
        2: ('Web App Security', 1.0),
        3: ('Information Leakage', 0.8),
        4: ('General Health', 0.8),
        5: ('External Account Exposure', 0.7),
        6: ('DNS Health', 0.7),
        7: ('IP Reputation', 0.6),
    }

    total_findings = 0
    total_rows = 0
    total_fp = 0
    total_info = 0

    for g in range(1, 8):
        cat_name, weight = categories[g]
        count = all_counts[g]
        rows = all_stats[g]['rows']
        total_findings += count
        total_rows += rows
        total_fp += all_stats[g]['fp_excluded']
        total_info += all_stats[g]['info_excluded']
        print(f"  GROUP {g}: {cat_name} (w={weight}) - {count} consolidated findings from {rows} rows")

    print(f"\n  TOTAL: {total_findings} consolidated findings")
    print(f"  Total rows processed: {total_rows}")
    print(f"  False positives excluded: {total_fp}")
    print(f"  Informational excluded: {total_info}")

    # Update progress tracker
    tracker_path = os.path.join(OUTPUT_DIR, 'analysis_progress_tracker.md')
    with open(tracker_path, 'w') as f:
        f.write("# Security Analysis Progress Tracker\n")
        f.write(f"**Analysis Date:** 2026-02-20\n")
        f.write(f"**CSV File:** {CSV_FILE}\n")
        f.write(f"**CSV Format:** {CSV_FORMAT} ({len(HEADERS)} columns)\n")
        f.write(f"**Status:** COMPLETED\n\n")
        f.write("---\n\n")
        f.write("## Summary\n\n")
        f.write(f"| Group | Category | Weight | Findings | Rows |\n")
        f.write(f"|-------|----------|--------|----------|------|\n")
        for g in range(1, 8):
            cat_name, weight = categories[g]
            f.write(f"| {g} | {cat_name} | {weight} | {all_counts[g]} | {all_stats[g]['rows']} |\n")
        f.write(f"| **Total** | | | **{total_findings}** | **{total_rows}** |\n\n")
        f.write(f"- False positives excluded: {total_fp}\n")
        f.write(f"- Informational excluded: {total_info}\n\n")

        for g in range(1, 8):
            cat_name, weight = categories[g]
            s = all_stats[g]
            f.write(f"---\n\n### GROUP {g}: {cat_name} (Weight {weight}) - COMPLETED\n\n")
            f.write(f"- Consolidated findings: {all_counts[g]}\n")
            f.write(f"- Raw findings: {s['findings']}\n")
            f.write(f"- Rows processed: {s['rows']}\n")
            f.write(f"- FP excluded: {s['fp_excluded']}\n")
            f.write(f"- Info excluded: {s['info_excluded']}\n")
            f.write(f"- Tracking: {dict(s['tracking'])}\n")
            if s['cvr']:
                avg_c = sum(x[0] for x in s['cvr']) / len(s['cvr'])
                avg_v = sum(x[1] for x in s['cvr']) / len(s['cvr'])
                avg_r = sum(x[2] for x in s['cvr']) / len(s['cvr'])
                f.write(f"- CVR Averages: C={avg_c:.1f}, V={avg_v:.1f}, R={avg_r:.1f}\n")
            if g == 5 and 'validation_needed' in s:
                f.write(f"- ACCOUNT_EXTERNAL_OWNED validation needed: {s['validation_needed']}\n")
            f.write("\n")

        f.write("---\n\n**Last Updated:** 2026-02-20\n")

    print(f"\n  Progress tracker saved: {tracker_path}")

    # Verify output files
    print("\n  Output files:")
    for g in range(1, 8):
        fpath = os.path.join(OUTPUT_DIR, f'findings_GROUP{g}_FULL_CONSOLIDATED.csv')
        if os.path.exists(fpath):
            size = os.path.getsize(fpath)
            with open(fpath, 'r') as f:
                lines = sum(1 for _ in f)
            print(f"    GROUP {g}: {fpath} ({lines} lines, {size} bytes)")
        else:
            print(f"    GROUP {g}: MISSING!")

    detail_files = os.listdir(DETAILS_DIR)
    print(f"\n  Detail files: {len(detail_files)} files in {DETAILS_DIR}")

    print("\n" + "=" * 70)
    print("ANALYSIS PIPELINE COMPLETE")
    print("=" * 70)
