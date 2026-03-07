#!/usr/bin/env python3
"""
Parse Nessus and Burp files as STANDALONE findings sources.
Injects findings into GROUP 1 (Nessus → Network Security) and GROUP 2 (Burp → Web App Security).
Then re-runs consolidation.
"""

import csv
import os
import re
import xml.etree.ElementTree as ET
from collections import defaultdict, Counter
from bs4 import BeautifulSoup

OUTPUT_DIR = './output'
DETAILS_DIR = './output/findings_details'
NESSUS_FILE = './obfuscated/FHCSD-ASM-NESSUS-2026_02.nessus'
BURP_FILE = './obfuscated/FHCSD-ASM-BURP-2026_02.html'

OUTPUT_FIELDS = ['Category', 'Tab', 'Priority', 'Item', 'Description', 'Recommendation', 'Tracking_Status', 'Avg_Risk']

NESSUS_SEV_MAP = {0: 'Info', 1: 'Low', 2: 'Medium', 3: 'High', 4: 'Critical'}

os.makedirs(DETAILS_DIR, exist_ok=True)

# ============================================================================
# PARSE NESSUS FILE → STANDALONE FINDINGS
# ============================================================================
print("=" * 70)
print("PARSING NESSUS FILE AS STANDALONE FINDINGS")
print("=" * 70)

nessus_findings = []
nessus_info_count = 0

tree = ET.parse(NESSUS_FILE)
root = tree.getroot()

hosts_processed = 0
for report_host in root.findall('.//ReportHost'):
    host_name = report_host.get('name', '')
    hosts_processed += 1

    # Get host IP from properties
    host_ip = host_name
    hostname = None
    for tag in report_host.findall('.//HostProperties/tag'):
        tag_name = tag.get('name', '')
        if tag_name == 'host-ip':
            host_ip = tag.text
        elif tag_name == 'hostname':
            hostname = tag.text

    for item in report_host.findall('.//ReportItem'):
        sev_num = int(item.get('severity', '0'))

        if sev_num == 0:
            nessus_info_count += 1
            continue  # Skip informational

        plugin_id = item.get('pluginID', '')
        plugin_name = item.get('pluginName', '')
        port = item.get('port', '0')
        protocol = item.get('protocol', 'tcp')
        severity = NESSUS_SEV_MAP.get(sev_num, 'Medium')

        raw_desc = (item.findtext('description', '') or '').strip()
        raw_solution = (item.findtext('solution', '') or '').strip()
        risk_factor = (item.findtext('risk_factor', '') or '').strip()
        cvss3 = item.findtext('cvss3_base_score', '')
        cvss2 = item.findtext('cvss_base_score', '')
        cvss = cvss3 or cvss2 or ''
        cves = [cve.text for cve in item.findall('cve') if cve.text]
        cve_str = ', '.join(cves) if cves else ''
        see_also = (item.findtext('see_also', '') or '').strip()

        # Build description (3-5 sentences)
        desc = f"A {severity.lower()} severity vulnerability '{plugin_name}' (Plugin ID: {plugin_id}) was identified on {host_ip}"
        if port and port not in ('0', ''):
            desc += f" port {port}/{protocol}"
        desc += ". "

        if raw_desc:
            # Truncate raw description to fit 3-5 sentence target
            truncated = raw_desc[:600]
            last_period = truncated.rfind('.')
            if last_period > 300:
                truncated = truncated[:last_period + 1]
            else:
                truncated += "..."
            desc += truncated + " "

        if cve_str:
            desc += f"This vulnerability is tracked as {cve_str}. "
        if cvss:
            desc += f"CVSS Score: {cvss}. "
        if not cve_str and not cvss:
            desc += "Consult the Nessus plugin documentation for detailed technical analysis. "

        # Build recommendation (3-5 sentences)
        if raw_solution and raw_solution.lower() != 'n/a':
            sol_truncated = raw_solution[:400]
            last_period = sol_truncated.rfind('.')
            if last_period > 200:
                sol_truncated = sol_truncated[:last_period + 1]
            else:
                sol_truncated += "..."
            rec = sol_truncated + " "
        else:
            rec = f"Apply vendor-recommended patches or configuration changes to remediate '{plugin_name}' on {host_ip}. "

        rec += "Verify remediation by re-scanning with Nessus after applying fixes. "
        rec += f"Priority: {severity} - address according to organizational vulnerability management SLAs. "
        if see_also and len(see_also) < 300:
            first_ref = see_also.split('\n')[0].strip()
            if first_ref:
                rec += f"Reference: {first_ref}"

        finding = {
            'Category': 'Network Security',
            'Tab': 'EXTERNAL_VULNERABILITIES',
            'Priority': severity,
            'Item': f"Nessus: {plugin_name} - {host_ip}:{port}/{protocol}",
            'Description': desc,
            'Recommendation': rec,
            'Tracking_Status': 'OPEN',
            'Avg_Risk': '',
            'Vuln_Type': f'NESSUS_{plugin_id}',
            'Asset': host_ip,
            'Plugin_Name': plugin_name,
        }
        nessus_findings.append(finding)

print(f"Nessus hosts scanned: {hosts_processed}")
print(f"Nessus findings (non-info): {len(nessus_findings)}")
print(f"Nessus informational skipped: {nessus_info_count}")

# Severity breakdown
nessus_sev = Counter(f['Priority'] for f in nessus_findings)
for sev in ['Critical', 'High', 'Medium', 'Low']:
    print(f"  {sev}: {nessus_sev.get(sev, 0)}")


# ============================================================================
# PARSE BURP HTML FILE → STANDALONE FINDINGS
# ============================================================================
print("\n" + "=" * 70)
print("PARSING BURP HTML FILE AS STANDALONE FINDINGS")
print("=" * 70)

burp_findings = []
burp_info_count = 0

print("Loading Burp HTML (this may take a moment for large files)...")
with open(BURP_FILE, 'r', errors='replace') as f:
    content = f.read()

# Burp HTML structure:
#   <span class="BODH0" id="N">N. <a href="...">Issue Type Name</a></span>
#     - followed by: h2 "Issue background", h2 "Issue remediation" (shared for all instances)
#   <span class="BODH1" id="N.M">N.M. URL_TOKEN [param]</span>
#     - followed by: h2 "Summary" (table with Severity/Confidence/Host/Path)
#     - h2 "Issue detail" (instance-specific detail)
#     - h2 "Request" / h2 "Response"

# Step 1: Parse BODH0 spans to get issue type names, background, and remediation
print("Parsing issue types (BODH0 sections)...")

# Use regex on raw HTML for speed on this 39MB file
bodh0_pattern = re.compile(
    r'<span\s+class="BODH0"\s+id="(\d+)"[^>]*>\d+\.\s*(?:<a[^>]*>)?(.*?)(?:</a>)?</span>',
    re.DOTALL
)
bodh0_matches = bodh0_pattern.findall(content)

issue_types = {}  # id -> {name, background, remediation}
for type_id, raw_name in bodh0_matches:
    # Clean HTML tags from name
    name = re.sub(r'<[^>]+>', '', raw_name).strip()
    issue_types[type_id] = {'name': name, 'background': '', 'remediation': ''}

print(f"Issue types found: {len(issue_types)}")

# For each BODH0, extract the "Issue background" and "Issue remediation" text
# These appear between the BODH0 and the first BODH1 under it
for type_id in issue_types:
    # Find the BODH0 section in the HTML
    bodh0_marker = f'id="{type_id}"'
    bodh0_idx = content.find(f'class="BODH0" {bodh0_marker}')
    if bodh0_idx < 0:
        continue

    # Find the first BODH1 under this type (limits our search scope)
    first_instance_marker = f'class="BODH1" id="{type_id}.'
    end_idx = content.find(first_instance_marker, bodh0_idx)
    if end_idx < 0:
        # Some types may have no instances (e.g., "Web cache poisoning" just has a type-level description)
        next_bodh0 = content.find('class="BODH0"', bodh0_idx + 50)
        end_idx = next_bodh0 if next_bodh0 > 0 else bodh0_idx + 10000

    section = content[bodh0_idx:end_idx]

    # Extract background
    bg_match = re.search(
        r'<h2>Issue background</h2>\s*<span[^>]*>(.*?)</span>',
        section, re.DOTALL
    )
    if bg_match:
        bg_text = re.sub(r'<[^>]+>', ' ', bg_match.group(1)).strip()
        bg_text = re.sub(r'\s+', ' ', bg_text)
        issue_types[type_id]['background'] = bg_text[:600]

    # Extract remediation
    rem_match = re.search(
        r'<h2>Issue remediation</h2>\s*<span[^>]*>(.*?)</span>',
        section, re.DOTALL
    )
    if rem_match:
        rem_text = re.sub(r'<[^>]+>', ' ', rem_match.group(1)).strip()
        rem_text = re.sub(r'\s+', ' ', rem_text)
        issue_types[type_id]['remediation'] = rem_text[:600]

for tid, info in sorted(issue_types.items(), key=lambda x: int(x[0])):
    print(f"  {tid}. {info['name']}")

# Step 2: Parse BODH1 spans to get individual instances with severity
print(f"\nParsing issue instances (BODH1 sections)...")

# Find all summary tables (one per instance) - each has severity, confidence, host, path
# Pattern: BODH1 span, then h2 Summary, then summary_table
bodh1_pattern = re.compile(
    r'<span\s+class="BODH1"\s+id="(\d+)\.(\d+)"[^>]*>(.*?)</span>',
    re.DOTALL
)
bodh1_matches = bodh1_pattern.findall(content)
print(f"Instance sections found: {len(bodh1_matches)}")

# For each instance, extract severity from the Summary table
for type_id, instance_num, instance_text in bodh1_matches:
    # Find the issue type this belongs to
    if type_id not in issue_types:
        continue

    issue_name = issue_types[type_id]['name']
    issue_bg = issue_types[type_id]['background']
    issue_rem = issue_types[type_id]['remediation']

    # Find this instance's Summary table in the HTML
    instance_id = f'{type_id}.{instance_num}'
    instance_marker = f'id="{instance_id}"'
    inst_idx = content.find(f'class="BODH1" {instance_marker}')
    if inst_idx < 0:
        continue

    # Limit search scope to next BODH1 or BODH0
    next_bodh = content.find('class="BODH1"', inst_idx + 50)
    next_bodh0 = content.find('class="BODH0"', inst_idx + 50)
    if next_bodh > 0 and (next_bodh0 < 0 or next_bodh < next_bodh0):
        scope_end = next_bodh
    elif next_bodh0 > 0:
        scope_end = next_bodh0
    else:
        scope_end = inst_idx + 50000

    inst_section = content[inst_idx:scope_end]

    # Extract severity from summary table
    sev_match = re.search(r'Severity:\s*</td>\s*<td><b>(.*?)</b>', inst_section)
    severity = sev_match.group(1).strip() if sev_match else ''

    # Extract confidence
    conf_match = re.search(r'Confidence:\s*</td>\s*<td><b>(.*?)</b>', inst_section)
    confidence = conf_match.group(1).strip() if conf_match else ''

    # Extract host
    host_match = re.search(r'Host:\s*</td>\s*<td><b>(.*?)</b>', inst_section)
    host = host_match.group(1).strip() if host_match else ''

    # Extract path
    path_match = re.search(r'Path:\s*</td>\s*<td><b>(.*?)</b>', inst_section)
    path = path_match.group(1).strip() if path_match else ''

    url = host + path if host else path

    # Extract instance-specific "Issue detail"
    detail_match = re.search(
        r'<h2>Issue detail</h2>\s*<span[^>]*>(.*?)</span>',
        inst_section, re.DOTALL
    )
    issue_detail = ''
    if detail_match:
        issue_detail = re.sub(r'<[^>]+>', ' ', detail_match.group(1)).strip()
        issue_detail = re.sub(r'\s+', ' ', issue_detail)[:600]

    # Normalize severity
    if not severity:
        severity = 'Medium'

    sev_lower = severity.lower()
    if 'high' in sev_lower:
        norm_sev = 'High'
    elif 'medium' in sev_lower:
        norm_sev = 'Medium'
    elif 'low' in sev_lower:
        norm_sev = 'Low'
    elif 'info' in sev_lower:
        burp_info_count += 1
        continue  # Skip informational
    else:
        norm_sev = 'Medium'

    # Build description (3-5 sentences)
    desc = f"A {norm_sev.lower()} severity web application vulnerability '{issue_name}' was identified"
    if url:
        desc += f" at {url}"
    desc += ". "
    if issue_detail:
        desc += issue_detail[:400] + " "
    elif issue_bg:
        desc += issue_bg[:400] + " "
    else:
        desc += "This vulnerability was detected by Burp Suite during web application security testing. "
    desc += f"Confidence: {confidence}. " if confidence else "Further manual verification may be needed. "
    desc += f"Exploitation of this issue could lead to data exposure, session compromise, or unauthorized access."

    # Build recommendation (3-5 sentences)
    rec = ''
    if issue_rem:
        rec += issue_rem[:400] + " "
    else:
        rec += f"Remediate the '{issue_name}' vulnerability according to OWASP guidelines. "
    rec += "Implement web application firewall (WAF) rules as an interim mitigation. "
    rec += f"Verify remediation through targeted re-testing with Burp Suite. "
    rec += f"Priority: {norm_sev} - address per organizational web security SLAs."

    finding = {
        'Category': 'Web App Security',
        'Tab': 'WEBAPP_VULNERABILITIES',
        'Priority': norm_sev,
        'Item': f"Burp: {issue_name[:80]} - {url[:60]}",
        'Description': desc,
        'Recommendation': rec,
        'Tracking_Status': 'OPEN',
        'Avg_Risk': '',
        'Vuln_Type': f"BURP_{issue_name[:50].replace(' ', '_').upper()}",
        'Asset': url[:200] if url else 'Web Application',
        'Plugin_Name': issue_name[:100],
    }
    burp_findings.append(finding)

print(f"Burp findings (non-info): {len(burp_findings)}")
print(f"Burp informational skipped: {burp_info_count}")

burp_sev = Counter(f['Priority'] for f in burp_findings)
for sev in ['Critical', 'High', 'Medium', 'Low']:
    print(f"  {sev}: {burp_sev.get(sev, 0)}")

# Show unique issue types
burp_types = Counter(f['Plugin_Name'] for f in burp_findings)
print(f"\nUnique Burp issue types: {len(burp_types)}")
for vtype, count in burp_types.most_common(15):
    print(f"  {vtype}: {count}")


# ============================================================================
# MERGE INTO EXISTING GROUP FINDINGS
# ============================================================================
print("\n" + "=" * 70)
print("MERGING NESSUS/BURP FINDINGS INTO GROUP OUTPUTS")
print("=" * 70)

# Load existing GROUP 1 findings and append Nessus
g1_path = os.path.join(OUTPUT_DIR, 'findings_GROUP1_FULL_CONSOLIDATED.csv')
existing_g1 = []
with open(g1_path, 'r') as f:
    reader = csv.DictReader(f)
    existing_g1 = list(reader)
print(f"Existing GROUP 1 findings: {len(existing_g1)}")

# Consolidate Nessus findings by plugin
nessus_by_plugin = defaultdict(list)
for f in nessus_findings:
    nessus_by_plugin[(f['Plugin_Name'], f['Priority'])].append(f)

nessus_consolidated = []
for (plugin_name, sev), findings in nessus_by_plugin.items():
    if len(findings) == 1:
        nessus_consolidated.append(findings[0])
    else:
        assets = list(set(f['Asset'] for f in findings))
        asset_list = ", ".join(assets[:5])
        if len(assets) > 5:
            asset_list += f", and {len(assets)-5} more"

        desc = (f"Nessus vulnerability '{plugin_name}' ({sev}) found on {len(findings)} instances across {len(assets)} hosts: {asset_list}. "
                + findings[0]['Description'].split('. ', 1)[-1] if '. ' in findings[0]['Description'] else findings[0]['Description'])

        consolidated = {
            'Category': 'Network Security',
            'Tab': 'EXTERNAL_VULNERABILITIES',
            'Priority': sev,
            'Item': f"Nessus: {plugin_name} - {len(findings)} instances across {len(assets)} hosts",
            'Description': desc[:2000],
            'Recommendation': findings[0]['Recommendation'],
            'Tracking_Status': 'OPEN',
            'Avg_Risk': '',
        }
        nessus_consolidated.append(consolidated)

        # Detail file
        detail_data = [{'Instance': i+1, 'Asset': f['Asset'], 'Details': f['Item'],
                       'Description': f['Description'][:500], 'Tracking_Status': 'OPEN', 'FP_Status': 'Verified'}
                      for i, f in enumerate(findings)]
        plugin_safe = re.sub(r'[^\w]', '_', plugin_name)[:50]
        detail_file = os.path.join(DETAILS_DIR, f'findings_detail_NESSUS_{plugin_safe}.csv')
        with open(detail_file, 'w', newline='') as csvf:
            w = csv.DictWriter(csvf, fieldnames=detail_data[0].keys())
            w.writeheader()
            w.writerows(detail_data)

print(f"Nessus consolidated: {len(nessus_findings)} -> {len(nessus_consolidated)} findings")

# Merge and save GROUP 1
merged_g1 = existing_g1 + nessus_consolidated
with open(g1_path, 'w', newline='') as f:
    w = csv.DictWriter(f, fieldnames=OUTPUT_FIELDS, extrasaction='ignore')
    w.writeheader()
    w.writerows(merged_g1)
print(f"Updated GROUP 1: {len(merged_g1)} findings (was {len(existing_g1)}, added {len(nessus_consolidated)} from Nessus)")


# Load existing GROUP 2 findings and append Burp
g2_path = os.path.join(OUTPUT_DIR, 'findings_GROUP2_FULL_CONSOLIDATED.csv')
existing_g2 = []
with open(g2_path, 'r') as f:
    reader = csv.DictReader(f)
    existing_g2 = list(reader)
print(f"\nExisting GROUP 2 findings: {len(existing_g2)}")

# Consolidate Burp findings by issue type
burp_by_type = defaultdict(list)
for f in burp_findings:
    burp_by_type[(f['Plugin_Name'], f['Priority'])].append(f)

burp_consolidated = []
for (issue_type, sev), findings in burp_by_type.items():
    if len(findings) == 1:
        burp_consolidated.append(findings[0])
    else:
        assets = list(set(f['Asset'] for f in findings if f['Asset']))
        asset_list = ", ".join(assets[:3])
        if len(assets) > 3:
            asset_list += f", and {len(assets)-3} more"

        desc = (f"Burp Suite identified '{issue_type}' ({sev}) on {len(findings)} instances"
                + (f" across URLs: {asset_list}" if assets else "") + ". "
                + findings[0]['Description'].split('. ', 1)[-1] if '. ' in findings[0]['Description'] else findings[0]['Description'])

        consolidated = {
            'Category': 'Web App Security',
            'Tab': 'WEBAPP_VULNERABILITIES',
            'Priority': sev,
            'Item': f"Burp: {issue_type[:80]} - {len(findings)} instances",
            'Description': desc[:2000],
            'Recommendation': findings[0]['Recommendation'],
            'Tracking_Status': 'OPEN',
            'Avg_Risk': '',
        }
        burp_consolidated.append(consolidated)

        # Detail file
        detail_data = [{'Instance': i+1, 'Asset': f['Asset'], 'Details': f['Item'],
                       'Description': f['Description'][:500], 'Tracking_Status': 'OPEN', 'FP_Status': 'Verified'}
                      for i, f in enumerate(findings)]
        type_safe = re.sub(r'[^\w]', '_', issue_type)[:50]
        detail_file = os.path.join(DETAILS_DIR, f'findings_detail_BURP_{type_safe}.csv')
        with open(detail_file, 'w', newline='') as csvf:
            w = csv.DictWriter(csvf, fieldnames=detail_data[0].keys())
            w.writeheader()
            w.writerows(detail_data)

print(f"Burp consolidated: {len(burp_findings)} -> {len(burp_consolidated)} findings")

# Merge and save GROUP 2
merged_g2 = existing_g2 + burp_consolidated
with open(g2_path, 'w', newline='') as f:
    w = csv.DictWriter(f, fieldnames=OUTPUT_FIELDS, extrasaction='ignore')
    w.writeheader()
    w.writerows(merged_g2)
print(f"Updated GROUP 2: {len(merged_g2)} findings (was {len(existing_g2)}, added {len(burp_consolidated)} from Burp)")


# ============================================================================
# SUMMARY
# ============================================================================
print("\n" + "=" * 70)
print("NESSUS/BURP INJECTION COMPLETE")
print("=" * 70)
print(f"  Nessus → GROUP 1: +{len(nessus_consolidated)} findings ({len(nessus_findings)} raw)")
print(f"  Burp → GROUP 2: +{len(burp_consolidated)} findings ({len(burp_findings)} raw)")
print(f"\n  GROUP 1 total: {len(merged_g1)} findings")
print(f"  GROUP 2 total: {len(merged_g2)} findings")
print(f"\n  Now re-run final_consolidation.py to update the master output.")
