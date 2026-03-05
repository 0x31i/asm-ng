# -*- coding: utf-8 -*-
# -----------------------------------------------------------------
# Name:         triage_prompt
# Purpose:      AI triage export/import logic for Claude Code
# -----------------------------------------------------------------

import json
import time

TRIAGE_VERSION = "1.0"

TRIAGE_INSTRUCTIONS = {
    "overview": (
        "You are an attack surface management analyst reviewing OSINT scan results. "
        "Classify each result as FP (false positive / noise), LEGIT (confirmed associated "
        "with target), or REVIEW (uncertain, needs human analyst). "
        "The known_assets section is CLIENT-PROVIDED GROUND TRUTH -- treat it as authoritative."
    ),
    "memory": (
        "Create and maintain a file called triage_context_{scan_id}.md in the same directory "
        "as this triage file. This is your working memory. Pre-populate it with the known_assets "
        "data, then update it as you discover patterns. READ this file before processing each "
        "batch of results. UPDATE it with every new pattern you discover. This ensures "
        "consistency across the entire triage session even as earlier context gets compressed."
    ),
    "known_assets_usage": [
        "known_assets is the client-provided ground truth -- treat it as authoritative",
        "Any result matching a known domain or subdomain of a known domain -> LEGIT",
        "Any IP within a known CIDR range or exact match -> LEGIT",
        "Any email matching known employees or on a known domain -> LEGIT",
        "Employee names found in WHOIS/LinkedIn for client domains -> LEGIT",
        "Employee names on UNRELATED domains/orgs -> FP (name collision)",
        "Results that are 1 hop from a known asset deserve closer scrutiny before marking FP",
        "Unknown assets that LOOK related but aren't in the known list -> REVIEW (not auto-LEGIT)",
    ],
    "output_format": (
        "Write your classifications to a file called triage_output_{scan_id}.json in the same "
        "directory. The file must have this exact JSON structure:\n"
        '{{\n'
        '  "triage_version": "1.0",\n'
        '  "scan_id": "<scan_id>",\n'
        '  "classifications": [\n'
        '    {{"id": "<result hash>", "class": "FP|LEGIT|REVIEW", "reason": "brief reason"}}\n'
        '  ]\n'
        '}}'
    ),
    "rules": [
        "Subdomains of known domains are LEGIT unless parked/default page",
        "CO_HOSTED_SITE on shared infrastructure (Cloudflare, AWS, etc.) with no org link = FP",
        "AFFILIATE_* results from shared hosting IPs with no whois/org match = FP",
        "sfp_dnsneighbor results on large shared hosting blocks = FP",
        "sfp_similar results with zero DNS/content overlap = FP",
        "Generic CDN/cloud IPs (Cloudflare, Akamai, Fastly, AWS CloudFront) = FP unless in known ranges",
        "SPF/DKIM includes for major providers (google, microsoft, sendgrid) = LEGIT infrastructure",
        "When uncertain, classify as REVIEW -- never guess FP on ambiguous results",
        "Record every pattern you discover in your context file for consistency",
    ],
}


def build_triage_export(scan_id, scan_name, scan_target, seed_targets,
                        known_assets, results, event_types=None):
    """Build the triage export JSON package.

    Args:
        scan_id (str): scan instance GUID
        scan_name (str): human-readable scan name
        scan_target (str): primary scan target
        seed_targets (list): all seed targets for the scan
        known_assets (dict): known assets grouped by type from knownAssetValues()
        results (list): scan result tuples from scanResultEvent()
        event_types (dict): optional mapping of event type -> description

    Returns:
        dict: triage package ready for json.dumps()
    """
    # Convert known asset sets to sorted lists for JSON serialization
    known_assets_serializable = {}
    for atype, values in known_assets.items():
        if values:
            known_assets_serializable[atype] = sorted(values)

    # Format results for export
    formatted_results = []
    for row in results:
        # Row format from scanResultEvent:
        # 0=generated, 1=data, 2=source_data, 3=module, 4=type,
        # 5=confidence, 6=visibility, 7=risk, 8=hash,
        # 9=source_event_hash, 10=event_descr, 11=event_type,
        # 12=scan_instance_id, 13=false_positive, 14=parent_fp,
        # 15=imported_from_scan, 16=tracking
        formatted_results.append({
            "id": row[8],               # hash (unique identifier)
            "module": row[3],           # generating module
            "type": row[4],             # event type code
            "type_name": row[10] if len(row) > 10 else "",  # human-readable type
            "data": row[1],             # the actual finding
            "source": row[2],           # what triggered this result
            "source_hash": row[9],      # source event hash for chain tracing
            "confidence": row[5],       # module confidence 0-100
            "visibility": row[6],       # visibility 0-100
            "risk": row[7],             # risk 0-100
            "fp_status": row[13],       # current FP flag (0=unreviewed, 1=FP, 2=validated)
        })

    instructions = dict(TRIAGE_INSTRUCTIONS)
    # Substitute scan_id into memory/output instructions
    instructions["memory"] = instructions["memory"].replace("{scan_id}", scan_id[:8])
    instructions["output_format"] = instructions["output_format"].replace("{scan_id}", scan_id[:8])

    package = {
        "triage_version": TRIAGE_VERSION,
        "scan_id": scan_id,
        "scan_name": scan_name,
        "scan_target": scan_target,
        "seed_targets": seed_targets if isinstance(seed_targets, list) else [seed_targets],
        "exported_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "known_assets": known_assets_serializable,
        "instructions": instructions,
        "total_results": len(formatted_results),
        "results": formatted_results,
    }

    return package


def parse_triage_import(data):
    """Parse a triage import JSON file and validate its structure.

    Args:
        data (str or dict): JSON string or already-parsed dict

    Returns:
        dict: {
            'scan_id': str,
            'classifications': {hash: {'class': str, 'reason': str}},
            'counts': {'FP': int, 'LEGIT': int, 'REVIEW': int},
            'errors': list of str
        }

    Raises:
        ValueError: if the data is not valid triage output
    """
    if isinstance(data, str):
        try:
            data = json.loads(data)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON: {e}") from e

    if not isinstance(data, dict):
        raise ValueError("Triage import must be a JSON object")

    if "triage_version" not in data:
        raise ValueError("Missing triage_version field")

    if "scan_id" not in data:
        raise ValueError("Missing scan_id field")

    if "classifications" not in data or not isinstance(data["classifications"], list):
        raise ValueError("Missing or invalid classifications array")

    valid_classes = {"FP", "LEGIT", "REVIEW"}
    classifications = {}
    counts = {"FP": 0, "LEGIT": 0, "REVIEW": 0}
    errors = []

    for i, entry in enumerate(data["classifications"]):
        if not isinstance(entry, dict):
            errors.append(f"Entry {i}: not an object")
            continue
        if "id" not in entry:
            errors.append(f"Entry {i}: missing id field")
            continue
        if "class" not in entry or entry["class"] not in valid_classes:
            errors.append(f"Entry {i} (id={entry.get('id', '?')}): invalid class '{entry.get('class')}'")
            continue

        cls = entry["class"]
        classifications[entry["id"]] = {
            "class": cls,
            "reason": entry.get("reason", ""),
        }
        counts[cls] += 1

    return {
        "scan_id": data["scan_id"],
        "classifications": classifications,
        "counts": counts,
        "errors": errors,
    }
