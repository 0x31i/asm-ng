#!/usr/bin/env python3
"""
ASM-NG Finding Enrichment Export

Exports scan findings as a structured prompt for Claude Code to enrich
with security analysis, context, and remediation recommendations.

Usage:
    python3 tools/enrich_export.py --scan-id <GUID> [--output-dir ~/Downloads/enrich]

The export creates a directory with:
    prompt.md          — The full enrichment prompt for Claude Code
    findings.json      — Raw findings data (Claude reads this)
    context.json       — Known assets + grade data (Claude reads this)
    README.md          — Instructions for running the enrichment

After Claude processes the prompt, it writes:
    enrichments.json   — Structured enrichment output

Then import with:
    python3 tools/enrich_import.py --scan-id <GUID> --dir ~/Downloads/enrich
"""

import argparse
import json
import os
import sys
import time

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from spiderfoot.db import SpiderFootDb


DEFAULT_OUTPUT_DIR = os.path.expanduser("~/Downloads/enrich")

ENRICHMENT_SYSTEM_PROMPT = """\
# ASM-NG Finding Enrichment

You are a senior attack surface management analyst enriching OSINT scan findings
with security context. For each finding, write a concise analyst note that helps
a junior analyst or client understand:

1. **What it is** — plain-English explanation of the finding
2. **Why it matters** — security implications specific to THIS target
3. **Context** — how it relates to other findings in the same scan
4. **Risk assessment** — realistic severity (not everything is critical)
5. **Remediation** — concrete, actionable fix (not generic advice)

## Rules

- Be concise. 2-4 sentences per finding. No filler.
- Reference other findings when relevant ("This host also exposes port 27017...")
- For informational findings (DNS records, WHOIS data, etc.), keep it to 1 sentence
- For critical findings (open ports, leaked creds, unauth endpoints), be thorough
- Use the known_assets to distinguish client infrastructure from third-party
- If a finding is almost certainly noise/FP, say so ("Likely FP: shared hosting IP")
- Write in second person ("Your staging server..." not "The target's staging server...")

## Output Format

Read `findings.json` and `context.json` from this directory.

Write your output to `enrichments.json` in this directory with this exact structure:

```json
{
  "enrichment_version": "1.0",
  "scan_id": "<from context.json>",
  "enrichments": [
    {
      "type": "EVENT_TYPE",
      "data": "the exact event data value",
      "source": "the exact source data value",
      "note": "Your enrichment note here"
    }
  ]
}
```

**IMPORTANT**: The `type`, `data`, and `source` fields must match the finding EXACTLY
(they are used as keys to store the note). Copy them verbatim from findings.json.

## Batching

If there are too many findings to process at once, process them in batches.
Write ALL enrichments to a single `enrichments.json` file when done.
It's fine to skip truly trivial findings (ROOT events, basic DNS lookups)
but err on the side of including rather than skipping.
"""


def get_db():
    """Initialize database connection."""
    db_url = os.environ.get('ASMNG_DATABASE_URL')
    if not db_url:
        print("ERROR: ASMNG_DATABASE_URL environment variable not set.")
        print("Example: export ASMNG_DATABASE_URL='postgresql://user:pass@localhost/asmng'")
        sys.exit(1)
    return SpiderFootDb({"__database": db_url})


def export_scan(scan_id, output_dir):
    """Export scan findings for Claude enrichment."""
    db = get_db()

    # Get scan metadata
    scan_info = db.scanInstanceGet(scan_id)
    if not scan_info:
        print(f"ERROR: Scan '{scan_id}' not found.")
        sys.exit(1)

    scan_name = scan_info[0]
    scan_target = scan_info[1]
    scan_status = scan_info[5]

    print(f"Scan: {scan_name}")
    print(f"Target: {scan_target}")
    print(f"Status: {scan_status}")

    if scan_status not in ('FINISHED', 'ABORTED', 'ERROR-FAILED'):
        print(f"WARNING: Scan status is '{scan_status}' — results may be incomplete.")

    # Get all scan results
    results = db.scanResultEvent(scan_id, eventType='ALL')
    if not results:
        print("ERROR: No results found for this scan.")
        sys.exit(1)

    print(f"Total findings: {len(results)}")

    # Get known assets for context
    known_assets = db.knownAssetValues(scan_target)
    known_assets_serial = {}
    for atype, values in known_assets.items():
        if values:
            known_assets_serial[atype] = sorted(values)

    # Get existing row notes (so we don't overwrite manual analyst notes)
    existing_notes = db.rowNotesForTarget(scan_target)
    existing_count = len(existing_notes)
    if existing_count > 0:
        print(f"Existing analyst notes: {existing_count} (will be preserved)")

    # Build findings list
    # Group by event type for Claude to process efficiently
    findings_by_type = {}
    skipped_root = 0

    for row in results:
        # Row format from scanResultEvent:
        # 0=generated, 1=data, 2=source_data, 3=module, 4=type,
        # 5=confidence, 6=visibility, 7=risk, 8=hash,
        # 9=source_event_hash, 10=event_descr, 11=event_type,
        # 12=scan_instance_id, 13=false_positive, 14=parent_fp,
        # 15=imported_from_scan, 16=tracking
        event_type = row[4]

        # Skip ROOT events — they're just the seed target
        if event_type == 'ROOT':
            skipped_root += 1
            continue

        finding = {
            "type": event_type,
            "type_name": row[10] if len(row) > 10 else event_type,
            "data": row[1],
            "source": row[2],
            "module": row[3],
            "confidence": row[5],
            "visibility": row[6],
            "risk": row[7],
            "fp_status": row[13],  # 0=unreviewed, 1=FP, 2=validated
            "has_existing_note": (event_type, row[1], row[2]) in existing_notes,
        }

        if event_type not in findings_by_type:
            findings_by_type[event_type] = {
                "type_name": finding["type_name"],
                "count": 0,
                "findings": [],
            }
        findings_by_type[event_type]["count"] += 1
        findings_by_type[event_type]["findings"].append(finding)

    total_findings = sum(g["count"] for g in findings_by_type.values())
    print(f"Enrichable findings: {total_findings} ({len(findings_by_type)} types, skipped {skipped_root} ROOT events)")

    # Build context
    context = {
        "scan_id": scan_id,
        "scan_name": scan_name,
        "scan_target": scan_target,
        "scan_status": scan_status,
        "exported_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "known_assets": known_assets_serial,
        "total_findings": total_findings,
        "type_summary": {
            t: {"type_name": g["type_name"], "count": g["count"]}
            for t, g in sorted(findings_by_type.items(), key=lambda x: -x[1]["count"])
        },
    }

    # Flatten findings for the JSON file (grouped by type for readability)
    all_findings = []
    for event_type in sorted(findings_by_type.keys()):
        group = findings_by_type[event_type]
        for f in group["findings"]:
            all_findings.append(f)

    # Create output directory
    os.makedirs(output_dir, exist_ok=True)

    # Write findings.json
    findings_path = os.path.join(output_dir, "findings.json")
    with open(findings_path, 'w', encoding='utf-8') as f:
        json.dump(all_findings, f, indent=2, ensure_ascii=False)
    print(f"Wrote: {findings_path} ({len(all_findings)} findings)")

    # Write context.json
    context_path = os.path.join(output_dir, "context.json")
    with open(context_path, 'w', encoding='utf-8') as f:
        json.dump(context, f, indent=2, ensure_ascii=False)
    print(f"Wrote: {context_path}")

    # Write prompt.md
    prompt_path = os.path.join(output_dir, "prompt.md")
    with open(prompt_path, 'w', encoding='utf-8') as f:
        f.write(ENRICHMENT_SYSTEM_PROMPT)
        f.write("\n---\n\n")
        f.write(f"## Scan Details\n\n")
        f.write(f"- **Target:** `{scan_target}`\n")
        f.write(f"- **Scan Name:** {scan_name}\n")
        f.write(f"- **Scan ID:** `{scan_id}`\n")
        f.write(f"- **Total Findings:** {total_findings}\n\n")

        if known_assets_serial:
            f.write("## Known Assets (Ground Truth)\n\n")
            for atype, values in sorted(known_assets_serial.items()):
                f.write(f"**{atype}:** {', '.join(values[:20])}")
                if len(values) > 20:
                    f.write(f" ... and {len(values) - 20} more")
                f.write("\n")
            f.write("\n")

        f.write("## Finding Summary by Type\n\n")
        f.write("| Type | Count | Description |\n")
        f.write("|------|-------|-------------|\n")
        for event_type, group in sorted(findings_by_type.items(), key=lambda x: -x[1]["count"]):
            f.write(f"| `{event_type}` | {group['count']} | {group['type_name']} |\n")
        f.write("\n")

        f.write("## Files in This Directory\n\n")
        f.write("- `findings.json` — All findings to enrich (read this)\n")
        f.write("- `context.json` — Scan metadata + known assets (read this)\n")
        f.write("- `enrichments.json` — **Write your output here**\n\n")

        f.write("## Start\n\n")
        f.write("Read `findings.json` and `context.json`, then process all findings.\n")
        f.write("Write the enrichment notes to `enrichments.json` using the format above.\n")

    print(f"Wrote: {prompt_path}")

    # Write README.md with usage instructions
    readme_path = os.path.join(output_dir, "README.md")
    with open(readme_path, 'w', encoding='utf-8') as f:
        f.write("# Enrichment Export\n\n")
        f.write(f"**Target:** {scan_target}\n")
        f.write(f"**Scan:** {scan_name}\n")
        f.write(f"**Exported:** {context['exported_at']}\n\n")
        f.write("## How to Use\n\n")
        f.write("### Step 1: Open this directory in Claude Code\n\n")
        f.write("```bash\n")
        f.write(f"cd {output_dir}\n")
        f.write("claude\n")
        f.write("```\n\n")
        f.write("### Step 2: Give Claude the prompt\n\n")
        f.write("Paste or reference `prompt.md` — Claude will read the JSON files\n")
        f.write("and write `enrichments.json` with analyst notes for every finding.\n\n")
        f.write("### Step 3: Import the enrichments\n\n")
        f.write("```bash\n")
        f.write(f"python3 tools/enrich_import.py --scan-id {scan_id} --dir {output_dir}\n")
        f.write("```\n\n")
        f.write("This writes all enrichment notes as row notes in ASM-NG.\n")
        f.write("They'll appear in the DATA/TYPE views immediately.\n")

    print(f"Wrote: {readme_path}")
    print()
    print("=" * 60)
    print("EXPORT COMPLETE")
    print("=" * 60)
    print()
    print("Next steps:")
    print(f"  1. cd {output_dir}")
    print(f"  2. claude")
    print(f"  3. Paste or reference prompt.md")
    print(f"  4. Claude writes enrichments.json")
    print(f"  5. python3 tools/enrich_import.py --scan-id {scan_id} --dir {output_dir}")


def main():
    parser = argparse.ArgumentParser(
        description="Export scan findings for Claude Code enrichment"
    )
    parser.add_argument(
        "--scan-id", required=True,
        help="Scan instance GUID"
    )
    parser.add_argument(
        "--output-dir", default=DEFAULT_OUTPUT_DIR,
        help=f"Output directory (default: {DEFAULT_OUTPUT_DIR})"
    )
    args = parser.parse_args()

    export_scan(args.scan_id, args.output_dir)


if __name__ == "__main__":
    main()
