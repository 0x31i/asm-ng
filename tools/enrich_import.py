#!/usr/bin/env python3
"""
ASM-NG Finding Enrichment Import

Imports Claude-generated enrichment notes and writes them as analyst
row notes in the database. Notes appear in DATA/TYPE views immediately.

Usage:
    python3 tools/enrich_import.py --scan-id <GUID> --dir ~/Downloads/enrich
    python3 tools/enrich_import.py --scan-id <GUID> --file ~/Downloads/enrich/enrichments.json

Options:
    --dry-run       Preview what would be imported without writing to DB
    --overwrite     Overwrite existing analyst notes (default: skip)
    --prefix        Prefix notes with [AI] tag (default: yes)
    --no-prefix     Don't prefix notes with [AI] tag
"""

import argparse
import json
import os
import sys
import time

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from spiderfoot.db import SpiderFootDb


AI_NOTE_PREFIX = "[AI] "


def get_db():
    """Initialize database connection."""
    db_url = os.environ.get('ASMNG_DATABASE_URL')
    if not db_url:
        print("ERROR: ASMNG_DATABASE_URL environment variable not set.")
        print("Example: export ASMNG_DATABASE_URL='postgresql://user:pass@localhost/asmng'")
        sys.exit(1)
    return SpiderFootDb({"__database": db_url})


def import_enrichments(scan_id, enrichments_path, dry_run=False,
                       overwrite=False, prefix=True):
    """Import enrichment notes into the database as row notes."""

    # Load enrichments
    if not os.path.isfile(enrichments_path):
        print(f"ERROR: File not found: {enrichments_path}")
        sys.exit(1)

    with open(enrichments_path, 'r', encoding='utf-8') as f:
        data = json.load(f)

    if not isinstance(data, dict) or "enrichments" not in data:
        print("ERROR: Invalid enrichments.json — missing 'enrichments' array")
        sys.exit(1)

    enrichments = data["enrichments"]
    if not enrichments:
        print("No enrichments to import.")
        return

    file_scan_id = data.get("scan_id", "")
    if file_scan_id and file_scan_id != scan_id:
        print(f"WARNING: File scan_id '{file_scan_id[:8]}...' doesn't match --scan-id '{scan_id[:8]}...'")
        resp = input("Continue anyway? [y/N] ")
        if resp.lower() != 'y':
            sys.exit(0)

    print(f"Enrichments to process: {len(enrichments)}")

    db = get_db()

    # Get scan target
    scan_info = db.scanInstanceGet(scan_id)
    if not scan_info:
        print(f"ERROR: Scan '{scan_id}' not found.")
        sys.exit(1)

    target = scan_info[1]  # seed_target
    print(f"Target: {target}")

    # Load existing notes to check for conflicts
    existing_notes = db.rowNotesForTarget(target)
    print(f"Existing analyst notes: {len(existing_notes)}")

    # Process enrichments
    stats = {
        "written": 0,
        "skipped_existing": 0,
        "skipped_empty": 0,
        "overwritten": 0,
        "errors": 0,
    }

    for i, enrichment in enumerate(enrichments):
        event_type = enrichment.get("type", "")
        event_data = enrichment.get("data", "")
        source_data = enrichment.get("source", "")
        note = enrichment.get("note", "").strip()

        if not note:
            stats["skipped_empty"] += 1
            continue

        if not event_type or not event_data:
            print(f"  WARN: Entry {i} missing type or data, skipping")
            stats["errors"] += 1
            continue

        # Check for existing note
        key = (event_type, event_data, source_data if source_data else None)
        has_existing = key in existing_notes

        if has_existing and not overwrite:
            existing_text = existing_notes[key]
            # If the existing note is already an AI note, we can update it
            if existing_text.startswith(AI_NOTE_PREFIX):
                pass  # Allow overwriting AI-generated notes
            else:
                stats["skipped_existing"] += 1
                continue

        # Add prefix
        if prefix:
            note_text = AI_NOTE_PREFIX + note
        else:
            note_text = note

        if dry_run:
            label = "OVERWRITE" if has_existing else "WRITE"
            print(f"  [{label}] {event_type}: {event_data[:60]}...")
            print(f"          Note: {note_text[:80]}...")
        else:
            try:
                db.rowNoteSet(target, event_type, event_data,
                              source_data if source_data else None,
                              note_text)
                if has_existing:
                    stats["overwritten"] += 1
                else:
                    stats["written"] += 1
            except Exception as e:
                print(f"  ERROR writing note for {event_type}/{event_data[:40]}: {e}")
                stats["errors"] += 1

    # Summary
    print()
    print("=" * 60)
    if dry_run:
        print("DRY RUN COMPLETE (no changes written)")
    else:
        print("IMPORT COMPLETE")
    print("=" * 60)
    print(f"  Written:           {stats['written']}")
    print(f"  Overwritten (AI):  {stats['overwritten']}")
    print(f"  Skipped (manual):  {stats['skipped_existing']}")
    print(f"  Skipped (empty):   {stats['skipped_empty']}")
    print(f"  Errors:            {stats['errors']}")

    if not dry_run and (stats['written'] > 0 or stats['overwritten'] > 0):
        print()
        print("Enrichment notes are now visible in the DATA/TYPE views.")
        print("Look for the note icon on each row.")


def main():
    parser = argparse.ArgumentParser(
        description="Import Claude enrichment notes as row notes in ASM-NG"
    )
    parser.add_argument(
        "--scan-id", required=True,
        help="Scan instance GUID"
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--dir",
        help="Directory containing enrichments.json"
    )
    group.add_argument(
        "--file",
        help="Path to enrichments.json directly"
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Preview import without writing to database"
    )
    parser.add_argument(
        "--overwrite", action="store_true",
        help="Overwrite existing manual analyst notes (default: skip them)"
    )
    parser.add_argument(
        "--prefix", action="store_true", default=True,
        help="Prefix notes with [AI] tag (default)"
    )
    parser.add_argument(
        "--no-prefix", action="store_true",
        help="Don't prefix notes with [AI] tag"
    )
    args = parser.parse_args()

    if args.dir:
        enrichments_path = os.path.join(args.dir, "enrichments.json")
    else:
        enrichments_path = args.file

    use_prefix = args.prefix and not args.no_prefix

    import_enrichments(
        scan_id=args.scan_id,
        enrichments_path=enrichments_path,
        dry_run=args.dry_run,
        overwrite=args.overwrite,
        prefix=use_prefix,
    )


if __name__ == "__main__":
    main()
