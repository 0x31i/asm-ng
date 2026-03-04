#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
manage_ext_keys.py — Local CLI for external API key lifecycle management.

Talks directly to the database (no HTTP required).
Must be run on the ASM-NG server with ASMNG_EXT_KEY_MASTER set.

Usage:
    python manage_ext_keys.py create --name "ACME SOC" [options]
    python manage_ext_keys.py list
    python manage_ext_keys.py revoke --id <key_id>
    python manage_ext_keys.py audit  --id <key_id> [--limit 50]
    python manage_ext_keys.py reveal --id <key_id>

Examples:
    python manage_ext_keys.py create \\
        --name "ACME SOC" \\
        --targets "fhcsd.org,client2.org" \\
        --scopes "assets:read,grades:read,findings:read" \\
        --ip-allowlist "203.0.113.0/24" \\
        --rpm 60 \\
        --expires "2027-01-01"

    python manage_ext_keys.py list
    python manage_ext_keys.py revoke --id <key_id>
    python manage_ext_keys.py audit  --id <key_id> --limit 20
    python manage_ext_keys.py reveal --id <key_id>
"""

import argparse
import json
import os
import sys
import uuid
from datetime import datetime, timezone

# Ensure the repo root is in path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def _get_db():
    """Open a SpiderFootDb connection."""
    from spiderfoot import SpiderFootDb, SpiderFootHelpers
    cfg = {
        '__modules__': {},
        '__correlationrules__': [],
        '_debug': False,
        '__webaddr': '127.0.0.1',
        '__webport': '5001',
        '__database': SpiderFootHelpers.dataPath(),
        '__loglevel': 'INFO',
        '__logfile': '',
    }
    return SpiderFootDb(cfg)


def _parse_date(date_str: str) -> int:
    """Parse YYYY-MM-DD to epoch milliseconds (UTC midnight)."""
    dt = datetime.strptime(date_str, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    return int(dt.timestamp() * 1000)


def cmd_create(args):
    """Create a new external API key."""
    from spiderfoot.ext_api import generate_ext_api_key

    # Generate key triple
    try:
        raw_key, key_hash, key_encrypted = generate_ext_api_key()
    except RuntimeError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)

    key_id = str(uuid.uuid4())

    # Parse arguments
    scopes = [s.strip() for s in (args.scopes or "assets:read,grades:read,findings:read").split(",")]
    targets = [t.strip() for t in args.targets.split(",")] if args.targets else None
    ip_allowlist = [ip.strip() for ip in args.ip_allowlist.split(",")] if args.ip_allowlist else None
    expires_at = _parse_date(args.expires) if args.expires else None
    rpm = args.rpm or 60

    dbh = _get_db()
    try:
        dbh.extApiKeyCreate(
            key_id=key_id,
            key_hash=key_hash,
            key_encrypted=key_encrypted,
            client_name=args.name,
            scopes=json.dumps(scopes),
            allowed_targets=json.dumps(targets) if targets else None,
            rate_limit_rpm=rpm,
            ip_allowlist=json.dumps(ip_allowlist) if ip_allowlist else None,
            expires_at=expires_at,
            notes=args.notes,
        )
    except Exception as e:
        print(f"ERROR creating key: {e}", file=sys.stderr)
        sys.exit(1)

    print()
    print("=" * 70)
    print("  EXTERNAL API KEY CREATED")
    print("=" * 70)
    print(f"  Key ID      : {key_id}")
    print(f"  Client      : {args.name}")
    print(f"  Scopes      : {', '.join(scopes)}")
    print(f"  Targets     : {', '.join(targets) if targets else 'ALL'}")
    print(f"  IP Allowlist: {', '.join(ip_allowlist) if ip_allowlist else 'any'}")
    print(f"  Rate limit  : {rpm} req/min")
    print(f"  Expires     : {args.expires or 'never'}")
    print()
    print("  ⚠  RAW KEY (save now — never shown again):")
    print()
    print(f"  {raw_key}")
    print()
    print("=" * 70)
    print()


def cmd_list(args):
    """List all external API keys."""
    dbh = _get_db()
    try:
        keys = dbh.extApiKeyList()
    except Exception as e:
        print(f"ERROR listing keys: {e}", file=sys.stderr)
        sys.exit(1)

    if not keys:
        print("No external API keys configured.")
        return

    fmt = "{:<38} {:<20} {:<8} {:<6} {:<12}"
    print()
    print(fmt.format("KEY ID", "CLIENT NAME", "ACTIVE", "RPM", "EXPIRES"))
    print("-" * 88)
    for k in keys:
        expires = "never"
        if k["expires_at"]:
            try:
                expires = datetime.fromtimestamp(k["expires_at"] / 1000, tz=timezone.utc).strftime("%Y-%m-%d")
            except Exception:
                expires = str(k["expires_at"])
        active = "yes" if k["active"] else "REVOKED"
        print(fmt.format(k["key_id"], k["client_name"][:20], active, k["rate_limit_rpm"], expires))
    print()


def cmd_revoke(args):
    """Revoke an external API key."""
    if not args.id:
        print("ERROR: --id is required", file=sys.stderr)
        sys.exit(1)

    dbh = _get_db()
    try:
        found = dbh.extApiKeyRevoke(args.id)
    except Exception as e:
        print(f"ERROR revoking key: {e}", file=sys.stderr)
        sys.exit(1)

    if not found:
        print(f"ERROR: Key not found: {args.id}", file=sys.stderr)
        sys.exit(1)

    print(f"Key {args.id} has been revoked.")


def cmd_audit(args):
    """Show audit log for an external API key."""
    if not args.id:
        print("ERROR: --id is required", file=sys.stderr)
        sys.exit(1)

    dbh = _get_db()
    try:
        entries = dbh.extApiKeyAuditEntries(args.id, limit=args.limit)
    except Exception as e:
        print(f"ERROR fetching audit log: {e}", file=sys.stderr)
        sys.exit(1)

    if not entries:
        print(f"No audit entries found for key {args.id}")
        return

    print()
    print(f"Audit log for key: {args.id}")
    print("-" * 80)
    for e in entries:
        ts = ""
        if e["created"]:
            try:
                ts = datetime.fromtimestamp(e["created"] / 1000, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
            except Exception:
                ts = str(e["created"])
        ip = e.get("ip_address") or "?"
        action = e.get("action") or ""
        detail = e.get("detail") or ""
        print(f"  {ts}  [{ip:15s}]  {action:<20}  {detail}")
    print()


def cmd_reveal(args):
    """Reveal (decrypt) the raw key for an existing key ID."""
    if not args.id:
        print("ERROR: --id is required", file=sys.stderr)
        sys.exit(1)

    from spiderfoot.ext_api import decrypt_ext_api_key

    dbh = _get_db()
    try:
        encrypted = dbh.extApiKeyGetEncrypted(args.id)
    except Exception as e:
        print(f"ERROR fetching encrypted key: {e}", file=sys.stderr)
        sys.exit(1)

    if encrypted is None:
        print(f"ERROR: Key not found: {args.id}", file=sys.stderr)
        sys.exit(1)

    try:
        raw_key = decrypt_ext_api_key(encrypted)
    except ValueError as e:
        print(f"ERROR: Decryption failed: {e}", file=sys.stderr)
        sys.exit(1)

    print()
    print(f"Key ID : {args.id}")
    print(f"Raw Key: {raw_key}")
    print()


def main():
    parser = argparse.ArgumentParser(
        description="ASM-NG External API Key Manager",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # create
    p_create = subparsers.add_parser("create", help="Create a new vendor API key")
    p_create.add_argument("--name", required=True, help="Vendor/client name (e.g. 'ACME SOC')")
    p_create.add_argument("--targets", help="Comma-separated target list (blank = ALL)")
    p_create.add_argument("--scopes", help="Comma-separated scopes (default: assets:read,grades:read,findings:read)")
    p_create.add_argument("--ip-allowlist", help="Comma-separated CIDR list (blank = any IP)")
    p_create.add_argument("--rpm", type=int, default=60, help="Rate limit (req/min, default 60)")
    p_create.add_argument("--expires", help="Expiry date YYYY-MM-DD (blank = never)")
    p_create.add_argument("--notes", help="Optional notes")

    # list
    subparsers.add_parser("list", help="List all vendor API keys")

    # revoke
    p_revoke = subparsers.add_parser("revoke", help="Revoke a vendor API key (soft delete)")
    p_revoke.add_argument("--id", required=True, help="Key ID to revoke")

    # audit
    p_audit = subparsers.add_parser("audit", help="Show audit log for a key")
    p_audit.add_argument("--id", required=True, help="Key ID")
    p_audit.add_argument("--limit", type=int, default=50, help="Max entries to show (default 50)")

    # reveal
    p_reveal = subparsers.add_parser("reveal", help="Decrypt and reveal raw key (requires ASMNG_EXT_KEY_MASTER)")
    p_reveal.add_argument("--id", required=True, help="Key ID to reveal")

    args = parser.parse_args()

    dispatch = {
        "create": cmd_create,
        "list": cmd_list,
        "revoke": cmd_revoke,
        "audit": cmd_audit,
        "reveal": cmd_reveal,
    }
    dispatch[args.command](args)


if __name__ == "__main__":
    main()
