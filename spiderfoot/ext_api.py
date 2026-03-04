# -*- coding: utf-8 -*-
"""
External API layer for ASM-NG — trusted third-party vendor access.

Security model (7 layers):
  1. nginx TLS termination + IP rate limiting (30 r/m per IP)
  2. Per-vendor API key (SHA-256 hashed in DB, raw never stored)
  3. Constant-time hmac.compare_digest() key comparison
  4. Key expiry timestamp check
  5. IP allowlist check per key (CIDR)
  6. Scope check (assets:read, grades:read, findings:read)
  7. Target ACL check (vendor only sees explicitly allowed targets)

Plus: per-key token-bucket rate limiter + audit log on every request.
"""

import hashlib
import hmac
import ipaddress
import json
import logging
import os
import secrets
import threading
import time
import uuid
from collections import defaultdict
from typing import Any, Dict, List, Optional

from cryptography.fernet import Fernet, InvalidToken
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel

from spiderfoot import SpiderFootDb

_log = logging.getLogger("spiderfoot.ext_api")

# ---------------------------------------------------------------------------
# Routers
# ---------------------------------------------------------------------------
ext_router = APIRouter()
admin_router = APIRouter()

_ext_security = HTTPBearer(auto_error=False)

# ---------------------------------------------------------------------------
# Master key / Fernet helpers
# ---------------------------------------------------------------------------

def _get_fernet() -> Fernet:
    """Load master Fernet key from environment. Raises RuntimeError if absent."""
    master = os.environ.get("ASMNG_EXT_KEY_MASTER")
    if not master:
        raise RuntimeError(
            "ASMNG_EXT_KEY_MASTER env var not set — "
            "cannot manage external API keys. "
            "Generate one with: python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\""
        )
    return Fernet(master.encode())


def generate_ext_api_key() -> tuple:
    """Generate a new external API key triple.

    Returns:
        tuple: (raw_key, key_hash, key_encrypted)
            raw_key       — given to vendor; never stored
            key_hash      — SHA-256 hex; stored for fast auth lookup
            key_encrypted — Fernet(master_secret).encrypt(raw_key); stored for admin reveal
    """
    raw = "asmng_ext_" + secrets.token_urlsafe(30)   # ~240-bit entropy
    key_hash = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    key_encrypted = _get_fernet().encrypt(raw.encode("utf-8")).decode("utf-8")
    return raw, key_hash, key_encrypted


def decrypt_ext_api_key(key_encrypted: str) -> str:
    """Decrypt stored ciphertext for admin key-reveal.

    Args:
        key_encrypted (str): Fernet-encrypted key blob from DB

    Returns:
        str: raw key string

    Raises:
        ValueError: if decryption fails (wrong master key or tampered data)
    """
    try:
        return _get_fernet().decrypt(key_encrypted.encode("utf-8")).decode("utf-8")
    except (InvalidToken, Exception) as e:
        raise ValueError(f"Key decryption failed: {e}") from e


# ---------------------------------------------------------------------------
# IP allowlist helper
# ---------------------------------------------------------------------------

def ip_in_allowlist(client_ip: str, cidr_list: list) -> bool:
    """Return True if client_ip falls within any CIDR in cidr_list."""
    try:
        addr = ipaddress.ip_address(client_ip)
        return any(
            addr in ipaddress.ip_network(cidr, strict=False)
            for cidr in cidr_list
        )
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Per-key sliding-window token bucket rate limiter
# ---------------------------------------------------------------------------

_rate_buckets: dict = defaultdict(list)
_rate_lock = threading.Lock()


def check_rate_limit(key_id: str, rpm: int) -> bool:
    """Thread-safe 60-second sliding-window rate check.

    Args:
        key_id (str): key UUID used as bucket identifier
        rpm (int): max requests per minute allowed

    Returns:
        bool: True if request is allowed, False if over limit
    """
    now = time.time()
    with _rate_lock:
        timestamps = [t for t in _rate_buckets[key_id] if now - t < 60.0]
        if len(timestamps) >= rpm:
            return False
        timestamps.append(now)
        _rate_buckets[key_id] = timestamps
        return True


# ---------------------------------------------------------------------------
# DB helper
# ---------------------------------------------------------------------------

def _get_db() -> SpiderFootDb:
    """Open a DB connection using config from environment / defaults."""
    from spiderfoot import SpiderFootHelpers
    from sflib import SpiderFoot
    from copy import deepcopy
    default_cfg = {
        '__modules__': {},
        '__correlationrules__': [],
        '_debug': False,
        '__webaddr': '127.0.0.1',
        '__webport': '5001',
        '__database': SpiderFootHelpers.dataPath(),
        '__loglevel': 'INFO',
        '__logfile': '',
    }
    dbh = SpiderFootDb(default_cfg)
    return dbh


# ---------------------------------------------------------------------------
# Kill-switch check
# ---------------------------------------------------------------------------

def _check_kill_switch(dbh: SpiderFootDb) -> None:
    """Raise HTTP 503 if the external API kill switch is OFF."""
    try:
        cfg = dbh.configGet()
        enabled = cfg.get("__ext_api_enabled", "1")
        if enabled != "1":
            raise HTTPException(503, "External API is currently disabled")
    except HTTPException:
        raise
    except Exception:
        pass  # DB error → don't block on kill-switch check


# ---------------------------------------------------------------------------
# Auth dependency
# ---------------------------------------------------------------------------

async def get_ext_client(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(_ext_security),
) -> dict:
    """FastAPI dependency: authenticate and authorise an external API call.

    Runs 7 security checks in order:
      1. Bearer token present and has expected prefix
      2. DB lookup by SHA-256 hash
      3. key.active == 1
      4. key not expired
      5. source IP in allowlist (if set)
      6. per-key token bucket rate limit
      7. audit log + last-used update

    Returns the key record dict on success; raises HTTPException otherwise.
    """
    # Extract source IP (nginx sets X-Real-IP)
    client_ip = (
        request.headers.get("X-Real-IP")
        or (request.client.host if request.client else "unknown")
    )

    def _deny(code: int, msg: str):
        raise HTTPException(status_code=code, detail=msg)

    # 1. Require Bearer token with expected prefix
    if not credentials or not credentials.credentials:
        _deny(401, "Missing Authorization header")

    raw_key = credentials.credentials
    if not raw_key.startswith("asmng_ext_"):
        _deny(401, "Invalid API key format")

    dbh = _get_db()

    # Kill-switch check first
    _check_kill_switch(dbh)

    # 2. DB lookup (constant-time hash comparison inside extApiKeyLookup)
    try:
        key_record = dbh.extApiKeyLookup(raw_key)
    except Exception as e:
        _log.error(f"DB error during ext key lookup: {e}")
        _deny(500, "Internal error")

    if not key_record:
        _deny(401, "Invalid or unknown API key")

    key_id = key_record["key_id"]

    # 3. Active check
    if not key_record.get("active"):
        dbh.auditLog(key_id, "EXT_AUTH_DENIED", "key revoked", client_ip)
        _deny(401, "API key has been revoked")

    # 4. Expiry check
    expires_at = key_record.get("expires_at")
    if expires_at and int(time.time() * 1000) > expires_at:
        dbh.auditLog(key_id, "EXT_AUTH_DENIED", "key expired", client_ip)
        _deny(401, "API key has expired")

    # 5. IP allowlist
    ip_allowlist_raw = key_record.get("ip_allowlist")
    if ip_allowlist_raw:
        try:
            cidr_list = json.loads(ip_allowlist_raw)
        except (json.JSONDecodeError, TypeError):
            cidr_list = []
        if cidr_list and not ip_in_allowlist(client_ip, cidr_list):
            dbh.auditLog(key_id, "EXT_AUTH_DENIED", f"IP not in allowlist: {client_ip}", client_ip)
            _deny(403, "Source IP not permitted for this key")

    # 6. Per-key rate limit
    rpm = key_record.get("rate_limit_rpm", 60)
    if not check_rate_limit(key_id, rpm):
        dbh.auditLog(key_id, "EXT_RATE_LIMIT", f"rpm={rpm}", client_ip)
        _deny(429, "Rate limit exceeded")

    # 7. Audit + last-used update
    path = request.url.path
    dbh.auditLog(key_id, "EXT_REQUEST", path, client_ip)
    try:
        dbh.extApiKeyUpdateLastUsed(key_id, client_ip)
    except Exception:
        pass  # Non-critical

    return key_record


# ---------------------------------------------------------------------------
# Scope + target ACL helpers
# ---------------------------------------------------------------------------

def require_scope(client: dict, scope: str) -> None:
    """Raise 403 if the key lacks the required scope."""
    try:
        scopes = json.loads(client.get("scopes") or "[]")
    except (json.JSONDecodeError, TypeError):
        scopes = []
    if scope not in scopes:
        raise HTTPException(403, f"Key lacks required scope: {scope}")


def require_target_access(client: dict, target: str) -> None:
    """Raise 403 if the key is not authorised for target.

    If allowed_targets is NULL the key has access to all targets.
    """
    allowed_raw = client.get("allowed_targets")
    if not allowed_raw:
        return  # NULL → unrestricted
    try:
        allowed = json.loads(allowed_raw)
    except (json.JSONDecodeError, TypeError):
        allowed = []
    if allowed and target not in allowed:
        raise HTTPException(403, "Key not authorized for this target")


# ---------------------------------------------------------------------------
# Pydantic response models (strict whitelist — no internal IDs leak)
# ---------------------------------------------------------------------------

class ExtAsset(BaseModel):
    asset_type: str
    asset_value: str
    source: str
    affinity: str
    tag: Optional[str] = None
    date_added: int


class ExtCategoryGrade(BaseModel):
    grade: str
    score: float
    weight: float


class ExtGrade(BaseModel):
    target: str
    overall_grade: str
    overall_score: float
    categories: Dict[str, ExtCategoryGrade]
    as_of: int
    snapshot_label: Optional[str] = None


class ExtFinding(BaseModel):
    event_type: str
    event_type_label: str
    data: str
    source_data: Optional[str] = None
    status: str


class ExtTargetSummary(BaseModel):
    target: str
    current_grade: Optional[str] = None
    current_score: Optional[float] = None
    last_scan: Optional[int] = None
    asset_count: int


class ExtKeyCreateRequest(BaseModel):
    client_name: str
    scopes: Optional[List[str]] = None
    allowed_targets: Optional[List[str]] = None
    rate_limit_rpm: int = 60
    ip_allowlist: Optional[List[str]] = None
    expires_at: Optional[int] = None
    notes: Optional[str] = None


class ExtKeyInfo(BaseModel):
    key_id: str
    client_name: str
    scopes: List[str]
    allowed_targets: Optional[List[str]] = None
    rate_limit_rpm: int
    ip_allowlist: Optional[List[str]] = None
    active: int
    created_at: int
    last_used_at: Optional[int] = None
    last_used_ip: Optional[str] = None
    expires_at: Optional[int] = None
    notes: Optional[str] = None


# ---------------------------------------------------------------------------
# Helper: build ExtGrade from a snapshot row dict
# ---------------------------------------------------------------------------

def _snapshot_to_ext_grade(snap) -> ExtGrade:
    """Convert a gradeSnapshotsForTarget row to ExtGrade."""
    # Row order from gradeSnapshotsForTarget:
    # scan_instance_id[0], seed_target[1], overall_score[2], overall_grade[3],
    # category_scores[4], finding_counts[5], total_findings[6], unique_findings[7],
    # correlation_counts[8], scan_started[9], scan_ended[10], created[11],
    # snapshot_excluded[12], snapshot_label[13]
    try:
        raw_cats = json.loads(snap[4] or "{}")
    except (json.JSONDecodeError, TypeError):
        raw_cats = {}

    categories: Dict[str, ExtCategoryGrade] = {}
    for cat_name, cat_data in raw_cats.items():
        if isinstance(cat_data, dict):
            categories[cat_name] = ExtCategoryGrade(
                grade=cat_data.get("grade", "N/A"),
                score=float(cat_data.get("score", 0)),
                weight=float(cat_data.get("weight", 0)),
            )

    return ExtGrade(
        target=snap[1],
        overall_grade=snap[3],
        overall_score=float(snap[2]),
        categories=categories,
        as_of=snap[9],
        snapshot_label=snap[13] if len(snap) > 13 else None,
    )


# ---------------------------------------------------------------------------
# External read-only endpoints  (prefix applied by sfapi.py: /v1/ext)
# ---------------------------------------------------------------------------

@ext_router.get("/health")
async def ext_health():
    """Health check — returns no version info to prevent enumeration."""
    return {"status": "ok"}


@ext_router.get("/targets", response_model=List[ExtTargetSummary])
async def ext_list_targets(
    client: dict = Depends(get_ext_client),
):
    """List targets the API key is authorised to see."""
    require_scope(client, "assets:read")

    dbh = _get_db()

    # Determine target filter
    allowed_raw = client.get("allowed_targets")
    if allowed_raw:
        try:
            target_filter = json.loads(allowed_raw)
        except (json.JSONDecodeError, TypeError):
            target_filter = []
    else:
        target_filter = None  # all targets

    # Gather target list from scan instances
    try:
        scans = dbh.scanInstanceList()
    except Exception:
        scans = []

    # Build unique target set
    seen = set()
    results = []
    for scan in scans:
        target = scan[2]  # seed_target
        if target_filter and target not in target_filter:
            continue
        if target in seen:
            continue
        seen.add(target)

        # Latest grade
        current_grade = None
        current_score = None
        last_scan = None
        try:
            snaps = dbh.gradeSnapshotsForTarget(target, limit=1)
            if snaps:
                latest = snaps[-1]
                current_grade = latest[3]
                current_score = float(latest[2])
                last_scan = latest[9]
        except Exception:
            pass

        # Asset count
        asset_count = 0
        try:
            asset_count = dbh.knownAssetTotal(target)
        except Exception:
            pass

        results.append(ExtTargetSummary(
            target=target,
            current_grade=current_grade,
            current_score=current_score,
            last_scan=last_scan,
            asset_count=asset_count,
        ))

    return results


@ext_router.get("/targets/{target}/grade", response_model=ExtGrade)
async def ext_target_grade(
    target: str,
    client: dict = Depends(get_ext_client),
):
    """Return the most recent grade snapshot for a target."""
    require_scope(client, "grades:read")
    require_target_access(client, target)

    dbh = _get_db()
    try:
        snaps = dbh.gradeSnapshotsForTarget(target, limit=100)
    except Exception as e:
        raise HTTPException(500, f"DB error: {e}")

    if not snaps:
        raise HTTPException(404, f"No grade data found for target: {target}")

    return _snapshot_to_ext_grade(snaps[-1])


@ext_router.get("/targets/{target}/grade/history", response_model=List[ExtGrade])
async def ext_target_grade_history(
    target: str,
    limit: int = Query(12, ge=1, le=100),
    client: dict = Depends(get_ext_client),
):
    """Return grade snapshot history for a target (oldest first)."""
    require_scope(client, "grades:read")
    require_target_access(client, target)

    dbh = _get_db()
    try:
        snaps = dbh.gradeSnapshotsForTarget(target, limit=limit)
    except Exception as e:
        raise HTTPException(500, f"DB error: {e}")

    return [_snapshot_to_ext_grade(s) for s in snaps]


@ext_router.get("/targets/{target}/assets", response_model=List[ExtAsset])
async def ext_target_assets(
    target: str,
    type: Optional[str] = Query(None, description="Filter by asset type"),
    status: Optional[str] = Query("CONFIRMED", description="Asset status filter"),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    client: dict = Depends(get_ext_client),
):
    """List known assets for a target."""
    require_scope(client, "assets:read")
    require_target_access(client, target)

    dbh = _get_db()
    try:
        rows = dbh.knownAssetList(
            target=target,
            assetType=type,
            status=status,
            limit=limit,
            offset=offset,
        )
    except Exception as e:
        raise HTTPException(500, f"DB error: {e}")

    results = []
    for row in rows:
        # knownAssetList columns: id[0], target[1], asset_type[2], asset_value[3],
        # source[4], import_batch[5], date_added[6], added_by[7], notes[8],
        # raw_value[9], status[10], entry_method[11], affinity[12], tag[13]
        results.append(ExtAsset(
            asset_type=row[2],
            asset_value=row[3],
            source=row[4],
            affinity=row[12] if len(row) > 12 else "DIRECT",
            tag=row[13] if len(row) > 13 else None,
            date_added=int(row[6]) if row[6] else 0,
        ))
    return results


@ext_router.get("/targets/{target}/findings", response_model=List[ExtFinding])
async def ext_target_findings(
    target: str,
    status: Optional[str] = Query("validated", description="validated or all"),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    client: dict = Depends(get_ext_client),
):
    """List confirmed/validated findings for a target. False positives are NEVER returned."""
    require_scope(client, "findings:read")
    require_target_access(client, target)

    dbh = _get_db()

    # Get validated items for this target
    try:
        validated_rows = dbh.targetValidatedListFull(target)
    except Exception as e:
        raise HTTPException(500, f"DB error fetching findings: {e}")

    results = []
    for row in validated_rows[offset:offset + limit]:
        # targetValidatedListFull: id[0], target[1], event_type[2],
        # event_data[3], source_data[4], date_added[5], notes[6]
        from spiderfoot.event_type_mapping import translate_event_type
        event_type = row[2]
        label = translate_event_type(event_type) if event_type else event_type
        results.append(ExtFinding(
            event_type=event_type,
            event_type_label=label or event_type,
            data=row[3],
            source_data=row[4],
            status="validated",
        ))

    return results


@ext_router.get("/targets/{target}/findings/summary")
async def ext_target_findings_summary(
    target: str,
    client: dict = Depends(get_ext_client),
):
    """Summary of validated findings by type for a target."""
    require_scope(client, "findings:read")
    require_target_access(client, target)

    dbh = _get_db()
    try:
        validated_rows = dbh.targetValidatedListFull(target)
    except Exception as e:
        raise HTTPException(500, f"DB error: {e}")

    by_type: Dict[str, int] = {}
    for row in validated_rows:
        event_type = row[2]
        by_type[event_type] = by_type.get(event_type, 0) + 1

    return {
        "by_type": by_type,
        "total_validated": len(validated_rows),
        "total_fp_hidden": True,   # false positives are never surfaced
    }


# ---------------------------------------------------------------------------
# Admin endpoints  (prefix: /v1/admin — nginx blocks from internet)
# ---------------------------------------------------------------------------

# Reuse the internal security scheme via import-time dependency
_admin_security = HTTPBearer(auto_error=False)


async def require_local(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(_admin_security),
):
    """Restrict admin endpoints to localhost callers only.

    Even if nginx is misconfigured, this provides a code-level guard.
    Also validates the existing internal API key.
    """
    client_ip = (
        request.headers.get("X-Real-IP")
        or (request.client.host if request.client else "unknown")
    )
    if client_ip not in ("127.0.0.1", "::1"):
        raise HTTPException(403, "Admin endpoints are localhost-only")

    # Validate internal API key (re-use app config pattern)
    if credentials:
        try:
            from sfapi import get_app_config
            import hmac as _hmac
            cfg = get_app_config()
            api_key = cfg.get_config().get("__webaddr_apikey")
            if api_key and not _hmac.compare_digest(credentials.credentials, api_key):
                raise HTTPException(401, "Invalid API key")
        except ImportError:
            pass  # If sfapi not available, skip key check (direct DB access)

    return credentials


@admin_router.post("/ext-keys", status_code=201)
async def admin_create_ext_key(
    body: ExtKeyCreateRequest,
    _auth=Depends(require_local),
):
    """Create a new external vendor API key. Returns raw key ONCE."""
    try:
        raw_key, key_hash, key_encrypted = generate_ext_api_key()
    except RuntimeError as e:
        raise HTTPException(500, str(e))

    key_id = str(uuid.uuid4())
    scopes = json.dumps(body.scopes or ["assets:read", "grades:read", "findings:read"])
    allowed_targets = json.dumps(body.allowed_targets) if body.allowed_targets else None
    ip_allowlist = json.dumps(body.ip_allowlist) if body.ip_allowlist else None

    dbh = _get_db()
    try:
        dbh.extApiKeyCreate(
            key_id=key_id,
            key_hash=key_hash,
            key_encrypted=key_encrypted,
            client_name=body.client_name,
            scopes=scopes,
            allowed_targets=allowed_targets,
            rate_limit_rpm=body.rate_limit_rpm,
            ip_allowlist=ip_allowlist,
            expires_at=body.expires_at,
            notes=body.notes,
        )
    except Exception as e:
        raise HTTPException(500, f"DB error creating key: {e}")

    _log.info(f"Created external API key {key_id} for client '{body.client_name}'")

    return {
        "key_id": key_id,
        "raw_key": raw_key,
        "client_name": body.client_name,
        "warning": "Save this key now — it will never be shown again",
    }


@admin_router.get("/ext-keys")
async def admin_list_ext_keys(_auth=Depends(require_local)):
    """List all external API keys (no hash or encrypted fields)."""
    dbh = _get_db()
    try:
        keys = dbh.extApiKeyList()
    except Exception as e:
        raise HTTPException(500, f"DB error listing keys: {e}")

    result = []
    for k in keys:
        result.append({
            "key_id": k["key_id"],
            "client_name": k["client_name"],
            "scopes": _safe_json_list(k["scopes"]),
            "allowed_targets": _safe_json_list(k["allowed_targets"]) if k["allowed_targets"] else None,
            "rate_limit_rpm": k["rate_limit_rpm"],
            "ip_allowlist": _safe_json_list(k["ip_allowlist"]) if k["ip_allowlist"] else None,
            "active": k["active"],
            "created_at": k["created_at"],
            "last_used_at": k["last_used_at"],
            "last_used_ip": k["last_used_ip"],
            "expires_at": k["expires_at"],
            "notes": k["notes"],
        })
    return result


@admin_router.delete("/ext-keys/{key_id}", status_code=200)
async def admin_revoke_ext_key(key_id: str, _auth=Depends(require_local)):
    """Revoke an external API key (soft delete — sets active=0)."""
    dbh = _get_db()
    try:
        found = dbh.extApiKeyRevoke(key_id)
    except Exception as e:
        raise HTTPException(500, f"DB error revoking key: {e}")

    if not found:
        raise HTTPException(404, f"Key not found: {key_id}")

    _log.info(f"Revoked external API key {key_id}")
    return {"revoked": True, "key_id": key_id}


@admin_router.get("/ext-keys/{key_id}/audit")
async def admin_ext_key_audit(
    key_id: str,
    limit: int = Query(100, ge=1, le=500),
    _auth=Depends(require_local),
):
    """Return audit log entries for an external API key."""
    dbh = _get_db()
    try:
        entries = dbh.extApiKeyAuditEntries(key_id, limit=limit)
    except Exception as e:
        raise HTTPException(500, f"DB error fetching audit log: {e}")

    return entries


@admin_router.get("/ext-keys/{key_id}/reveal")
async def admin_reveal_ext_key(key_id: str, _auth=Depends(require_local)):
    """Decrypt and return the raw API key for admin reveal.

    Requires ASMNG_EXT_KEY_MASTER in environment.
    """
    dbh = _get_db()
    try:
        encrypted = dbh.extApiKeyGetEncrypted(key_id)
    except Exception as e:
        raise HTTPException(500, f"DB error: {e}")

    if encrypted is None:
        raise HTTPException(404, f"Key not found: {key_id}")

    try:
        raw_key = decrypt_ext_api_key(encrypted)
    except ValueError as e:
        raise HTTPException(500, f"Decryption failed: {e}")

    return {"key_id": key_id, "raw_key": raw_key}


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------

def _safe_json_list(value) -> list:
    """Parse a JSON string to list, returning [] on failure."""
    if not value:
        return []
    try:
        result = json.loads(value)
        return result if isinstance(result, list) else []
    except (json.JSONDecodeError, TypeError):
        return []
