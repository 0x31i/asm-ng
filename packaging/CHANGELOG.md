# Changelog

All notable changes to this project will be documented in this file.

## [5.3.0] - 2026-03-04

### Added

#### Enterprise External API for Trusted Vendors
- New `spiderfoot/ext_api.py` — dedicated FastAPI router for third-party vendor access with seven stacked security layers
- Vendor-facing endpoints at `/v1/ext/*` (publicly routable via nginx): health, targets, grade, grade history, assets, findings, findings summary
- Admin-only endpoints at `/v1/admin/*` (nginx blocks from internet): create/list/revoke/audit/reveal vendor keys
- `manage_ext_keys.py` — local CLI for full key lifecycle (create, list, revoke, audit, reveal)
- New web UI page at `/extapi` (Settings → External API) for key creation and management
- Vendor key encryption: raw key shown once at creation; Fernet-encrypted blob stored in DB; SHA-256 hash used for auth lookups — DB breach alone yields nothing usable
- `ASMNG_EXT_KEY_MASTER` env var — 256-bit Fernet master key for vendor key encryption/decryption
- Kill switch: `__ext_api_enabled` config key toggles all `/v1/ext/*` access without deleting keys
- Per-key controls: scopes (`assets:read`, `grades:read`, `findings:read`), target ACL, IP allowlist (CIDR), rate limit (RPM), expiry timestamp
- Per-key sliding-window token bucket rate limiter (thread-safe, 60-second window)
- All external API requests written to `tbl_audit_log` with IP address and endpoint
- `tbl_ext_api_keys` table added (migration-safe; auto-created on first launch)
- New documentation: `documentation/vendor_api.md` — complete vendor integration guide with curl examples and Python client code

#### Security Hardening
- **CORS wildcard removed** — `CORSMiddleware` now uses explicit origin list from `ASMNG_CORS_ORIGINS` env var (default: `http://127.0.0.1:5001` only); was previously `allow_origins=["*"]`
- **Timing attack fixed** — internal API key comparison in `sfapi.py` now uses `hmac.compare_digest()` instead of `==`
- **IP-level rate limiting** — `slowapi` middleware added to FastAPI app; 200 req/min per IP default; degrades gracefully if `slowapi` not installed
- Added `slowapi>=0.5.1` and `limits>=3.6.0` to `requirements.txt`
- nginx: new `ext_api` rate limit zone (30 req/min per IP, burst 10); `/v1/admin/` deny-all block; internal `/api/` restricted to RFC-1918 + localhost

#### Manual Grade Entry
- `gradeSnapshotStoreManual()` DB method — store a manually-entered grade snapshot with custom score, grade, per-category breakdown, label, and date
- Manual snapshots appear alongside scan-derived snapshots in grade history views
- Supports entering baseline/pre-engagement grades without running a full scan

#### Analyst Annotations
- `tbl_analyst_type_comments` — per-event-type analyst commentary, persisted by target + event type across all scans
- `tbl_analyst_row_notes` — per-finding row-level notes, persisted by target + event type + data + source across all scans
- Both annotation tables auto-created during schema migration
- Annotations included in result exports

#### Grade Snapshot Enhancements
- `snapshot_excluded` column — mark snapshots to exclude from grade history charts without deletion
- `snapshot_label` column — human-readable label for manual and notable automated snapshots
- `gradeSnapshotSetExcluded()` and label update methods

#### Known Assets Enhancements
- `affinity` column — `DIRECT` / `INFERRED` / `INDIRECT` relationship classification
- `tag` column — freeform tag for grouping and filtering assets
- `raw_value` column — original pre-normalized asset value
- `status` column — `CONFIRMED` / `POTENTIAL` / `HISTORICAL` status
- `entry_method` column — `MANUAL` / `IMPORTED` / `SCAN_DERIVED`
- `event_type` column — event type from which the asset was discovered
- `tbl_asset_tags` table — named color-coded tags for asset organization
- `knownAssetSetStatusBulk()`, `knownAssetBulkUpdate()`, `knownAssetMerge()` bulk operations

#### Other
- `tbl_saved_searches` table — save and recall results-table search queries
- `tbl_asset_import_history` — audit trail for bulk import operations

### Changed
- Platform description updated: 280+ → 288 modules
- README: grading table updated to include AI Security category (weight 0.9)
- README: database tables section updated with all new tables
- README: architecture diagram updated to include External API and vendor layer
- `documentation/api_reference.md` — complete rewrite covering all four API surfaces

### Fixed
- `hmac.compare_digest()` used for all API key comparisons (timing attack mitigation)
- `CORSMiddleware` restricted from wildcard to explicit origin list

---

## [Unreleased - Previous]

### Added
- **AI/ML Infrastructure Discovery** — 3 new modules for external AI attack surface detection:
  - `sfp_ai_fingerprint` — detects and fingerprints 15+ AI/ML inference frameworks (Ollama, NVIDIA Triton, vLLM, TorchServe, TensorFlow Serving, MLflow, BentoML, Gradio, Ray Dashboard, Streamlit, LM Studio, MCP servers) via port analysis, banner fingerprinting, and active HTTP probes; checks for unauthenticated model access
  - `sfp_ai_subdomain` — discovers AI-related subdomains via Certificate Transparency logs and DNS brute-forcing with an 80+ term AI-specific wordlist; detects cloud AI service CNAME patterns (SageMaker, Azure OpenAI, HuggingFace)
  - `sfp_ai_webcontent` — analyzes web content for embedded AI SDK imports, chat widget markers, leaked AI API keys, and inference endpoint references
- 4 new event types: `AI_INFRASTRUCTURE_DETECTED`, `AI_MODEL_EXPOSED`, `AI_ENDPOINT_UNAUTHENTICATED`, `AI_API_KEY_LEAKED`
- AI event types integrated into grading system (unauthenticated endpoints scored as critical severity)
- AI subdomain wordlist (`spiderfoot/dicts/ai-subdomains.txt`)
- **PostgreSQL database backend** — production-ready backend:
  - Automatic PostgreSQL installation and configuration on first launch (Debian/Kali/Ubuntu, macOS, RHEL/Fedora)
  - Thread-safe connection pooling with semaphore-gated access (64 concurrent connections default)
  - Transparent SQL translation via `PgCursorWrapper` (no code changes needed for existing queries)
  - Automatic INT-to-BIGINT conversion for millisecond timestamp compatibility
  - Configurable via environment variables: `ASMNG_DATABASE_URL`, `ASMNG_DB_TYPE`, `ASMNG_PG_AUTO_SETUP`
  - Auto-detection priority: explicit DSN → env var → localhost probe → auto-setup
- Automated changelog generation enabled in CI.

## [5.2.5] - 2025-06-24
- Initial automated changelog entry.
