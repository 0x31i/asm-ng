# API Reference

ASM-NG exposes four distinct API surfaces. Each serves a different consumer and uses a different authentication mechanism. This document is a complete reference for all four surfaces.

---

## API Overview

| Surface | Port | Prefix | Auth | Consumers |
|---|---|---|---|---|
| REST API | 8001 | `/api/` | Bearer token (API key) | Internal tooling, CI/CD, automation |
| External Vendor API | 8001 | `/v1/ext/` | Bearer token (vendor key) | Trusted external integrations |
| Admin API | 8001 | `/v1/admin/` | Localhost-only | Key management (never expose via nginx) |
| Web UI API | 5001 | `/` | Session cookie | Browser (CherryPy) |

---

## REST API

**Base URL:** `http://<host>:8001/api/`

The REST API is the primary machine-to-machine interface for ASM-NG. It is implemented with FastAPI and covers scans, workspaces, modules, and configuration.

### Authentication

All REST API requests require a Bearer token:

```
Authorization: Bearer <api_key>
```

The API key is configured in the web UI under Settings.

---

### Scans

#### List Scans

```
GET /api/scans
```

Query parameters:

| Parameter | Type | Default | Description |
|---|---|---|---|
| `limit` | integer | 50 | Maximum number of results to return |
| `offset` | integer | 0 | Pagination offset |

#### Create Scan

```
POST /api/scans
```

Request body:

```json
{
  "name": "My Scan",
  "target": "example.com",
  "modules": ["sfp_dnsresolve", "sfp_ssl"],
  "type_filter": []
}
```

#### Get Scan Detail

```
GET /api/scans/{scan_id}
```

#### Delete Scan

```
DELETE /api/scans/{scan_id}
```

#### Stop Active Scan

```
POST /api/scans/{scan_id}/stop
```

#### Get Scan Results

```
GET /api/scans/{scan_id}/results
```

Query parameters:

| Parameter | Type | Default | Description |
|---|---|---|---|
| `event_types` | string[] | — | Filter by event type(s) |
| `limit` | integer | 1000 | Maximum number of events to return |
| `offset` | integer | 0 | Pagination offset |

#### Export Scan

```
GET /api/scans/{scan_id}/export
```

Query parameters:

| Parameter | Type | Default | Description |
|---|---|---|---|
| `format` | string | `json` | Export format: `json`, `csv`, or `xml` |
| `legacy` | boolean | false | Use legacy export format |

---

### Workspaces

#### List Workspaces

```
GET /api/workspaces
```

#### Create Workspace

```
POST /api/workspaces
```

Request body:

```json
{
  "name": "My Workspace",
  "description": "Optional description"
}
```

#### Get Workspace Detail

```
GET /api/workspaces/{id}
```

#### Delete Workspace

```
DELETE /api/workspaces/{id}
```

#### Add Target to Workspace

```
POST /api/workspaces/{id}/targets
```

Request body:

```json
{
  "target": "example.com",
  "target_type": "DOMAIN_NAME",
  "metadata": {}
}
```

#### List Workspace Targets

```
GET /api/workspaces/{id}/targets
```

#### Remove Target from Workspace

```
DELETE /api/workspaces/{id}/targets/{target_id}
```

#### Start Multi-Target Scan

```
POST /api/workspaces/{id}/multi-scan
```

Request body:

```json
{
  "targets": ["example.com", "sub.example.com"],
  "modules": ["sfp_dnsresolve", "sfp_ssl"],
  "scan_options": {}
}
```

---

### Configuration

#### Get Configuration

```
GET /api/config
```

#### List Modules

```
GET /api/modules
```

#### List Event Types

```
GET /api/event-types
```

---

## External Vendor API

**Base URL:** `http://<host>:8001/v1/ext/`

The External Vendor API is designed for trusted external integrations such as GRC platforms, security dashboards, and ticketing systems. It is hardened, rate-limited, and scoped to only the data explicitly authorized for each vendor key.

For the full dedicated guide including key provisioning, scope definitions, rate limiting, and integration examples, see `documentation/vendor_api.md`.

### Authentication

All requests require a vendor Bearer token:

```
Authorization: Bearer asmng_ext_<key>
```

Vendor keys are created and managed via the Admin API or the web UI. Each key carries a defined set of scopes and optionally restricts access to specific targets and source IP addresses.

---

### Endpoints

#### Health Check

```
GET /v1/ext/health
```

Returns:

```json
{"status": "ok"}
```

No authentication required. Use this for liveness probes.

#### List Authorized Targets

```
GET /v1/ext/targets
```

Required scope: `assets:read`

Returns the list of targets the vendor key is authorized to query.

#### Get Target Grade

```
GET /v1/ext/targets/{target}/grade
```

Required scope: `grades:read`

Returns the latest overall security grade (A through F) for the specified target.

#### Get Grade History

```
GET /v1/ext/targets/{target}/grade/history
```

Required scope: `grades:read`

Query parameters:

| Parameter | Type | Default | Description |
|---|---|---|---|
| `limit` | integer | 12 | Number of historical grade snapshots to return |

#### List Assets

```
GET /v1/ext/targets/{target}/assets
```

Required scope: `assets:read`

Query parameters:

| Parameter | Type | Default | Description |
|---|---|---|---|
| `type` | string | — | Filter by asset type |
| `status` | string | `CONFIRMED` | Asset status filter |
| `limit` | integer | 100 | Maximum results |
| `offset` | integer | 0 | Pagination offset |

#### List Findings

```
GET /v1/ext/targets/{target}/findings
```

Required scope: `findings:read`

Query parameters:

| Parameter | Type | Default | Description |
|---|---|---|---|
| `status` | string | `validated` | Finding status filter |
| `limit` | integer | 100 | Maximum results |
| `offset` | integer | 0 | Pagination offset |

#### Get Findings Summary

```
GET /v1/ext/targets/{target}/findings/summary
```

Required scope: `findings:read`

Returns aggregated finding counts by severity and status.

---

## Admin API

**Base URL:** `http://127.0.0.1:8001/v1/admin/`

The Admin API manages vendor keys and their audit logs. It is restricted to localhost and must never be exposed via nginx or any reverse proxy. All vendor key management operations — including key creation and revocation — go through this surface or the web UI.

### Authentication

The Admin API is only reachable from localhost. No additional token is required beyond network access, except for the `/reveal` endpoint which requires the `ASMNG_EXT_KEY_MASTER` environment variable to be set.

---

### Endpoints

#### Create Vendor Key

```
POST /v1/admin/ext-keys
```

Request body:

```json
{
  "client_name": "Acme Corp Dashboard",
  "scopes": ["assets:read", "grades:read"],
  "allowed_targets": ["example.com"],
  "rate_limit_rpm": 60,
  "ip_allowlist": ["203.0.113.10"],
  "expires_at": "2027-01-01T00:00:00Z",
  "notes": "Integration for Q1 reporting"
}
```

The raw key is returned once in the response and cannot be retrieved again. Store it immediately.

#### List Vendor Keys

```
GET /v1/admin/ext-keys
```

Returns all keys including revoked keys. Raw key values are never returned from this endpoint.

#### Revoke Vendor Key

```
DELETE /v1/admin/ext-keys/{key_id}
```

Performs a soft delete. The key is immediately invalidated but the record is retained for audit purposes.

#### Get Key Audit Log

```
GET /v1/admin/ext-keys/{key_id}/audit
```

Query parameters:

| Parameter | Type | Default | Description |
|---|---|---|---|
| `limit` | integer | 100 | Maximum log entries to return |

#### Reveal Raw Key

```
GET /v1/admin/ext-keys/{key_id}/reveal
```

Decrypts and returns the raw vendor key. Requires `ASMNG_EXT_KEY_MASTER` to be set. Use only for emergency key recovery.

---

## Web UI API

**Base URL:** `http://<host>:5001/`

The Web UI API is implemented in CherryPy and is the backend for the ASM-NG browser interface. It returns HTML for page routes and JSON for data endpoints. Authentication is session-based via login cookie.

### Authentication

Log in at `/login`. All subsequent requests use the session cookie set by the login response. This surface is not intended for programmatic use; use the REST API for automation.

---

### Selected Endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/scanlist` | List all scans |
| `POST` | `/startscan` | Start a new scan |
| `GET` | `/scangrade?id=<scanId>` | Get the grade for a scan |
| `GET` | `/knownassetlist?target=...` | List known assets for a target |
| `POST` | `/knownassetadd` | Add a known asset |
| `GET` | `/workspacelist` | List workspaces |
| `GET` | `/extapi` | External API management page |
| `POST` | `/extapicreatekey` | Create a vendor key from the web UI |
| `GET` | `/extapirevoke?id=<key_id>` | Revoke a vendor key |
| `GET` | `/auditlog` | View the audit log |

---

## Environment Variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `ASMNG_DATABASE_URL` | Yes | — | PostgreSQL DSN (e.g. `postgresql://user:pass@localhost/asmng`) |
| `ASMNG_EXT_KEY_MASTER` | For ext key mgmt | — | Fernet master key for vendor key encryption |
| `ASMNG_CORS_ORIGINS` | No | `http://127.0.0.1:5001` | Comma-separated list of allowed CORS origins |
| `ASMNG_PG_POOL_MAX` | No | `64` | PostgreSQL connection pool size |

---

## curl Examples

### Start a Scan (REST API)

```bash
curl -s -X POST http://127.0.0.1:8001/api/scans \
  -H "Authorization: Bearer <api_key>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "example.com recon",
    "target": "example.com",
    "modules": ["sfp_dnsresolve", "sfp_ssl", "sfp_whois"],
    "type_filter": []
  }'
```

### List Workspace Targets (REST API)

```bash
curl -s http://127.0.0.1:8001/api/workspaces/<workspace_id>/targets \
  -H "Authorization: Bearer <api_key>"
```

### Get Target Grade (External Vendor API)

```bash
curl -s http://127.0.0.1:8001/v1/ext/targets/example.com/grade \
  -H "Authorization: Bearer asmng_ext_<vendor_key>"
```

### Get Grade History (External Vendor API)

```bash
curl -s "http://127.0.0.1:8001/v1/ext/targets/example.com/grade/history?limit=12" \
  -H "Authorization: Bearer asmng_ext_<vendor_key>"
```

### Create a Vendor Key (Admin API — localhost only)

```bash
curl -s -X POST http://127.0.0.1:8001/v1/admin/ext-keys \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "Acme Corp Dashboard",
    "scopes": ["assets:read", "grades:read", "findings:read"],
    "allowed_targets": ["example.com"],
    "rate_limit_rpm": 60,
    "ip_allowlist": [],
    "expires_at": "2027-01-01T00:00:00Z",
    "notes": "Acme quarterly reporting integration"
  }'
```

The raw key is returned once. Copy and store it before closing the response.

### Revoke a Vendor Key (Admin API — localhost only)

```bash
curl -s -X DELETE http://127.0.0.1:8001/v1/admin/ext-keys/<key_id>
```

### Export Scan Results as CSV (REST API)

```bash
curl -s "http://127.0.0.1:8001/api/scans/<scan_id>/export?format=csv" \
  -H "Authorization: Bearer <api_key>" \
  -o scan_results.csv
```

---

## See Also

- `documentation/vendor_api.md` — Full vendor integration guide: key provisioning, scope reference, rate limiting, and integration patterns
- `documentation/configuration.md` — Configuration reference including API key setup
- `documentation/setup.md` — Installation and environment setup
