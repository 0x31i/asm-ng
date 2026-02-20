# Implementation Plan: AI/ML Infrastructure Discovery Modules for asm-ng

## Feasibility Assessment

**Verdict: Fully feasible.** The existing SpiderFoot plugin architecture is ideally suited for this. The codebase already has:
- Shodan/Censys modules that find open ports and banners (`sfp_shodan`, `sfp_censys`)
- Certificate Transparency log querying (`sfp_crt`)
- DNS brute-forcing with custom wordlists (`sfp_dnsbrute`)
- Web content analysis modules that consume `TARGET_WEB_CONTENT` events
- TCP port scanning (`sfp_portscan_tcp`)
- A well-defined event type system, legacy mapping, and grading configuration

Every detection layer described in the research maps directly to existing architectural patterns.

---

## Module Design (3 New Modules)

### Module 1: `sfp_ai_fingerprint` — AI Infrastructure Detection & Active Fingerprinting
**Covers: Research Layers 1 (Passive) + 2 (Active Fingerprinting)**

**How it works:**
- Watches `TCP_PORT_OPEN`, `TCP_PORT_OPEN_BANNER`, and `WEBSERVER_BANNER` events produced by existing modules (Shodan, Censys, port scanner)
- When a known AI port is seen (11434, 8000, 8501, 8080, 5000, 3000, 7860, 8265, 1234), performs active HTTP fingerprinting
- Sends framework-specific probe requests using `self.sf.fetchUrl()`:
  - `GET /api/tags` → Ollama
  - `GET /v2/health/ready` → Triton Inference Server
  - `GET /v1/models` → OpenAI-compatible (vLLM, LiteLLM, LocalAI)
  - `GET /ping` → TorchServe
  - `GET /v1/models/{name}/metadata` → TensorFlow Serving
  - `GET /api/2.0/mlflow/experiments/list` → MLflow
  - `GET /healthz` + `GET /docs` → BentoML
  - `POST` with JSON-RPC 2.0 `tools/list` → MCP servers
  - `GET /api/` on port 7860 → Gradio
  - `GET /` on port 8265 → Ray Dashboard
- Analyzes response headers (`NV-Status`, `Server: uvicorn`) and body content to confirm frameworks
- Checks for unauthenticated model access (lists models, attempts inference)
- Also watches `WEBSERVER_BANNER` for AI-related strings in banners from any module

**Watches:** `TCP_PORT_OPEN`, `TCP_PORT_OPEN_BANNER`, `WEBSERVER_BANNER`, `IP_ADDRESS`
**Produces:** `AI_INFRASTRUCTURE_DETECTED`, `AI_MODEL_EXPOSED`, `AI_ENDPOINT_UNAUTHENTICATED`, `SOFTWARE_USED`

**Configuration options:**
- `ai_ports` — List of AI-specific ports to probe (configurable, with sane defaults)
- `active_fingerprint` — Enable/disable active HTTP probing (default: True)
- `check_auth` — Check whether endpoints require authentication (default: True)
- `probe_timeout` — Timeout for fingerprint probes in seconds (default: 15)

**Flags:** `["slow", "invasive"]` — active fingerprinting sends HTTP requests to targets

---

### Module 2: `sfp_ai_subdomain` — AI Subdomain & Certificate Discovery
**Covers: Research Layer 3**

**How it works:**
- Watches `DOMAIN_NAME` events
- Queries crt.sh for CT log certificates matching AI-related subdomain patterns
- Also performs targeted DNS brute-forcing using a bundled AI-specific wordlist
- Matches patterns: `inference.*`, `ml.*`, `ai.*`, `model.*`, `llm.*`, `chat.*`, `copilot.*`, `predict.*`, `serving.*`, `genai.*`, `gpu.*`, `triton.*`, `mlflow.*`, `ollama.*`, `huggingface.*`, `sagemaker.*`, `bedrock.*`, `vertex.*`, `openai.*`
- Produces `INTERNET_NAME` events that flow into the normal scan pipeline (DNS resolution → IP discovery → port scanning → Module 1 fingerprinting)

**Watches:** `DOMAIN_NAME`
**Produces:** `INTERNET_NAME`, `INTERNET_NAME_UNRESOLVED`, `AI_INFRASTRUCTURE_DETECTED`

**Configuration options:**
- `ai_subdomain_list` — Override the default AI subdomain wordlist
- `query_ct_logs` — Query crt.sh for AI-related certificates (default: True)
- `dns_bruteforce` — Brute-force AI subdomains via DNS (default: True)
- `check_cloud_patterns` — Check cloud provider AI patterns like *.sagemaker.* (default: True)

**Flags:** `[]` — passive by default (CT logs are public, DNS is normal)

---

### Module 3: `sfp_ai_webcontent` — AI Web Content & SDK Detection
**Covers: Research Layer 4**

**How it works:**
- Watches `TARGET_WEB_CONTENT` and `URL_JAVASCRIPT` events
- Scans HTML/JS content using regex patterns for:
  - **AI SDK imports:** `openai`, `@anthropic-ai/sdk`, `@vercel/ai`, `langchain`, `@huggingface/inference`, `cohere-ai`, `@google/generative-ai`, `replicate`, `@mistralai/mistralai`
  - **Chat widget markers:** `window.__ada`, `window.voiceflow`, `chatbase.co/embed`, `intercom`, `drift`
  - **API key patterns:** `sk-[a-zA-Z0-9]{20,}` (OpenAI), `hf_[a-zA-Z0-9]{20,}` (HuggingFace), `sk-ant-[a-zA-Z0-9]{20,}` (Anthropic), `AIza[a-zA-Z0-9_-]{35}` (Google AI)
  - **API endpoint references:** `/v1/chat/completions`, `/v1/embeddings`, `/api/generate`, `/v2/models`
- Produces events for each detection type

**Watches:** `TARGET_WEB_CONTENT`, `URL_JAVASCRIPT`, `LINKED_URL_EXTERNAL`
**Produces:** `AI_INFRASTRUCTURE_DETECTED`, `AI_API_KEY_LEAKED`, `SOFTWARE_USED`

**Configuration options:**
- `detect_sdks` — Detect AI SDK imports (default: True)
- `detect_api_keys` — Detect leaked API keys (default: True)
- `detect_widgets` — Detect AI chat widgets (default: True)
- `detect_endpoints` — Detect AI API endpoint references (default: True)

**Flags:** `[]` — purely analyzes already-fetched content

---

## New Event Types (4 types)

Register in `spiderfoot/db.py` `eventDetails`:

| Event Type | Description | Private | Category |
|---|---|---|---|
| `AI_INFRASTRUCTURE_DETECTED` | AI/ML Infrastructure Detected | 0 | DESCRIPTOR |
| `AI_MODEL_EXPOSED` | AI Model Exposed via Inference API | 0 | DESCRIPTOR |
| `AI_ENDPOINT_UNAUTHENTICATED` | AI Endpoint Without Authentication | 0 | DESCRIPTOR |
| `AI_API_KEY_LEAKED` | AI Service API Key Leaked | 0 | DATA |

---

## Event Type Legacy Mapping

Add to `spiderfoot/event_type_mapping.py` `EVENT_TYPE_LEGACY_MAPPING`:

| New Type | Legacy Type | Rationale |
|---|---|---|
| `AI_INFRASTRUCTURE_DETECTED` | `SOFTWARE_USED` | AI framework = software on host |
| `AI_MODEL_EXPOSED` | `SOFTWARE_USED` | Model = software component |
| `AI_ENDPOINT_UNAUTHENTICATED` | `VULNERABILITY_DISCLOSURE` | Unauth access = vulnerability |
| `AI_API_KEY_LEAKED` | `HASH` | Credential leak → generic data |

---

## Grading Configuration

Add to `spiderfoot/grade_config.py` `DEFAULT_EVENT_TYPE_GRADING`:

| Event Type | Category | Rank | Points | Logic |
|---|---|---|---|---|
| `AI_ENDPOINT_UNAUTHENTICATED` | Network Security | 1 | -20 | `unverified_exists` |
| `AI_MODEL_EXPOSED` | Network Security | 2 | -10 | `unverified_exists` |
| `AI_INFRASTRUCTURE_DETECTED` | Information / Reference | 5 | 0 | `informational` |
| `AI_API_KEY_LEAKED` | Information Leakage | 1 | -20 | `count_scaled` |

---

## New Data File

### `spiderfoot/dicts/ai-subdomains.txt`
AI-specific subdomain wordlist (~80 entries):
```
inference
ml
ai
model
models
llm
chat
copilot
predict
prediction
serving
genai
gen-ai
gpu
triton
mlflow
ollama
huggingface
sagemaker
bedrock
vertex
openai
anthropic
langchain
vector
embedding
embeddings
rag
agent
agents
ai-api
ml-api
api-ai
ml-platform
ai-platform
training
notebook
jupyter
tensorboard
mlops
feature-store
model-registry
pipeline
...
```

---

## Event Flow Diagram

```
                    ┌─────────────┐
                    │  DOMAIN_NAME│
                    └──────┬──────┘
                           │
              ┌────────────┼────────────────┐
              │            │                │
              ▼            ▼                ▼
     ┌────────────┐ ┌──────────┐   ┌──────────────┐
     │sfp_crt     │ │sfp_dns   │   │sfp_ai_       │
     │(CT logs)   │ │brute     │   │subdomain     │
     └─────┬──────┘ └────┬─────┘   │(AI wordlist) │
           │              │         └──────┬───────┘
           └──────┬───────┘                │
                  │ INTERNET_NAME          │
                  ▼                        │
         ┌────────────────┐                │
         │sfp_dnsresolve  │◄───────────────┘
         │→ IP_ADDRESS    │
         └───────┬────────┘
                 │
        ┌────────┼────────────┐
        ▼        ▼            ▼
 ┌──────────┐ ┌─────────┐ ┌─────────┐
 │sfp_shodan│ │sfp_     │ │sfp_     │
 │          │ │censys   │ │portscan │
 └────┬─────┘ └────┬────┘ └────┬────┘
      │             │           │
      └──────┬──────┘           │
             │ TCP_PORT_OPEN    │
             │ BANNER           │
             ▼                  │
   ┌──────────────────┐        │
   │sfp_ai_fingerprint│◄───────┘
   │(probe & confirm) │
   └────────┬─────────┘
            │
            ▼
   AI_INFRASTRUCTURE_DETECTED
   AI_MODEL_EXPOSED
   AI_ENDPOINT_UNAUTHENTICATED


   ┌─────────────────────┐
   │TARGET_WEB_CONTENT   │  (from sfp_spider)
   │URL_JAVASCRIPT       │
   └──────────┬──────────┘
              │
              ▼
   ┌──────────────────┐
   │sfp_ai_webcontent │
   │(JS/SDK analysis) │
   └────────┬─────────┘
            │
            ▼
   AI_INFRASTRUCTURE_DETECTED
   AI_API_KEY_LEAKED
   SOFTWARE_USED
```

---

## File-by-File Changes

### New Files (5):
1. `modules/sfp_ai_fingerprint.py` — Module 1
2. `modules/sfp_ai_subdomain.py` — Module 2
3. `modules/sfp_ai_webcontent.py` — Module 3
4. `spiderfoot/dicts/ai-subdomains.txt` — AI subdomain wordlist
5. `test/unit/modules/test_sfp_ai_fingerprint.py` — Tests for Module 1
6. `test/unit/modules/test_sfp_ai_subdomain.py` — Tests for Module 2
7. `test/unit/modules/test_sfp_ai_webcontent.py` — Tests for Module 3

### Modified Files (3):
1. `spiderfoot/db.py` — Add 4 new event types to `eventDetails` list
2. `spiderfoot/event_type_mapping.py` — Add legacy mappings for new types
3. `spiderfoot/grade_config.py` — Add grading rules for new types

---

## Implementation Priority / Build Order

1. **Phase 1 — Foundation** (do first):
   - Register the 4 new event types in `db.py`
   - Add legacy mappings in `event_type_mapping.py`
   - Add grading rules in `grade_config.py`
   - Create `spiderfoot/dicts/ai-subdomains.txt` wordlist

2. **Phase 2 — Module 1: `sfp_ai_fingerprint`** (highest value):
   - This is the core module. Once existing Shodan/Censys/port scan modules find AI ports, this module confirms and classifies them.
   - Provides the most immediate security value (finding exposed AI endpoints).

3. **Phase 3 — Module 2: `sfp_ai_subdomain`**:
   - Broadens discovery by finding AI-related subdomains that might not be in standard wordlists.
   - Feeds discovered hostnames into the normal pipeline → DNS → IP → ports → Module 1.

4. **Phase 4 — Module 3: `sfp_ai_webcontent`**:
   - Analyzes fetched web content for embedded AI integrations.
   - Catches AI usage that isn't visible at the infrastructure level.

5. **Phase 5 — Tests**:
   - Unit tests for all 3 modules following the existing pattern.
