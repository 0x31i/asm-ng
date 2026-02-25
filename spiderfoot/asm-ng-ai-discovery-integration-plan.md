# ASM-NG AI Discovery Module — Integration Blueprint

## Document Purpose

This document outlines the full architectural plan for integrating open-source AI infrastructure discovery tools into the ASM-NG platform as seamless, modular capabilities. The goal is to extend ASM-NG's existing scanning and analysis pipeline to detect, fingerprint, and assess externally-exposed AI/ML infrastructure — a critical blind spot in modern attack surface management.

---

## Executive Summary

The research identified **9 primary open-source tools** and **4 detection layers** that can be woven into ASM-NG's module architecture. Rather than building AI discovery from scratch, we'll wrap these battle-tested projects into standardized ASM-NG modules that feed into your existing GROUP-based processing pipeline. Think of it like building a new wing on a house — the plumbing (data pipeline) and electrical (reporting) already exist; we're just adding rooms (modules) that connect to them.

The integration follows three phases: **Foundation** (core scanning engine), **Expansion** (vulnerability + BOM capabilities), and **Maturity** (automated workflows + MITRE ATLAS mapping).

---

## Architecture Overview: The Four-Layer Detection Model

Each layer maps to a detection stage, and each stage is backed by one or more open-source tools. These layers mirror what the research identified as the ideal AI discovery pipeline:

```
┌─────────────────────────────────────────────────────────────────────┐
│                        ASM-NG CORE ENGINE                           │
│                  (Existing GROUP Pipeline + Reporting)               │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  LAYER 1              LAYER 2              LAYER 3       LAYER 4    │
│  Passive Recon        Active Fingerprint   Subdomain/CT  Web Content│
│  ┌──────────┐        ┌──────────────┐     ┌──────────┐ ┌─────────┐ │
│  │ Shodan   │        │ AI-Infra-    │     │ crt.sh   │ │ JS SDK  │ │
│  │ Censys   │───────▶│ Guard        │────▶│ subfinder│─│ Analysis│ │
│  │ API      │        │ ai-exploits  │     │ httpx    │ │ API Key │ │
│  │ Queries  │        │ Nuclei       │     │ CT Logs  │ │ Chat    │ │
│  └──────────┘        │ garak        │     └──────────┘ │ Widgets │ │
│       │              │ MCP Detect   │          │       └─────────┘ │
│       │              └──────────────┘          │            │      │
│       ▼                     ▼                  ▼            ▼      │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │               UNIFIED FINDINGS DATABASE                     │   │
│  │         (Feeds into existing GROUP processing)              │   │
│  └─────────────────────────────────────────────────────────────┘   │
│       │                                                            │
│       ▼                                                            │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐     │
│  │ AI-BOM       │  │ MITRE ATLAS  │  │ Risk Scoring &       │     │
│  │ Generation   │  │ Mapping      │  │ Existing Vuln Groups │     │
│  │ (CycloneDX)  │  │ (Technique   │  │ (GROUP 1-8 Pipeline) │     │
│  │              │  │  Tagging)    │  │                      │     │
│  └──────────────┘  └──────────────┘  └──────────────────────┘     │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

**Analogy:** Think of each layer like a stage in airport security. Layer 1 is the ticket counter — you're checking names against a list (passive scanning of known AI ports on Shodan). Layer 2 is the metal detector — actively probing each person/host for what they're carrying (fingerprinting frameworks). Layer 3 is checking the manifest — finding every flight/subdomain that could have AI cargo. Layer 4 is the baggage X-ray — looking inside the web content for hidden AI integrations. Miss any layer, and something gets through.

---

## Module Inventory: Open-Source Tools → ASM-NG Modules

### Module Map

| # | ASM-NG Module Name | Upstream Tool(s) | GitHub Source | License | Detection Layer | Priority |
|---|---|---|---|---|---|---|
| M1 | `ai-passive-recon` | Shodan API, Censys API | Custom (API wrappers) | N/A | Layer 1 | 🔴 P0 |
| M2 | `ai-fingerprint` | Tencent AI-Infra-Guard | `Tencent/AI-Infra-Guard` | MIT | Layer 2 | 🔴 P0 |
| M3 | `ai-vuln-scan` | Protect AI ai-exploits + Nuclei | `protectai/ai-exploits` | Apache 2.0 | Layer 2 | 🔴 P0 |
| M4 | `ai-subdomain-enum` | subfinder, crt.sh, httpx | Custom (wraps existing tools) | N/A | Layer 3 | 🟡 P1 |
| M5 | `ai-web-content` | Custom JS/SDK analyzer | Custom | N/A | Layer 4 | 🟡 P1 |
| M6 | `ai-llm-probe` | NVIDIA garak | `NVIDIA/garak` | Apache 2.0 | Layer 2 | 🟡 P1 |
| M7 | `ai-mcp-detect` | Wallarm MCP template | `wallarm/mcp-jsonrpc2-ultimate-detect` | — | Layer 2 | 🟡 P1 |
| M8 | `ai-bom-gen` | Trusera ai-bom + Cisco AIBOM | `Trusera/ai-bom`, `cisco/ai-defense` | Various | Post-processing | 🟢 P2 |
| M9 | `ai-repo-scan` | AIShield Watchtower + ModelScan | `bosch-aisecurity-aishield/watchtower`, `protectai/modelscan` | Various | Supplementary | 🟢 P2 |

---

## Phase 1: Foundation (Weeks 1–4) — "Get Eyes on the Target"

**Goal:** Stand up the core scanning capability — passive recon + active fingerprinting. This gives ASM-NG the ability to answer: *"Does this target have any externally-exposed AI infrastructure?"*

---

### Module M1: `ai-passive-recon` — Passive Internet Scanning

**What it does:** Queries Shodan and Censys for known AI service ports and banners within client IP ranges. This is the "wide net" that identifies candidate hosts before active probing.

**Upstream tooling:** Custom Python wrapper around Shodan and Censys APIs, following the Cisco Talos methodology.

**Implementation:**

```
asm-ng/
└── modules/
    └── ai-discovery/
        └── m1-passive-recon/
            ├── __init__.py
            ├── config.yaml           # Port definitions, banner patterns, API keys
            ├── shodan_scanner.py      # Shodan API query engine
            ├── censys_scanner.py      # Censys API query engine
            ├── port_signatures.yaml   # AI-specific port→service mappings
            ├── output_adapter.py      # Normalizes results → ASM-NG schema
            └── tests/
                ├── test_shodan.py
                └── test_censys.py
```

**`port_signatures.yaml` — Core Detection Targets:**

```yaml
ai_service_ports:
  - port: 11434
    service: "Ollama"
    protocol: "HTTP"
    validation_path: "/api/tags"
    risk_tier: "critical"    # Unauthenticated LLM access
    
  - port: 8000
    service: "Triton/vLLM"
    protocol: "HTTP"
    validation_path: "/v1/models"
    risk_tier: "high"
    note: "Shared port - requires Layer 2 fingerprinting to differentiate"
    
  - port: 8501
    service: "TensorFlow Serving / Streamlit"
    protocol: "HTTP/gRPC"
    validation_path: "/v1/models"
    risk_tier: "high"
    
  - port: 8080
    service: "TorchServe"
    protocol: "HTTP"
    validation_path: "/ping"
    expected_response: "Healthy"
    risk_tier: "high"
    
  - port: 8081
    service: "TorchServe Management"
    protocol: "HTTP"
    risk_tier: "critical"    # Management API = full control
    
  - port: 5000
    service: "MLflow"
    protocol: "HTTP"
    validation_path: "/api/2.0/mlflow/experiments/list"
    risk_tier: "critical"    # Experiment data, model artifacts
    
  - port: 3000
    service: "BentoML"
    protocol: "HTTP"
    validation_path: "/healthz"
    risk_tier: "high"
    
  - port: 7860
    service: "Gradio"
    protocol: "HTTP"
    risk_tier: "medium"
    
  - port: 8501
    service: "Streamlit"
    protocol: "HTTP"
    risk_tier: "medium"
    
  - port: 8265
    service: "Ray Dashboard"
    protocol: "HTTP"
    risk_tier: "critical"    # RCE history, cluster access
    
  - port: 1234
    service: "LM Studio"
    protocol: "HTTP"
    risk_tier: "high"

banner_indicators:
  - pattern: "Server: uvicorn"
    confidence: "low"
    note: "Broad indicator for Python-based AI backends"
  - pattern: "Server: tritonserver"
    confidence: "high"
  - pattern: "Ollama"
    confidence: "high"

shodan_dorks:
  - query: 'http.title:"MLflow" port:5000'
    target: "MLflow"
  - query: '"tritonserver" port:8000'
    target: "Triton Inference Server"
  - query: 'port:11434 "Ollama"'
    target: "Ollama"
  - query: '"v2/models" port:8000'
    target: "Generic ML Serving (v2 protocol)"
  - query: 'http.title:"Jupyter" port:8888'
    target: "Jupyter Notebook"
  - query: 'http.title:"Gradio"'
    target: "Gradio Interface"
  - query: 'http.title:"Ray Dashboard"'
    target: "Ray Cluster Dashboard"
```

**Shodan Query Logic (pseudocode):**

```python
# For each client engagement:
# 1. Get client IP ranges / ASN from existing ASM-NG asset inventory
# 2. Query Shodan for each AI port, scoped to client ranges
# 3. Check banner indicators as secondary signal
# 4. Normalize output → pass to M2 for active fingerprinting

def scan_passive(client_ip_ranges: list, client_asn: str = None):
    candidates = []
    
    for port_def in load_yaml("port_signatures.yaml")["ai_service_ports"]:
        # Scope query to client
        query = f"port:{port_def['port']} net:{','.join(client_ip_ranges)}"
        results = shodan_api.search(query)
        
        for host in results:
            candidates.append({
                "ip": host["ip_str"],
                "port": port_def["port"],
                "suspected_service": port_def["service"],
                "banner": host.get("data", ""),
                "risk_tier": port_def["risk_tier"],
                "detection_layer": "passive",
                "confidence": "medium",  # Passive = medium until confirmed
                "needs_active_fingerprint": True,
                "source": "shodan"
            })
    
    # Banner-based secondary detection
    for indicator in load_yaml("port_signatures.yaml")["banner_indicators"]:
        query = f'"{indicator["pattern"]}" net:{",".join(client_ip_ranges)}'
        # ... same pattern
    
    return candidates
```

**Output schema** (what gets passed downstream to M2 and into the ASM-NG findings DB):

```json
{
  "module": "ai-passive-recon",
  "timestamp": "2026-02-25T12:00:00Z",
  "target_scope": "client-xyz",
  "findings": [
    {
      "asset_ip": "203.0.113.45",
      "asset_port": 11434,
      "suspected_service": "Ollama",
      "banner_excerpt": "Ollama is running",
      "detection_method": "shodan_port_query",
      "confidence": "medium",
      "risk_tier": "critical",
      "needs_active_fingerprint": true,
      "atlas_technique": "AML.T0013",
      "raw_shodan_data": { }
    }
  ]
}
```

**Integration with existing ASM-NG:**
- Passive recon findings feed into a new `AI_Infrastructure` tab in the Excel output
- Each finding becomes a row that the existing GROUP pipeline can process
- Risk tiers align with the existing atypical technology detection framework (Tier 1–4 from the abnormal tech work)

---

### Module M2: `ai-fingerprint` — Active Fingerprinting via AI-Infra-Guard

**What it does:** Takes candidate hosts from M1 and actively probes them to confirm the specific AI framework, version, and exposure level. This is the "metal detector" — you've flagged a host on port 8000, but is it Triton, vLLM, or something else entirely?

**Upstream tooling:** Tencent AI-Infra-Guard (`Tencent/AI-Infra-Guard`, MIT license)

**Why AI-Infra-Guard as the core:**
- YAML-based fingerprint rules → easy to extend without modifying code
- Already covers 30+ AI framework components
- 400+ CVE detection rules included
- Docker-based deployment → clean isolation
- Architecture mirrors Nuclei (which your ai-exploits module will also use)

**Analogy:** AI-Infra-Guard's fingerprint YAML files are like a field guide for birdwatching. Each entry says "if you see these feathers (headers), hear this call (response pattern), and it lives in this habitat (port), it's a Red-Tailed Hawk (Ollama v0.3.x)." We're adding this field guide to ASM-NG's binoculars.

**Implementation:**

```
asm-ng/
└── modules/
    └── ai-discovery/
        └── m2-fingerprint/
            ├── __init__.py
            ├── config.yaml
            ├── infra_guard_wrapper.py      # Wraps AI-Infra-Guard CLI/API
            ├── custom_fingerprints/        # Our extensions to the YAML rules
            │   ├── mcp_servers.yaml        # MCP detection (from Wallarm)
            │   ├── openai_compatible.yaml  # vLLM/LiteLLM/LocalAI differentiator
            │   └── cloud_ai_services.yaml  # SageMaker, Vertex, Bedrock patterns
            ├── graphw00f_adapter.py        # Error-message-based differentiation
            ├── probe_engine.py             # Orchestrates probes against candidates
            ├── output_adapter.py
            ├── Dockerfile                  # Isolated AI-Infra-Guard runtime
            └── tests/
```

**AI-Infra-Guard Integration Pattern:**

```python
# AI-Infra-Guard stores fingerprints in data/fingerprints/*.yaml
# and vuln rules in data/vuln/*.yaml
#
# We DON'T fork the repo. Instead:
# 1. Pull AI-Infra-Guard as a Docker image or git submodule
# 2. Mount our custom_fingerprints/ as additional rule directories
# 3. Feed it targets from M1 passive recon output
# 4. Capture structured output → normalize to ASM-NG schema

class AIInfraGuardWrapper:
    """
    Wraps Tencent AI-Infra-Guard scanning engine.
    
    Deployment options:
      - Docker: docker run -v ./custom_fingerprints:/app/data/custom tencent/ai-infra-guard
      - Local: pip install + cli invocation
    """
    
    def __init__(self, custom_rules_dir="./custom_fingerprints"):
        self.custom_rules = custom_rules_dir
        # AI-Infra-Guard supports both WebUI and CLI modes
        # We use CLI for automation
    
    def scan_target(self, ip: str, port: int, suspected_service: str = None):
        """
        Probe a single target with AI-Infra-Guard fingerprint rules.
        Returns confirmed service identity + any CVEs detected.
        """
        # AI-Infra-Guard YAML fingerprint example:
        # ---
        # name: Ollama
        # rules:
        #   - method: GET
        #     path: /api/tags
        #     matchers:
        #       - type: status
        #         status: [200]
        #       - type: word
        #         words: ["models"]
        #         part: body
        
        result = run_infra_guard_cli(
            target=f"{ip}:{port}",
            fingerprint_dirs=["data/fingerprints", self.custom_rules],
            vuln_dirs=["data/vuln"],
            output_format="json"
        )
        
        return self._normalize(result)
    
    def scan_batch(self, candidates: list):
        """
        Batch scan all candidates from M1 passive recon.
        """
        confirmed = []
        for candidate in candidates:
            result = self.scan_target(
                ip=candidate["asset_ip"],
                port=candidate["asset_port"],
                suspected_service=candidate.get("suspected_service")
            )
            if result["confirmed"]:
                result["passive_data"] = candidate  # Preserve M1 context
                confirmed.append(result)
        
        return confirmed
```

**Custom Fingerprint Extension — OpenAI-Compatible API Differentiator:**

This is critical because vLLM, LiteLLM, LocalAI, and others all serve on `/v1/chat/completions`. Path matching alone can't tell them apart. We need error message fingerprinting (the graphw00f technique).

```yaml
# custom_fingerprints/openai_compatible.yaml
# 
# Problem: Multiple frameworks share /v1/chat/completions
# Solution: Send malformed requests and analyze error signatures

name: "OpenAI-Compatible Backend Differentiator"
description: "Distinguishes between vLLM, LiteLLM, LocalAI, etc."

probes:
  - id: "vllm_detect"
    method: POST
    path: "/v1/chat/completions"
    body: '{"model": "NONEXISTENT", "messages": [{"role": "user", "content": "test"}]}'
    matchers:
      - type: word
        words: ["vllm", "AsyncLLMEngine"]
        part: body
        condition: or
    tags: ["vllm"]
    
  - id: "litellm_detect"
    method: GET
    path: "/health/liveliness"    # LiteLLM-specific health endpoint
    matchers:
      - type: status
        status: [200]
      - type: word
        words: ["litellm"]
        part: body
    tags: ["litellm"]
    
  - id: "localai_detect"
    method: GET
    path: "/v1/models"
    matchers:
      - type: word
        words: ["LocalAI"]
        part: header
    tags: ["localai"]
    
  - id: "header_analysis"
    method: GET
    path: "/v1/models"
    extract:
      - header: "server"        # "uvicorn" = Python-based (vLLM, FastAPI)
      - header: "x-powered-by"  # Sometimes reveals framework
      - header: "x-request-id"  # Pattern differs by framework
```

**Confirmed finding output (M2 → findings DB):**

```json
{
  "module": "ai-fingerprint",
  "asset_ip": "203.0.113.45",
  "asset_port": 11434,
  "confirmed_service": "Ollama",
  "confirmed_version": "0.3.12",
  "authentication": "none",
  "models_exposed": ["llama3.1:8b", "codellama:13b"],
  "cves_detected": ["CVE-2024-XXXXX"],
  "confidence": "high",
  "risk_tier": "critical",
  "detection_layer": "active",
  "atlas_techniques": ["AML.T0013", "AML.T0014"],
  "vuln_type": "AI-Infrastructure-Exposure",
  "finding_title": "Unauthenticated Ollama LLM Server Exposed",
  "remediation_priority": "immediate"
}
```

---

### Module M3: `ai-vuln-scan` — Vulnerability Scanning via Nuclei + ai-exploits

**What it does:** Takes confirmed AI services from M2 and runs vulnerability-specific checks. While M2 says "this is MLflow," M3 says "this MLflow has LFI and unauthenticated access."

**Upstream tooling:** Protect AI's `ai-exploits` Nuclei templates + ProjectDiscovery Nuclei engine

**Implementation:**

```
asm-ng/
└── modules/
    └── ai-discovery/
        └── m3-vuln-scan/
            ├── __init__.py
            ├── config.yaml
            ├── nuclei_runner.py        # Nuclei CLI wrapper
            ├── templates/
            │   ├── ai-exploits/        # git submodule → protectai/ai-exploits
            │   ├── mcp-detect/         # Wallarm MCP detection template
            │   └── custom/             # Our custom templates
            │       ├── ollama-unauth.yaml
            │       ├── gradio-ssrf.yaml
            │       └── ray-dashboard-rce.yaml
            ├── output_adapter.py
            └── tests/
```

**Nuclei integration pattern:**

```python
class NucleiAIScanner:
    """
    Runs Nuclei with AI-specific templates against confirmed AI hosts.
    
    Template sources:
    1. protectai/ai-exploits - MLflow LFI, Ray RCE, BentoML, AnythingLLM
    2. Wallarm MCP detection - JSON-RPC 2.0 MCP server probes
    3. Custom templates - additional checks we write
    """
    
    def __init__(self):
        self.template_dirs = [
            "templates/ai-exploits/nuclei/",
            "templates/mcp-detect/",
            "templates/custom/"
        ]
    
    def scan_confirmed_hosts(self, confirmed_findings: list):
        """
        Run Nuclei against hosts confirmed by M2.
        Only scans relevant templates based on confirmed service type.
        """
        target_file = self._write_targets(confirmed_findings)
        
        # Nuclei CLI invocation
        # -t = template dirs
        # -target = input file
        # -jsonl = structured output
        cmd = [
            "nuclei",
            "-target", target_file,
            "-t", ",".join(self.template_dirs),
            "-jsonl",
            "-severity", "critical,high,medium",
            "-rate-limit", "50",  # Be responsible
            "-timeout", "10"
        ]
        
        results = subprocess.run(cmd, capture_output=True, text=True)
        return self._parse_nuclei_output(results.stdout)
    
    def scan_service_specific(self, host: str, port: int, service: str):
        """
        Run only templates relevant to the identified service.
        
        Example: If M2 confirmed MLflow, only run:
          - mlflow-lfi.yaml
          - mlflow-unauth.yaml
          - mlflow-rce.yaml
        """
        service_template_map = {
            "MLflow": ["mlflow-*.yaml"],
            "Ray Dashboard": ["ray-*.yaml"],
            "Ollama": ["ollama-*.yaml"],
            "BentoML": ["bentoml-*.yaml"],
            "Gradio": ["gradio-*.yaml"],
            "MCP Server": ["mcp-*.yaml"],
            "AnythingLLM": ["anythingllm-*.yaml"],
        }
        
        templates = service_template_map.get(service, ["*.yaml"])
        # ... run nuclei with filtered templates
```

**Key ai-exploits templates we're wrapping:**

| Template | Target | Vulnerability | Severity |
|---|---|---|---|
| `mlflow-lfi.yaml` | MLflow | Local File Inclusion | Critical |
| `mlflow-unauth.yaml` | MLflow | Unauthenticated experiment access | High |
| `ray-dashboard-rce.yaml` | Ray | Remote Code Execution | Critical |
| `bentoml-*.yaml` | BentoML | Various endpoint exposures | High |
| `anythingllm-*.yaml` | AnythingLLM | Auth bypass, SSRF | High |
| `mcp-jsonrpc2-ultimate-detect.yaml` | MCP Servers | Exposed MCP internals | High |

**Where this fits in the existing pipeline:**

Findings from M3 map directly into your existing vulnerability processing. Each vuln gets:
- `Vuln_Type`: "AI-Infrastructure-Vulnerability"
- `Asset`: IP:port
- `Plugin_Name`: Template ID (e.g., "mlflow-lfi")
- Severity aligned with your existing tier system
- These flow into GROUP processing alongside your SpiderFoot/Burp findings

---

## Phase 2: Expansion (Weeks 5–8) — "Map the Full Surface"

**Goal:** Add subdomain enumeration, web content analysis, and LLM-specific probing. Now we're answering: *"What AI services exist that we DIDN'T find through port scanning?"*

---

### Module M4: `ai-subdomain-enum` — Subdomain & Certificate Discovery

**What it does:** Finds AI-related subdomains and certificate registrations that reveal AI infrastructure before it's even port-scanned.

**Approach:** Custom module wrapping existing recon tools with an AI-specific wordlist.

```
asm-ng/
└── modules/
    └── ai-discovery/
        └── m4-subdomain-enum/
            ├── __init__.py
            ├── config.yaml
            ├── ct_log_scanner.py       # crt.sh / Censys CT log queries
            ├── dns_bruteforce.py       # subfinder + custom AI wordlist
            ├── cloud_pattern_match.py  # SageMaker, Vertex, Bedrock patterns
            ├── wordlists/
            │   └── ai-subdomains.txt   # AI-specific subdomain wordlist
            ├── liveness_checker.py     # httpx wrapper for alive checks
            ├── output_adapter.py
            └── tests/
```

**AI-specific subdomain wordlist (`ai-subdomains.txt`):**

```
inference
ml
ai
model
llm
chat
copilot
predict
serving
genai
gpu
triton
mlflow
jupyter
notebook
huggingface
openai
bedrock
sagemaker
vertex
ollama
gradio
streamlit
comfyui
langchain
vectordb
embeddings
rag
agent
mcp
training
fine-tune
dataset
pipeline
```

**CT Log reconnaissance command (the foundation):**

```bash
# This is the "golden query" from the research
curl -s "https://crt.sh/?q=%25.${TARGET_DOMAIN}&output=json" \
  | jq -r '.[].name_value' \
  | sort -u \
  | grep -iE '(inference|ml|ai|model|llm|chat|copilot|predict|gpu|triton|mlflow|serving|genai|ollama|gradio|streamlit|jupyter|notebook|sagemaker|vertex|bedrock|huggingface)'
```

**Cloud provider pattern matching:**

```yaml
# cloud_ai_patterns.yaml
cloud_patterns:
  aws_sagemaker:
    pattern: "*.sagemaker.{region}.amazonaws.com"
    regions: ["us-east-1", "us-west-2", "eu-west-1"]
    risk_note: "SageMaker endpoints may expose model artifacts"
    
  azure_inference:
    pattern: "*.inference.{region}.azurecontainer.io"
    risk_note: "Azure container inference endpoints"
    
  huggingface_endpoints:
    pattern: "*.endpoints.huggingface.cloud"
    risk_note: "Dedicated HuggingFace inference endpoints"
    
  google_vertex:
    pattern: "*.aiplatform.googleapis.com"
    risk_note: "Vertex AI prediction endpoints"
```

**Pipeline flow:**

```
M4 discovers subdomains → httpx liveness check → alive hosts fed to M1/M2 for scanning
```

---

### Module M5: `ai-web-content` — Web Content Analysis for Embedded AI

**What it does:** Crawls discovered web assets looking for AI integrations that don't expose backend ports — things like embedded chatbots, SDK imports, and leaked API keys in JavaScript.

**Real-world example:** A company's main website at `www.example.com` has no open AI ports, but their JavaScript bundle imports `@anthropic-ai/sdk` and contains a hardcoded `sk-ant-*` API key. M1–M3 would never find this. M5 catches it.

```
asm-ng/
└── modules/
    └── ai-discovery/
        └── m5-web-content/
            ├── __init__.py
            ├── config.yaml
            ├── js_analyzer.py          # JavaScript SDK/import detection
            ├── api_key_detector.py      # AI API key pattern matching
            ├── chat_widget_detector.py  # Embedded chatbot fingerprinting
            ├── signatures/
            │   ├── sdk_imports.yaml     # Known AI SDK import patterns
            │   ├── api_key_patterns.yaml
            │   └── chat_widgets.yaml
            ├── output_adapter.py
            └── tests/
```

**Detection signatures:**

```yaml
# sdk_imports.yaml
javascript_sdk_patterns:
  - name: "OpenAI SDK"
    patterns: ["openai", "from 'openai'", "require('openai')"]
    risk: "high"
    
  - name: "Anthropic SDK"
    patterns: ["@anthropic-ai/sdk", "anthropic"]
    risk: "high"
    
  - name: "Vercel AI SDK"
    patterns: ["@vercel/ai", "ai/react"]
    risk: "medium"
    
  - name: "LangChain JS"
    patterns: ["@langchain", "langchain/llms"]
    risk: "medium"
    
  - name: "HuggingFace JS"
    patterns: ["@huggingface/inference"]
    risk: "medium"

# api_key_patterns.yaml
api_key_patterns:
  - name: "OpenAI API Key"
    regex: "sk-[a-zA-Z0-9]{20,}"
    severity: "critical"
    
  - name: "HuggingFace Token"
    regex: "hf_[a-zA-Z0-9]{20,}"
    severity: "critical"
    
  - name: "Anthropic API Key"
    regex: "sk-ant-[a-zA-Z0-9-]{20,}"
    severity: "critical"

# chat_widgets.yaml
chat_widget_markers:
  - name: "Ada Chat"
    indicators: ["window.__ada", "ada.ai"]
    
  - name: "Voiceflow"
    indicators: ["window.voiceflow", "voiceflow.com"]
    
  - name: "Chatbase"
    indicators: ["chatbase.co/embed", "chatbase-bubble"]
    
  - name: "Intercom AI"
    indicators: ["intercomSettings", "widget.intercom.io"]
    note: "Check if AI features enabled"
```

---

### Module M6: `ai-llm-probe` — LLM Endpoint Validation via garak

**What it does:** For confirmed LLM endpoints, uses NVIDIA's garak to validate they're actually serving models and assess their security posture (prompt injection, jailbreak susceptibility).

**Upstream tooling:** NVIDIA garak (`NVIDIA/garak`, Apache 2.0)

```
asm-ng/
└── modules/
    └── ai-discovery/
        └── m6-llm-probe/
            ├── __init__.py
            ├── config.yaml
            ├── garak_wrapper.py        # garak CLI/API integration
            ├── probe_profiles/
            │   ├── discovery.yaml      # Lightweight: "Is this an LLM?"
            │   ├── auth_check.yaml     # "Does it require authentication?"
            │   └── security_posture.yaml # Deeper: injection, jailbreak
            ├── output_adapter.py
            └── tests/
```

**Probe profiles — tiered approach:**

```yaml
# discovery.yaml — Lightweight probe: "Is this actually an LLM?"
# Run this first. If it confirms LLM, escalate to deeper probes.
profile: "discovery"
generators:
  - type: "rest"
    target_endpoint: "${TARGET_URL}"
probes:
  - "encoding.InjectBase64"    # Simple probe to test if endpoint responds to prompts
detectors:
  - "always.Pass"              # Just checking for ANY coherent response

---
# auth_check.yaml — "Does it require authentication?"
profile: "auth_check"
# Attempt inference without credentials
# If successful = CRITICAL finding (unauthenticated LLM access)

---
# security_posture.yaml — Deeper security assessment
# Only run with explicit client authorization
profile: "security_posture"
probes:
  - "promptinject.HijackHateHumansMini"  # Prompt injection
  - "dan.Dan_11_0"                         # Jailbreak
  - "leakreplay.LiteratureCloze80"         # Training data extraction
```

**When to use each profile:**

| Profile | When | Authorization Needed |
|---|---|---|
| `discovery` | Always — confirms LLM presence | Standard ASM scope |
| `auth_check` | Always on confirmed LLMs | Standard ASM scope |
| `security_posture` | Only on client-owned assets | Explicit pentest authorization |

---

### Module M7: `ai-mcp-detect` — MCP Server Detection

**What it does:** Specifically probes for exposed Model Context Protocol (MCP) servers, which are an emerging and high-risk attack surface. MCP servers can expose tools, resources, and prompts to unauthorized callers.

**Upstream tooling:** Wallarm's `mcp-jsonrpc2-ultimate-detect` Nuclei template

**Implementation:** This is lightweight enough to be a sub-module within M3 (Nuclei runner), but gets its own logical module for clarity:

```yaml
# Wallarm MCP detection — JSON-RPC 2.0 probes
# These probe methods reveal if an MCP server is active and what it exposes

probes:
  - method: "tools/list"
    description: "Lists all tools the MCP server can execute"
    risk: "critical - reveals available actions"
    
  - method: "resources/list"
    description: "Lists all resources (data sources) available"
    risk: "high - reveals data access paths"
    
  - method: "prompts/list"
    description: "Lists available prompt templates"
    risk: "medium - reveals AI capabilities"
    
  - method: "rpc.discover"
    description: "Full JSON-RPC capability discovery"
    risk: "high - reveals complete API surface"
```

---

## Phase 3: Maturity (Weeks 9–12+) — "Catalog and Standardize"

**Goal:** Generate AI Bills of Materials, map everything to MITRE ATLAS, and build the reporting/compliance layer.

---

### Module M8: `ai-bom-gen` — AI Bill of Materials Generation

**What it does:** Takes all discovered AI components and generates standardized AI-BOMs in CycloneDX 1.6 and SPDX 3.0 formats for compliance and inventory tracking.

**Upstream tooling:** Trusera `ai-bom` (13 auto-registered scanners) + Cisco `ai-defense/aibom`

```
asm-ng/
└── modules/
    └── ai-discovery/
        └── m8-bom-gen/
            ├── __init__.py
            ├── config.yaml
            ├── bom_generator.py        # Aggregates all findings → BOM
            ├── cyclonedx_adapter.py     # CycloneDX 1.6 output
            ├── spdx_adapter.py          # SPDX 3.0 output
            ├── sarif_adapter.py         # SARIF for CI/CD integration
            └── tests/
```

**BOM entry for a discovered Ollama instance:**

```json
{
  "bom-ref": "ai-component-001",
  "type": "machine-learning-model",
  "name": "Ollama Server",
  "version": "0.3.12",
  "description": "Externally exposed Ollama LLM serving instance",
  "properties": [
    { "name": "discovery:method", "value": "passive-recon + active-fingerprint" },
    { "name": "discovery:module", "value": "M1 → M2 → M3" },
    { "name": "exposure:authentication", "value": "none" },
    { "name": "exposure:models", "value": "llama3.1:8b, codellama:13b" },
    { "name": "atlas:technique", "value": "AML.T0013, AML.T0014" },
    { "name": "risk:tier", "value": "critical" }
  ],
  "evidence": {
    "occurrences": [
      { "location": "203.0.113.45:11434" }
    ]
  }
}
```

---

### Module M9: `ai-repo-scan` — Repository & Model File Scanning

**What it does:** Scans discovered repositories and model files for hardcoded secrets, PII, unsafe serialization, and malicious payloads.

**Upstream tooling:** 
- AIShield Watchtower (Bosch) — scans GitHub, HuggingFace, S3 for secrets/PII in AI repos
- Protect AI ModelScan — detects malicious code in serialized model files (.pkl, .h5, .pt)

```
asm-ng/
└── modules/
    └── ai-discovery/
        └── m9-repo-scan/
            ├── __init__.py
            ├── config.yaml
            ├── watchtower_wrapper.py    # AIShield Watchtower integration
            ├── modelscan_wrapper.py     # ModelScan integration
            ├── output_adapter.py
            └── tests/
```

**Use cases:**
- Client's GitHub org has a public repo with a `requirements.txt` including `torch==1.9.0` (known vuln)
- Model file on public S3 contains pickle deserialization exploit
- HuggingFace model card leaks internal infrastructure details

---

## MITRE ATLAS Mapping — Every Finding Gets a Technique ID

All modules tag findings with MITRE ATLAS technique IDs for standardized reporting:

| ASM-NG Finding | ATLAS Technique | Description |
|---|---|---|
| Exposed AI service discovered (passive) | AML.T0013 | Discover ML Model Ontology |
| AI framework identified (active) | AML.T0014 | Discover ML Model Family |
| Unauthenticated inference API | AML.TA0004 | ML Model Access |
| Leaked API key in JavaScript | AML.T0000 | Search Victim's Public Materials |
| AI subdomain found via CT logs | AML.T0003 | Search Victim-Owned Websites |
| Prompt injection possible | AML.T0051 | LLM Prompt Injection |
| Model file contains malicious payload | AML.T0010 | ML Supply Chain Compromise |

---

## Integration with Existing ASM-NG GROUP Pipeline

This is where it all connects to what you already have. The AI discovery modules produce findings that slot into your existing 8-GROUP processing workflow:

```
┌──────────────────────────────────────────────┐
│           AI DISCOVERY MODULES               │
│    M1 → M2 → M3 → M4 → M5 → M6 → M7       │
└──────────────┬───────────────────────────────┘
               │
               ▼
┌──────────────────────────────────────────────┐
│        NEW: AI_Findings_Raw.xlsx             │
│   (Standardized output from all modules)     │
│                                              │
│   Columns:                                   │
│   - Vuln_Type (matches existing schema)      │
│   - Asset (IP:port or subdomain)             │
│   - Plugin_Name (module + template ID)       │
│   - Severity (Critical/High/Medium/Low)      │
│   - AI_Service (Ollama, MLflow, etc.)        │
│   - Auth_Status (none/weak/strong)           │
│   - Models_Exposed (if applicable)           │
│   - ATLAS_Technique (AML.TXXXX)             │
│   - Detection_Layer (passive/active/etc.)    │
│   - Confidence (high/medium/low)             │
│   - Remediation_Priority (immediate/short/long)│
└──────────────┬───────────────────────────────┘
               │
               ▼
┌──────────────────────────────────────────────┐
│     EXISTING GROUP PIPELINE                  │
│                                              │
│   Option A: New GROUP 9 (AI-specific)        │
│   - Processes AI_Findings_Raw.xlsx           │
│   - Applies atypical tech detection logic    │
│   - Generates AI-specific risk narrative     │
│                                              │
│   Option B: Merge into existing GROUPs       │
│   - AI web app vulns → GROUP 1              │
│   - AI infrastructure → GROUP 2             │
│   - AI certificates → GROUP 3              │
│   - AI as atypical tech → existing detection│
└──────────────┬───────────────────────────────┘
               │
               ▼
┌──────────────────────────────────────────────┐
│     FINAL CONSOLIDATION                      │
│   - AI findings included alongside existing  │
│   - AI-BOM appended as supplementary section │
│   - MITRE ATLAS mapping in executive summary │
└──────────────────────────────────────────────┘
```

**Recommendation:** Start with **Option A (GROUP 9)** for Phase 1–2. It keeps AI findings isolated and easy to debug. Once stable, evaluate merging into existing GROUPs for Phase 3.

---

## Full Project Directory Structure

```
asm-ng/
├── modules/
│   ├── existing-modules/          # Your current SpiderFoot, Burp, etc.
│   │
│   └── ai-discovery/             # NEW: All AI discovery modules
│       ├── __init__.py
│       ├── orchestrator.py        # Master controller: runs M1→M9 in sequence
│       ├── config/
│       │   ├── global_config.yaml # API keys, rate limits, scope
│       │   └── risk_tiers.yaml    # AI-specific risk tier definitions
│       │
│       ├── shared/
│       │   ├── output_schema.py   # Unified finding schema (all modules use)
│       │   ├── atlas_mapper.py    # MITRE ATLAS technique tagger
│       │   ├── deduplicator.py    # Cross-module dedup logic
│       │   └── obfuscation.py     # Your existing obfuscation pipeline hooks
│       │
│       ├── m1-passive-recon/      # Shodan/Censys passive scanning
│       ├── m2-fingerprint/        # AI-Infra-Guard active fingerprinting
│       ├── m3-vuln-scan/          # Nuclei + ai-exploits vuln scanning
│       ├── m4-subdomain-enum/     # CT log + DNS AI subdomain discovery
│       ├── m5-web-content/        # JavaScript/SDK/API key analysis
│       ├── m6-llm-probe/          # garak LLM validation + security
│       ├── m7-mcp-detect/         # Wallarm MCP server detection
│       ├── m8-bom-gen/            # AI-BOM generation (CycloneDX/SPDX)
│       └── m9-repo-scan/          # Watchtower + ModelScan
│
├── group-prompts/
│   ├── GROUP1-8/                  # Existing processing prompts
│   └── GROUP9-AI/                 # NEW: AI-specific processing prompt
│
├── docker/
│   ├── ai-infra-guard/            # AI-Infra-Guard container
│   ├── nuclei/                    # Nuclei + templates container
│   └── garak/                     # garak container
│
└── vendor/                        # Git submodules for upstream tools
    ├── AI-Infra-Guard/            # Tencent/AI-Infra-Guard
    ├── ai-exploits/               # protectai/ai-exploits
    ├── garak/                     # NVIDIA/garak
    ├── ai-bom/                    # Trusera/ai-bom
    └── watchtower/                # bosch-aisecurity-aishield/watchtower
```

---

## Orchestration: How a Full Scan Runs

```python
# orchestrator.py — Master scan controller

class AIDiscoveryOrchestrator:
    """
    Runs all AI discovery modules in the correct sequence.
    
    Analogy: Think of this like a medical diagnostic pipeline.
    - M1 (passive) = initial screening / blood test → "something might be here"
    - M2 (fingerprint) = specialist examination → "it's definitely X"
    - M3 (vuln scan) = detailed imaging → "here's exactly what's wrong"
    - M4 (subdomain) = checking family history → "there might be more we haven't seen"
    - M5 (web content) = checking lifestyle → "hidden risk factors"
    - M6 (LLM probe) = stress test → "how bad is it under pressure?"
    - M7 (MCP detect) = checking connected systems → "what else is exposed?"
    - M8 (BOM gen) = full medical report → "here's the complete picture"
    - M9 (repo scan) = genetic testing → "supply chain risks"
    """
    
    def run_full_scan(self, client_config: dict):
        # Phase 1: Discovery
        passive_results = M1_PassiveRecon().scan(client_config["ip_ranges"])
        fingerprinted = M2_Fingerprint().scan(passive_results)
        vulns = M3_VulnScan().scan(fingerprinted)
        
        # Phase 2: Expansion
        subdomains = M4_SubdomainEnum().scan(client_config["domains"])
        # Feed discovered subdomains back through M1→M2→M3
        subdomain_hosts = M1_PassiveRecon().scan_hosts(subdomains)
        subdomain_fingerprinted = M2_Fingerprint().scan(subdomain_hosts)
        subdomain_vulns = M3_VulnScan().scan(subdomain_fingerprinted)
        
        web_content = M5_WebContent().scan(client_config["web_assets"])
        llm_probes = M6_LLMProbe().scan(fingerprinted.filter(type="llm"))
        mcp_findings = M7_MCPDetect().scan(fingerprinted)
        
        # Phase 3: Reporting
        all_findings = merge_and_dedup(
            vulns, subdomain_vulns, web_content, llm_probes, mcp_findings
        )
        
        bom = M8_BOMGen().generate(all_findings)
        repo_findings = M9_RepoScan().scan(client_config.get("repos", []))
        
        # Output → feeds into GROUP 9 processing
        export_to_excel(all_findings, "AI_Findings_Raw.xlsx")
        export_bom(bom, format="cyclonedx")
        
        return all_findings
```

---

## Implementation Timeline

| Week | Phase | Modules | Milestone |
|---|---|---|---|
| 1–2 | Foundation | M1 (passive recon) | Shodan/Censys queries return AI candidates for test client |
| 2–3 | Foundation | M2 (fingerprint) | AI-Infra-Guard Docker deployed, confirming services |
| 3–4 | Foundation | M3 (vuln scan) | Nuclei + ai-exploits running, vulns detected |
| 4 | Foundation | Integration | M1→M2→M3 pipeline working end-to-end, output → Excel |
| 5–6 | Expansion | M4 (subdomain) | CT log + DNS enumeration finding AI subdomains |
| 6–7 | Expansion | M5 (web content) | JS analysis catching embedded AI, leaked keys |
| 7–8 | Expansion | M6 + M7 (LLM + MCP) | garak validating LLMs, MCP servers detected |
| 8 | Expansion | Integration | Full Layer 1–4 pipeline operational |
| 9–10 | Maturity | M8 (BOM) | CycloneDX AI-BOMs generated per engagement |
| 10–11 | Maturity | M9 (repo scan) | Watchtower + ModelScan integrated |
| 11–12 | Maturity | GROUP 9 + ATLAS | Full reporting pipeline with MITRE ATLAS mapping |

---

## Risk Tiers for AI Findings (Aligned to Existing Framework)

| Tier | Criteria | Examples | Response Time |
|---|---|---|---|
| **Tier 0 — Emergency** | Unauthenticated AI admin/management with RCE | Ray Dashboard RCE, TorchServe management API exposed | Immediate (hours) |
| **Tier 1 — Critical** | Unauthenticated LLM/model access, leaked production API keys | Ollama without auth, hardcoded `sk-*` keys, MLflow LFI | 1–24 hours |
| **Tier 2 — High** | Authenticated but misconfigured AI services, weak auth on inference APIs | Gradio with default creds, BentoML without TLS, exposed Jupyter | 1–7 days |
| **Tier 3 — Medium** | AI subdomains revealing architecture, embedded chatbots without guardrails, exposed model cards | `ml.example.com` in CT logs, chat widget without rate limiting | 1–2 weeks |
| **Tier 4 — Low/Informational** | AI technology detected (shadow IT awareness), SDK imports without key exposure | Vercel AI SDK imported, HuggingFace integration detected | Track and monitor |

---

## Obfuscation Considerations

Since AI findings will contain sensitive client data (IPs, domains, model names, API keys), they **must** pass through your existing obfuscation pipeline before analysis:

- AI service IPs → `IP_ADDRESS_TOKEN_#####`
- Discovered subdomains → `DOMAIN_TOKEN_#####`
- Model names (if client-specific) → `AI_MODEL_TOKEN_#####`
- API keys (always) → `API_KEY_TOKEN_#####` (redact entirely — never include actual keys in reports)
- Shodan/Censys raw data → full tokenization before GROUP processing

**New obfuscation patterns to add:**

```python
# Add to existing obfuscation regex patterns
ai_obfuscation_patterns = {
    r'sk-[a-zA-Z0-9]{20,}': 'OPENAI_KEY_REDACTED',
    r'hf_[a-zA-Z0-9]{20,}': 'HF_TOKEN_REDACTED',
    r'sk-ant-[a-zA-Z0-9-]{20,}': 'ANTHROPIC_KEY_REDACTED',
    r'AKIA[0-9A-Z]{16}': 'AWS_KEY_REDACTED',
}
```

---

## Next Steps (Actionable)

1. **Set up the `ai-discovery/` directory structure** in the ASM-NG repo
2. **Clone AI-Infra-Guard** as a git submodule: `git submodule add https://github.com/Tencent/AI-Infra-Guard.git vendor/AI-Infra-Guard`
3. **Clone ai-exploits** templates: `git submodule add https://github.com/protectai/ai-exploits.git vendor/ai-exploits`
4. **Build M1** first — get Shodan queries working against a test IP range
5. **Build M2** — get AI-Infra-Guard Docker container running and accepting M1 output
6. **Build M3** — install Nuclei, point it at ai-exploits templates
7. **Test the M1→M2→M3 chain** against a known Ollama/MLflow instance (set one up in a lab)
8. **Create GROUP 9 prompt** to process AI findings alongside existing GROUPs
