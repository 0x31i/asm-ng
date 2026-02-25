# ASM-NG AI Discovery Expansion — Strategic & Technical Plan

## Context

ASM-NG already has a working AI discovery foundation (3 modules, 4 event types, grading integration). The uploaded blueprint (`spiderfoot/asm-ng-ai-discovery-integration-plan.md`) proposes 9 modules across 3 phases. This plan validates that blueprint against what's already built, identifies what's truly new vs. enhancements, proposes additional high-value modules beyond the original 9, and packages the whole thing as a standalone CISO-ready service offering.

**Why now:** The AI attack surface is exploding — 175,000+ exposed Ollama servers (Jan 2026), active LLMjacking campaigns (Operation Bizarre Bazaar), EU AI Act compliance deadline Aug 2026, OWASP Top 10 for Agentic Applications just released, and 80% of CISOs prioritizing AI security budget. The AI red teaming market is growing at 30.5% CAGR ($1.3B → $18.6B by 2035). There is no open-source competitor doing comprehensive outside-in AI discovery + testing at this level.

### Key Decisions
- **Architecture:** All new modules follow the standard SpiderFoot plugin pattern (`modules/sfp_ai_*.py`) — consistent with existing 3 AI modules, leverages event pipeline, grading, and correlation engine
- **Service tiers:** Build platform to support all three tiers (Discovery Scan, Security Assessment, Continuous Monitoring)
- **External tools strategy:** Use external tools where they're genuinely superior (garak for LLM probing — maintains community-updated probe/detector library; Nuclei for vuln scanning — 400+ AI CVE templates from protectai/ai-exploits; ModelScan for model file analysis — deep binary introspection). Use pure Python/HTTP probing via `self.sf.fetchUrl()` for everything else (fingerprinting, subdomain enum, shadow AI, vector DB scanning, MCP detection). External tools integrated as optional enhancers — modules work standalone with HTTP probing, get deeper capability when external tools are available.

---

## Part 1: Blueprint Validation — What's Already Built vs. What's New

### Module Overlap Analysis

| Blueprint Module | Existing ASM-NG Module | Status | Recommendation |
|---|---|---|---|
| M1: `ai-passive-recon` (Shodan/Censys) | `sfp_shodan.py` + `sfp_censys.py` exist as general modules | **Partially covered** | Create new `sfp_ai_passive_recon.py` that wraps existing Shodan/Censys modules with AI-specific dorks and port signatures. Don't rebuild API wrappers — reuse `self.sf.fetchUrl()` pattern. |
| M2: `ai-fingerprint` (AI-Infra-Guard) | `sfp_ai_fingerprint.py` already detects 11 frameworks | **Heavily overlaps** | Enhance existing module: add AI-Infra-Guard's YAML rules as additional detection signatures. Don't create separate module — extend `sfp_ai_fingerprint.py` with the graphw00f differentiator and OpenAI-compatible backend detection. |
| M3: `ai-vuln-scan` (Nuclei + ai-exploits) | `sfp_tool_nuclei.py` exists for general Nuclei scanning | **Partially covered** | Create `sfp_ai_vulnscan.py` that extends the Nuclei pattern with AI-specific template directories (protectai/ai-exploits). Reuse the Nuclei runner pattern from `sfp_tool_nuclei.py`. |
| M4: `ai-subdomain-enum` | `sfp_ai_subdomain.py` already does CT logs + DNS brute-force with 84-term wordlist + cloud CNAME patterns | **Already built** | Enhance existing module: expand wordlist from 84 → 150+ terms (add `mcp`, `agent`, `rag`, `vector`, `embedding`, `finetune`, `comfyui`, `langserve`, etc.). Add subfinder integration as optional tool. |
| M5: `ai-web-content` | `sfp_ai_webcontent.py` already detects SDKs, API keys, chat widgets, endpoints | **Already built** | Enhance existing module: add MCP client detection patterns, AI agent framework detection (CrewAI, AutoGen, LangGraph), more API key patterns (Mistral, Groq, Together, Fireworks). |
| M6: `ai-llm-probe` (garak) | No equivalent | **Truly new** | Build `sfp_ai_llm_probe.py` — garak wrapper for LLM endpoint validation and security posture assessment. |
| M7: `ai-mcp-detect` (Wallarm) | No equivalent | **Truly new** | Build `sfp_ai_mcp_detect.py` — JSON-RPC 2.0 MCP server probing via Wallarm template + custom probes. |
| M8: `ai-bom-gen` (Trusera ai-bom) | No equivalent | **Truly new** | Build `sfp_ai_bom.py` — aggregates all AI findings into CycloneDX 1.6 / SPDX 3.0 AI-BOM format. |
| M9: `ai-repo-scan` (Watchtower/ModelScan) | No equivalent | **Truly new** | Build `sfp_ai_repo_scan.py` — scans discovered repos/model files for secrets, PII, malicious payloads. |

### Net Assessment: 4 truly new modules needed, 5 are enhancements to existing code

---

## Part 2: Additional Modules Beyond the Original 9

These are the modules that will differentiate ASM-NG from every competitor and make CISOs say "I need this NOW."

### M10: `sfp_ai_shadow_discovery` — Shadow AI SaaS Detection
**The CISO pain point:** 49% of employees use unsanctioned AI tools. 75% of CISOs have already found shadow AI. This module discovers which AI SaaS services the organization is unknowingly using.

**Detection methods:**
- DNS query analysis: Resolve organizational domains for CNAME/A records pointing to AI SaaS providers (openai.com, anthropic.com, replicate.com, together.ai, groq.com, fireworks.ai, perplexity.ai, claude.ai, copilot.microsoft.com, gemini.google.com)
- Certificate transparency: Find certificates issued to org subdomains proxying AI services
- Web traffic indicators: Detect outbound connections to AI API endpoints in web content (CSP headers referencing AI domains, iframe embeds)
- OAuth/SSO integration discovery: Find AI apps registered in the org's identity provider via exposed `.well-known/openid-configuration` or similar
- DNS TXT records: Some AI SaaS services require domain verification TXT records

**New event type:** `AI_SHADOW_SERVICE_DETECTED`
**Grading impact:** Information Leakage, -15 points (count_scaled)

### M11: `sfp_ai_agent_mapper` — Agentic AI Infrastructure Discovery
**The CISO pain point:** OWASP just released the Top 10 for Agentic Applications. AI agents are the next shadow IT — operating autonomously across systems with delegated credentials.

**Detection methods:**
- Discover exposed agent orchestration frameworks: CrewAI, AutoGen, LangGraph, Semantic Kernel endpoints
- Detect agent-to-agent communication channels (inter-agent protocols, shared memory stores)
- Find exposed agent registries and A2A (Agent-to-Agent) protocol endpoints
- Identify agent tool access patterns (what MCP servers/tools agents can invoke)
- Detect exposed agent memory stores (Redis, Memcached used for agent state)

**Ports/endpoints to probe:**
- CrewAI: typically on custom ports, look for `/crew/kickoff` endpoints
- LangServe: `/invoke`, `/batch`, `/stream` endpoints (FastAPI-based)
- AutoGen: WebSocket connections for multi-agent chat
- Semantic Kernel: `/api/skills` endpoint pattern

**New event types:** `AI_AGENT_INFRASTRUCTURE_DETECTED`, `AI_AGENT_TOOL_EXPOSED`
**Grading impact:** Network Security, -15 points

### M12: `sfp_ai_vectordb_scanner` — RAG Infrastructure Exposure
**The CISO pain point:** RAG (Retrieval-Augmented Generation) is how enterprises ground LLMs in proprietary data. Exposed vector databases = exposed corporate knowledge base.

**Detection methods:**
- Port scanning for vector databases: Pinecone (443 SaaS), Weaviate (8080), ChromaDB (8000), Milvus (19530/9091), Qdrant (6333/6334), pgvector (5432), Redis Vector (6379)
- Active probing: `GET /api/v1/collections` (ChromaDB), `GET /v1/schema` (Weaviate), `GET /collections` (Qdrant), `GET /api/v1/health` (Milvus)
- Authentication check: Attempt to list collections/indexes without credentials
- Data exposure assessment: If unauthenticated, enumerate collection names (reveals what data is being RAG'd)
- Embedding model detection: Identify which embedding models are being used (reveals AI strategy)

**New event type:** `AI_VECTORDB_EXPOSED`, `AI_RAG_DATA_EXPOSED`
**Grading impact:** Information Leakage, -25 points (this is corporate knowledge exposure)

### M13: `sfp_ai_gpu_cluster` — GPU/Compute Infrastructure Discovery
**The CISO pain point:** GPU clusters are expensive and high-value targets for cryptojacking and LLMjacking. Exposed GPU management interfaces = compute theft + lateral movement.

**Detection methods:**
- NVIDIA DCGM Exporter (9400): Prometheus metrics endpoint reveals GPU model, utilization, memory
- NVIDIA GPU Operator: Kubernetes API exposure with GPU scheduling info
- Kubernetes Dashboard (exposed): Look for GPU resource requests in pod specs
- SLURM (6817/6818): HPC job scheduler commonly used for ML training
- Ray Cluster (8265 already covered, add worker node discovery on 10001-10099)
- Determined AI (8080): ML training platform
- Kubeflow (8080): ML pipeline orchestrator, pipelines dashboard

**New event type:** `AI_COMPUTE_CLUSTER_EXPOSED`
**Grading impact:** Network Security, -20 points

### M14: `sfp_ai_data_pipeline` — ML Data Pipeline Exposure
**The CISO pain point:** Training data pipelines expose the most sensitive corporate data — customer data, proprietary algorithms, competitive intelligence.

**Detection methods:**
- Apache Airflow (8080): DAG UI exposure, look for ML/AI pipeline names
- Kubeflow Pipelines (8080): ML pipeline metadata and artifacts
- MLflow Tracking (5000 — extend M2): Experiment data, model artifacts, dataset references
- DVC (Data Version Control): `.dvc` files in exposed repos revealing S3/GCS data paths
- Label Studio (8080): Annotation platform with training data
- Weights & Biases: Look for exposed `wandb` API calls and project references in web content
- Feature stores: Feast (6566), Tecton endpoints

**New event type:** `AI_DATA_PIPELINE_EXPOSED`, `AI_TRAINING_DATA_EXPOSED`
**Grading impact:** Information Leakage, -20 points

### M15: `sfp_ai_model_registry` — Model Registry & Hub Exposure
**The CISO pain point:** Organizations host private model registries. Exposed registries reveal proprietary models, fine-tuning data, and competitive AI strategy.

**Detection methods:**
- MLflow Model Registry (5000): List registered models, versions, stages
- Hugging Face Hub (private instances): `/api/models` endpoint
- NVIDIA NGC (private): Container/model registry exposure
- DVC model storage: S3/GCS paths in `.dvc` files
- OCI registries with ML model artifacts: Check for model-related tags in container registries
- Weights & Biases Model Registry: Exposed project artifacts

**New event type:** `AI_MODEL_REGISTRY_EXPOSED`
**Grading impact:** Information Leakage, -20 points

---

## Part 3: Standalone Service Packaging — "AI Attack Surface Assessment"

### Service Name Options (pick one)
1. **"AI Attack Surface Discovery"** — straightforward, matches industry terminology
2. **"Shadow AI Assessment"** — hits the #1 CISO pain point directly
3. **"AI Infrastructure Reconnaissance"** — technical, appeals to security teams
4. **"AI Exposure Audit"** — compliance-friendly, appeals to GRC teams

**Recommended:** **"AI Attack Surface Discovery & Assessment"** — covers both discovery and testing

### Three Service Tiers

#### Tier 1: "AI Discovery Scan" — $3K-5K (automated, quick turnaround)
- **Duration:** 24-48 hours
- **Modules:** M1 (passive recon) + enhanced M2 (fingerprint) + enhanced M4 (subdomain) + enhanced M5 (web content) + M10 (shadow AI) + M12 (vector DB) + M15 (model registry)
- **Deliverable:** Automated AI Asset Inventory report
  - Total AI services discovered (by type)
  - Shadow AI SaaS services in use
  - Exposed endpoints with authentication status
  - AI-BOM (lightweight, discovery-only)
  - Risk heat map
- **Target buyer:** CISO doing initial AI governance assessment
- **Selling stat:** "The average organization has 3x more AI endpoints than they realize"

#### Tier 2: "AI Security Assessment" — $15K-25K (automated + manual validation)
- **Duration:** 1-2 weeks
- **Modules:** All of Tier 1 + M3 (vuln scan) + M6 (LLM probe) + M7 (MCP detect) + M11 (agent mapper) + M13 (GPU cluster) + M14 (data pipeline)
- **Deliverable:** Full AI Security Assessment Report
  - Everything from Tier 1
  - Vulnerability findings with CVE mapping
  - LLM security posture (prompt injection, jailbreak susceptibility)
  - MCP server exposure analysis
  - AI agent infrastructure map
  - MITRE ATLAS technique mapping
  - Prioritized remediation roadmap
  - Full CycloneDX AI-BOM
- **Target buyer:** CISO preparing for EU AI Act compliance or board presentation
- **Selling stat:** "175,000 Ollama servers exposed globally; we find the ones in YOUR network"

#### Tier 3: "Continuous AI Monitoring" — $5K-10K/month (ongoing)
- **Duration:** Continuous
- **Modules:** All modules running on a schedule (weekly passive, monthly active)
- **Deliverable:** Monthly AI Exposure Dashboard + alerts
  - New AI services detected (delta from last scan)
  - Shadow AI trend tracking
  - Compliance posture tracking (EU AI Act readiness score)
  - AI-BOM version diff (what changed since last period)
  - Quarterly executive summary
- **Target buyer:** CISO with mature AI governance program
- **Selling stat:** "Shadow AI adoption tripled in 2025; employees add new AI tools weekly"

### Report Structure (Tier 2 Example)

```
1. Executive Summary (1 page)
   - AI exposure risk score (A-F, using existing grading system)
   - Key findings count by severity
   - Top 3 critical findings
   - MITRE ATLAS technique coverage

2. AI Asset Inventory
   - Discovered AI infrastructure (table: service, location, auth status, risk tier)
   - Shadow AI SaaS services (table: service, detection method, data risk)
   - AI subdomains and certificates
   - AI-BOM summary

3. Vulnerability Findings
   - Critical/High/Medium/Low breakdown
   - Each finding: description, evidence, ATLAS mapping, remediation
   - LLM security posture results
   - MCP server exposure analysis

4. AI Agent & Data Pipeline Analysis
   - Agent infrastructure map (visual)
   - Data pipeline exposure analysis
   - Vector database / RAG infrastructure findings
   - GPU/compute cluster exposure

5. Compliance Mapping
   - EU AI Act readiness indicators
   - NIST AI RMF alignment
   - OWASP Top 10 for LLM Apps coverage
   - OWASP Top 10 for Agentic Applications coverage

6. Remediation Roadmap
   - Prioritized by risk tier (Emergency → Critical → High → Medium)
   - Quick wins (< 1 day)
   - Short-term (1-7 days)
   - Medium-term (1-4 weeks)

7. Appendix
   - Full AI-BOM (CycloneDX format)
   - Raw findings data
   - Methodology and tool versions
```

---

## Part 4: CISO-Intriguing Marketing Angles

### Key Stats That Sell (all sourced from 2025-2026 research)
- "175,000+ exposed Ollama AI servers found globally in January 2026" (SentinelLABS)
- "49% of employees use unsanctioned AI tools; 69% of C-suite knows and does nothing" (BlackFog)
- "75% of CISOs have found shadow AI already running in their environments" (industry survey)
- "Operation Bizarre Bazaar: attackers are scanning for exposed AI endpoints and reselling access within hours" (Pillar Security)
- "The EU AI Act compliance deadline is August 2, 2026 — penalties up to 35M EUR or 7% of global turnover"
- "87% of breaches span multiple attack surfaces; AI is the newest one most organizations don't monitor" (Unit 42)
- "Only 19% of organizations govern AI accounts with the same rigor as human users" (industry data)
- "AI red teaming services market growing 30.5% CAGR to $18.6B by 2035" (Market.us)

### Board-Level Talking Points
1. **"Do you know where AI lives in your organization?"** — Most organizations can't answer this. ASM-NG's AI Discovery provides the inventory.
2. **"Your AI is your newest unmonitored attack surface"** — Just like shadow IT in 2015, shadow AI in 2026 is the blind spot that leads to breaches.
3. **"Compliance isn't optional"** — EU AI Act, NIST AI RMF, and sector-specific regulations require AI asset inventories. An AI-BOM is the SBOM equivalent for AI.
4. **"Attackers are already looking"** — Operation Bizarre Bazaar proved that threat actors systematically scan for and exploit exposed AI infrastructure. The question isn't IF but WHEN.

### Competitive Differentiation
- **vs. Tenable One AI Exposure:** ASM-NG is open-source, customizable, no per-seat SaaS lock-in. Tenable is cloud-only; ASM-NG discovers on-prem AI too.
- **vs. CrowdStrike AI-SPM:** CrowdStrike requires Falcon agent deployment. ASM-NG does outside-in discovery with zero agent installation.
- **vs. Point solutions (Protect AI, Lakera, etc.):** They do one thing (model scanning OR red teaming). ASM-NG does the full pipeline: discover → fingerprint → test → inventory → report.
- **vs. Manual pentesting:** ASM-NG automates what would take weeks of manual reconnaissance. The scan runs in hours, not days.

### Compliance Angles
- **EU AI Act (Aug 2026):** AI-BOM generation directly supports transparency requirements for GPAI models
- **NIST AI RMF:** AI asset inventory maps to GOVERN and MAP functions
- **MITRE ATLAS:** Every finding tagged with ATLAS technique IDs for standardized threat intelligence
- **OWASP Top 10 LLM:** Module coverage maps to LLM01-LLM10 risks
- **OWASP Top 10 Agentic:** Agent mapper module specifically addresses ASI01-ASI10
- **ISO/IEC 42001:** AI-BOM documentation supports AI management system requirements
- **SOC 2 / ISO 27001:** AI infrastructure discovery feeds into asset management controls

---

## Part 5: Implementation Plan

### Priority Order (what to build first)

**Phase A — Enhance Existing (Weeks 1-3)**
Files to modify:
- `/home/user/asm-ng/modules/sfp_ai_fingerprint.py` — Add AI-Infra-Guard YAML rules, OpenAI-compatible backend differentiator, graphw00f technique
- `/home/user/asm-ng/modules/sfp_ai_subdomain.py` — Expand wordlist to 150+ terms, add subfinder integration
- `/home/user/asm-ng/modules/sfp_ai_webcontent.py` — Add MCP client detection, agent framework detection, more API key patterns (Mistral, Groq, Together, Fireworks, Deepseek)
- `/home/user/asm-ng/spiderfoot/dicts/ai-subdomains.txt` — Expand from 84 to 150+ entries

**Phase B — New Core Modules (Weeks 3-8)**
New files to create:
- `/home/user/asm-ng/modules/sfp_ai_passive_recon.py` — Shodan/Censys AI-specific dorks (wraps existing API patterns)
- `/home/user/asm-ng/modules/sfp_ai_vulnscan.py` — Nuclei + ai-exploits template runner
- `/home/user/asm-ng/modules/sfp_ai_llm_probe.py` — garak wrapper for LLM validation
- `/home/user/asm-ng/modules/sfp_ai_mcp_detect.py` — MCP server probing (JSON-RPC 2.0)

**Phase C — Differentiator Modules (Weeks 8-14)**
New files to create:
- `/home/user/asm-ng/modules/sfp_ai_shadow_discovery.py` — Shadow AI SaaS detection
- `/home/user/asm-ng/modules/sfp_ai_vectordb_scanner.py` — RAG infrastructure exposure
- `/home/user/asm-ng/modules/sfp_ai_agent_mapper.py` — Agentic AI infrastructure discovery
- `/home/user/asm-ng/modules/sfp_ai_gpu_cluster.py` — GPU/compute infrastructure discovery
- `/home/user/asm-ng/modules/sfp_ai_data_pipeline.py` — ML data pipeline exposure
- `/home/user/asm-ng/modules/sfp_ai_model_registry.py` — Model registry/hub exposure

**Phase D — Reporting & Compliance (Weeks 14-18)**
New files to create:
- `/home/user/asm-ng/modules/sfp_ai_bom.py` — AI-BOM generation (CycloneDX 1.6 / SPDX 3.0)
- `/home/user/asm-ng/modules/sfp_ai_repo_scan.py` — Repository & model file scanning

Supporting infrastructure to modify:
- `/home/user/asm-ng/spiderfoot/db.py` — Register new event types
- `/home/user/asm-ng/spiderfoot/grade_config.py` — Add grading rules for new event types
- `/home/user/asm-ng/spiderfoot/event_type_mapping.py` — Add legacy mappings
- `/home/user/asm-ng/correlations/` — Add AI-specific YAML correlation rules (e.g., `ai_unauthenticated_cluster.yaml`, `ai_shadow_saas_sprawl.yaml`, `ai_data_exposure_chain.yaml`)

### New Event Types to Register

| Event Type | Category | Points | Scoring |
|---|---|---|---|
| `AI_SHADOW_SERVICE_DETECTED` | Information Leakage | -15 | count_scaled |
| `AI_AGENT_INFRASTRUCTURE_DETECTED` | Network Security | -15 | unverified_exists |
| `AI_AGENT_TOOL_EXPOSED` | Network Security | -15 | unverified_exists |
| `AI_VECTORDB_EXPOSED` | Information Leakage | -25 | unverified_exists |
| `AI_RAG_DATA_EXPOSED` | Information Leakage | -25 | unverified_exists |
| `AI_COMPUTE_CLUSTER_EXPOSED` | Network Security | -20 | unverified_exists |
| `AI_DATA_PIPELINE_EXPOSED` | Information Leakage | -20 | unverified_exists |
| `AI_TRAINING_DATA_EXPOSED` | Information Leakage | -20 | unverified_exists |
| `AI_MODEL_REGISTRY_EXPOSED` | Information Leakage | -20 | unverified_exists |
| `AI_MCP_SERVER_EXPOSED` | Network Security | -20 | unverified_exists |
| `AI_LLM_VULN_DETECTED` | Network Security | -20 | crit_high_med |
| `AI_BOM_GENERATED` | Information / Reference | 0 | informational |

### New Correlation Rules to Create

- `ai_unauthenticated_cluster.yaml` — Multiple unauthenticated AI services on same host = critical cluster exposure
- `ai_shadow_sprawl.yaml` — >5 shadow AI SaaS services detected = governance failure
- `ai_data_exposure_chain.yaml` — Exposed vector DB + exposed model registry + exposed data pipeline = full AI supply chain compromise
- `ai_credential_leak_chain.yaml` — AI API key leaked + corresponding AI service detected = confirmed exploitation risk
- `ai_mcp_tool_chain.yaml` — Exposed MCP server + exposed tools + no auth = agent hijack risk

---

## Verification & Testing

1. **Unit tests:** Create `test/unit/modules/test_sfp_ai_*.py` for each new module following existing patterns
2. **Integration tests:** Set up local test targets (Ollama, MLflow, ChromaDB, Weaviate instances in Docker) and validate end-to-end discovery pipeline
3. **Correlation tests:** Verify new YAML rules trigger correctly with synthetic event data
4. **Grading tests:** Verify new event types impact security grades as configured
5. **Report tests:** Generate sample AI-BOM output and validate CycloneDX schema compliance
6. **Run existing test suite:** `python3 -m pytest test/unit/modules/test_sfp_ai_*.py -v` to ensure no regressions

---

## Summary: Total Module Inventory After Implementation

| # | Module | Status | Phase |
|---|---|---|---|
| Existing | `sfp_ai_fingerprint.py` | Enhance | A |
| Existing | `sfp_ai_subdomain.py` | Enhance | A |
| Existing | `sfp_ai_webcontent.py` | Enhance | A |
| M1 | `sfp_ai_passive_recon.py` | New | B |
| M3 | `sfp_ai_vulnscan.py` | New | B |
| M6 | `sfp_ai_llm_probe.py` | New | B |
| M7 | `sfp_ai_mcp_detect.py` | New | B |
| M10 | `sfp_ai_shadow_discovery.py` | New | C |
| M11 | `sfp_ai_agent_mapper.py` | New | C |
| M12 | `sfp_ai_vectordb_scanner.py` | New | C |
| M13 | `sfp_ai_gpu_cluster.py` | New | C |
| M14 | `sfp_ai_data_pipeline.py` | New | C |
| M15 | `sfp_ai_model_registry.py` | New | C |
| M8 | `sfp_ai_bom.py` | New | D |
| M9 | `sfp_ai_repo_scan.py` | New | D |

**Total: 3 enhanced + 12 new = 15 AI modules — the most comprehensive AI attack surface discovery capability in any open-source ASM platform.**

---

## Deliverable

This plan will be committed as `spiderfoot/asm-ng-ai-discovery-expansion-plan.md` to the `claude/wip-HkGQ5` branch and pushed. This serves as the strategic roadmap companion to the existing `asm-ng-ai-discovery-integration-plan.md` blueprint — the original covers the "how" for modules M1-M9, this document covers the "what else" (M10-M15), "why" (market/CISO angles), and "how to sell it" (service tiers, report structure, competitive positioning).

### Sources
- [AI Red Teaming Services Market ($18.6B by 2035, 30.5% CAGR)](https://market.us/report/ai-red-teaming-services-market/)
- [2026 CISO Budget Benchmark Report — Wiz](https://www.wiz.io/reports/ciso-security-budget-benchmark-2026)
- [AI Revolution Reshapes CISO Spending for 2026](https://securityboulevard.com/2026/02/ai-revolution-reshapes-ciso-spending-for-2026-security-leaders-prioritize-defense-automation/)
- [OWASP AIBOM Initiative](https://owasp.org/www-project-aibom/)
- [From SBOM to AI-BOM: Rethinking Supply Chain Security](https://www.pointguardai.com/blog/from-sbom-to-ai-bom-rethinking-supply-chain-security-in-the-ai-era)
- [S&P Global: Continuous AI Red Teaming Is Critical](https://mindgard.ai/resources/analyst-report-s-p-global-market-intelligence)
- [Cisco AI Defense Expansion (AI BOM, MCP Catalog, Agentic Guardrails)](https://newsroom.cisco.com/c/r/newsroom/en/us/a/y2026/m02/cisco-redefines-security-for-the-agentic-era.html)
- [The 2026 Ultimate Guide to AI Penetration Testing](https://www.penligent.ai/hackinglabs/the-2026-ultimate-guide-to-ai-penetration-testing-the-era-of-agentic-red-teaming/)
- [Agentic AI in Penetration Testing — Cloud Security Alliance](https://cloudsecurityalliance.org/blog/2026/02/05/ai-agents-and-how-they-are-used-in-pentesting)
- [OWASP AI SBOM Initiative](https://genai.owasp.org/ai-sbom-initiative/)
- [Agent-BOM: AI Supply Chain Security Scanner](https://github.com/msaad00/agent-bom)
- [Trusera ai-bom: SBOM for AI Agent Workflows](https://github.com/Lab700xOrg/aisbom)
