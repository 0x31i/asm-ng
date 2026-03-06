# ASM-NG x Claude Max Integration Plan

**Status:** Research / Planning
**Date:** 2026-03-05

---

## Current State

ASM-NG uses **Claude Code (via Max subscription)** for all AI processing. The current
workflow is manual: export triage JSON from the web UI, paste into Claude Code for
classification (FP/LEGIT/REVIEW), then import the results back. The grading engine
is pure algorithmic (weighted category scores). Correlation is YAML-rule-based.

There is also a legacy `sfp_ai_summary.py` module that references the OpenAI API,
but it's unused — all real AI work goes through Claude Code.

**The opportunity:** Streamline the Claude Code workflow with better export/import
tooling, and explore future direct API integration for fully automated processing.

**Important note on pricing:** Claude Max ($100-200/mo) covers Claude Code CLI usage
but does NOT include Anthropic API access. Direct API integration (calling Claude
from inside the web app) requires separate API billing (~$3/M input, $15/M output
for Sonnet). The Claude Code CLI approach costs $0 beyond your Max subscription.

---

## Idea 1: Rewrite `sfp_ai_summary.py` for Claude

**Effort:** Low | **Impact:** Medium

The existing summary module references OpenAI but is unused. Rewrite it to generate
a structured summary prompt that integrates with the Claude Code export/import workflow,
or optionally calls the Anthropic API directly if an API key is configured.

**Changes:**
- Rewrite prompt to use Claude's system message format with security analyst persona
- Leverage Claude's 200K context window — include ALL events, not just last N
- Output structured JSON instead of free-text
- Dual mode: export-for-Claude-Code (free) or direct API call (paid)

---

## Idea 2: Automated Triage Agent

**Effort:** Medium | **Impact:** High

The triage system (`triage_prompt.py`) already has excellent classification logic (FP/LEGIT/REVIEW) with ground-truth anchoring against known assets. Currently this requires manual LLM interaction. Automate it.

**How it works:**
1. On scan completion, gather all unreviewed findings
2. Load known assets for the target (ground truth)
3. Build the triage prompt automatically (already implemented in `triage_prompt.py`)
4. Send to Claude Opus with the full triage instructions
5. Parse the structured JSON response: `{id, class, reason}`
6. Auto-apply FP/LEGIT classifications; flag REVIEW items for analyst
7. Store `triage_source = 'claude_auto'` for audit trail

**Why Claude Max matters:** A full scan can have 500-2000+ findings. Triaging all of them in one shot requires massive context + strong reasoning. Claude Opus with 200K context handles this. At per-token pricing this would cost $15-40 per scan — with Max it's free.

**Safety rails:**
- Never auto-apply without `--auto-triage` flag or config toggle
- Log all AI classifications with reasoning
- Analyst can override any AI decision
- Confidence threshold: only auto-apply if Claude reports >90% confidence
- Weekly audit report of AI triage accuracy vs analyst corrections

---

## Idea 3: Intelligent Event Enrichment Pipeline

**Effort:** Medium | **Impact:** High

Instead of one big summary at scan end, inject Claude into the event processing pipeline for real-time enrichment.

**New module: `sfp_claude_enrich.py`**
- Watches: `VULNERABILITY_CVE_*`, `MALICIOUS_*`, `AI_INFRASTRUCTURE_DETECTED`, `DARKNET_MENTION_*`
- For each high-severity finding, queries Claude with context:
  - What is this vulnerability? (CVE explanation)
  - What's the real-world exploitability?
  - What's the business impact for this specific asset type?
  - Recommended remediation steps
- Emits: `FINDING_ENRICHMENT` event with structured analysis
- UI displays enrichment alongside the raw finding

**Batching strategy:** Don't call Claude per-event (too slow). Buffer 10-20 events, send as batch with "analyze these findings" prompt. This balances latency vs context.

---

## Idea 4: Natural Language Scan Query Interface

**Effort:** Medium | **Impact:** High

Let analysts ask questions about scan results in plain English.

**Examples:**
- "What are the most critical findings for acme.com?"
- "Show me all exposed AI infrastructure that doesn't require authentication"
- "Compare the last 3 scans — what's new, what's fixed?"
- "Which findings should I prioritize for the Tuesday remediation meeting?"
- "Explain the credential leak chain correlation in simple terms"

**Implementation:**
- New `/query` endpoint in the web UI
- Sends analyst question + scan context to Claude
- Claude has access to: scan results, grades, correlations, known assets, FP history
- Returns structured response with finding references (clickable links to specific events)
- Conversation memory within session for follow-up questions

**Claude Max advantage:** Interactive back-and-forth with an analyst is inherently multi-turn and token-heavy. Max makes this viable for daily use.

---

## Idea 5: Executive Report Generation

**Effort:** Medium | **Impact:** High

Auto-generate client-ready reports from scan data.

**Current state:** Analysts manually write reports from scan results.

**With Claude:**
1. Feed scan results + grades + correlations + triage decisions into Claude
2. Generate structured report:
   - Executive summary (2-3 paragraphs, non-technical)
   - Risk score breakdown by category with trend arrows
   - Top 10 critical findings with plain-English explanations
   - Remediation roadmap (prioritized action items)
   - Comparison with previous scan (what improved, what regressed)
   - Appendix: full technical findings
3. Output as Markdown (paste into Obsidian) or HTML/PDF

**Template system:** Define report templates per client tier:
- `executive_brief.md` — 1-page C-suite summary
- `technical_report.md` — full findings with evidence
- `remediation_plan.md` — action items with timelines
- `compliance_report.md` — mapped to specific frameworks (SOC2, NIST, etc.)

---

## Idea 6: Smart Correlation Rule Generation

**Effort:** Medium | **Impact:** Medium

Currently 51 YAML correlation rules are hand-written. Use Claude to discover new correlation patterns.

**How:**
1. After each scan, send the full event graph to Claude
2. Ask: "What interesting patterns, chains, or correlations do you see that our existing rules don't cover?"
3. Claude outputs candidate YAML rules in the existing format
4. Analyst reviews and approves new rules
5. Approved rules get added to `/correlations/`

**Ongoing learning:** Track which Claude-suggested correlations analysts confirm vs reject. Feed this back as few-shot examples for better suggestions.

---

## Idea 7: Anomaly Explanation & Context

**Effort:** Low | **Impact:** Medium

The threat intel module (`sfp__ai_threat_intel.py`) uses IsolationForest for anomaly detection but only flags anomalies numerically. Add Claude to explain WHY something is anomalous.

**Flow:**
1. IsolationForest flags event as anomaly (score < threshold)
2. Extract the feature vector that caused the anomaly
3. Send to Claude: "This event was flagged as anomalous. Here's the event, its features, and the baseline distribution. Explain why this is unusual and what it might indicate."
4. Store explanation as `ANOMALY_EXPLANATION` event

---

## Idea 8: Grading Narrative & Recommendations

**Effort:** Low | **Impact:** Medium

The grading system produces letter grades (A-F) per category. Add Claude-generated narratives.

**For each category grade:**
- "Your Network Security score dropped from B to D because 3 new critical ports were found open (8080, 9090, 27017) that weren't present in the January scan. Port 27017 (MongoDB) is especially concerning as it's commonly targeted by automated scanners."
- "Recommended: Close ports 8080 and 9090 at the firewall. Restrict MongoDB (27017) to internal network only."

**For the overall grade:**
- Trend analysis: "This is the third consecutive scan showing decline in Cloud Infrastructure. The pattern suggests misconfigured IaC templates are being redeployed."
- Peer comparison: "Compared to similar-sized organizations, your AI/ML Security score (C) is below average. Most organizations in your sector score B or higher."

---

## Idea 9: Module Selection Optimizer

**Effort:** Low | **Impact:** Medium

ASM-NG has 200+ modules. Most scans don't need all of them. Use Claude to recommend optimal module sets.

**How:**
1. Analyst describes the target: "E-commerce company, AWS-hosted, uses Cloudflare"
2. Claude recommends: "Enable these 45 modules, skip these 155. Here's why..."
3. Or: after a scan completes, Claude reviews which modules produced zero findings and suggests disabling them for future scans of this target
4. Track module yield rate per target over time

---

## Idea 10: Continuous Monitoring Intelligence

**Effort:** High | **Impact:** Very High

For bimonthly scans, use Claude to generate a "changes briefing" — what changed between scans and what it means.

**Scan Diff Analysis:**
1. Compare current scan results with previous scan
2. Categorize changes: NEW findings, RESOLVED findings, CHANGED findings
3. For each change, Claude explains the significance:
   - "New: Port 443 certificate changed issuer from DigiCert to Let's Encrypt. This could indicate infrastructure migration or a potential MITM if unexpected."
   - "Resolved: The exposed S3 bucket `acme-backups` is no longer publicly accessible. Good."
   - "Changed: 12 new subdomains discovered. 3 appear to be development environments (dev.*, staging.*, test.*) that may not have production-grade security."

**Alert Classification:**
- URGENT: new critical findings that weren't present before
- NOTABLE: significant changes worth mentioning to the client
- ROUTINE: expected changes, informational only

---

## Idea 11: Known Asset Discovery Assistant

**Effort:** Medium | **Impact:** Medium

During client onboarding, analysts manually populate known assets. Claude can help.

**Flow:**
1. Analyst provides seed info: "Company: Acme Corp, domain: acme.com"
2. Claude analyzes first scan results and suggests known assets:
   - "Based on scan results, these appear to be legitimate Acme assets: [list with reasoning]"
   - "These appear to be third-party services used by Acme: [list]"
   - "These are uncertain — please verify: [list]"
3. Analyst confirms/rejects, building the known asset inventory faster

---

## Idea 12: Prompt-Driven Custom Analysis

**Effort:** Low | **Impact:** Medium

Let analysts write ad-hoc analysis prompts that run against scan data.

**Examples:**
- "Find all findings that suggest this company recently migrated cloud providers"
- "Identify any indicators that suggest a recent security incident"
- "Map all third-party JavaScript dependencies and assess supply chain risk"
- "Which findings would matter most for a SOC2 Type II audit?"

**Implementation:** Simple text box in the UI that wraps the analyst's question with scan context and sends to Claude. No predefined template needed.

---

## Idea 13: Multi-Scan Campaign Analysis

**Effort:** High | **Impact:** Very High

For clients with multiple targets (e.g., 20 domains, 50 IPs), analyze the full portfolio.

**Claude analyzes:**
- Cross-target patterns: "5 of your 20 domains share the same misconfigured CORS policy"
- Systemic issues: "All AWS-hosted targets have the same S3 bucket naming convention that's discoverable"
- Trend across portfolio: "Your retail division (8 targets) scores consistently worse than your corporate division (12 targets)"
- Shared infrastructure risks: "3 targets share the same Cloudflare zone — a single compromise affects all"

---

## Idea 14: Improved AI Threat Intel Processing

**Effort:** Medium | **Impact:** Medium

The current `sfp__ai_threat_intel.py` uses sklearn IsolationForest. Replace or supplement with Claude for:

1. **Better feature extraction:** Instead of numeric features, send raw event data to Claude for semantic understanding
2. **Attack chain reconstruction:** Claude can reason about causal relationships between findings (port open -> service detected -> vulnerability found -> exploit available)
3. **Threat actor attribution:** Match finding patterns against known TTPs (MITRE ATT&CK mapping)
4. **Predictive analysis:** "Based on the exposed services and current threat landscape, these are the most likely attack vectors"

---

## Idea 15: Client Communication Drafts

**Effort:** Low | **Impact:** Medium

Auto-draft client-facing communications:

- **Initial findings email:** "Hi [Client], your scan completed. Here's a brief overview..."
- **Critical finding alert:** "We detected [finding] which requires immediate attention because..."
- **Monthly digest:** Summary of scan activity, grade changes, resolved items
- **Remediation guidance:** Step-by-step fix instructions tailored to the client's tech stack

---

## Implementation Priority Matrix

| # | Idea | Effort | Impact | Priority |
|---|------|--------|--------|----------|
| 1 | Replace OpenAI with Claude in summary module | Low | Medium | P0 - Do first |
| 2 | Automated triage agent | Medium | High | P0 - Do first |
| 8 | Grading narrative & recommendations | Low | Medium | P1 - Quick win |
| 7 | Anomaly explanation | Low | Medium | P1 - Quick win |
| 15 | Client communication drafts | Low | Medium | P1 - Quick win |
| 3 | Intelligent event enrichment pipeline | Medium | High | P1 - High value |
| 5 | Executive report generation | Medium | High | P1 - High value |
| 4 | Natural language scan query | Medium | High | P2 - Next phase |
| 12 | Prompt-driven custom analysis | Low | Medium | P2 - Builds on #4 |
| 9 | Module selection optimizer | Low | Medium | P2 - Nice to have |
| 11 | Known asset discovery assistant | Medium | Medium | P2 - Onboarding |
| 6 | Smart correlation rule generation | Medium | Medium | P3 - Advanced |
| 10 | Continuous monitoring intelligence | High | Very High | P3 - Game changer |
| 13 | Multi-scan campaign analysis | High | Very High | P3 - Game changer |
| 14 | Improved AI threat intel | Medium | Medium | P3 - Enhancement |

---

## Technical Architecture

### Claude Integration Layer

Create a shared Claude client module that all features use:

```
spiderfoot/claude_client.py
  - Singleton Anthropic client (reuse connection)
  - Rate limiting / queuing (respect Max plan limits)
  - Prompt template registry
  - Response caching (same input = same output, skip API call)
  - Cost tracking (even on Max, track token usage for optimization)
  - Fallback chain: Claude Opus -> Claude Sonnet -> local model
  - Structured output parsing (JSON mode)
```

### Configuration

```
New global options:
  _claude_api_key          — Anthropic API key (or env ANTHROPIC_API_KEY)
  _claude_model            — Default model (claude-sonnet-4-6 / claude-opus-4-6)
  _claude_auto_triage      — Enable automated triage (default: off)
  _claude_enrich           — Enable finding enrichment (default: on)
  _claude_report_template  — Report template selection
  _claude_max_tokens       — Max output tokens per call
```

### Database Additions

```sql
tbl_claude_analyses:
  id VARCHAR PRIMARY KEY
  scan_instance_id VARCHAR
  analysis_type VARCHAR  -- 'triage', 'enrichment', 'report', 'query', 'narrative'
  prompt_hash VARCHAR    -- for caching
  input_tokens INT
  output_tokens INT
  model VARCHAR
  response_data JSON
  created_ts INT

tbl_claude_triage_log:
  id VARCHAR PRIMARY KEY
  scan_instance_id VARCHAR
  event_hash VARCHAR     -- which finding was triaged
  classification VARCHAR -- FP, LEGIT, REVIEW
  confidence FLOAT       -- 0.0 - 1.0
  reasoning TEXT
  analyst_override VARCHAR  -- NULL = accepted, or analyst's correction
  created_ts INT
```

---

## Cost Analysis: Claude Code CLI vs Anthropic API

| Approach | How | Cost |
|----------|-----|------|
| **Claude Code CLI** (current) | Export → Claude Code → Import | $0 (covered by Max sub) |
| **Anthropic API** (future) | Web app calls API directly | ~$3-15/scan (Sonnet) |

### Per-Scan API Cost Estimates (Sonnet 4.6)

| Task | Input tokens | Output tokens | Cost |
|------|-------------|---------------|------|
| Full triage (1500 findings) | ~80K | ~30K | ~$0.70 |
| Finding enrichment (all) | ~100K | ~50K | ~$1.05 |
| Executive report | ~80K | ~10K | ~$0.39 |
| Grade narratives | ~20K | ~5K | ~$0.14 |
| **Total per scan** | | | **~$2.28** |

At 20 scans/month with Sonnet, full automation costs ~$46/month via API.
The Claude Code CLI approach costs $0 but requires manual steps.

**Recommendation:** Start with CLI export/import (implemented). Move to API
when the workflow is proven and you want one-click automation.

---

## Next Steps

1. Build `spiderfoot/claude_client.py` shared integration layer
2. Swap `sfp_ai_summary.py` to use Claude (Idea 1)
3. Implement automated triage with safety rails (Idea 2)
4. Add grading narratives (Idea 8) — quickest visible impact
5. Build report generation templates (Idea 5)
6. Design the `/query` natural language interface (Idea 4)
