# ASM-NG × Claude: Intelligent Triage Integration — Research Plan

**Purpose of this document:** Feed into Claude deep research to explore architectures,
prior art, prompt engineering strategies, and implementation approaches for safely
integrating Claude AI into the ASM-NG attack surface management platform.

---

## 1. What is ASM-NG?

ASM-NG is a Python 3 OSINT/attack surface management platform (288 modules) that
automates reconnaissance and security data gathering for penetration testers, security
analysts, and SOC teams. It is built on the SpiderFoot engine.

### How a scan works (internal pipeline)

```
Admin sets target (e.g., "example.com")
        │
        ▼
Root event created → pushed to central eventQueue
        │
        ▼
Main scan loop pops events from eventQueue
        │
        ├── Looks up which modules subscribe to that event type
        ├── Dispatches event to each subscribed module (in thread)
        │
        ▼
Module runs → may produce 0-N new SpiderFootEvent objects
        │
        ▼
New events pushed back to eventQueue → triggers more modules
        │
        ▼  (cascades until queue empty or scan stopped)
All results stored in PostgreSQL (tbl_scan_results)
        │
        ▼
Analyst reviews results, marks false positives, validates findings
```

### Event system

- Every piece of discovered data is a **SpiderFootEvent** with: `eventType`, `data`,
  `sourceEvent`, `module`, `confidence`, `risk`, `visibility`
- 120+ distinct event types: `IP_ADDRESS`, `EMAILADDR`, `INTERNET_NAME`,
  `TCP_PORT_OPEN`, `EMAILADDR_COMPROMISED`, `PASSWORD_COMPROMISED`, `SSL_CERTIFICATE_MISMATCH`,
  `WEBSERVER_TECHNOLOGY`, `AI_INFRASTRUCTURE_DETECTED`, `SOCIAL_MEDIA`, etc.
- Modules subscribe to specific event types and produce other event types
  (e.g., `sfp_dnsresolve` subscribes to `INTERNET_NAME`, produces `IP_ADDRESS`)

### False positive system (current, manual)

- `tbl_scan_results` has a `false_positive` column (0/1)
- `tbl_target_false_positives` stores persistent per-target FP rules
  (target + event_type + event_data + source_data)
- Analysts manually mark rows as FP in the UI
- FP rows are excluded from exported reports and the external vendor API
- **There is no automated FP detection today** — everything is 100% manual

### Noise problem (current)

- When a module discovers a shared/CDN IP (e.g., Cloudflare 104.21.x.x), ASM-NG
  dispatches every IP-subscriber module against it: port scanners, geo-lookup, reverse
  DNS, reputation checks, vulnerability lookups — all wasted effort
- When a breach module finds an email that has zero connection to the target, all
  email-subscriber modules spin up trying to enrich it
- There is no "signal quality gate" before dispatching events to modules
- This causes scans against large targets to run for hours pursuing garbage leads

---

## 2. The Two Problems We Want to Solve

### Problem A: False Positive Detection at Scale

**Definition:** A finding is a false positive when the data technically exists in a data
source but is not actually a risk or relevant to the target being assessed.

**Examples:**
- `alice@example.com` appears in a breach database, but the breach record was
  for a different "example.com" that has no relation to the target
- `198.51.100.1` resolves to `example.com` but is a Cloudflare anycast IP shared
  by 200,000 other domains — not the target's owned infrastructure
- A subdomain `legacy.example.com` is flagged as "expired SSL certificate" but
  it's been decommissioned and is returning a parking page
- A password hash in a paste site matches a pattern for the target's domain but
  is from a different organization with a similar name

**Current analyst burden:** A scan of a mid-size organization produces 500-2000 findings.
An analyst must manually review each one to mark FPs. This takes hours per target and
does not scale when managing dozens of targets continuously.

**What we want:** Claude to review batches of findings, assess FP probability for each,
and either auto-mark high-confidence FPs or surface medium-confidence ones for quick
human confirmation — with reasoning attached.

### Problem B: Noise Filtering (Scan Efficiency)

**Definition:** A scan event is "noise" when pursuing it further (running more modules
against it) will not produce actionable findings for the target, only waste time/API
calls/cost.

**Examples of noise patterns:**
- An IP that resolves to a well-known CDN (Cloudflare, Akamai, Fastly, AWS CloudFront)
  with hundreds of thousands of other domains — not target-owned infrastructure
- A discovered email address that is clearly a generic role address at a completely
  unrelated domain (found via a link on the target's site)
- A subdomain that returns a DNS NXDOMAIN or CNAME to a generic parking page
- A social media profile found via keyword search with no real connection to the target
- A "technology detected" event for a ubiquitous JavaScript library (jQuery, Bootstrap)
  that does not represent a unique fingerprint

**Current behavior:** All events (noise or signal) are dispatched to every subscribed
module with no quality gate. A single noise IP can trigger 20+ modules, each making
external API calls.

**What we want:** A lightweight signal-quality assessment that runs before (or
asynchronously alongside) module dispatch, assigns a "pursue" score to each event, and
either suppresses low-value events from further module chaining or deprioritizes them
in the queue.

---

## 3. Proposed Integration Architecture (Conceptual — Needs Research)

### Option A: Post-Scan Batch Reviewer (Lowest Risk)

```
Scan completes (or reaches checkpoint)
        │
        ▼
Claude Reviewer Job triggered (async, background)
        │
        ▼
Batch findings by event type (50-100 per API call)
        │
        ▼
Claude analyzes batch with target context + event type knowledge
Returns: [{finding_id, fp_probability, confidence, reasoning}]
        │
        ├── fp_probability > 0.90 → auto-mark as FP in DB
        ├── fp_probability 0.60-0.90 → flag for human review with reasoning
        └── fp_probability < 0.60 → no action
        │
        ▼
Analyst reviews "flagged" queue (much shorter than full results)
```

**Pros:** Safe, no impact on scan performance, can be retried/audited
**Cons:** Does not prevent noise from wasting time during the scan itself

### Option B: In-Scan Async Noise Scorer

```
Module produces new event → pushed to eventQueue
        │
        ├── (synchronous path) Event immediately dispatched to subscribed modules
        │   (current behavior — not blocked)
        │
        └── (async path) Event also sent to NoiseScorer queue
                │
                ▼
        Claude / heuristic scorer evaluates signal quality
        Returns: noise_score (0.0 = pure noise, 1.0 = high signal)
                │
                ▼
        Score written to event record in DB
        Future events derived from this event inherit parent's noise_score
        Events below threshold excluded from future module dispatch
```

**Pros:** Progressively learns to stop pursuing noise; can prune whole subtrees
**Cons:** Async means first-level noise still dispatched; need careful threshold tuning

### Option C: Synchronous Pre-Dispatch Gate (Most Impactful, Most Risk)

```
New event arrives at eventQueue processor
        │
        ▼
BEFORE dispatching to modules: check noise gate
        │
        ├── Rule-based fast check (known CDN ranges, known parking CNAMEs) → instant
        ├── Cache hit (same data scored before) → instant
        └── Ambiguous → fast Claude call (structured, <200ms target)
        │
        ▼
Score >= threshold → dispatch normally
Score < threshold → suppress (event stored but not dispatched)
                   → suppression reason logged in DB
```

**Pros:** Prevents noise from generating API costs downstream
**Cons:** Introduces latency into scan critical path; risk of suppressing real signals

### Option D: Hybrid (Recommended for Research)

Combine all three:
1. **Synchronous rule-based gate** — no Claude, instant, catches obvious noise
   (CDN IPs, parking domains, known benign patterns)
2. **Async noise scorer** — Claude scores events in background; prunes at next
   occurrence of same data pattern
3. **Post-scan FP reviewer** — Claude batch-reviews all findings after scan,
   marks/flags FPs with reasoning

This separates latency-sensitive decisions (rule-based) from intelligence-heavy
decisions (Claude), and keeps Claude out of the synchronous hot path.

---

## 4. Technical Context: How Claude Would Be Called

### API approach

- Anthropic API via the `anthropic` Python SDK
- API key stored in ASM-NG's existing config system (settings page)
- Each Claude call is logged in `tbl_audit_log` with token counts
- Admin can set a monthly token budget cap; reviewer jobs stop if exceeded

### Batching strategy

Rather than one API call per finding (catastrophically expensive), batch by event type:

```python
# Pseudo-code for batch FP reviewer
findings_by_type = group_by_event_type(scan_findings)

for event_type, findings in findings_by_type.items():
    for chunk in chunks(findings, size=75):
        prompt = build_fp_review_prompt(target, event_type, chunk)
        response = claude.messages.create(
            model="claude-opus-4-6",
            max_tokens=4096,
            messages=[{"role": "user", "content": prompt}]
        )
        results = parse_fp_response(response)
        apply_fp_decisions(results)
```

### Structured output

Claude should return JSON-structured responses to make parsing reliable:

```json
[
  {
    "finding_id": "abc123",
    "fp_probability": 0.92,
    "confidence": "high",
    "reasoning": "This IP (104.21.5.8) belongs to Cloudflare's anycast range and
                  is shared infrastructure, not owned by the target.",
    "category": "shared_infrastructure"
  },
  ...
]
```

### Context to provide Claude

For each batch call, Claude needs:
1. **Target context** — what the target is (domain, org name, industry if known)
2. **Event type definition** — what this type of finding means in OSINT context
3. **Module that produced it** — which tool/source generated this data
4. **Source event** — what triggered this finding (chain context)
5. **Analyst annotations** — any existing notes on this target/finding type
6. **Historical FP patterns** — what types of findings have been marked FP for
   this target before (learning from analyst behavior)

---

## 5. Safety Constraints (Non-Negotiable)

These constraints must be designed in from the start:

1. **No auto-delete** — Claude can mark findings as FP (flip the `false_positive` flag)
   but never deletes records. All Claude decisions are reversible by the analyst.

2. **Reasoning required** — Every Claude FP decision must store its reasoning in
   `tbl_analyst_type_comments` or a new `tbl_ai_triage_log` table. Analysts can read
   why Claude made the decision.

3. **Confidence threshold control** — The admin sets the auto-mark threshold
   (default: require ≥ 0.92 confidence for auto-mark). Below threshold → queue for
   human review, never auto-mark.

4. **Human review queue** — A dedicated UI view shows all "Claude-flagged but not
   auto-marked" findings, with Claude's reasoning, allowing one-click confirm/reject.

5. **Audit trail** — Every Claude action (auto-mark, flag, noise-suppress) is written
   to `tbl_audit_log` with: claude_model_used, token_count, reasoning_summary.

6. **Kill switch** — A single config toggle to disable all Claude triage globally
   (separate from the external API kill switch).

7. **No data sent without consent** — The Claude integration is opt-in. On first use,
   admin sees exactly what data is sent to the API. Sensitive findings (credentials,
   PII) should be summarized/truncated before sending.

8. **False negative bias** — When uncertain, Claude should lean toward NOT marking
   something as FP. A missed FP costs analyst time. An incorrect FP suppresses a
   real finding and could cause a security miss. Err on the side of caution.

---

## 6. New Database Objects Needed

### `tbl_ai_triage_log`
```sql
CREATE TABLE tbl_ai_triage_log (
    id              BIGINT PRIMARY KEY,
    scan_instance_id VARCHAR NOT NULL,
    finding_hash    VARCHAR NOT NULL,       -- links to tbl_scan_results.hash
    triage_type     VARCHAR NOT NULL,       -- 'fp_review' | 'noise_score'
    model_used      VARCHAR NOT NULL,       -- e.g., 'claude-opus-4-6'
    fp_probability  REAL,                   -- 0.0-1.0
    noise_score     REAL,                   -- 0.0-1.0
    confidence      VARCHAR,                -- 'low'|'medium'|'high'
    category        VARCHAR,                -- 'shared_infrastructure'|'unrelated_breach'|etc.
    reasoning       TEXT,                   -- Claude's explanation
    action_taken    VARCHAR,                -- 'auto_marked_fp'|'flagged_review'|'suppressed'|'none'
    human_override  INT DEFAULT 0,          -- 1 if analyst disagreed with Claude
    token_input     INT,
    token_output    INT,
    created_at      BIGINT NOT NULL
);
```

### `tbl_ai_noise_cache`
```sql
CREATE TABLE tbl_ai_noise_cache (
    cache_key       VARCHAR NOT NULL PRIMARY KEY,  -- hash(event_type + data)
    noise_score     REAL NOT NULL,
    reasoning       TEXT,
    hit_count       INT DEFAULT 1,
    created_at      BIGINT NOT NULL,
    expires_at      BIGINT                         -- cache TTL
);
```

---

## 7. New UI Components Needed

### A. AI Triage Review Queue
- Separate results view tab: "AI Flagged"
- Shows Claude-flagged findings with FP probability, confidence, and reasoning
- Per-row: [Mark FP] [Keep — Not FP] buttons (one-click, no confirm dialog)
- Bulk actions: "Accept all high-confidence flags" button
- Analyst agreement tracking (human_override column)

### B. AI Triage Settings Panel
- Enable/disable Claude triage (global toggle)
- API key input (stored in existing config system)
- Auto-mark threshold slider (0.80 – 0.99, default 0.92)
- Monthly token budget (input + usage meter)
- Model selector (Opus 4.6 / Sonnet 4.6 / Haiku 4.5)
- Noise filtering: enable/disable + threshold
- "What gets sent to Claude" transparency section

### C. Per-Finding Triage Status Badge
- In the results table, add a small badge next to findings that Claude reviewed:
  - `AI: FP?` (orange) — flagged for review
  - `AI: FP` (red) — auto-marked as FP by Claude
  - `AI: ✓` (green) — Claude reviewed, not an FP
  - `AI: Noise` (grey) — suppressed as noise

---

## 8. Prompt Engineering Considerations

### Key challenge: What does Claude know about OSINT data?

Claude has strong general knowledge of:
- IP address ownership, CDN ranges, cloud provider IP blocks
- Common breach databases and their reliability
- Certificate transparency logs and their meaning
- Common subdomain patterns (parking, CDN, generic)
- Social engineering indicators
- Whois/registration patterns

Claude needs to be given as context:
- What ASM-NG modules produced the data and how reliable each module is
- The specific target (domain/org/industry)
- Whether the finding is a root-level discovery or deeply chained (chain depth)
- The parent event that triggered this finding (source context)

### Prompt structure hypothesis

```
SYSTEM:
You are an OSINT security analyst assistant reviewing findings from an
automated attack surface scan of [target_description].
Your job is to identify false positives — findings that are technically
present in data sources but are not actually relevant to or owned by the target.

For each finding, return a JSON object with:
- fp_probability (0.0-1.0): probability this is a false positive
- confidence: "low" | "medium" | "high"
- reasoning: brief explanation (1-2 sentences)
- category: classify the FP type if applicable

Err on the side of caution. If uncertain, return fp_probability < 0.7.
Never return fp_probability > 0.85 unless you are very confident.

USER:
Target: example.com (mid-size US financial services company)
Event type: EMAILADDR_COMPROMISED (email address found in breach database)
Source module: sfp_haveibeen (HaveIBeenPwned API)

Findings to review:
[
  {
    "id": "a1b2c3",
    "data": "alice@example.com",
    "source_data": "Adobe breach (2013)",
    "chain_depth": 2
  },
  ...
]
```

### Noise scoring prompt structure hypothesis

```
You are evaluating whether continuing to investigate this network artifact
will yield actionable security findings for the target [target].

Artifact: [event_type] → [data]
Source: [parent_event_type] → [parent_data]
Discovery depth: [chain_depth]

Rate the investigation value (0.0-1.0):
1.0 = definitely target-owned, high value to investigate
0.0 = definitely generic/shared/noise, waste of time to investigate

Return JSON: {score, reasoning, category}
```

---

## 9. Research Questions for Claude Deep Research

The following questions should be explored in depth. This is the core research agenda.

### 9.1 Prior Art and Existing Approaches

- How have existing SIEM and SOAR platforms (Splunk SOAR, Microsoft Sentinel, Palo Alto
  XSOAR, IBM QRadar) integrated LLMs for alert triage and false positive reduction?
  What architectures did they choose? What went wrong?

- Are there academic papers or industry research on LLM-assisted security finding triage?
  What accuracy rates have been demonstrated? What failure modes were identified?

- How does Microsoft Copilot for Security approach FP reduction? What prompt patterns
  does it use? What are its known limitations?

- What is the current state of the art in "agentic" security analysis? (AutoGPT-for-security
  type approaches, tools like Nuclei-AI, Burp AI extensions, etc.)

### 9.2 Prompt Engineering for Security Classification

- What prompt patterns produce the most reliable structured JSON output from Claude
  for classification tasks?

- How should a security FP-classification prompt be structured to minimize hallucination?
  (Claude should say "I don't know" rather than invent a reason something is an FP)

- What is the optimal batch size for security finding classification prompts?
  (token efficiency vs context window vs coherence tradeoffs)

- How should confidence calibration be approached? (We want "fp_probability: 0.9" to
  actually mean ~90% confidence, not just Claude's vague sense of certainty)

- How can we use Claude's extended thinking / reasoning for higher-stakes FP decisions
  while using faster models for obvious noise?

- What context injection strategies work best when the domain knowledge (OSINT data
  types, specific module behavior) is not in Claude's training data?

### 9.3 Architecture: Async vs Synchronous LLM in Scan Pipelines

- What are the architectural patterns for integrating LLM calls into event-driven,
  queue-based processing systems without introducing latency into the critical path?

- How should the async noise scorer interact with a scan that is actively dispatching
  events? Can it retroactively prune events that are still in flight?

- What database/queue patterns are suitable for "Claude result arrives after event
  already dispatched" scenarios?

- How do production ML systems handle the "cold start" problem — when an asset hasn't
  been seen before and there's no cached noise score?

### 9.4 Batching and Cost Management

- What is the expected token cost per finding for batch FP review with Claude Opus 4.6
  vs Sonnet 4.6 vs Haiku 4.5? At what volume does cost become prohibitive?

- What batching strategies minimize cost while maintaining quality?
  (group by event type? group by data source? group by risk level?)

- Should different Claude models be used for different triage stages?
  (Haiku for fast noise pre-screening, Opus for high-stakes FP decisions?)

- How can the system learn over time from analyst feedback to reduce the number of
  Claude calls needed? (i.e., if Claude has been 100% correct on "Cloudflare IPs are
  noise" for 500 decisions, cache that pattern locally without calling Claude again)

### 9.5 Data Privacy and Security

- What data minimization strategies should be applied before sending OSINT findings
  to an external LLM API?

- For security-sensitive findings (leaked passwords, PII), what should be
  truncated/hashed/summarized before the API call?

- Are there on-premises LLM deployment options (Ollama, vLLM, local Claude via
  Bedrock) that would allow this integration for air-gapped or compliance-heavy
  environments? What quality/cost tradeoffs do they introduce?

- What are the data retention implications of sending scan findings to the Claude API?
  How does Anthropic's data retention policy interact with SOC 2, GDPR, and HIPAA
  requirements that target organizations may have?

### 9.6 Reliability and Failure Modes

- What happens when the Claude API is unavailable? The scan should not fail or pause.
  What graceful degradation pattern is appropriate?

- How do we detect when Claude is "confidently wrong" — returning high-probability FP
  scores on things that are not actually false positives?

- What feedback loops can detect model drift over time? (e.g., analyst override rate
  increasing is a signal that the prompt or thresholds need recalibration)

- How should the system handle ambiguous edge cases — findings that are FP for some
  customers but real for others (e.g., a pentest target that legitimately uses Cloudflare)?

### 9.7 Agentic Extension (Future)

- Beyond reactive triage, what would it look like for Claude to proactively suggest
  next steps during a scan? (e.g., "I see this subdomain looks like a staging
  environment — consider running `sfp_webanalyze` and `sfp_ssl` against it specifically")

- How would a Claude agent safely interact with the scan engine to add targets, adjust
  module config, or create follow-up scans without over-escalating privileges?

- What guardrails are needed to prevent a Claude agent from causing unintended
  reconnaissance (e.g., accidentally running active scanning against systems it shouldn't)?

- Is there a path to Claude understanding the full scan graph (what discovered what,
  in what order) and using that graph structure to make better triage decisions?

---

## 10. Implementation Phasing

### Phase 1: Post-Scan FP Reviewer (Build first — safe, no scan impact)
- New module: `spiderfoot/ai_triage.py` — standalone reviewer class
- Triggered manually from scan results UI ("Run AI Triage") or automatically on scan completion
- Batch reviews all findings by event type
- Writes results to `tbl_ai_triage_log`
- New "AI Flagged" tab in results UI
- Success metric: analyst agreement rate > 85% on auto-marked FPs

### Phase 2: Noise Score Cache Builder (Runs alongside Phase 1)
- Every FP review result also populates `tbl_ai_noise_cache`
- Over time, builds a local knowledge base of known-noise patterns
- This cache will power Phase 3 without requiring Claude calls for known patterns

### Phase 3: Async Noise Scorer (After Phase 1 is validated)
- New background thread in `SpiderFootScanner`: `_noiseScorer`
- Checks cache first; only calls Claude for cache misses
- Assigns noise scores to events in DB
- UI shows noise-suppressed events in a collapsed/greyed state
- Analyst can un-suppress individual events if needed

### Phase 4: Rule-Based Synchronous Gate (Can run in parallel with Phase 3)
- No Claude calls — pure heuristics derived from accumulated Phase 1/2/3 data
- Known CDN ranges (Cloudflare, Akamai, Fastly, AWS) → instant noise
- Known parking CNAME patterns → instant suppress
- This alone could eliminate 20-30% of wasted module dispatches with zero API cost

### Phase 5: Agentic Suggestions (Research phase first, implement later)
- Claude can suggest scan strategy adjustments mid-scan
- Requires much more work on safety and guardrails
- Should not be built until Phases 1-4 are stable and validated

---

## 11. Success Metrics

| Metric | Phase 1 | Phase 2-3 | Phase 4-5 |
|--------|---------|-----------|-----------|
| Analyst FP review time (per target) | -60% | -75% | -80% |
| False negative rate (real findings auto-suppressed) | < 0.5% | < 1% | < 0.5% |
| Analyst agreement with Claude auto-marks | > 85% | > 88% | > 90% |
| Scan duration (mid-size target) | no change | -20% | -35% |
| External API calls per scan | no change | -15% | -30% |
| Claude API cost per scan (avg) | < $0.10 | < $0.08 | < $0.05 |

---

## 12. Open Questions Requiring Research Answers

1. Should FP decisions be scoped per-scan or per-target (persistent)?
   If Claude marks something as FP in scan #3, should it auto-mark it in scan #4?

2. What is the right granularity for noise scoring — per event instance or per
   (event_type, data_pattern) tuple?

3. How do we handle the bootstrapping problem — a new target has no analyst history
   for Claude to learn from?

4. Is there a lighter-weight model than Claude that could handle the high-frequency
   noise scoring decisions, with Claude reserved for FP review?

5. Should the integration be a SpiderFoot module (with all the module lifecycle
   benefits) or a standalone service outside the module system?

6. What is the right prompt caching strategy for Anthropic's prompt caching feature,
   given that the system prompt (event type definitions, module descriptions) is
   repeated across many calls?

---

## 13. Codebase Reference (For Research Context)

Key files in ASM-NG:

| File | Purpose |
|------|---------|
| `sfscan.py` | `SpiderFootScanner` class — central `eventQueue`, module dispatch loop |
| `sflib.py` | `SpiderFoot` base class — HTTP, DNS, utility methods |
| `spiderfoot/db.py` | All DB methods — `scanResultEvent()`, `targetFalsePositives()`, etc. |
| `sfapi.py` | FastAPI REST layer |
| `sfwebui.py` | CherryPy web UI — analyst-facing endpoints |
| `modules/sfp_*.py` | 288 individual modules |
| `spiderfoot/ext_api.py` | External vendor API (built in v5.3.0) |

Key database tables:

| Table | Purpose |
|-------|---------|
| `tbl_scan_results` | All scan findings (`false_positive` column) |
| `tbl_target_false_positives` | Persistent per-target FP rules |
| `tbl_analyst_type_comments` | Analyst notes per event type |
| `tbl_analyst_row_notes` | Analyst notes per finding row |
| `tbl_grade_snapshots` | Scan quality grades (A-F) |
| `tbl_audit_log` | All admin/analyst actions |

---

*Document created: 2026-03-04*
*For: Claude deep research — ASM-NG AI integration planning*
*Author: 0x31i / ASM-NG project*
