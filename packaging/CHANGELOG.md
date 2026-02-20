# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Added
- **AI/ML Infrastructure Discovery** — 3 new modules for external AI attack surface detection:
  - `sfp_ai_fingerprint` — detects and fingerprints 15+ AI/ML inference frameworks (Ollama, NVIDIA Triton, vLLM, TorchServe, TensorFlow Serving, MLflow, BentoML, Gradio, Ray Dashboard, Streamlit, LM Studio, MCP servers) via port analysis, banner fingerprinting, and active HTTP probes; checks for unauthenticated model access
  - `sfp_ai_subdomain` — discovers AI-related subdomains via Certificate Transparency logs and DNS brute-forcing with an 80+ term AI-specific wordlist; detects cloud AI service CNAME patterns (SageMaker, Azure OpenAI, HuggingFace)
  - `sfp_ai_webcontent` — analyzes web content for embedded AI SDK imports, chat widget markers, leaked AI API keys, and inference endpoint references
- 4 new event types: `AI_INFRASTRUCTURE_DETECTED`, `AI_MODEL_EXPOSED`, `AI_ENDPOINT_UNAUTHENTICATED`, `AI_API_KEY_LEAKED`
- AI event types integrated into grading system (unauthenticated endpoints scored as critical severity)
- AI subdomain wordlist (`spiderfoot/dicts/ai-subdomains.txt`)
- **PostgreSQL database backend** — production-ready dual-backend support:
  - Automatic PostgreSQL installation and configuration on first launch (Debian/Kali/Ubuntu, macOS, RHEL/Fedora)
  - Thread-safe connection pooling with semaphore-gated access (64 concurrent connections default)
  - Transparent SQL translation via `PgCursorWrapper` (no code changes needed for existing queries)
  - Automatic INT-to-BIGINT conversion for millisecond timestamp compatibility
  - Bidirectional migration tool (`python -m spiderfoot.db_migrate`) between SQLite and PostgreSQL
  - Configurable via environment variables: `ASMNG_DATABASE_URL`, `ASMNG_DB_TYPE`, `ASMNG_PG_AUTO_SETUP`
  - Auto-detection priority: explicit DSN → env var → localhost probe → auto-setup → SQLite fallback
- Automated changelog generation enabled in CI.

## [5.2.5] - 2025-06-24
- Initial automated changelog entry.
