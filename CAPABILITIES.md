# ASM-NG — Tools, APIs & Capabilities

ASM-NG is an active and passive attack surface management platform built on the SpiderFoot engine.
It runs **308 scanning modules** against a target, pulling from **100+ third-party APIs and data sources**
to map every exposed asset, credential leak, vulnerability, and brand risk — then correlates everything
into prioritized, graded findings.

---

## Quick Navigation

| Category | Summary |
|---|---|
| [DNS & Network](#dns--network) | Subdomain discovery, zone transfers, passive DNS |
| [Threat Intelligence & Reputation](#threat-intelligence--reputation) | 60+ blacklist, IOC, and reputation feeds |
| [Breach & Leaked Credentials](#breach--leaked-credentials) | Credential databases, paste sites, infostealer logs |
| [Dark Web & Tor Monitoring](#dark-web--tor-monitoring) | Onion search engines, ransomware feeds, defacement tracking |
| [Social Media & Account Discovery](#social-media--account-discovery) | 500+ platforms, social profile correlation |
| [Search Engines & OSINT Aggregators](#search-engines--osint-aggregators) | Google, Bing, Shodan, Censys, Fofa, ZoomEye, and more |
| [Email & Contact Intelligence](#email--contact-intelligence) | Email discovery, disposable detection, breach cross-reference |
| [WHOIS & Domain Intelligence](#whois--domain-intelligence) | Forward/reverse WHOIS, ownership history |
| [SSL / TLS & Certificates](#ssl--tls--certificates) | Certificate parsing, CT log mining, TLS weakness scanning |
| [Web Technology Detection](#web-technology-detection) | CMS, frameworks, software stack fingerprinting |
| [Vulnerability Scanning](#vulnerability-scanning) | Nuclei, Nmap, Gobuster, RetireJS, subdomain takeover |
| [Brand Protection & Phishing](#brand-protection--phishing) | Lookalike domains, phishing feeds, dark web brand mentions |
| [Cloud Storage & Infrastructure](#cloud-storage--infrastructure) | S3, Azure Blob, GCS bucket discovery and content listing |
| [Geolocation & Physical Intelligence](#geolocation--physical-intelligence) | IP geolocation, WiFi AP mapping, address resolution |
| [Company & Corporate Intelligence](#company--corporate-intelligence) | SEC EDGAR, GLEIF, OpenCorporates, subsidiary discovery |
| [Cryptocurrency & Blockchain](#cryptocurrency--blockchain) | Wallet detection, on-chain transaction monitoring |
| [AI Infrastructure Discovery](#ai-infrastructure-discovery) | 22 modules dedicated to mapping AI/ML attack surface |
| [Content & Metadata Extraction](#content--metadata-extraction) | Emails, phones, hashes, credit cards, documents |
| [Correlation Engine](#correlation-engine) | 63 automated cross-finding risk rules |
| [Platform Features](#platform-features) | Web UI, REST API, CLI, grading, workspaces |

---

## DNS & Network

Discovers every hostname, subdomain, IP, and DNS record associated with a target — actively and passively.

| Module | What It Does | Data Source |
|---|---|---|
| dnsbrute | Brute-forces common hostnames to find hidden subdomains | Local wordlist |
| dnscommonsrv | Brute-forces SRV records (XMPP, SIP, etc.) | Local |
| dnsgrep | Passive DNS lookup against Rapid7 Sonar dataset | DNSGrep API |
| dnsdumpster | Passive subdomain enumeration | HackerTarget |
| dnsneighbor | Reverse-resolves IPs adjacent to the target | Local |
| dnsraw | Retrieves all raw DNS records (A, MX, TXT, NS, etc.) | Local |
| dnsresolve | Resolves discovered hostnames back to IPs | Local |
| dnszonexfer | Attempts full DNS zone transfers | Local |
| sublist3r | Passive subdomain enumeration | Sublist3r API |
| securitytrails | Passive DNS and WHOIS history | SecurityTrails |
| crobat_api | Subdomain enumeration via Omnisint | Crobat / Omnisint |
| projectdiscovery | Subdomain discovery from chaos.projectdiscovery.io | Project Discovery |
| mnemonic | Historical passive DNS records | Mnemonic |
| zetalytics | Hosts and subdomains on target domain | Zetalytics |
| hostio | Domain/IP relationship graph | host.io |
| networksdb | IP and domain intelligence | NetworksDB |
| opennic | Alternative DNS system queries | OpenNIC |
| google_tag_manager | Finds hosts sharing the same GTM container ID | Web-based |

---

## Threat Intelligence & Reputation

Checks every discovered IP, domain, and host against the world's major threat intelligence feeds, blocklists, and abuse databases.

### Reputation & IOC Feeds

| Module | What It Does | Data Source |
|---|---|---|
| alienvault | Threat intel and IOC lookups | AlienVault OTX |
| alienvaultiprep | IP reputation database | AlienVault |
| abuseipdb | Malicious IP reports | AbuseIPDB |
| abusech | Malicious hosts, domains, and IPs | Abuse.ch |
| greynoise | IP enrichment and internet noise classification | GreyNoise |
| greynoise_community | Community-tier IP reputation | GreyNoise |
| virustotal | IP and domain reputation | VirusTotal |
| xforce | IP reputation and passive DNS | IBM X-Force |
| talosintel | Malicious IPs and netblocks | Cisco Talos |
| emergingthreats | Malicious netblocks and IPs | Emerging Threats |
| threatcrowd | IP, domain, and email cross-reference | ThreatCrowd |
| threatminer | Passive DNS and malware IOCs | ThreatMiner |
| maltiverse | Malicious IP activity | Maltiverse |
| malwarepatrol | Malware distribution database | Malware Patrol |
| bambenek | DGA and threat actor feeds | Bambenek Consulting |
| cinsscore | Malicious netblock scoring | CINS Army |
| fraudguard | Fraud and threat assessment | Fraudguard |
| pulsedive | IOC enrichment | Pulsedive |
| hybridanalysis | Malware sandbox / domain lookup | Hybrid Analysis |
| opencti | Enterprise threat intelligence platform | OpenCTI |
| misp | Shared threat intelligence platform | MISP |
| mandiant_ti | Advanced persistent threat intelligence | Mandiant |
| recordedfuture | Vulnerability and risk intelligence | Recorded Future |
| ipqualityscore | Fraud and abuse scoring | IPQualityScore |
| onyphe | Threat lists, vulnerabilities, geolocation | Onyphe |
| spur | Malicious proxy and VPN detection | Spur |
| luminar | Dark web and threat intelligence | Luminar |
| deepdarkcti | Ransomware leak site and forum watchlists | deepdarkCTI |
| customfeed | User-supplied custom threat feeds | Custom |

### DNS Filtering / Safe Browsing

| Module | What It Does | Data Source |
|---|---|---|
| cloudflaredns | Checks if host is blocked by Cloudflare DNS | Cloudflare |
| opendns | Checks if host is blocked by OpenDNS | OpenDNS |
| quad9 | Checks if host is blocked by Quad9 | Quad9 |
| googlecsafebrowsing | Checks Google Safe Browsing | Google |
| adguard_dns | Checks AdGuard DNS block lists | AdGuard |
| cleanbrowsing | Checks CleanBrowsing DNS filters | CleanBrowsing |
| comodo | Checks Comodo Secure DNS | Comodo |
| yandexdns | Checks Yandex DNS | Yandex |

### Spam & Abuse Blacklists

| Module | What It Does | Data Source |
|---|---|---|
| spamhaus | Zen database for malicious IPs | Spamhaus |
| sorbs | Open relays and proxy lists | SORBS |
| spamcop | Spam reporting blacklist | SpamCop |
| uceprotect | Multi-level IP blacklist | UCEPROTECT |
| surbl | Spam URL blacklist | SURBL |
| cleantalk | Spam IP database | CleanTalk |
| botscout | Spam-bot IP and email database | BotScout |
| botvrij | Malicious domain list | botvrij.eu |
| dronebl | Open relay and proxy database | DroneBL |
| honeypot | Project Honey Pot spam intelligence | Project Honey Pot |
| greensnow | Brute-force and attack IP list | Greensnow |
| blocklistde | Attack IP database | blocklist.de |
| phishtank | Phishing domain database | PhishTank |
| openphish | Phishing URL feed | OpenPhish |
| phishstats | Phishing IP database | PhishStats |
| adblock | AdBlock Plus filter lists | Adblock Plus |
| vxvault | Malicious domain and IP list | VXVault |
| coinblocker | Cryptojacking domain lists | CoinBlocker |

---

## Breach & Leaked Credentials

Identifies compromised emails, passwords, and credentials across breach databases, paste sites, and infostealer logs.

| Module | What It Does | Data Source |
|---|---|---|
| haveibeenpwned | Checks emails against known breaches | HaveIBeenPwned |
| dehashed | Full breach record lookups | Dehashed |
| leakcheck | Credential breach database | LeakCheck |
| snusbase | Breach database search | Snusbase |
| breachparse_ng | Private breach credential search | bp-ng API |
| stealerlog_check | Infostealer log lookups | Hudson Rock Cavalier |
| psbdmp | Pastebin breach dump search | PSBDMP |
| citadel | Breach lookup by email/domain | Leak-Lookup |
| ransomwatch | Ransomware group leak site monitoring | Ransomware.live |
| apileak | Searches GitHub and paste sites for leaked API keys | GitHub / Paste Sites |
| tool_h8mail | Multi-source email OSINT and breach hunting | Multiple |
| intelx | Breach, paste, and dark web search | IntelligenceX |
| openbugbounty | Public vulnerability disclosure reports | OpenBugBounty |

---

## Dark Web & Tor Monitoring

Searches Tor-based search engines, ransomware leak sites, defacement archives, and underground forums for target mentions.

| Module | What It Does | Data Source |
|---|---|---|
| darkweb_aggregate | Multi-engine Tor search (Haystak, Tor66) | Tor Search Engines |
| torch | TORCH Tor search engine | TORCH |
| ahmia | Ahmia Tor search engine | Ahmia |
| onionsearchengine | .onion search engine | Onion Search Engine |
| onioncity | Google CSE over Tor content | Google CSE + Tor |
| torexits | Checks if IP is a known Tor exit node | Tor Project |
| brand_darkweb | Searches dark web for brand impersonation | Dark Web |
| deepdarkcti | Ransomware and underground forum watchlists | deepdarkCTI |
| iknowwhatyoudownload | Checks for torrent activity from IP | IKNOWWHATYOUDOWNLOAD |
| zoneh | Website defacement tracking | zone-h.org |
| wikileaks | Searches Wikileaks for domain/email mentions | Wikileaks |
| multiproxy | Open proxy list checking | Multiproxy.org |
| voipbl | VoIP abuse blacklist | VoIPBL |

---

## Social Media & Account Discovery

Maps a target's presence across hundreds of online platforms and social networks.

| Module | What It Does | Data Source |
|---|---|---|
| accounts | Checks 500+ platforms for associated accounts | Multiple |
| twitter | Gathers profile info from Twitter/X | Twitter |
| instagram | Discovers Instagram presence | Instagram |
| github | Finds public code repositories | GitHub |
| reddit | Monitors subreddits for mentions | Reddit |
| flickr | Searches Flickr for domain/email mentions | Flickr |
| slideshare | Discovers SlideShare profiles | SlideShare |
| mastodon | Monitors Mastodon for mentions | Mastodon |
| bluesky | Monitors Bluesky for mentions | Bluesky |
| telegram | Monitors Telegram channels | Telegram |
| discord | Monitors Discord channels | Discord |
| matrix | Monitors Matrix servers | Matrix.org |
| rocketchat | Monitors Rocket.Chat servers | Rocket.Chat |
| mattermost | Monitors Mattermost servers | Mattermost |
| gravatar | Retrieves profile info from Gravatar | Gravatar |
| stackoverflow | Searches StackOverflow for mentions | Stack Overflow |
| sociallinks | Social media and dark web intelligence | SocialLinks.io |
| socialprofiles | Discovers social profiles for identified names | Multiple |

---

## Search Engines & OSINT Aggregators

Uses major search engines, internet-wide scanners, and passive reconnaissance services to build a full picture of the target's exposed infrastructure.

| Module | What It Does | Data Source |
|---|---|---|
| googlesearch | Subdomain and link discovery via Google CSE | Google CSE |
| bingsearch | Subdomain and link discovery | Bing |
| duckduckgo | Search and target discovery | DuckDuckGo |
| bingsharedip | Finds hosts sharing the same IP via Bing | Bing |
| commoncrawl | URL discovery from the CommonCrawl dataset | CommonCrawl |
| pastebin | Searches paste sites via Google CSE | Pastebin / Google |
| pasterack | Searches GitHub Gists, Rentry, dpaste, and others | Multiple paste sites |
| searchcode | Code repository discovery | Searchcode |
| grep_app | Code search for links and emails | grep.app |
| shodan | Port, service, and banner information for IPs | Shodan |
| censys | Host and service discovery | Censys |
| binaryedge | Breaches, vulnerabilities, and passive DNS | BinaryEdge |
| fofa | Domain and IP infrastructure search | Fofa |
| zoomeye | Infrastructure and service search | ZoomEye |
| netlas | Domain and IP intelligence | Netlas |
| fullhunt | Attack surface discovery | FullHunt |
| leakix | Exposed service discovery | LeakIX |
| hackertarget | Co-hosted site discovery | HackerTarget |
| robtex | Shared-IP host discovery | Robtex |
| viewdns | Co-hosted site discovery | ViewDNS |
| bgpview | BGP and network routing intelligence | BGPView |
| ripe | European IP registry lookups | RIPE |
| arin | North American IP registry lookups | ARIN |
| urlscan | URL and page scan history | URLScan.io |
| archiveorg | Historical page versions and content | Wayback Machine |
| ciscocumbrella | Domain and threat investigation | Cisco Umbrella |
| crt | Subdomain discovery from CT logs | crt.sh |
| search_dork | Advanced dork-based search (filetype:, inurl:, etc.) | DuckDuckGo |
| deepinfo | Passive DNS and infrastructure mapping | Deepinfo |
| onyphe | Threat, vulnerability, and geolocation data | Onyphe |
| fsecure_riddler | Network and infrastructure info | F-Secure Riddler |
| intelx | Dark web, breach, and paste search | IntelligenceX |
| abstractapi | Domain, phone, and IP lookups | AbstractAPI |
| c99 | Geolocation and proxy detection | C99 |
| criminalip | Domain, IP, and phone intelligence | CriminalIP |

---

## Email & Contact Intelligence

Discovers email addresses, phone numbers, and contact records associated with the target, and validates or enriches them.

| Module | What It Does | Data Source |
|---|---|---|
| hunter | Email and employee discovery | Hunter.io |
| emailformat | Email pattern discovery | email-format.com |
| emailcrawlr | Email and phone discovery | EmailCrawlr |
| emailrep | Email reputation scoring | EmailRep.io |
| snov | Email discovery from domains | Snov.io |
| debounce | Detects disposable/temporary email addresses | Debounce.io |
| trumail | Detects disposable email addresses | Trumail |
| nameapi | Detects disposable email addresses | NameAPI |
| fullcontact | Email and domain enrichment | FullContact |
| email | Extracts email addresses from web content | Local |
| phone | Extracts phone numbers from web content | Local |
| callername | US phone number location and reputation | Callername |
| numverify | Phone number carrier and location lookup | numverify.com |
| textmagic | Phone number type identification | TextMagic |
| twilio | Phone number intelligence (with Caller Name add-on) | Twilio |

---

## WHOIS & Domain Intelligence

Maps domain ownership, registration history, and registrant relationships — forward and in reverse.

| Module | What It Does | Data Source |
|---|---|---|
| whois | WHOIS lookups for domains and netblocks | WHOIS |
| reversewhois | Reverse WHOIS by registrant | reversewhois.io |
| whoisfreaks | Reverse WHOIS by email, name, or company | Whoisfreaks |
| whoisology | Reverse WHOIS lookups | Whoisology |
| whoxy | Reverse WHOIS lookups | Whoxy |
| jsonwhoiscom | WHOIS record search | JsonWHOIS |
| securitytrails | Passive DNS and WHOIS history | SecurityTrails |
| tldsearch | Searches all TLDs for domains with the same name | Local |
| similar | Identifies similar/squatted/typo domains | Local |
| tool_dnstwist | Typosquatting and bitsquatting domain discovery | DNSTwist |

---

## SSL / TLS & Certificates

Parses certificates, mines Certificate Transparency logs for new hostnames, and scans for TLS weaknesses.

| Module | What It Does | Data Source |
|---|---|---|
| sslcert | Retrieves and parses SSL/TLS certificate details | Local |
| certspotter | Gathers certificates from CertSpotter CT log feed | CertSpotter |
| crt | Mines crt.sh Certificate Transparency logs for subdomains | crt.sh |
| circllu | Queries CIRCL.LU passive DNS and SSL databases | CIRCL.LU |
| tool_testsslsh | Identifies TLS/SSL weaknesses and misconfigurations | testssl.sh |

---

## Web Technology Detection

Fingerprints the technology stack behind every web property, including CMS, frameworks, and third-party integrations.

| Module | What It Does | Data Source |
|---|---|---|
| webserver | Retrieves web server banners and version info | Local |
| webframework | Identifies frontend frameworks (jQuery, React, etc.) | Local |
| whatcms | CMS identification | WhatCMS.org |
| tool_cmseek | Identifies and audits CMS installations | Local |
| tool_wappalyzer | Full technology stack fingerprinting | Wappalyzer |
| tool_whatweb | Web technology identification | WhatWeb |
| builtwith | Technology stack, email, and tracking code discovery | BuiltWith |
| crxcavator | Chrome extension discovery and analysis | CRXcavator |
| apple_itunes | Mobile app discovery | Apple iTunes |
| koodous | Android app intelligence | Koodous |
| dockerhub | Container image discovery | Docker Hub |
| huggingface | AI model and dataset repository search | Hugging Face |

---

## Vulnerability Scanning

Actively tests targets for exploitable vulnerabilities using industry-standard tools and custom scanning logic.

| Module | What It Does | Tool / Source |
|---|---|---|
| tool_nuclei | Fast, template-based vulnerability scanner (thousands of templates) | Nuclei |
| tool_nmap | Port scanning and OS fingerprinting | Nmap |
| tool_gobuster | Web path and directory brute-forcing | Gobuster |
| tool_wafw00f | Web Application Firewall detection | Wafw00f |
| tool_retirejs | Detects JavaScript libraries with known CVEs | RetireJS |
| tool_snallygaster | Finds sensitive file leaks on HTTP servers | Snallygaster |
| tool_trufflehog | Searches git repositories for secrets and credentials | TruffleHog |
| tool_testsslsh | TLS/SSL weakness identification | testssl.sh |
| tool_dnstwist | Typosquatting and bitsquatting detection | DNSTwist |
| tool_nbtscan | NETBIOS nameserver scanning | NBTScan |
| tool_onesixtyone | SNMP service scanner | Onesixtyone |
| portscan_tcp | Scans common TCP ports across all discovered hosts | Local |
| spider | Web crawler for content and link extraction | Local |
| junkfiles | Discovers exposed backup/temp files (e.g. .bak, .swp) | Local |
| intfiles | Discovers exposed documents, archives, and config files | Local |
| subdomain_takeover | Checks all subdomains for takeover vulnerabilities | Local |
| punkspider | Checks punkspider.io for indexed vulnerabilities | Punkspider.io |
| ai_vulnscan | Scans AI/ML infrastructure using Nuclei AI templates | Nuclei |

---

## Brand Protection & Phishing

Monitors for lookalike domains, phishing campaigns, and brand impersonation across the open and dark web.

| Module | What It Does | Data Source |
|---|---|---|
| brand_impersonation | Scores lookalike domains using TLSH fuzzy hashing and favicon similarity | Local |
| brand_darkweb | Searches the dark web for brand impersonation activity | Dark Web |
| phishtank | Known phishing domain database | PhishTank |
| openphish | Live phishing URL feed | OpenPhish |
| phishstats | Phishing IP tracking | PhishStats |
| googlecsafebrowsing | Google Safe Browsing phishing and malware lists | Google |
| tool_dnstwist | Typosquatted domain discovery | DNSTwist |

---

## Cloud Storage & Infrastructure

Discovers publicly exposed cloud storage buckets and CDN infrastructure, then attempts to list bucket contents.

| Module | What It Does | Data Source |
|---|---|---|
| s3bucket | Discovers Amazon S3 buckets and lists contents | AWS S3 |
| azureblobstorage | Discovers Azure Blob Storage and lists contents | Azure |
| googleobjectstorage | Discovers Google Cloud Storage buckets | Google Cloud |
| digitaloceanspace | Discovers Digital Ocean Spaces | Digital Ocean |
| grayhatwarfare | Finds buckets matching the target domain | Grayhat Warfare |
| cloudfront | Identifies Amazon CloudFront CDN usage | AWS |
| hosting | Maps IPs to cloud hosting providers (AWS, Azure, GCP, etc.) | Local |

---

## Geolocation & Physical Intelligence

Resolves IPs and addresses to physical locations, and discovers nearby WiFi access points.

| Module | What It Does | Data Source |
|---|---|---|
| ipinfo | IP geolocation | ipinfo.io |
| ipstack | IP geolocation | ipstack.com |
| ipapicom | IP geolocation | ipapi.com |
| ipapico | IP geolocation | ipapi.co |
| googlemaps | Physical address and coordinate lookup | Google Maps |
| openstreetmap | Address to coordinate resolution | OpenStreetMap |
| unwiredlabs | Geolocation via cell towers, WiFi, and IP | UnwiredLabs |
| seon | Geolocation and risk scoring | Seon.io |
| wigle | WiFi access point discovery and mapping | WiGLE |
| openwifimap | Public WiFi hotspot discovery | OpenWifiMap.net |
| wificafespots | WiFi hotspot intelligence | WiFiCafeSpots.com |
| wifimapio | WiFi map and hotspot data | WiFiMap.io |

---

## Company & Corporate Intelligence

Identifies corporate entities, subsidiaries, key personnel, and relationships linked to the target.

| Module | What It Does | Data Source |
|---|---|---|
| associated_company | Discovers subsidiaries and sister companies | SEC EDGAR, GLEIF, Wikidata |
| opencorporates | Company registration and officer information | OpenCorporates |
| gleif | Legal entity identification | GLEIF |
| rocketreach | Contact and employee intelligence | RocketReach |
| seon | Company and contact risk intelligence | Seon.io |
| sociallinks | Corporate social and dark web intelligence | SocialLinks.io |
| company | Extracts company names from discovered content | Local |
| venmo | Public payment network profile lookup | Venmo |

---

## Cryptocurrency & Blockchain

Identifies cryptocurrency wallet addresses in content, checks their reputation, and monitors on-chain transactions.

| Module | What It Does | Data Source |
|---|---|---|
| bitcoin | Identifies Bitcoin addresses in web content | Local |
| bitcoinwhoswho | Checks wallet reputation | Bitcoin Who's Who |
| blockchain | Checks Bitcoin wallet balances | blockchain.info |
| ethereum | Identifies Ethereum addresses in web content | Local |
| etherscan | Checks Ethereum wallet balances and activity | Etherscan |
| arbitrum | Monitors Arbitrum L2 blockchain transactions | Arbiscan |
| bnb | Monitors Binance Smart Chain transactions | BscScan |
| tron | Monitors Tron blockchain transactions | TronGrid |

---

## AI Infrastructure Discovery

22 specialized modules purpose-built to discover, map, and audit AI and machine learning infrastructure — an attack surface most tools completely miss.

### Detection & Fingerprinting

| Module | What It Does |
|---|---|
| ai_fingerprint | Detects exposed AI inference services (Ollama, Triton, vLLM, LiteLLM, LocalAI) via port probing |
| ai_jsdetect | Finds AI SDK imports and chat widgets embedded in web pages |
| ai_webcontent | Identifies AI SDK integrations, MCP clients, agentic frameworks, chatbots, and leaked API keys in web content |
| ai_csp | Extracts AI service dependencies from Content Security Policy headers and plugin manifests |
| ai_shadow_discovery | Finds shadow AI SaaS integrations (OpenAI, Anthropic, Cohere, Mistral, etc.) |

### Reconnaissance & Discovery

| Module | What It Does |
|---|---|
| ai_subdomain | Discovers AI/ML-specific subdomains via CT logs and DNS brute-force |
| ai_ct_deep | Deep Certificate Transparency mining for AI infrastructure patterns |
| ai_passive_recon | Finds AI infrastructure via Shodan and Censys dorks |
| ai_repo_scan | Scans public GitHub repositories for AI model files and leaked API keys |
| ai_historical | Queries the Wayback Machine for historical AI infrastructure evidence |
| ai_llm_probe | Validates live LLM endpoints with prompt probes |
| ai_mcp_detect | Detects MCP (Model Context Protocol) servers via JSON-RPC 2.0 probing |

### Infrastructure Components

| Module | What It Does |
|---|---|
| ai_model_registry | Finds exposed model registries (MLflow, HuggingFace, NVIDIA NGC) |
| ai_data_pipeline | Detects exposed ML data pipelines (Airflow, Label Studio, etc.) |
| ai_gpu_cluster | Finds exposed GPU/compute cluster interfaces (NVIDIA DCGM, SLURM, Ray) |
| ai_vectordb_scanner | Detects exposed vector databases (ChromaDB, Weaviate, Qdrant, Milvus) |
| ai_agent_mapper | Detects agentic AI frameworks (CrewAI, AutoGen, LangServe) |

### Governance & Compliance

| Module | What It Does |
|---|---|
| ai_governance | Checks for published AI governance policies and responsible AI statements |
| ai_vendor_audit | Identifies third-party AI vendor integrations (Zendesk AI, Intercom, Ada, etc.) |
| ai_compliance | Maps findings to AI compliance frameworks (EU AI Act, NIST AI RMF, ISO 42001) |
| ai_bom | Produces an AI Bill of Materials — a complete inventory of all discovered AI components |
| ai_summary | Uses an LLM to generate a plain-English summary of all scan findings |
| ai_threat_intel | AI-enhanced threat intelligence enrichment |

---

## Content & Metadata Extraction

Automatically extracts structured data from web pages, documents, and binary files — no configuration required.

| What It Extracts | Module |
|---|---|
| Email addresses | email |
| Phone numbers | phone |
| Human names | names |
| Company names | company |
| Country names | countryname |
| MD5 / SHA hashes | hashes |
| Credit card numbers | creditcard |
| IBAN numbers | iban |
| Bitcoin / Ethereum wallet addresses | bitcoin, ethereum |
| Base64-encoded strings | base64 |
| Strings in binary files | binstring |
| HTTP cookies | cookie |
| SQL / application error messages | errors |
| Forms, file upload endpoints | pageinfo |
| Document and image metadata (EXIF, author, etc.) | filemeta |
| Non-standard HTTP headers | strangeheaders |
| Interesting files (.bak, .sql, .zip, .env, etc.) | junkfiles, intfiles |

---

## Correlation Engine

63 automated YAML rules that run after a scan completes, correlating findings across all modules to surface the highest-risk patterns.

### Rule Categories

| Category | Example Rules |
|---|---|
| **AI Risk** | Unauthenticated AI clusters, shadow AI sprawl, leaked AI credentials, MCP tool exposure, AI governance absence |
| **Infrastructure Exposure** | Open S3/Azure/GCS buckets, exposed databases, RDP exposure, internal services exposed to internet |
| **Data Breach** | Email in multiple breach databases, credential + ransomware leak combination, paste-only email exposure |
| **Certificate Risk** | Expiring or expired certificates, misconfigured TLS |
| **DNS Risk** | Zone transfer vulnerabilities, missing SPF/DMARC, stale DNS records |
| **Brand & Phishing** | Lookalike domain + phishing feed match, dark web brand mention |
| **Cross-Scan Intelligence** | Shared IPs across scans, shared SSL certificates, shared registrant emails, technology outliers |
| **Threat Correlation** | Multiple malicious indicators on same host, malware + phishing co-hosting |

---

## Platform Features

### Web UI
- Real-time scan monitoring dashboard with module pipeline, live event types, and 100-item discovery feed
- Security grading system — A through F, across 7 weighted categories
- Findings and vulnerability views with analyst comments and row-level notes
- Known asset management — bulk import/export of IPs, domains, employees
- False positive tracking — three-state system (Unvalidated / False Positive / Validated) with cross-scan persistence
- Workspace management — multi-target scanning, workspace cloning and merging
- Export formats: CSV, JSON, XLSX (Excel), GEXF (for graph tools), Nessus/Burp compatible output
- Duplication check and deduplication tooling
- Full user management with audit logging (user / action / IP / timestamp)

### REST API
- Full feature parity with the Web UI
- FastAPI-based with WebSocket support for streaming results
- Bearer token authentication
- Workspace, scan, and result management endpoints
- Streaming responses for large datasets

### CLI
- Interactive command-line interface for all scan functions
- Module enable/disable management
- Live progress monitoring during scans
- Output in pretty-print, JSON, or CSV formats

---

## By The Numbers

| Metric | Count |
|---|---|
| Scanning modules | 308 |
| Third-party API integrations | 100+ |
| Automated correlation rules | 63 |
| Distinct event/finding types | 130+ |
| Social / account platforms checked | 500+ |
| AI/ML-specific discovery modules | 22 |
| Export formats | CSV, JSON, XLSX, GEXF |
| Database backend | PostgreSQL |
