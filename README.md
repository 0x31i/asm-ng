# ASM-NG (Attack Surface Management - Next Generation)

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](https://raw.githubusercontent.com/0x31i/asm-ng/master/LICENSE)
[![Python Version](https://img.shields.io/badge/python-3.9+-green)](https://www.python.org)
[![Stable Release](https://img.shields.io/badge/version-5.2.9-blue.svg)](https://github.com/0x31i/asm-ng/releases/tag/v5.2.9)
[![Production Grade](https://img.shields.io/badge/Production-Grade-blue.svg)](https://github.com/0x31i/asm-ng)
[![AI Enhanced](https://img.shields.io/badge/AI-Enhanced-orange.svg)](https://github.com/0x31i/asm-ng)
[![CI status](https://github.com/0x31i/asm-ng/workflows/Tests/badge.svg)](https://github.com/0x31i/asm-ng/actions?query=workflow%3A"Tests")
[![Docker CI Build](https://github.com/0x31i/asm-ng/workflows/Docker%20Image%20CI/badge.svg)](https://github.com/0x31i/asm-ng/actions?query=workflow%3A"Docker%20Image%20CI")
[![Code QL](https://github.com/0x31i/asm-ng/workflows/CodeQL/badge.svg)](https://github.com/0x31i/asm-ng/actions?query=workflow%3A"CodeQL")
[![Last Commit](https://img.shields.io/github/last-commit/0x31i/asm-ng)](https://github.com/0x31i/asm-ng/commits/master)
[![Discord](https://img.shields.io/discord/770524432464216074)](https://discord.gg/vyvztrG)
![Active Development](https://img.shields.io/badge/Maintenance%20Level-Actively%20Developed-brightgreen.svg)

**ASM-NG** is a production-ready, enterprise-grade open source intelligence (OSINT) and attack surface management platform. Built on a battle-tested scanning engine with 200+ modules, it integrates advanced storage capabilities, AI-powered threat intelligence, and comprehensive security hardening to make intelligence data easily navigable and actionable.

ASM-NG features an embedded web server providing a clean, modern web-based interface, and can also be used entirely via the command line. It's written in **Python 3** and **MIT-licensed**.

> **Note:** ASM-NG is built on the SpiderFoot OSINT engine. The core scanning engine, modules, and internal class names retain their original naming for stability. All user-facing branding, documentation, and deployment tooling has been updated to ASM-NG.

---

## Platform Architecture

```mermaid
graph TD;
    A[User] -->|Web UI| B[ASM-NG Core Engine];
    A -->|CLI| B;
    B --> C[Modules];
    B --> D[Database];
    B --> E[API];
    C --> F[External Data Sources];
    E --> G[SIEM/SOAR/Integrations];
    B --> H[Scheduler];
    B --> I[Correlation Engine];
    B --> J[Reporting & Export];
```

---

## What Makes ASM-NG Different

This platform includes production-ready enterprise features beyond the original engine:

- **Advanced Storage Engine**: High-performance data storage with optimized querying and reporting
- **AI-Powered Threat Intelligence**: Automated threat analysis and intelligent pattern recognition
- **Security Hardening**: Enhanced security controls, input validation, and secure configurations
- **Comprehensive Reporting**: Advanced analytics and customizable report generation
- **Performance Optimization**: Scalable architecture for enterprise workloads
- **Production Configuration**: Ready-to-deploy configurations for enterprise environments

![ASM-NG v5](./documentation/images/v5.png)

---

## Features

### Core Platform

- Web-based UI or CLI
- Over 200 modules with enterprise enhancements
- Python 3.9+
- YAML-configurable [correlation engine](/correlations/README.md) with 37+ pre-defined rules
- CSV/JSON/GEXF export with advanced formatting options
- API key export/import
- SQLite and PostgreSQL back-end for enterprise scalability
- Highly configurable with production-ready defaults
- Fully documented with enterprise deployment guides
- Advanced visualizations and analytics
- TOR integration for dark web searching
- Docker and Kubernetes deployment support
- Integrates with tools like DNSTwist, Whatweb, Nmap, and CMSeeK
- Comprehensive REST API for enterprise integration

---

## Visual Workflow: Typical OSINT Scan

```mermaid
graph LR;
    A[Start Scan] --> B[Select Target];
    B --> C[Choose Modules];
    C --> D[Run Scan];
    D --> E[Data Collection];
    E --> F[Correlation & Analysis];
    F --> G[View Results];
    G --> H[Export/Integrate];
```

---

## Enterprise Capabilities

### AI-Powered Intelligence

- **Automated Threat Analysis**: Machine learning algorithms analyze patterns and identify threats
- **Intelligent Pattern Recognition**: AI-powered correlation of indicators across data sources
- **Predictive Analytics**: Threat trend analysis and risk prediction capabilities
- **Natural Language Processing**: Automated analysis of text-based intelligence sources

### Security & Compliance

- **Enhanced Input Validation**: Comprehensive sanitization and validation of all inputs
- **Security Configuration**: Hardened default configurations and security best practices
- **Audit Logging**: Comprehensive audit trails for compliance and forensic analysis
- **Access Controls**: Role-based access control and authentication mechanisms

### Performance & Scalability

- **High-Performance Storage**: Optimized database operations with compression and indexing
- **Concurrent Processing**: Advanced threading and asynchronous processing capabilities
- **Resource Management**: Intelligent resource allocation and memory optimization
- **Load Balancing**: Support for distributed scanning across multiple instances

### Advanced Analytics

- **Custom Dashboards**: Configurable dashboards with real-time metrics and KPIs
- **Comprehensive Reporting**: Advanced report generation with customizable templates
- **Data Visualization**: Interactive charts, graphs, and network topology views
- **Export Capabilities**: Multiple export formats with enterprise-grade data handling

### Enterprise Integration

- **REST API**: Comprehensive API for seamless integration with security tools
- **Webhook Support**: Real-time notifications and event-driven integrations
- **SIEM Integration**: Direct integration with popular SIEM platforms
- **CI/CD Pipeline Support**: Automated scanning integration for DevSecOps workflows

---

## Deployment Overview

```mermaid
graph TD;
    A[User/Analyst] -->|Web UI/CLI| B[ASM-NG Container];
    B --> C[Persistent Storage];
    B --> D[Network];
    B --> E[External APIs];
    B --> F[SIEM/SOAR];
    B --> G[Monitoring];
```

---

## Documentation

Comprehensive documentation is available for all aspects of ASM-NG:

### Quick Links

- **[Installation Guide](documentation/installation.md)** - Complete setup instructions
- **[Quick Start Guide](documentation/quickstart.md)** - Get scanning quickly
- **[User Guide](documentation/user_guide.md)** - Fundamental concepts and usage
- **[CLI Reference](documentation/user_guide.md)** - Command-line interface guide
- **[API Documentation](documentation/api_reference.md)** - REST API reference
- **[Module Guide](documentation/modules.md)** - Understanding modules

---

## Uses

ASM-NG can be used offensively (e.g. in a red team exercise or penetration test) for reconnaissance of your target or defensively to gather information about what you or your organisation might have exposed over the Internet.

You can target the following entities in a scan:

- IP address
- Domain/sub-domain name
- Hostname
- Network subnet (CIDR)
- ASN
- E-mail address
- Phone number
- Username
- Person's name
- Bitcoin address

The platform's 200+ modules feed each other in a publisher/subscriber model to ensure maximum data extraction to do things like:

- [Host/sub-domain/TLD enumeration/extraction](https://asciinema.org/a/295912)
- [Email address, phone number and human name extraction](https://asciinema.org/a/295947)
- [Bitcoin and Ethereum address extraction](https://asciinema.org/a/295957)
- [Check for susceptibility to sub-domain hijacking](https://asciinema.org/a/344377)
- DNS zone transfers
- [Threat intelligence and Blacklist queries](https://asciinema.org/a/295949)
- API integration with [SHODAN](https://asciinema.org/a/127601), [HaveIBeenPwned](https://asciinema.org/a/128731), [GreyNoise](https://asciinema.org/a/295943), AlienVault, SecurityTrails, etc.
- [Social media account enumeration](https://asciinema.org/a/295923)
- [S3/Azure/Digitalocean bucket enumeration/scraping](https://asciinema.org/a/295941)
- IP geo-location
- Web scraping, web content analysis
- [Image, document and binary file meta data analysis](https://asciinema.org/a/296274)
- Dark web searches
- [Port scanning and banner grabbing](https://asciinema.org/a/295939)
- [Data breach searches](https://asciinema.org/a/296145)
- So much more...

---

## Getting Started

### Standard Installation (Recommended for Kali/Debian/Ubuntu)

```bash
git clone https://github.com/0x31i/asm-ng.git
cd asm-ng
python3 -m venv venv
source venv/bin/activate
pip3 install -r requirements.txt
python3 ./sf.py -l 127.0.0.1:5001
```

### Update Existing Installation

```bash
cd asm-ng
git pull origin master
source venv/bin/activate  # If using virtual environment
pip3 install -r requirements.txt
python3 ./sf.py -l 127.0.0.1:5001
```

> **Note for Kali/Debian 12+ users:** These systems use "externally managed" Python environments. You must use a virtual environment (`python3 -m venv venv`) to install packages with pip. The commands above handle this automatically.

### Docker Deployment

```bash
# Production deployment with optimized configuration
docker-compose -f docker-compose-prod.yml up -d

# Development environment
docker-compose up -d
```

### CLI Command Aliases (New Host Setup)

When installing on a new host, set up convenience aliases so you can invoke the platform by its new name. Add these to your shell profile (`~/.bashrc`, `~/.zshrc`, etc.):

```bash
# ASM-NG CLI aliases
alias asm-ng='python3 /path/to/asm-ng/sf.py'
alias asm-ng-cli='python3 /path/to/asm-ng/sfcli.py'
alias asm-ng-api='python3 /path/to/asm-ng/sfapi.py'
```

Or, if installed via `pip install .` or `setup.py`, both the legacy `spiderfoot`/`spiderfoot-cli`/`spiderfoot-api` commands **and** the new `asm-ng`/`asm-ng-cli`/`asm-ng-api` commands are registered automatically.

> **Important:** On every new host, you need to either run the pip install (which registers both old and new CLI commands) or manually configure the shell aliases above.

---

## Database Configuration

ASM-NG supports both SQLite (default) and PostgreSQL for enterprise scalability:

### PostgreSQL Setup

For high-volume deployments, configure PostgreSQL:

```bash
# Install PostgreSQL and dependencies
sudo apt-get install postgresql postgresql-contrib
pip3 install psycopg2-binary

# Create database and user
sudo -u postgres psql
CREATE DATABASE asm_ng;
CREATE USER asm_ng_user WITH PASSWORD 'secure_password';
GRANT ALL PRIVILEGES ON DATABASE asm_ng TO asm_ng_user;
\q

# Configure for PostgreSQL
python3 ./sf.py --init-db postgresql://asm_ng_user:secure_password@localhost/asm_ng
```

---

## Community

Whether you're a contributor, user, or just curious about ASM-NG and OSINT in general, we'd love to have you join our community! ASM-NG has a [Discord server](https://discord.gg/vyvztrG) for seeking help, requesting features, or general OSINT discussion.

---

## Writing Correlation Rules

We have a comprehensive write-up and reference of the correlation rule-set [here](/correlations/README.md).

Also take a look at the [template.yaml](/correlations/template.yaml) file for a walk through. The existing [37 rules](/correlations) are also quite readable and good starting points for additional rules.

---

## Modules / Integrations

ASM-NG has over 200 modules, most of which *don't require API keys*, and many of those that do require API keys *have a free tier*.

See the [Module Guide](documentation/modules.md) for the full list and details.

---

## Version Management

ASM-NG uses a centralized version management system:

- **Single Source of Truth**: All versions controlled from the `VERSION` file
- **Automated Updates**: Use `python update_version.py` to update all version references
- **Consistency Checking**: Validate version consistency with `python update_version.py --check`
- **Release Management**: Streamlined version bumping with `python update_version.py --set X.Y.Z`

---

## REST API Usage

The ASM-NG REST API allows you to interact with the platform programmatically.

### Available Endpoints

- `GET /api/scan/start`: Start a new scan
- `POST /api/scan/stop`: Stop an ongoing scan
- `GET /api/scan/results`: Retrieve scan results
- `GET /api/modules`: List available modules
- `GET /api/scans/active`: List active scans
- `GET /api/scan/status`: Get the status of a specific scan
- `GET /api/scans/history`: List the history of all scans performed
- `GET /api/scan/export`: Export scan results in various formats (e.g., CSV, JSON)
- `POST /api/keys/import`: Import API keys for various modules
- `GET /api/keys/export`: Export API keys for various modules

### Example Usage

```bash
curl -X GET "http://127.0.0.1:8000/api/scan/start?target=example.com&modules=module1,module2"
```

```bash
curl -X POST "http://127.0.0.1:8000/api/scan/stop" -d '{"scan_id": "12345"}'
```

```bash
curl -X GET "http://127.0.0.1:8000/api/scan/results?scan_id=12345"
```

For more detailed instructions and examples, refer to the [API documentation](documentation/api_reference.md).

---

## Active Maintenance

ASM-NG is actively maintained with regular updates and contributions. Issues and pull requests are actively managed. The community is engaged through discussions and contributions.

Maintainer: 0x31i <elias@sims.dev>

---

*For more diagrams and visualizations, see the documentation and web UI dashboards!*
