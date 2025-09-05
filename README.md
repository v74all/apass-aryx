# APASS ARYX — Beta v1 (Under Development)

"No mask can hide. APASS ARYX sees through."

⚠️ This software is in Beta v1 and under active development. Some features are incomplete and may change.

[![Version](https://img.shields.io/badge/version-Beta%20v1-orange.svg)](https://github.com/v74all/apass-aryx)
[![Status](https://img.shields.io/badge/status-Under%23Development-yellow.svg)](https://github.com/v74all/apass-aryx)
[![License](https://img.shields.io/badge/license-Proprietary%20%E2%80%94%20All%20Rights%20Reserved-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-green.svg)](https://python.org)

Multilingual guide: English | فارسی

APASS ARYX is a comprehensive Android APK analysis framework (static + dynamic + network + threat intelligence) built by Aiden Azad (V7lthronyx). It exposes malicious behavior in Android apps with practical workflows and clear outputs.

---

## Table of contents

- Overview
- Features
- Architecture
- Requirements
- Installation
- Quick start
- Web UI
- CLI usage
- Configuration
- Folder structure
- Resources and signatures
- Included scripts
- Web API endpoints
- Troubleshooting
- FAQ
- Roadmap
- Contributing
- License
- فارسی (خلاصه)

---

## Overview

APASS ARYX targets malware analysts, DFIR professionals, and reverse engineers. The framework blends advanced static analysis, Frida-powered dynamic runs on Android devices/emulators, network capture, and threat intel enrichment. Outputs are organized, repeatable, and designed for both quick triage and deep dives.

## Features

- Static analysis
  - AndroidManifest and permission mapping
  - DEX/Smali structure hints, strings, resources extraction
  - Certificate and signing checks
  - Crypto findings (hard-coded keys, algorithms)
  - YARA scanning (baseline + community rules)

- Dynamic analysis (Frida-based)
  - Hooking and runtime behavior tracing
  - Memory/heap observations, payload indicators
  - Anti-analysis bypass hooks (SSL pinning, root checks)
  - File/db/prefs activity tracking

- Network analysis
  - Traffic capture (adb/tcpdump integration helpers)
  - Indicators of C2, beaconing, data exfiltration
  - Domain intelligence and watchlist checks

- Threat Intelligence
  - Optional VirusTotal / Hybrid Analysis lookups
  - IOC extraction and enrichment

- Orchestration
  - Unified or advanced engine selection
  - Batch mode (folder scans)
  - Timeouts, retries, and worker limits

- Outputs
  - JSON, TXT, and HTML reports
  - IOC feeds and MITRE mappings (when enabled)

- Web UI
  - Job submission (single/batch)
  - Job status, history, and report downloads
  - Basic diagnostics and cleanup utilities

---

## Architecture

- Entry points
  - CLI: `apass-aryx.py` (core) and `apass_aryx.py` (import-friendly wrapper)
  - Web UI: `web_app.py` (Flask)

- Core modules (see `src/`)
  - `core/advanced_analysis.py`, `core/unified_analysis.py`
  - `analyzers/advanced_static_analyzer.py`, `analyzers/enhanced_dynamic_analyzer.py`, etc.
  - `utils/` with logging, progress, reporting, device manager, and TI helpers

- Resources
  - `resources/yara/*` for YARA rules
  - `resources/signatures/*` for domain watchlists and sample IOCs
  - `resources/binaries/*` for Frida server binaries

- Scripts
  - Convenience shell scripts for adb capture, Frida management, and workspace maintenance

---

## Requirements

- OS: Linux recommended (dev-tested)
- Python: 3.10+
- Android device/emulator for dynamic runs (adb accessible)
- Optional external tools (install as needed):
  - Frida (device-side server from `resources/binaries`)
  - adb, tcpdump/mitm tooling depending on your workflow

Python packages commonly used by the project include Flask/Flask-WTF for the web UI and typical analysis libs. Since the codebase is evolving, install packages on demand per error messages until a pinned `requirements.txt` is published.

---

## Installation

1) Clone the repository

2) Create and activate a Python virtual environment

3) Install required Python packages (Flask, flask-wtf, jinja2, werkzeug, psutil, pyyaml, etc.)

4) Ensure adb is on PATH if you plan to run dynamic analysis

---

## Quick start

- Web UI (recommended): run `web_app.py` and open the printed URL. Upload an APK or start a batch. Reports will be placed under `analysis_results/`.

- CLI: use analyze/batch subcommands to process files from the terminal (see below).

---

## Web UI

Entrypoint: `web_app.py`

Main views

- `/` — Home / recent jobs
- `/jobs` — Jobs list (enhanced view available)
- `/job/<job_id>` — Job details and report links
- `/status` — System/status page
- `/compare` — Compare results between jobs

Key settings

- Upload directory: temporary system folder (see `UPLOAD_FOLDER` in `web_app.py`)
- Reports path: `analysis_results/`
- Jobs storage: `jobs_data.pkl`

Security

- CSRF protection enabled (Flask-WTF)
- `SECRET_KEY` auto-generated unless provided via env var

---

## CLI usage

CLI entry is `apass-aryx.py`. Common subcommands implemented or planned:

- `web` — launch the web interface
- `status` — environment and dependency checks
- `analyze` — analyze a single APK
  - Options: `--engine [auto|unified|advanced]`, `--timeout <seconds>`
- `batch` — analyze a folder of APKs
  - Options: `--recursive`, `--max-workers <n>`, `--fail-fast`
- `config` — show or set configuration values
- `upgrade` — migrate configuration to new defaults

Default behavior is driven by `config.yaml` unless overridden on the CLI.

---

## Configuration

Top-level file: `config.yaml`

- `analysis`
  - `engine`: `auto` (default), `unified`, or `advanced`
  - `timeout`: default 300 seconds
  - `report_formats`: `json`, `txt`, `html`

- `batch`
  - `max_workers`: default 2 (0 = sequential)
  - `recursive`: true/false
  - `fail_fast`: optional; stop early on errors (if supported)

- `web`
  - `host`, `port`, `debug`

- `logging`
  - `level`: `DEBUG|INFO|WARNING|ERROR|CRITICAL`
  - `file`: `apass-aryx.log` (empty string to disable file logging)
  - `console`: true/false

Advanced orchestrator: `orchestrator_config.yaml`

- `analysis_duration`, `max_parallel_tools`, `enable_real_time_monitoring`, `threat_intelligence_enabled`, `auto_cleanup`, `advanced_correlation`
- `monitoring` thresholds
- `scoring` weights for different analyzers
- `threat_intelligence` API keys and caps
- `output` toggles for reports/feeds/mitre mapping
- `resources` limits

---

## Folder structure

```text
apass-aryx.py                # CLI entry (core)
apass_aryx.py                # Import wrapper
web_app.py                   # Flask web UI
config.yaml                  # Main config
orchestrator_config.yaml     # Orchestrator advanced config
resources/                   # YARA, signatures, frida binaries
scripts/                     # Shell helpers (adb, frida, housekeeping)
src/                         # Core Python packages (analyzers, utils)
static/, templates/          # Web UI assets and pages
analysis_results/            # Generated reports (created at runtime)
apass-aryx.log               # Log file (if enabled)
```

---

## Resources and signatures

- `resources/yara/*` — Baseline + community YARA rules
- `resources/signatures/iocs_sample.json` — Example IOC feed format
- `resources/signatures/domains_watchlist.txt` — Domains of interest
- `resources/binaries/frida-server-*` — Frida server builds for different CPU ABIs

---

## Included scripts

- `scripts/adb_network_capture.sh` — Network capture helper via adb
- `scripts/frida_manager.sh` — Start/stop Frida server on device
- `scripts/run-analysis.sh` — Convenience wrapper for a full analysis pass
- `scripts/cleanup.sh` — Remove temps and old outputs
- `scripts/complete-analysis.sh`, `scripts/final-status.sh`, `scripts/workspace-status.sh`

Note: Review each script before use and adapt paths to your environment.

---

## Web API endpoints

Public routes (HTML)

- `GET /` — Home
- `GET /jobs` — Jobs list
- `GET /job/<job_id>` — Job details
- `GET /status` — System/status page
- `GET /compare` — Compare results

API routes (JSON)

- `GET /api/jobs` — Paginated job history, supports `page`, `per_page`, and filters
- `GET /api/job/<job_id>` — Single job details
- `POST /api/job/<job_id>/cancel` — Cancel a running job
- `DELETE /api/jobs/<job_id>` or `POST /api/job/<job_id>/delete` — Delete a job
- `GET /api/status` — System and service status
- `POST /api/test-connectivity` — Connectivity diagnostics
- `POST /api/cleanup` — Cleanup old artifacts
- `GET /api/diagnostics` — Environment diagnostics
- `POST /api/clear-logs` — Clear server logs

Reports

- `GET /report/<job_id>/<path:report_file>` — Download a report artifact for a job

---

## Troubleshooting

- Status page 500 (Jinja UndefinedError)
  - Known during Beta: some fields (e.g., `tools`) may be missing from the status context and cause a 500 on `/status`.
  - Workaround: use `/api/status` for raw diagnostics while the UI is being stabilized.

- CSRF errors on POST endpoints
  - Ensure your requests include the CSRF token or use provided HTML forms/endpoints with `@csrf.exempt` where appropriate.

- Dynamic analysis not running
  - Verify adb connectivity, device authorization, and that a matching `frida-server` is running on the device. Use `scripts/frida_manager.sh`.

- Reports not found
  - Check `analysis_results/` and job page `/job/<job_id>`. Ensure `report_formats` include the type you expect.

- Logs
  - See `apass-aryx.log` and `/api/diagnostics`. You can clear with `/api/clear-logs`.

---

## FAQ

Q: Which engine should I use?

A: `auto` chooses the best available engine. Use `unified` for a lighter pass or `advanced` when you need deeper coverage and have Frida/device ready.

Q: Where are artifacts stored?

A: Reports are stored under `analysis_results/` and job metadata in `jobs_data.pkl`.

Q: Can I bring my own YARA rules?

A: Yes. Add them under `resources/yara/` and ensure file permissions are correct.

---

## Roadmap (short)

- Stabilize `/status` view and system checks
- Pin and publish dependencies (`requirements.txt`)
- Expand HTML reporting and comparison views
- More robust batch orchestration and retries
- Containerized runner and CI/CD samples

---

## Contributing

Contributions are welcome. Please open an issue to discuss ideas and follow the coding style used in `src/`. For significant changes, propose the design first.

---

## License

Proprietary — All Rights Reserved. See the `LICENSE` file.

---

## فارسی (خلاصه)

APASS ARYX یک چارچوب تحلیل APK اندروید است که تحلیل ایستا، پویا (Frida)، شبکه و هوش تهدید را ترکیب می‌کند. برای پژوهشگران امنیت، تحلیل‌گران بدافزار و مهندسان معکوس ساخته شده است.

ویژگی‌ها (خلاصه)

- تحلیل ایستا: مانیفست و مجوزها، منابع، رشته‌ها، گواهی‌نامه و YARA
- تحلیل پویا: Hook با Frida، عبور از ضدتحلیل، رصد رفتار زمان‌اجرا
- تحلیل شبکه: کپچر ترافیک، تشخیص C2 و نشتی داده
- هوش تهدید: غنی‌سازی IOC و یکپارچه‌سازی با سرویس‌های خارجی (اختیاری)
- وب UI: ارسال کار، وضعیت، تاریخچه و دانلود گزارش‌ها

پیش‌نیازها

- لینوکس، Python 3.10+
- برای تحلیل پویا: دستگاه/شبیه‌ساز اندروید + adb + frida-server

شروع سریع

- اجرای وب: فایل `web_app.py` را اجرا کنید و در مرورگر باز کنید. APK را آپلود کنید و گزارش‌ها را از `analysis_results/` بردارید.
- CLI: از دستورات `analyze` و `batch` در `apass-aryx.py` استفاده کنید.

پیکربندی

- فایل `config.yaml` برای تنظیم موتور تحلیل، زمان‌بندی، فرمت گزارش‌ها، لاگینگ و …
- فایل `orchestrator_config.yaml` برای تنظیمات پیشرفته (TI، امتیازدهی، منابع، خروجی‌ها)

عیب‌یابی

- خطای 500 در `/status`: یک مشکل شناخته‌شده در بتا است؛ از `/api/status` استفاده کنید.
- مشکلات CSRF: از فرم‌های داخلی استفاده کنید یا توکن را ارسال کنید.
- عدم اجرای تحلیل پویا: اتصال adb و اجرای frida-server را بررسی کنید.

مجوز: کلیه حقوق محفوظ است (All Rights Reserved). جزئیات در فایل `LICENSE`.


- **Behavioral Pattern Recognition**: Machine learning-based anomaly detection
- **Malware Family Classification**: Automated threat categorization and similarity analysis
- **Risk Scoring**: Multi-factor threat assessment with confidence metrics
- **IOC Generation**: Automated Indicators of Compromise extraction
- **Threat Attribution**: Malware family mapping, actor profiling

### Web-Based Dashboard & Reporting

- **Interactive HTML Dashboard**: Real-time analysis visualization with responsive design
- **Multi-Format Reports**: JSON, XML, TXT, HTML, and PDF export capabilities
- **Job Management**: Background processing, queue management, progress tracking
- **Comparative Analysis**: Side-by-side APK comparison and differential analysis
- **Historical Tracking**: Analysis session management and timeline visualization
- **RESTful API**: Programmatic access for automation and integration

#### 🔧 **Advanced Automation & Integration**

- **Batch Processing**: Concurrent analysis of multiple APKs with intelligent resource management
- **CI/CD Integration**: Jenkins, GitHub Actions, GitLab CI pipeline support
- **Cloud Deployment**: Docker containerization, Kubernetes orchestration ready
- **Custom Orchestrator**: Advanced analysis workflows with configurable pipelines
- **Plugin Architecture**: Extensible analyzer modules and custom script integration

### 🏗️ Architecture & Project Structure

```
apass-aryx/
├── src/                          # Core Analysis Engine
│   ├── core/                     # Central analysis engines
│   │   ├── unified_analysis.py   # Main unified analysis pipeline
│   │   ├── advanced_analysis.py  # Advanced analysis orchestrator
│   │   └── advanced_analysis_impl.py # Implementation details
│   ├── analyzers/                # Specialized analyzers
│   │   ├── enhanced_static_analyzer.py    # Advanced static analysis
│   │   ├── enhanced_dynamic_analyzer.py   # Dynamic runtime analysis
│   │   ├── analysis_dashboard.py          # Dashboard generation
│   │   ├── device_orchestrator.py         # Device management
│   │   ├── malware_analyzer.py            # Malware detection engine
│   │   └── tool_integrations.py           # External tool integrations
│   └── utils/                    # Utility modules
│       ├── threat_intelligence.py         # Threat intel APIs
│       ├── report_generator.py            # Report formatting
│       └── cloud_uploader.py              # Cloud storage integration
├── scripts/                      # Automation & Instrumentation
│   ├── frida/                    # Frida instrumentation scripts
│   │   ├── comprehensive_analysis.js      # Complete runtime analysis
│   │   ├── advanced_malware_analyzer.js   # Advanced malware detection
│   │   ├── network_analyzer.js            # Network traffic analysis
│   │   ├── memory_analyzer.js             # Memory scanning & extraction
│   │   ├── crypto_file_bypass_dump.js     # Crypto & bypass techniques
│   │   └── reverse_engineering.js         # RE automation tools
│   ├── complete-analysis.sh      # Orchestrated analysis pipeline
│   ├── run-organized-analysis.sh # Organized output management
│   ├── domain-osint.sh          # Domain intelligence gathering
│   └── cleanup.sh               # Workspace maintenance
├── resources/                    # Analysis Resources
│   ├── yara/                     # YARA rule sets
│   │   ├── malware_baseline.yar  # Core malware signatures
│   │   └── community/            # Community-contributed rules
│   ├── signatures/               # Threat signatures & IOCs
│   │   ├── domains_watchlist.txt # Malicious domain database
│   │   └── iocs_sample.json      # Indicators of compromise
│   ├── binaries/                 # Required binaries
│   │   └── frida-server-*        # Frida server binaries
│   └── analysis_config.json      # Main configuration file
├── analysis_results/             # Analysis outputs
│   └── unified_output/           # Organized results by session
├── templates/                    # Web interface templates
├── static/                       # Web assets (CSS, JS, images)
├── web_app.py                   # Flask web application
├── apass-aryx.py               # Main CLI interface
└── config.yaml                # System configuration
```

### ✅ System Requirements

#### **Essential Dependencies**
- **Python**: 3.8+ (recommended: 3.9+)
- **Android SDK Platform Tools**: `adb`, `aapt`, `aapt2`
- **Java Development Kit**: JDK 8+ for APK processing
- **Frida**: `frida-tools` and device-specific `frida-server`

#### **Optional Enhancements**
- **APKTool**: Advanced APK decompilation
- **JADX**: Java decompiler integration
- **YARA**: Pattern matching engine
- **Docker**: Containerized deployment
- **Redis**: Caching and job queue management

### 🚀 Installation Guide

#### **Quick Setup**
```bash
# Clone the repository
git clone https://github.com/v74all/apass-aryx.git
cd apass-aryx

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # Linux/macOS
# .venv\Scripts\activate   # Windows

# Install Python dependencies
pip install -r requirements.txt

# Install Android SDK tools (if not present)
./scripts/tools/install_android_tools.sh
```

#### **Advanced Setup**
```bash
# Configure analysis environment
cp config.yaml.example config.yaml
cp resources/analysis_config.json.example resources/analysis_config.json

# Deploy Frida server to device/emulator
adb push resources/binaries/frida-server-* /data/local/tmp/frida-server
adb shell chmod 755 /data/local/tmp/frida-server

# Verify installation
python apass-aryx.py status
```

### 📖 Usage Examples

#### **Command Line Interface**

**Single APK Analysis:**
```bash
# Complete analysis (static + dynamic + network)
python apass-aryx.py analyze sample.apk

# Static analysis only
python apass-aryx.py analyze sample.apk --engine unified --static-only

# Dynamic analysis with device targeting
python apass-aryx.py analyze sample.apk --dynamic-only --device emulator-5554 --duration 180 --install
```

**Batch Processing:**
```bash
# Analyze multiple APKs
python apass-aryx.py batch /path/to/apk/directory --max-workers 4 --recursive

# Advanced batch with custom configuration
python apass-aryx.py batch samples/ --engine advanced --timeout 600 --formats json,html
```

**Device Management:**
```bash
# List connected devices
python apass-aryx.py device list

# Device health check
python apass-aryx.py device checks --device emulator-5554

# Install and monitor APK
python apass-aryx.py device install sample.apk --device emulator-5554 --monitor
```

#### **Web Interface**

**Start Web Server:**
```bash
# Development server
python web_app.py

# Production deployment
python apass-aryx.py web --host 0.0.0.0 --port 8080 --workers 4
```

**Dashboard Access:**
- **Main Interface**: `http://localhost:5000`
- **Analysis Dashboard**: `http://localhost:5000/status`
- **Job Management**: `http://localhost:5000/jobs`
- **API Endpoints**: `http://localhost:5000/api/`

#### **Direct Script Execution**

**Frida Scripts:**
```bash
# Advanced malware analysis
frida -U -f com.target.app -l scripts/frida/advanced_malware_analyzer.js --no-pause

# Network traffic monitoring
frida -U -f com.target.app -l scripts/frida/network_analyzer.js --no-pause

# Memory analysis and extraction
frida -U -f com.target.app -l scripts/frida/memory_analyzer.js --no-pause
```

**Shell Scripts:**
```bash
# Complete orchestrated analysis
./scripts/complete-analysis.sh sample.apk

# Domain intelligence gathering
./scripts/domain-osint.sh malicious-domain.com

# Workspace cleanup
./scripts/cleanup.sh --preserve-results
```

### 🔧 Configuration Management

#### **Main Configuration (config.yaml)**
```yaml
analysis:
  engine: "auto"                 # auto, unified, advanced
  timeout: 300                   # Analysis timeout in seconds
  report_formats: ["json", "html", "txt"]
  retries: 2                     # Retry failed analyses

batch:
  max_workers: 4                 # Concurrent analysis jobs
  recursive: true                # Recursive directory scanning
  fail_fast: false              # Continue on individual failures

web:
  host: "0.0.0.0"               # Web server bind address
  port: 5000                    # Web server port
  debug: false                  # Enable debug mode

logging:
  level: "INFO"                 # DEBUG, INFO, WARNING, ERROR, CRITICAL
  file: "apass-aryx.log"        # Log file path
  console: true                 # Enable console logging
```

#### **Analysis Configuration (resources/analysis_config.json)**
```json
{
  "static_analysis": {
    "enable_manifest_analysis": true,
    "enable_permission_analysis": true,
    "enable_string_extraction": true,
    "enable_certificate_analysis": true,
    "enable_yara_scanning": true,
    "yara_rules_path": "resources/yara/"
  },
  "dynamic_analysis": {
    "enable_frida_hooks": true,
    "enable_network_monitoring": true,
    "enable_memory_analysis": true,
    "analysis_duration": 300,
    "auto_install": false
  },
  "reporting": {
    "generate_dashboard": true,
    "include_screenshots": true,
    "compress_outputs": false,
    "save_raw_data": true
  }
}
```

### 📊 Analysis Outputs & Reports

#### **Organized Output Structure**

All analysis results are systematically organized under `analysis_results/unified_output/<timestamp>/`:

```
analysis_results/unified_output/advanced_analysis_20250905_101524/
├── reports/
│   ├── analysis_dashboard.html          # Interactive web dashboard
│   ├── comprehensive_report.json        # Machine-readable full report
│   ├── comprehensive_report.txt         # Human-readable summary
│   ├── executive_summary.md             # Executive briefing
│   └── threat_intelligence_report.pdf   # Threat intel analysis
├── artifacts/
│   ├── extracted_assets/                # Assets, resources, files
│   ├── decompiled_code/                 # JADX/APKTool output
│   ├── certificates/                    # Certificate analysis
│   ├── strings_analysis.txt             # Extracted strings
│   └── yara_matches.json               # YARA rule hits
├── dynamic/
│   ├── frida_logs/                      # Runtime analysis logs
│   ├── memory_dumps/                    # Memory snapshots
│   ├── api_calls.json                  # System call traces
│   └── behavioral_analysis.json        # Behavior patterns
├── network/
│   ├── traffic_capture.pcap             # Network packet capture
│   ├── dns_queries.json                # DNS resolution logs
│   ├── http_transactions.json          # HTTP/HTTPS traffic
│   └── c2_analysis.json                # C2 communication analysis
├── static/
│   ├── manifest_analysis.json          # AndroidManifest analysis
│   ├── permission_analysis.json        # Permission risk assessment
│   ├── code_analysis.json              # Code structure analysis
│   └── crypto_analysis.json            # Cryptographic findings
└── logs/
    ├── analysis.log                     # Detailed analysis log
    ├── errors.log                       # Error and warning log
    └── debug.log                        # Debug information
```

#### **Dashboard Features**

The interactive HTML dashboard provides:

- **Real-time Analysis Progress**: Live updates during analysis execution
- **Threat Risk Scoring**: Visual risk assessment with confidence metrics
- **Interactive Charts**: Network topology, call graphs, timeline visualization
- **Drill-down Analysis**: Detailed views of findings, artifacts, and indicators
- **Export Capabilities**: PDF reports, IOC feeds, STIX/TAXII format
- **Comparison Tools**: Side-by-side analysis comparison for multiple APKs

### 🧰 Advanced Features & Tools

#### **Frida Instrumentation Scripts**

**Comprehensive Analysis (`comprehensive_analysis.js`)**:
- Real-time method hooking and behavior monitoring
- SSL pinning bypass and certificate trust manipulation
- Anti-analysis detection and evasion techniques
- Dynamic string decryption and asset extraction

**Network Analysis (`network_analyzer.js`)**:
- Multi-protocol traffic interception (HTTP/HTTPS, WebSocket, TCP/UDP)
- C2 communication pattern detection and behavioral analysis
- DGA (Domain Generation Algorithm) detection
- Advanced beaconing analysis with ML-based anomaly detection

**Memory Analysis (`memory_analyzer.js`)**:
- Advanced memory scanning with entropy analysis
- Encryption key extraction and cryptographic artifact recovery
- Payload detection and classification with AI pattern matching
- Real-time memory monitoring and suspicious activity detection

**Malware Analysis (`advanced_malware_analyzer.js`)**:
- Anti-debugging and anti-analysis bypass techniques
- Runtime unpacking and deobfuscation
- Malware family classification and attribution
- Advanced persistence mechanism detection

#### **Shell Automation Scripts**

**Complete Analysis (`complete-analysis.sh`)**:
- Orchestrated end-to-end analysis pipeline
- Multi-stage analysis with intelligent dependency management
- Automated report generation and artifact organization
- Integration with external threat intelligence sources

**Domain OSINT (`domain-osint.sh`)**:
- Comprehensive domain intelligence gathering
- Whois, DNS, and certificate transparency analysis
- Reputation scoring and threat actor attribution
- Integration with threat intelligence feeds

#### **External Tool Integrations**

APASS ARYX seamlessly integrates with industry-standard tools:

- **Androguard**: Advanced APK analysis and metadata extraction
- **APKiD**: Packer and obfuscator detection
- **JADX**: Java decompilation and code analysis
- **Quark Engine**: Behavioral analysis and malware detection
- **MobSF**: Mobile security framework integration
- **VirusTotal**: Hash-based threat intelligence lookup
- **YARA**: Custom rule-based pattern matching
- **Cutter/Radare2**: Reverse engineering and binary analysis

### 🛡️ Security & Best Practices

#### **Secure Analysis Environment**
- **Isolated Execution**: VM/container-based analysis environments
- **Network Segmentation**: Controlled network access during dynamic analysis
- **Artifact Quarantine**: Secure handling of potentially malicious content
- **Access Control**: Role-based access to analysis results and sensitive data

#### **Ethical Usage Guidelines**
- **Authorization**: Only analyze APKs you are legally authorized to examine
- **Data Privacy**: Implement proper data handling for extracted sensitive information
- **Responsible Disclosure**: Follow coordinated vulnerability disclosure practices
- **Legal Compliance**: Ensure compliance with local laws and regulations

### ❓ Troubleshooting & Support

#### **Common Issues**

**Installation Problems:**
```bash
# ADB not found
export PATH=$PATH:/path/to/android-sdk/platform-tools

# Python dependency conflicts
python -m pip install --force-reinstall -r requirements.txt

# Frida server version mismatch
adb shell killall frida-server
adb push resources/binaries/frida-server-$(frida --version | cut -d' ' -f1)-android-arm64 /data/local/tmp/frida-server
```

**Analysis Failures:**
```bash
# Check device connectivity
adb devices

# Verify Frida server status
adb shell ps | grep frida

# Review analysis logs
tail -f analysis_results/*/logs/analysis.log
```

**Performance Optimization:**
```bash
# Adjust worker count based on system resources
python apass-aryx.py batch samples/ --max-workers $(nproc)

# Enable analysis caching
export APASS_CACHE_ENABLED=1

# Monitor system resources
python apass-aryx.py status --system-info
```

#### **Getting Help**
- **Documentation**: Comprehensive guides in the `docs/` directory
- **Issue Tracker**: Report bugs and request features on GitHub
- **Community Support**: Join discussions and share insights
- **Professional Support**: Enterprise support options available

### 📈 Performance & Scalability

#### **System Requirements by Scale**

**Small Scale (1-10 APKs/day)**:
- CPU: 4 cores, 8GB RAM
- Storage: 100GB SSD
- Network: Standard internet connection

**Medium Scale (10-100 APKs/day)**:
- CPU: 8 cores, 16GB RAM
- Storage: 500GB NVMe SSD
- Network: High-speed internet with traffic shaping

**Large Scale (100+ APKs/day)**:
- CPU: 16+ cores, 32GB+ RAM
- Storage: 1TB+ NVMe SSD with backup
- Network: Dedicated analysis network with monitoring

#### **Optimization Features**
- **Intelligent Caching**: Result caching to avoid redundant analysis
- **Resource Management**: Dynamic resource allocation based on workload
- **Distributed Analysis**: Support for multi-node analysis clusters
- **Queue Management**: Advanced job scheduling and priority handling
---

## فارسی

### 🎯 معرفی کلی

⚠️ **این نرم‌افزار در حال حاضر در نسخه Beta v1 و در حال توسعه است. ممکن است برخی قابلیت‌ها ناقص یا در حال تغییر باشند.**

APASS ARYX یک فریم‌ورک نسل جدید تحلیل APK اندروید است که برای پژوهشگران امنیتی، تحلیلگران بدافزار، مهندسان معکوس و متخصصان امنیت سایبری طراحی شده است. این ابزار با ترکیب تحلیل ایستای پیشرفته، ابزاردهی زمان‌اجرای پویا، پایش جامع ترافیک شبکه و تشخیص تهدید مبتنی بر هوش مصنوعی، بینش عمیقی از رفتار و وضعیت امنیتی اپلیکیشن‌های اندروید ارائه می‌دهد.

### ✨ ویژگی‌های اصلی

#### 🔍 **تحلیل ایستای پیشرفته**

- **تحلیل مانیفست و مجوزها**: بررسی عمیق AndroidManifest.xml، مجوزهای خطرناک و بردارهای افزایش اختیارات
- **تحلیل ساختار کد**: تحلیل فایل‌های DEX، نقشه‌برداری از سلسله‌مراتب کلاس‌ها، استخراج امضای متدها
- **استخراج منابع**: دارایی‌ها، نقشه‌ها، رشته‌ها، طرح‌بندی‌ها با تطبیق الگوی هوشمند
- **تحلیل گواهی**: تأیید امضای کد، اعتبارسنجی زنجیره گواهی، تحلیل مخزن اعتماد
- **تشخیص رمزنگاری**: کلیدهای هاردکُد، الگوریتم‌های رمزگذاری، پیاده‌سازی‌های کریپتو
- **هوش رشته‌ای**: استخراج URL، نقاط پایانی API، تشخیص اسرار، رمزگشایی رشته‌های مبهم‌شده
- **اسکن قوانین YARA**: امضاهای بدافزار سفارشی، الگوهای رفتاری، طبقه‌بندی خانواده

#### ⚡ **تحلیل زمان‌اجرای پویا**

- **ابزاردهی مبتنی بر Frida**: هوک زمان‌واقعی متدها، پایش رفتار زمان‌اجرا
- **تحلیل حافظه**: بررسی هیپ، استخراج پیلود، بازیابی کلید رمزگذاری
- **پایش فراخوانی API**: فراخوانی‌های سیستم، فراخوانی‌های کتابخانه، ارتباطات بین‌پردازه‌ای
- **دور زدن ضد تحلیل**: دور زدن تشخیص روت، طفره از دیباگر، دور زدن پین کردن SSL
- **پروفایل رفتار زمان‌اجرا**: عملیات فایل، تعاملات پایگاه داده، تغییرات تنظیمات
- **تشخیص تزریق پردازه**: تلاش‌های تزریق کد، بارگذاری پویا، فراخوانی‌های بازتابی

#### 🌐 **تحلیل ترافیک شبکه**

- **پشتیبانی از پروتکل**: HTTP/HTTPS، WebSocket، TCP/UDP، DNS، Firebase، gRPC، MQTT
- **رهگیری ترافیک**: ضبط بسته در زمان واقعی، رمزگشایی SSL/TLS
- **تشخیص ارتباط C2**: تشخیص الگوی فرمان و کنترل، تحلیل بیکن
- **هوش دامنه**: تشخیص دامنه‌های مشکوک، تحلیل DGA (الگوریتم تولید دامنه)
- **پایش استخراج داده**: ردیابی انتقال داده‌های حساس
- **اثرانگشت‌گیری شبکه**: کشف سرویس، شناسایی پروتکل، اسکن آسیب‌پذیری

#### 🧠 **هوش تهدید مبتنی بر هوش مصنوعی**

- **تشخیص الگوی رفتاری**: تشخیص ناهنجاری مبتنی بر یادگیری ماشین
- **طبقه‌بندی خانواده بدافزار**: طبقه‌بندی خودکار تهدید و تحلیل شباهت
- **امتیازدهی خطر**: ارزیابی تهدید چندعاملی با معیارهای اطمینان
- **تولید IOC**: استخراج خودکار شاخص‌های سازش
- **انتساب تهدید**: نقشه‌برداری خانواده بدافزار، پروفایل‌سازی عامل

#### 📊 **داشبورد وب و گزارش‌دهی**

- **داشبورد HTML تعاملی**: تجسم تحلیل زمان‌واقعی با طراحی پاسخگو
- **گزارش چندفرمته**: قابلیت صادرات JSON، XML، TXT، HTML و PDF
- **مدیریت کار**: پردازش پس‌زمینه، مدیریت صف، ردیابی پیشرفت
- **تحلیل مقایسه‌ای**: مقایسه جنب‌به‌جنب APK و تحلیل تفاضلی
- **ردیابی تاریخی**: مدیریت جلسات تحلیل و تجسم خط زمانی
- **API RESTful**: دسترسی برنامه‌نویسی برای خودکارسازی و یکپارچه‌سازی

### 🚀 راهنمای نصب

#### **نصب سریع**

```bash
# کلون کردن مخزن
git clone https://github.com/v74all/apass-aryx.git
cd apass-aryx

# ایجاد محیط مجازی
python -m venv .venv
source .venv/bin/activate  # Linux/macOS

# نصب وابستگی‌های پایتون
pip install -r requirements.txt

# نصب ابزارهای Android SDK
./scripts/tools/install_android_tools.sh
```

#### **پیکربندی پیشرفته**

```bash
# پیکربندی محیط تحلیل
cp config.yaml.example config.yaml
cp resources/analysis_config.json.example resources/analysis_config.json

# استقرار سرور Frida روی دستگاه
adb push resources/binaries/frida-server-* /data/local/tmp/frida-server
adb shell chmod 755 /data/local/tmp/frida-server

# تأیید نصب
python apass-aryx.py status
```

### 📖 نمونه‌های استفاده

#### **رابط خط فرمان**

**تحلیل تک APK:**
```bash
# تحلیل کامل (ایستا + پویا + شبکه)
python apass-aryx.py analyze sample.apk

# فقط تحلیل ایستا
python apass-aryx.py analyze sample.apk --engine unified --static-only

# تحلیل پویا با هدف‌گیری دستگاه
python apass-aryx.py analyze sample.apk --dynamic-only --device emulator-5554 --duration 180 --install
```

**پردازش دسته‌ای:**
```bash
# تحلیل چندین APK
python apass-aryx.py batch /path/to/apk/directory --max-workers 4 --recursive

# دسته پیشرفته با پیکربندی سفارشی
python apass-aryx.py batch samples/ --engine advanced --timeout 600 --formats json,html
```

#### **رابط وب**

**راه‌اندازی سرور وب:**
```bash
# سرور توسعه
python web_app.py

# استقرار تولید
python apass-aryx.py web --host 0.0.0.0 --port 8080 --workers 4
```

**دسترسی داشبورد:**
- **رابط اصلی**: `http://localhost:5000`
- **داشبورد تحلیل**: `http://localhost:5000/status`
- **مدیریت کار**: `http://localhost:5000/jobs`
- **نقاط پایانی API**: `http://localhost:5000/api/`

### 🔧 مدیریت پیکربندی

#### **پیکربندی اصلی (config.yaml)**

```yaml
analysis:
  engine: "auto"                 # auto, unified, advanced
  timeout: 300                   # مهلت تحلیل بر حسب ثانیه
  report_formats: ["json", "html", "txt"]
  retries: 2                     # تلاش مجدد تحلیل‌های ناموفق

batch:
  max_workers: 4                 # کارهای تحلیل همزمان
  recursive: true                # اسکن بازگشتی دایرکتوری
  fail_fast: false              # ادامه در شکست‌های فردی

web:
  host: "0.0.0.0"               # آدرس اتصال سرور وب
  port: 5000                    # پورت سرور وب
  debug: false                  # فعال‌سازی حالت اشکال‌زدایی

logging:
  level: "INFO"                 # DEBUG, INFO, WARNING, ERROR, CRITICAL
  file: "apass-aryx.log"        # مسیر فایل لاگ
  console: true                 # فعال‌سازی لاگ کنسول
```

### 🛡️ امنیت و بهترین روش‌ها

#### **محیط تحلیل امن**
- **اجرای ایزوله**: محیط‌های تحلیل مبتنی بر VM/کانتینر
- **بخش‌بندی شبکه**: دسترسی کنترل‌شده شبکه در طول تحلیل پویا
- **قرنطینه آرتیفکت**: مدیریت امن محتوای احتمالاً مخرب
- **کنترل دسترسی**: دسترسی مبتنی بر نقش به نتایج تحلیل و داده‌های حساس

#### **رهنمودهای استفاده اخلاقی**
- **مجوز**: فقط APKهایی را تحلیل کنید که قانوناً مجاز به بررسی آن‌ها هستید
- **حریم خصوصی داده**: پیاده‌سازی مدیریت مناسب داده برای اطلاعات حساس استخراج‌شده
- **افشای مسئولانه**: پیروی از روش‌های افشای هماهنگ آسیب‌پذیری
- **انطباق قانونی**: اطمینان از انطباق با قوانین و مقررات محلی

### عملکرد و مقیاس‌پذیری

#### **نیازمندی‌های سیستم بر حسب مقیاس**

**مقیاس کوچک (1-10 APK در روز)**:
- CPU: 4 هسته، 8GB RAM
- ذخیره‌سازی: 100GB SSD
- شبکه: اتصال اینترنت استاندارد

**مقیاس متوسط (10-100 APK در روز)**:
- CPU: 8 هسته، 16GB RAM
- ذخیره‌سازی: 500GB NVMe SSD
- شبکه: اینترنت پرسرعت با شکل‌دهی ترافیک

**مقیاس بزرگ (100+ APK در روز)**:
- CPU: 16+ هسته، 32GB+ RAM
- ذخیره‌سازی: 1TB+ NVMe SSD با پشتیبان‌گیری
- شبکه: شبکه تحلیل اختصاصی با پایش

---

## 🤝 مشارکت در توسعه

ما از مشارکت در APASS ARYX استقبال می‌کنیم! لطفاً:

1. مخزن را فورک کنید
2. شاخه ویژگی ایجاد کنید
3. تغییرات خود را اعمال کنید
4. در صورت لزوم تست اضافه کنید
5. درخواست کشش ارسال کنید

### منابع و پیوندها

- **مستندات پروژه**: [docs/](docs/)
- **ردیاب مسائل**: [GitHub Issues](https://github.com/v74all/apass-aryx/issues)
- **یادداشت‌های انتشار**: [CHANGELOG.md](CHANGELOG.md)
- **راهنمای مشارکت**: [CONTRIBUTING.md](CONTRIBUTING.md)

### 🧩 یکپارچه‌سازی ابزارهای خارجی اختیاری

APASS ARYX می‌تواند از ابزارهای مختلف در صورت وجود استفاده کند:

- **Androguard (Python)**: بینش مانیفست، مجوزها، گواهی‌ها
- **APKiD (CLI)**: تشخیص پکر/مبهم‌ساز/امضا
- **Quark Engine (CLI)**: قوانین رفتاری؛ گزارش‌ها تحت آرتیفکت‌های تحلیل ذخیره می‌شوند
- **YARA (yara-python)**: اسکن با استفاده از قوانین در `resources/yara/**`
- **MobSF (REST)**: تنظیم متغیر محیط برای فعال‌سازی اسکن API
  - MOBSF_URL (مثل <http://127.0.0.1:8000>)
  - MOBSF_API_KEY
- **VirusTotal (REST)**: جستجوی هش از طریق VT v3 API
  - VT_API_KEY
- **AVClass (CLI)**: عادی‌سازی برچسب‌های AV با استفاده از نتایج VT
- **Cutter + r2frida، Ghidra، Qiling**: حضور برای پیگیری دستی تشخیص داده می‌شود

### ⚠️ تکذیب‌نامه

APASS ARYX فقط برای اهداف مشروع پژوهش امنیتی و آموزشی در نظر گرفته شده است. کاربران مسئول اطمینان از انطباق استفاده خود با قوانین و مقررات قابل اجرا هستند. نویسندگان مسئولیتی در قبال سوء استفاده از این ابزار ندارند.

### 📜 مجوز

حق نشر محفوظ است (All Rights Reserved). کپی‌برداری، توزیع یا تغییر این نرم‌افزار بدون اجازهٔ کتبی صاحب اثر ممنوع است. مشارکت برای ارتقا و بهبود پروژه پذیرفته می‌شود و ارسال هرگونه مشارکت به‌منزلهٔ واگذاری غیرانحصاری حقوق لازم برای ادغام در پروژه طبق شرایط فایل `LICENSE` است.

### 👤 نویسنده

**نویسنده**: Aiden Azad — برند V7lthronyx

- **GitHub**: <https://github.com/v74all>
- **YouTube**: <https://youtube.com/@v7lthronyx>
- **Instagram**: <https://instagram.com/v7lthronyx.core>

---

*APASS ARYX - افشای تهدیدها، حفاظت از سیستم‌ها.*

"هیچ نقابی نمی‌تواند پنهان شود. APASS ARYX از میان می‌بیند."
