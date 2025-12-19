# Real-Time File Integrity Monitoring (FIM) System

A comprehensive, production-ready File Integrity Monitoring system designed to detect, log, and alert on file system changes in real-time. Built for security professionals, system administrators, and organizations requiring robust integrity monitoring capabilities.

## 🎯 Overview

The FIM Agent provides continuous monitoring of critical directories, maintaining secure baselines of file hashes and generating detailed security logs with precise timestamps. It identifies what changed, when it changed, and why it matters from a security perspective, making it an essential tool for detecting unauthorized modifications, malware activity, and compliance violations.

## ✨ Key Features

### Core Capabilities
- **Real-Time Monitoring**: Continuous file system watching with instant event detection
- **Secure Baseline Management**: SHA-256 hash-based integrity verification
- **Comprehensive Event Detection**: Tracks file creation, modification, deletion, and movement
- **Tamper-Evident Logging**: Immutable log storage with integrity protection
- **Content Inspection**: Automatic classification of sensitive data (private, secret, internal)
- **AI-Powered Risk Assessment**: Intelligent threat analysis with risk scoring
- **MITRE ATT&CK Mapping**: Automatic tagging of events with relevant attack techniques

### Security Features
- **Governance Compliance**: Configurable exclusion rules to avoid monitoring personal data
- **Admin Approval Workflow**: High-risk events require administrative approval
- **SIEM Integration**: Native support for Wazuh and other SIEM platforms
- **Multi-Format Logging**: JSON, text, and Wazuh-compatible output formats
- **Risk-Based Alerting**: Configurable thresholds for automated security alerts

### Operational Features
- **CLI Interface**: Command-line tools for baseline management and timeline analysis
- **REST API**: FastAPI-based web service for programmatic access
- **Web Dashboard**: Interactive timeline visualization for event analysis
- **Attacker Timeline View**: Chronological reconstruction of system activity
- **Flexible Filtering**: Query events by severity, path, time range, and risk score

## 📋 Requirements

- Python 3.8 or higher
- Windows, Linux, or macOS
- SQLite3 (included with Python)

## 🚀 Quick Start

### Installation

1. **Clone the repository:**
```bash
git clone <repository-url>
cd capstone-g
```

2. **Install dependencies:**
```bash
pip install -r requirements.txt
```

3. **Configure the agent:**
```bash
cp config/config_example.yaml config/config.yaml
# Edit config.yaml with your settings
```

### Basic Usage

1. **Initialize the baseline:**
```bash
python -m fim_agent.cli.main init-baseline
```

2. **Start monitoring:**
```bash
python -m fim_agent.cli.main run-agent
```

3. **View the event timeline:**
```bash
python -m fim_agent.cli.main timeline
```

## 📖 Documentation

Comprehensive documentation is available in the `docs/` directory:

- **[Architecture Guide](docs/architecture.md)**: System design and component overview
- **[Usage Guide](docs/usage.md)**: Detailed usage instructions and API reference
- **[Interpreting Output](docs/interpreting_output.md)**: Understanding events, alerts, and SIEM integration

## ⚙️ Configuration

The FIM Agent is configured via YAML files. Key configuration options include:

```yaml
# Directories to monitor
monitored_directories:
  - "./critical_files"

# Directories to exclude
exclude_directories:
  - "./.git"
  - "./venv"

# Alert thresholds
alert_min_risk_score: 70
alert_min_ai_risk_score: 70

# Admin approval settings
require_admin_for_alerts: true
admin_min_risk_score: 80
admin_min_ai_risk_score: 75
```

See `config/config_example.yaml` for a complete configuration reference.

## 🔍 Usage Examples

### Command-Line Interface

**View high-severity events:**
```bash
python -m fim_agent.cli.main timeline --severity high
```

**Filter events by path:**
```bash
python -m fim_agent.cli.main timeline --path-filter "watched/test"
```

**Query events in a time range:**
```bash
python -m fim_agent.cli.main timeline --from 2025-01-01T00:00:00 --to 2025-01-02T00:00:00
```

### Web API

**Start the web server:**
```bash
python -m fim_agent.cli.main serve-web --host 127.0.0.1 --port 8080
```

**Access the API:**
- API Documentation: `http://localhost:8080/docs` (Swagger UI)
- Events Endpoint: `http://localhost:8080/api/events`
- Statistics: `http://localhost:8080/api/stats/summary`

**Example API queries:**
```bash
# Get high-severity events
curl "http://localhost:8080/api/events?severity=high&limit=50"

# Get events with risk score >= 80
curl "http://localhost:8080/api/events?min_risk=80"
```

## 🏗️ Architecture

The FIM Agent is built with a modular architecture:

```
┌─────────────┐
│   CLI/Web   │
└──────┬──────┘
       │
┌──────▼──────────────────┐
│      Core Engine        │
├──────────────────────────┤
│  Watcher  │  Hasher     │
│  Events   │  Storage    │
│  Governance              │
└──────────────────────────┘
```

### Core Components

- **watcher.py**: Real-time file system monitoring using watchdog
- **hasher.py**: SHA-256 hash computation and baseline management
- **events.py**: Event processing and security context enrichment
- **storage.py**: Tamper-evident SQLite storage layer
- **governance.py**: Privacy and compliance rule enforcement
- **content_inspector.py**: Content analysis and classification
- **ai_client.py**: AI-powered risk assessment

## 🔒 Security Features

### Integrity Verification
- SHA-256 hash-based file integrity checking
- Baseline comparison for unauthorized modifications
- Tamper-evident event logging

### Privacy & Compliance
- Configurable exclusion patterns for sensitive directories
- Content classification (public, private, secret, internal)
- Governance rules to prevent monitoring of personal data

### Threat Detection
- Executable file detection (.exe, .dll, .ps1, etc.)
- Suspicious content pattern matching
- AI-driven risk scoring and classification
- MITRE ATT&CK technique mapping

### Access Control
- Admin approval workflow for high-risk events
- Password-protected web dashboard
- Environment variable-based authentication

## 📊 SIEM Integration

The FIM Agent produces SIEM-friendly logs in JSON format, compatible with Wazuh, Splunk, ELK Stack, and other platforms.

### Log Format

Logs include standardized fields for SIEM ingestion:
- `source`: "fim_agent"
- `category`: "file_integrity"
- `host`: Hostname where the agent is running
- `rule`: Wazuh-compatible rule structure
- `mitre_techniques`: MITRE ATT&CK techniques array

### Wazuh Integration

See [Interpreting Output](docs/interpreting_output.md#integrating-with-wazuh) for detailed Wazuh configuration instructions, including:
- Filebeat configuration
- Custom decoders
- Alert rules
- Query examples

## 🧪 Testing

Run the test suite:
```bash
pytest tests/
```

## 📝 Event Types

The FIM Agent detects and logs the following event types:

- **create**: New file detected
- **modify**: File content changed
- **delete**: File removed
- **rename**: File renamed
- **move_in**: File moved into monitored directory
- **move_out**: File moved out of monitored directory

Each event includes:
- Precise timestamp (ISO 8601)
- File path and hash values
- Security context (severity, risk score, MITRE tags)
- Content classification
- AI risk assessment
- User and process information (when available)

## 🎯 Use Cases

- **Security Monitoring**: Detect unauthorized file modifications and malware activity
- **Compliance**: Maintain audit trails for regulatory requirements
- **Incident Response**: Reconstruct attacker timelines and system changes
- **Change Management**: Track and verify authorized system modifications
- **Forensics**: Detailed logging for security investigations

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📄 License

[Specify your license here]

## 🙏 Acknowledgments

Built as a capstone project demonstrating real-world security monitoring capabilities.

---

**Note**: This system is designed for security monitoring and should be deployed in accordance with your organization's security policies and compliance requirements.

