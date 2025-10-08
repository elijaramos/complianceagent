# Azure Compliance Agent

**Automated Azure compliance scanning, analysis, and remediation powered by AI**

**Developer:** Elija Ramos, CISSP | GRC Engineering & Information Security

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![NIST CSF 2.0](https://img.shields.io/badge/NIST-CSF%202.0-green.svg)](https://www.nist.gov/cyberframework)

## Overview

The Azure Compliance Agent is an intelligent automation tool that demonstrates practical expertise in **cloud security, GRC Engineering, and AI-driven compliance**. This project showcases the integration of cybersecurity frameworks (NIST CSF 2.0), cloud infrastructure security (Azure), and emerging AI technologies to solve real-world GRC Engineering challenges.

Built to scan Azure infrastructure for security and compliance violations, the agent uses Claude AI to generate detailed remediation plans and executes approved fixes—all while maintaining comprehensive audit trails and human oversight required in enterprise GRC programs.

### Key Capabilities

- **🔍 Automated Compliance Scanning**: Discovers misconfigurations across Azure resources (storage accounts, network security groups, etc.)
- **🤖 AI-Powered Risk Analysis**: Leverages Claude AI to analyze findings, prioritize by risk severity, and generate contextual remediation plans
- **✅ GRC Control Framework**: Human-in-the-loop approval workflow ensures no changes execute without explicit authorization—critical for SOX, HIPAA, and regulatory compliance
- **⚙️ SDK-Based Remediation**: Uses Azure Python SDK (not CLI) for reliable, auditable, and repeatable resource updates
- **🔄 Disaster Recovery Ready**: Creates rollback snapshots before each change to support incident response and business continuity
- **📊 Audit-Ready Reporting**: Generates comprehensive compliance reports with before/after comparisons and complete audit trails
- **🛡️ NIST CSF 2.0 Aligned**: Maps controls directly to NIST Cybersecurity Framework categories (IDENTIFY, PROTECT, DETECT, RESPOND, RECOVER)

### Why This Matters for GRC Engineering

This project demonstrates core GRC Engineering principles:
- **Risk Management Engineering**: Automated vulnerability identification and risk-based prioritization at scale
- **Compliance-as-Code**: Policy automation using YAML-defined rules, reducing manual audit burden through continuous monitoring
- **Security Orchestration**: Integration of security tooling with cloud infrastructure (Azure) for automated remediation
- **Governance Automation**: Programmatic control implementation with approval workflows and audit trail generation
- **AI-Driven GRC**: Practical application of LLMs for intelligent security analysis and decision support
- **Access Governance**: Service principal management and least-privilege access control enforcement

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                   Azure Compliance Agent                     │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌──────────┐   ┌──────────┐   ┌──────────┐   ┌─────────┐ │
│  │ Scanner  │──>│ Analyzer │──>│   Agent   │──>│ Reports │ │
│  │ (Azure)  │   │ (Claude) │   │(Workflow) │   │         │ │
│  └──────────┘   └──────────┘   └──────────┘   └─────────┘ │
│       │              │               │                      │
│       v              v               v                      │
│  ┌──────────────────────────────────────────────────────┐  │
│  │            Remediator (Azure SDK)                    │  │
│  └──────────────────────────────────────────────────────┘  │
│                           │                                 │
└───────────────────────────┼─────────────────────────────────┘
                            v
                   ┌─────────────────┐
                   │ Azure Resources │
                   └─────────────────┘
```

### Components

1. **Scanner** (`src/scanner.py`): Queries Azure resources and evaluates against NIST CSF rules
2. **Analyzer** (`src/analyzer.py`): Uses Claude AI to generate remediation plans with context
3. **Remediator** (`src/remediator.py`): Executes fixes using Azure SDK with safety checks
4. **Agent** (`src/agent.py`): Orchestrates the complete workflow with approval gates
5. **Quick Start** (`quick_start.py`): User-friendly CLI interface

## Installation

### Prerequisites

- Python 3.8 or higher
- Azure subscription with appropriate permissions
- Anthropic API key for Claude
- Azure Service Principal with:
  - Reader role (for scanning)
  - Contributor role on resource groups (for remediation)

### Setup

1. **Clone the repository**
   ```bash
   git clone <your-repo-url>
   cd azure-compliance-agent
   ```

2. **Create virtual environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure environment variables**

   Create a `.env` file in the project root:
   ```env
   # Azure credentials
   AZURE_SUBSCRIPTION_ID=your-subscription-id
   AZURE_TENANT_ID=your-tenant-id
   AZURE_CLIENT_ID=your-service-principal-client-id
   AZURE_CLIENT_SECRET=your-service-principal-secret

   # Anthropic API key
   ANTHROPIC_API_KEY=sk-ant-your-api-key
   ```

5. **Verify configuration**
   ```bash
   python quick_start.py
   ```
   Select option 4 (Test Azure Connection) and 5 (Test Claude Connection)

## Quick Start

### Interactive CLI

The easiest way to use the agent:

```bash
python quick_start.py
```

This provides a menu-driven interface with options for:
- Scan-only (read-only compliance audit)
- Full compliance cycle (scan → analyze → remediate → verify)
- View last report
- Test connections

### Programmatic Usage

```python
from src.agent import ComplianceAgent

# Initialize agent
agent = ComplianceAgent(
    azure_subscription_id="your-sub-id",
    azure_tenant_id="your-tenant-id",
    azure_client_id="your-client-id",
    azure_client_secret="your-secret",
    anthropic_api_key="your-claude-key"
)

# Run complete workflow
result = agent.run_full_cycle()

print(f"Fixed {result['before_scan']['total_violations'] - result['after_scan']['total_violations']} violations")
```

## Configuration

### Application Settings

Edit `settings.py` to customize:

- **Claude Model**: Change AI model version
  ```python
  CLAUDE_MODEL = "claude-sonnet-4-20250514"
  ```

- **Azure Timeouts**: Adjust API timeout and retry settings
  ```python
  AZURE_TIMEOUT = 60
  AZURE_MAX_RETRIES = 3
  ```

- **Report Directories**: Change output locations
  ```python
  REPORTS_DIR = "reports"
  APPROVALS_DIR = "approvals"
  LOGS_DIR = "logs"
  ```

- **Workflow Behavior**: Control approval requirements
  ```python
  REQUIRE_APPROVAL = True
  AUTO_APPROVE_LOW_RISK = False
  ```

### Compliance Rules

Edit `config/nist_csf_rules.yaml` to add or modify compliance checks:

```yaml
rules:
  - id: PR.DS-1-storage-encryption
    nist_function: PROTECT
    category: PR.DS-1
    description: "Storage accounts must use encryption at rest"
    resource_type: Microsoft.Storage/storageAccounts
    severity: HIGH
    check:
      property: properties.encryption.services.blob.enabled
      operator: equals
      value: true
```

## Usage Examples

### Scan Only (No Changes)

```bash
python quick_start.py
# Select option 1: Scan Only
```

This performs a read-only audit and generates a report showing all violations without making any changes.

### Full Compliance Cycle

```bash
python quick_start.py
# Select option 2: Full Compliance Cycle
```

**Workflow:**
1. Scans Azure environment
2. Sends findings to Claude AI for analysis
3. Displays proposed remediations
4. Requests your approval
5. Executes only approved changes
6. Re-scans to verify improvements
7. Generates final report

### Scheduled Scanning

**Linux/Mac (cron):**
```bash
# Daily scan at 2 AM
0 2 * * * cd /path/to/project && /path/to/venv/bin/python quick_start.py
```

**Windows (Task Scheduler):**
```powershell
schtasks /create /tn "ComplianceScan" /tr "python quick_start.py" /sc daily /st 02:00
```

## Project Structure

```
azure-compliance-agent/
├── .claude/                      # Claude Code IDE settings
│   └── settings.json            # Disable co-authorship, etc.
├── config/                      # Configuration files
│   └── nist_csf_rules.yaml     # NIST CSF compliance rules
├── src/                         # Core application modules
│   ├── __init__.py
│   ├── agent.py                # Main workflow orchestrator
│   ├── analyzer.py             # Claude AI integration
│   ├── remediator.py           # Azure SDK remediation
│   └── scanner.py              # Azure resource scanning
├── approvals/                   # Generated approval requests
├── logs/                        # Workflow audit logs
├── reports/                     # Compliance scan reports
├── rollback_snapshots/          # Pre-change snapshots
├── .env                         # Environment variables (not in git)
├── .gitignore                   # Git ignore patterns
├── quick_start.py               # Interactive CLI interface
├── readme.md                    # This file
├── requirements.txt             # Python dependencies
└── settings.py                  # Application configuration
```

## Development

### Adding New Compliance Rules

1. Edit `config/nist_csf_rules.yaml`
2. Add rule definition with check criteria
3. Test with scan-only mode
4. Add remediation logic to `src/remediator.py` if needed

### Extending to New Azure Resources

1. Add resource-specific scanning method in `src/scanner.py`
2. Define compliance rules in `config/nist_csf_rules.yaml`
3. Implement remediation function in `src/remediator.py`
4. Update `execute_remediation()` router

### Testing

Run individual components:

```bash
# Test scanner
python src/scanner.py

# Test analyzer
python src/analyzer.py

# Test remediator (WARNING: will modify Azure resources)
python src/remediator.py
```

## Security Considerations

- **Never commit `.env`**: Contains secrets (already in .gitignore)
- **Service Principal Permissions**: Use least privilege (Reader + specific Contributor roles)
- **Approval Required**: Always review AI recommendations before execution
- **Audit Trails**: All actions logged to `logs/workflow_*.jsonl`
- **Rollback Snapshots**: Created automatically before each change

## Compliance & Security Frameworks

### Currently Implemented
- ✅ **NIST Cybersecurity Framework (CSF) 2.0**: Core compliance ruleset with mappings to NIST functions and categories
- ✅ **CIS Controls**: Implements key Azure security benchmarks (encryption, access control, logging)
- ✅ **Defense in Depth**: Multi-layer security validation across network, data, and access controls

### Planned Extensions
- 🔄 **SOC 2 Type II Controls**: Mapping to Trust Service Criteria (Security, Availability, Confidentiality)
- 🔄 **PCI DSS v4.0**: Payment card data protection requirements
- 🔄 **HIPAA Security Rule**: Healthcare PHI protection controls
- 🔄 **ISO 27001**: Information security management system controls
- 🔄 **CIS Azure Benchmarks v2.0**: Full benchmark implementation

## Technical Skills Demonstrated

**Cloud Security:**
- Azure Resource Management (ARM) API integration
- Azure RBAC and service principal configuration
- Cloud security posture management (CSPM) principles
- Infrastructure-as-Code security scanning

**GRC Engineering:**
- NIST CSF framework implementation and automation
- Compliance-as-code and continuous control monitoring
- Risk-based prioritization and automated remediation
- Audit trail generation and evidence collection automation

**Development & Automation:**
- Python SDK integration (Azure, Anthropic)
- RESTful API consumption and error handling
- YAML-based policy definition (compliance-as-code)
- CLI tool development with user experience focus

**AI & Emerging Tech:**
- Large Language Model (LLM) integration for security analysis
- Prompt engineering for compliance recommendations
- AI-assisted decision support in security operations

## Roadmap

- [ ] Multi-subscription support for enterprise deployments
- [ ] Azure Policy integration for preventive controls
- [ ] Terraform/IaC state file scanning (shift-left security)
- [ ] SIEM integration (Splunk/Sentinel) for alert correlation
- [ ] Slack/Teams notifications for security teams
- [ ] Executive dashboard with KPI tracking
- [ ] Custom rule templating for organization-specific policies
- [ ] Cost optimization tied to security posture

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Professional Context

This project was developed as a portfolio demonstration of practical **GRC Engineering** and cloud security expertise by **Elija Ramos, CISSP**. It represents the intersection of traditional information security governance with modern cloud infrastructure, automation engineering, and AI technologies.

**Key Competencies Highlighted:**
- GRC Engineering: Building scalable compliance and governance systems
- Enterprise cloud security architecture and implementation
- Regulatory compliance automation (NIST, CIS, SOC 2, HIPAA)
- Risk assessment engineering and automated security control implementation
- Python development for security and compliance automation
- AI/ML integration for intelligent security operations
- DevSecOps and security-as-code practices

## Contact & Support

**Elija Ramos, CISSP**
GRC Engineering & Information Security

For questions, collaboration, or professional inquiries:
- GitHub Issues: Use this repository's issue tracker
- Email: [your-email@example.com]

## Acknowledgments

- Built with [Azure SDK for Python](https://github.com/Azure/azure-sdk-for-python)
- Powered by [Claude AI](https://www.anthropic.com/claude) - Anthropic's advanced language model
- Compliance rules based on [NIST Cybersecurity Framework 2.0](https://www.nist.gov/cyberframework)
- Inspired by real-world GRC Engineering challenges in enterprise cloud security

---

**Version:** 1.0.0
**Last Updated:** October 2025
**Developer:** Elija Ramos, CISSP
