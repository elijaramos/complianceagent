# Changelog

All notable changes to the Azure Compliance Agent will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Nothing yet - check back for future features!

## [1.1.0] - 2025-01-10

### Added
- **Azure Monitor diagnostic logging support** 🎉
  - Full NIST CSF DE.CM-7 (Continuous Monitoring) implementation
  - Scanner checks diagnostic settings via MonitorManagementClient
  - Remediator creates diagnostic settings for StorageRead/Write/Delete
  - Added `azure-mgmt-monitor==6.0.2` dependency
- **Professional Excel reports** with color-coded severity levels
- **Technical implementation details** in remediation plans
- **Azure Portal UI guidance** after successful remediations

### Fixed
- **Scanner property paths** now use correct Azure Python SDK snake_case
  - Fixed `allow_blob_public_access` and `encryption` detection
  - Violations now clear after successful remediation
- **Dangerous command detection** false positives eliminated
- **JSON parsing** now handles Claude AI markdown code blocks
- **NameError** in analyzer.py variable reference

### Changed
- **Enhanced terminal output** readability and formatting
- **Renamed "Rule" to "NIST CSF Rule"** throughout UI
- **Added CHANGELOG.md** following Keep a Changelog format
- **Documentation improvements** with end-to-end data flow diagrams

## [1.0.0] - 2025-01-10

### Added
- **Initial Release** - Full compliance workflow implementation
  - Azure resource scanning against NIST CSF 2.0 controls
  - AI-powered analysis using Claude Sonnet 4.5
  - Human-in-the-loop approval workflow
  - SDK-based automated remediation
  - Rollback snapshot creation before changes
  - Comprehensive audit logging (JSONL format)

- **NIST CSF 2.0 Compliance Rules**
  - PR.DS-1: Storage account encryption at rest
  - PR.DS-1: Disable public blob access
  - PR.AC-4: Network Security Group restrictions
  - PR.AC-1: RBAC (no classic administrators)

- **Professional Excel Reports**
  - 3-sheet workbook: Summary, Violations, Recommendations
  - Color-coded severity levels (Critical=Red, High=Orange, Medium=Yellow, Low=Green)
  - Auto-filters and frozen headers
  - Audit-ready formatting with proper alignment

- **Security Features**
  - Pre-flight safety validation (risk scoring)
  - Dangerous command detection (blocks delete/purge/destroy)
  - Rollback snapshots for disaster recovery
  - Service principal authentication with least privilege

- **GRC Engineering Focus**
  - Policy-as-code (YAML-defined rules)
  - Compliance-as-code automation
  - Complete audit trails for evidence collection
  - Risk-based prioritization of findings

- **Developer Experience**
  - Quick start CLI menu interface
  - Comprehensive WHY comments throughout codebase
  - End-to-end data flow documentation
  - Azure Portal UI guidance after remediations

### Documentation
- Professional README with GRC Engineering positioning
  - Portfolio-optimized for CISSP certification showcase
  - Technical skills demonstration section
  - Complete architecture and data flow diagrams
  - Industry compliance framework roadmap (SOC 2, HIPAA, ISO 27001, PCI DSS)

- Claude Code settings for IDE integration
  - Custom settings for development workflow
  - Local settings excluded from version control

### Dependencies
- `azure-identity==1.15.0` - Azure authentication
- `azure-mgmt-resource==23.0.1` - Resource management
- `azure-mgmt-storage==21.1.0` - Storage account management
- `azure-mgmt-network==25.3.0` - Network security groups
- `azure-mgmt-security==6.0.0` - Security center integration
- `azure-mgmt-monitor==6.0.2` - Diagnostic logging (added in unreleased)
- `anthropic==0.69.0` - Claude AI integration
- `python-dotenv==1.0.0` - Environment variable management
- `pyyaml==6.0.1` - Compliance rules configuration
- `openpyxl==3.1.2` - Excel report generation

---

## Release Notes

### Version 1.0.0 Highlights

This initial release provides a **production-ready GRC automation tool** that:

1. **Scans Azure infrastructure** against NIST Cybersecurity Framework 2.0
2. **Analyzes findings** using Claude AI for intelligent remediation planning
3. **Requires human approval** before making any changes (governance)
4. **Executes remediations** using Azure Python SDK (not CLI)
5. **Verifies compliance** improved with before/after comparison
6. **Generates reports** in professional Excel format for auditors

### Compliance Coverage

- ✅ **Storage Security**: Encryption, public access controls
- ✅ **Network Security**: NSG rule validation
- ✅ **Access Control**: RBAC enforcement
- ✅ **Logging & Monitoring**: Diagnostic settings (unreleased)

### Future Roadmap

- Multi-subscription support for enterprise deployments
- Azure Policy integration for preventive controls
- Terraform/IaC state file scanning (shift-left security)
- SIEM integration (Splunk/Sentinel) for alert correlation
- Additional compliance frameworks (SOC 2, HIPAA, ISO 27001, PCI DSS)
- Executive dashboard with KPI tracking
- Custom rule templating for organization-specific policies

---

## Developer Notes

### Commit Hash to Version Mapping
- `00f74a4` - v1.0.0 Initial Release
- `9265c9e` - Unreleased (Azure Monitor support)

### How to Update This Changelog

When making changes, add entries under `[Unreleased]` in the appropriate category:
- **Added** - New features
- **Changed** - Changes to existing functionality
- **Deprecated** - Soon-to-be removed features
- **Removed** - Removed features
- **Fixed** - Bug fixes
- **Security** - Vulnerability fixes

When releasing a new version:
1. Change `[Unreleased]` to `[X.Y.Z] - YYYY-MM-DD`
2. Add new `[Unreleased]` section at top
3. Update version in `settings.py`
4. Tag release in git: `git tag vX.Y.Z`

---

**Maintained by:** Elija Ramos, CISSP | GRC Engineering & Information Security
