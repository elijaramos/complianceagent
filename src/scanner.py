"""
Azure Compliance Scanner for NIST CSF

This module implements automated compliance scanning for Azure resources against
NIST Cybersecurity Framework (CSF) 2.0 controls. It identifies misconfigurations
and security risks in Azure infrastructure.

WHY THIS EXISTS:
- Manual compliance checks are error-prone and time-consuming
- Organizations need continuous monitoring to maintain security posture
- Regulatory frameworks (GDPR, HIPAA, PCI DSS) require documented evidence of controls
- Early detection of misconfigurations prevents security incidents and data breaches
"""

import os
import sys
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from pathlib import Path

import yaml
from azure.identity import ClientSecretCredential
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.resource import ResourceManagementClient
from azure.core.exceptions import AzureError, HttpResponseError

# Import configuration settings
sys.path.insert(0, str(Path(__file__).parent.parent))
from settings import REPORTS_DIR


class AzureScanner:
    """
    Scans Azure resources for compliance with NIST CSF controls.
    
    WHY USE THIS CLASS:
    - Centralizes Azure authentication and client management
    - Provides reusable scanning logic across multiple resource types
    - Generates actionable compliance reports for security teams
    - Enables automated compliance monitoring in CI/CD pipelines
    
    Architecture:
    - Uses Azure SDK management libraries (azure-mgmt-*) to query resource configurations
    - Authenticates via Service Principal (ClientSecretCredential) for non-interactive scenarios
    - Loads compliance rules from YAML for flexibility and maintainability
    - Separates scanning logic by resource type for modularity
    """
    
    def __init__(self, subscription_id: str, tenant_id: str, client_id: str, 
                 client_secret: str, rules_path: str = "config/nist_csf_rules.yaml"):
        """
        Initialize Azure compliance scanner with credentials and rules.
        
        WHY THESE PARAMETERS:
        - subscription_id: Defines the Azure subscription scope to scan
        - tenant_id: Identifies the Azure AD tenant for authentication
        - client_id: Service Principal application ID (used for non-interactive auth)
        - client_secret: Service Principal password/secret (proves identity)
        - rules_path: Allows different rule sets (dev/prod, different frameworks)
        
        WHY SERVICE PRINCIPAL AUTH:
        - Enables automation without user interaction
        - Can be scoped with minimal required permissions (principle of least privilege)
        - Supports secret rotation and centralized credential management
        - Works in CI/CD pipelines, scheduled tasks, and containerized environments
        
        Args:
            subscription_id: Azure subscription ID to scan
            tenant_id: Azure Active Directory tenant ID
            client_id: Service Principal application (client) ID
            client_secret: Service Principal secret value
            rules_path: Path to NIST CSF rules YAML file
            
        Raises:
            FileNotFoundError: If rules file doesn't exist
            yaml.YAMLError: If rules file is malformed
        """
        self.subscription_id = subscription_id
        
        # Azure SDK Pattern: ClientSecretCredential is used for service-to-service authentication
        # It implements the OAuth 2.0 client credentials flow, exchanging the client secret
        # for a time-limited access token. Tokens are cached and automatically refreshed.
        self.credential = ClientSecretCredential(
            tenant_id=tenant_id,
            client_id=client_id,
            client_secret=client_secret
        )
        
        # Azure SDK Pattern: Management clients provide typed interfaces to Azure Resource Manager (ARM)
        # Each client corresponds to a specific Azure service (storage, network, compute, etc.)
        # They handle REST API calls, pagination, retries, and response deserialization
        self.storage_client = StorageManagementClient(
            credential=self.credential,
            subscription_id=subscription_id
        )
        
        self.network_client = NetworkManagementClient(
            credential=self.credential,
            subscription_id=subscription_id
        )
        
        self.resource_client = ResourceManagementClient(
            credential=self.credential,
            subscription_id=subscription_id
        )
        
        # Load compliance rules from YAML
        # WHY YAML: Human-readable, supports comments, easy for security teams to maintain
        self.rules = self._load_rules(rules_path)
        
        # Store scan results for report generation
        self.scan_results: List[Dict[str, Any]] = []
        
    def _load_rules(self, rules_path: str) -> List[Dict[str, Any]]:
        """
        Load compliance rules from YAML configuration file.
        
        WHY EXTERNAL RULES FILE:
        - Allows security teams to update rules without code changes
        - Supports versioning and auditing of compliance requirements
        - Enables different rule sets for different environments (dev/prod)
        - Makes it easy to add new controls as regulations evolve
        
        Args:
            rules_path: Path to YAML rules file
            
        Returns:
            List of rule dictionaries
            
        Raises:
            FileNotFoundError: If rules file doesn't exist
            yaml.YAMLError: If YAML is malformed
        """
        rules_file = Path(rules_path)
        
        if not rules_file.exists():
            raise FileNotFoundError(
                f"Rules file not found: {rules_path}\n"
                f"Expected location: {rules_file.absolute()}"
            )
        
        try:
            with open(rules_file, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)
                rules = data.get('rules', [])
                print(f"✓ Loaded {len(rules)} compliance rules from {rules_path}")
                return rules
        except yaml.YAMLError as e:
            raise yaml.YAMLError(f"Failed to parse rules file: {e}")
    
    def scan_all_resources(self) -> Dict[str, Any]:
        """
        Main entry point: Scan all Azure resources for compliance violations.
        
        WHY THIS METHOD:
        - Provides single entry point for complete compliance scan
        - Coordinates scanning across multiple resource types
        - Aggregates results for unified reporting
        - Handles errors gracefully to ensure partial results are still useful
        
        Returns:
            Dictionary containing:
                - timestamp: When scan was performed
                - subscription_id: Azure subscription scanned
                - total_violations: Total number of compliance violations found
                - violations_by_severity: Breakdown by severity level
                - results: Detailed violation information
                
        WHY THIS STRUCTURE:
        - timestamp: Enables trending analysis and audit trails
        - subscription_id: Critical for multi-subscription environments
        - severity breakdown: Helps prioritize remediation efforts
        - detailed results: Provides actionable information for fixes
        """
        print(f"\n{'='*70}")
        print(f"Starting Azure Compliance Scan")
        print(f"Subscription: {self.subscription_id}")
        print(f"Timestamp: {datetime.utcnow().isoformat()}")
        print(f"{'='*70}\n")
        
        # Reset results for new scan
        self.scan_results = []
        
        # Scan different resource types
        # WHY SEPARATE METHODS: Each Azure service has different APIs and data structures
        # This separation makes the code maintainable and testable
        try:
            storage_violations = self._scan_storage_accounts()
            print(f"✓ Storage scan complete: {len(storage_violations)} violations found")
        except Exception as e:
            print(f"✗ Storage scan failed: {e}")
            storage_violations = []
        
        try:
            nsg_violations = self._scan_nsgs()
            print(f"✓ NSG scan complete: {len(nsg_violations)} violations found")
        except Exception as e:
            print(f"✗ NSG scan failed: {e}")
            nsg_violations = []
        
        # Combine all violations
        self.scan_results = storage_violations + nsg_violations
        
        # Generate summary statistics
        summary = self._generate_summary()
        
        print(f"\n{'='*70}")
        print(f"Scan Complete: {summary['total_violations']} total violations")
        print(f"{'='*70}\n")
        
        return summary
    
    def _scan_storage_accounts(self) -> List[Dict[str, Any]]:
        """
        Scan all storage accounts in subscription for compliance violations.
        
        WHY STORAGE ACCOUNTS ARE CRITICAL:
        - Often store sensitive data (PII, financial records, health data)
        - Frequently misconfigured with public access, leading to data breaches
        - Encryption and logging are essential for compliance (GDPR, HIPAA, PCI DSS)
        - Common attack vector: exposed storage accounts are actively scanned by attackers
        
        Azure SDK Pattern:
        - storage_client.storage_accounts.list() returns an iterator (lazy loading)
        - Each item is a StorageAccount object with nested properties
        - Properties follow Azure Resource Manager (ARM) structure
        
        Returns:
            List of violation dictionaries with details for remediation
        """
        violations = []
        
        # Get all storage rules from loaded compliance rules
        storage_rules = [
            r for r in self.rules 
            if r.get('resource_type') == 'Microsoft.Storage/storageAccounts'
        ]
        
        print(f"\nScanning Storage Accounts ({len(storage_rules)} rules)...")
        
        try:
            # Azure SDK Pattern: list() returns a paged iterator
            # The SDK automatically handles pagination (continuation tokens)
            # This is efficient for subscriptions with many resources
            storage_accounts = list(self.storage_client.storage_accounts.list())
            print(f"  Found {len(storage_accounts)} storage account(s)")
            
            if not storage_accounts:
                print("  ⚠ No storage accounts found in subscription")
                return violations
            
            for account in storage_accounts:
                # Extract resource group from ARM resource ID
                # Azure resource IDs follow pattern: /subscriptions/{sub}/resourceGroups/{rg}/providers/{provider}/{type}/{name}
                resource_group = account.id.split('/')[4]
                
                print(f"  Checking: {account.name} (RG: {resource_group})")
                
                # Get detailed properties that may not be in list response
                # WHY: List operations return minimal data for performance
                # Get operations return complete resource details
                try:
                    account_details = self.storage_client.storage_accounts.get_properties(
                        resource_group_name=resource_group,
                        account_name=account.name
                    )
                except HttpResponseError as e:
                    print(f"    ✗ Failed to get properties: {e.message}")
                    continue
                
                # Check each storage rule against this account
                for rule in storage_rules:
                    violation = self._check_storage_rule(
                        account_details, 
                        rule, 
                        resource_group
                    )
                    if violation:
                        violations.append(violation)
                        severity_symbol = "🔴" if rule['severity'] == "CRITICAL" else "🟡"
                        print(f"    {severity_symbol} VIOLATION: {rule['description']}")
        
        except AzureError as e:
            print(f"  ✗ Azure API error: {e}")
            raise
        
        return violations
    
    def _check_storage_rule(self, account: Any, rule: Dict[str, Any], 
                           resource_group: str) -> Optional[Dict[str, Any]]:
        """
        Check a single storage account against a compliance rule.
        
        WHY SEPARATE METHOD:
        - Keeps rule checking logic isolated and testable
        - Allows easy addition of new rule types
        - Simplifies error handling for individual rules
        
        Args:
            account: Azure StorageAccount object
            rule: Rule dictionary from YAML
            resource_group: Resource group name (for reporting)
            
        Returns:
            Violation dictionary if rule failed, None if passed
        """
        check = rule.get('check', {})
        property_path = check.get('property')
        operator = check.get('operator')
        expected_value = check.get('value')
        
        # Navigate nested property path (e.g., "properties.encryption.services.blob.enabled")
        # WHY: Azure API responses have deeply nested structures
        actual_value = self._get_nested_property(account, property_path)
        
        # Evaluate rule based on operator
        is_compliant = self._evaluate_rule(actual_value, operator, expected_value)
        
        if not is_compliant:
            return {
                'rule_id': rule['id'],
                'resource_type': rule['resource_type'],
                'resource_name': account.name,
                'resource_group': resource_group,
                'severity': rule['severity'],
                'description': rule['description'],
                'nist_function': rule.get('nist_function'),
                'nist_category': rule.get('category'),
                'expected': expected_value,
                'actual': actual_value,
                'timestamp': datetime.utcnow().isoformat()
            }
        
        return None
    
    def _scan_nsgs(self) -> List[Dict[str, Any]]:
        """
        Scan all Network Security Groups for compliance violations.
        
        WHY NSGs ARE CRITICAL:
        - Act as virtual firewalls controlling network traffic to Azure resources
        - Misconfigured NSGs expose resources to internet attacks (brute force, DDoS, exploits)
        - Allow rules with source 0.0.0.0/0 are the most common security misconfiguration
        - Attackers actively scan for publicly exposed resources (SSH, RDP, databases)
        
        Azure SDK Pattern:
        - NSGs are listed across all resource groups in subscription
        - Security rules are nested within NSG properties
        - Rules have priority (lower numbers evaluated first)
        
        Returns:
            List of violation dictionaries
        """
        violations = []
        
        # Get NSG rules from compliance rules
        nsg_rules = [
            r for r in self.rules 
            if r.get('resource_type') == 'Microsoft.Network/networkSecurityGroups'
        ]
        
        print(f"\nScanning Network Security Groups ({len(nsg_rules)} rules)...")
        
        try:
            # Azure SDK Pattern: list_all() gets NSGs across all resource groups
            # Alternative: list(resource_group_name) for single resource group
            nsgs = list(self.network_client.network_security_groups.list_all())
            print(f"  Found {len(nsgs)} NSG(s)")
            
            if not nsgs:
                print("  ⚠ No NSGs found in subscription")
                return violations
            
            for nsg in nsgs:
                # Extract resource group from ARM resource ID
                resource_group = nsg.id.split('/')[4]
                
                print(f"  Checking: {nsg.name} (RG: {resource_group})")
                
                # Check each NSG rule
                for rule in nsg_rules:
                    violation = self._check_nsg_rule(nsg, rule, resource_group)
                    if violation:
                        violations.append(violation)
                        severity_symbol = "🔴" if rule['severity'] == "CRITICAL" else "🟡"
                        print(f"    {severity_symbol} VIOLATION: {rule['description']}")
        
        except AzureError as e:
            print(f"  ✗ Azure API error: {e}")
            raise
        
        return violations
    
    def _check_nsg_rule(self, nsg: Any, rule: Dict[str, Any], 
                        resource_group: str) -> Optional[Dict[str, Any]]:
        """
        Check NSG security rules for dangerous configurations.
        
        WHY THIS IS COMPLEX:
        - NSGs have multiple security rules, each with different properties
        - Must check combinations of properties (source + access + direction)
        - "not_contains" operator requires checking all rules don't match pattern
        
        Security Logic:
        - Checks if ANY security rule allows unrestricted inbound access (0.0.0.0/0)
        - This is the most dangerous misconfiguration (exposes resources to internet)
        
        Args:
            nsg: Azure NetworkSecurityGroup object
            rule: Compliance rule dictionary
            resource_group: Resource group name
            
        Returns:
            Violation dictionary if dangerous rule found, None if safe
        """
        check = rule.get('check', {})
        operator = check.get('operator')
        
        if operator == 'not_contains':
            # Check if any security rule matches the dangerous pattern
            dangerous_pattern = check.get('value', {})
            
            # NSG security rules are in properties.security_rules
            security_rules = getattr(nsg, 'security_rules', []) or []
            
            for sec_rule in security_rules:
                # Check if this rule matches ALL criteria in the dangerous pattern
                matches_pattern = True
                
                for pattern_key, pattern_value in dangerous_pattern.items():
                    # Navigate nested properties (e.g., "properties.sourceAddressPrefix")
                    actual_value = self._get_nested_property(sec_rule, pattern_key)
                    
                    # WHY STRING COMPARISON: Azure API may return "*" or "0.0.0.0/0" or "Internet"
                    # All represent "any source address"
                    if pattern_key == 'properties.sourceAddressPrefix':
                        # Check for common "any source" patterns
                        if actual_value not in ['0.0.0.0/0', '*', 'Internet']:
                            matches_pattern = False
                            break
                    elif actual_value != pattern_value:
                        matches_pattern = False
                        break
                
                # If we found a rule matching the dangerous pattern, it's a violation
                if matches_pattern:
                    return {
                        'rule_id': rule['id'],
                        'resource_type': rule['resource_type'],
                        'resource_name': nsg.name,
                        'resource_group': resource_group,
                        'severity': rule['severity'],
                        'description': rule['description'],
                        'nist_function': rule.get('nist_function'),
                        'nist_category': rule.get('category'),
                        'violating_rule': sec_rule.name,
                        'violating_rule_details': {
                            'source': sec_rule.source_address_prefix,
                            'destination_port': sec_rule.destination_port_range,
                            'protocol': sec_rule.protocol,
                            'access': sec_rule.access,
                            'direction': sec_rule.direction,
                            'priority': sec_rule.priority
                        },
                        'timestamp': datetime.utcnow().isoformat()
                    }
        
        return None
    
    def _get_nested_property(self, obj: Any, property_path: str) -> Any:
        """
        Navigate nested object properties using dot notation.
        
        WHY NEEDED:
        - Azure SDK returns deeply nested objects
        - Rules specify property paths like "properties.encryption.services.blob.enabled"
        - Avoids hardcoding property access patterns
        
        Example:
            obj = StorageAccount(properties=Properties(encryption=Encryption(services=...)))
            _get_nested_property(obj, "properties.encryption.services.blob.enabled")
            
        Args:
            obj: Python object (usually Azure SDK model)
            property_path: Dot-separated property path
            
        Returns:
            Property value or None if path doesn't exist
        """
        if not property_path:
            return obj
        
        # Split path and navigate step by step
        parts = property_path.split('.')
        current = obj
        
        for part in parts:
            if hasattr(current, part):
                current = getattr(current, part)
            elif isinstance(current, dict) and part in current:
                current = current[part]
            else:
                # Property doesn't exist (might be optional in Azure API)
                return None
        
        return current
    
    def _evaluate_rule(self, actual_value: Any, operator: str, expected_value: Any) -> bool:
        """
        Evaluate if actual value meets expected value based on operator.
        
        WHY SEPARATE METHOD:
        - Centralizes comparison logic
        - Makes it easy to add new operators
        - Handles None/null cases consistently
        
        Args:
            actual_value: Value from Azure resource
            operator: Comparison operator (equals, not_equals, etc.)
            expected_value: Expected value from rule
            
        Returns:
            True if compliant, False if violation
        """
        if operator == 'equals':
            return actual_value == expected_value
        elif operator == 'not_equals':
            return actual_value != expected_value
        elif operator == 'contains':
            return expected_value in (actual_value or [])
        elif operator == 'not_contains':
            return expected_value not in (actual_value or [])
        else:
            print(f"  ⚠ Unknown operator: {operator}")
            return True  # Unknown operators pass by default (fail-safe)
    
    def _generate_summary(self) -> Dict[str, Any]:
        """
        Generate summary statistics from scan results.
        
        WHY SUMMARY STATISTICS:
        - Executives need high-level metrics (total violations, trends)
        - Security teams need severity breakdown for prioritization
        - Audit trails require timestamps and subscription tracking
        
        Returns:
            Summary dictionary with aggregated scan results
        """
        # Count violations by severity
        severity_counts = {
            'CRITICAL': 0,
            'HIGH': 0,
            'MEDIUM': 0,
            'LOW': 0
        }
        
        for result in self.scan_results:
            severity = result.get('severity', 'UNKNOWN')
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        return {
            'timestamp': datetime.utcnow().isoformat(),
            'subscription_id': self.subscription_id,
            'total_violations': len(self.scan_results),
            'violations_by_severity': severity_counts,
            'results': self.scan_results
        }
    
    def generate_scan_report(self, output_path: Optional[str] = None) -> str:
        """
        Generate human-readable compliance report and save to file.
        
        WHY TEXT REPORTS:
        - Easy to email, share, and review without special tools
        - Can be committed to git for version control and trending
        - Provides context and remediation guidance for security teams
        - Serves as audit evidence for compliance frameworks
        
        Args:
            output_path: Path to save report file (defaults to REPORTS_DIR/compliance_report.txt)

        Returns:
            Report content as string
        """
        # Use default path from settings if not provided
        if output_path is None:
            output_path = f"{REPORTS_DIR}/compliance_report.txt"

        # Ensure reports directory exists
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Build report content
        report_lines = []
        report_lines.append("=" * 80)
        report_lines.append("AZURE COMPLIANCE SCAN REPORT")
        report_lines.append("=" * 80)
        report_lines.append(f"Timestamp: {datetime.utcnow().isoformat()}")
        report_lines.append(f"Subscription: {self.subscription_id}")
        report_lines.append(f"Total Violations: {len(self.scan_results)}")
        report_lines.append("=" * 80)
        report_lines.append("")
        
        # Group violations by severity
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            severity_violations = [
                v for v in self.scan_results 
                if v.get('severity') == severity
            ]
            
            if not severity_violations:
                continue
            
            report_lines.append(f"\n{'='*80}")
            report_lines.append(f"{severity} SEVERITY ({len(severity_violations)} violations)")
            report_lines.append(f"{'='*80}\n")
            
            for i, violation in enumerate(severity_violations, 1):
                report_lines.append(f"{i}. {violation.get('description', 'N/A')}")
                report_lines.append(f"   Rule ID: {violation.get('rule_id', 'N/A')}")
                report_lines.append(f"   Resource: {violation.get('resource_name', 'N/A')}")
                report_lines.append(f"   Resource Group: {violation.get('resource_group', 'N/A')}")
                report_lines.append(f"   NIST CSF: {violation.get('nist_function', 'N/A')} - {violation.get('nist_category', 'N/A')}")
                
                # Show violating NSG rule details if present
                if 'violating_rule' in violation:
                    report_lines.append(f"   Violating NSG Rule: {violation['violating_rule']}")
                    details = violation.get('violating_rule_details', {})
                    report_lines.append(f"      Source: {details.get('source', 'N/A')}")
                    report_lines.append(f"      Destination Port: {details.get('destination_port', 'N/A')}")
                    report_lines.append(f"      Protocol: {details.get('protocol', 'N/A')}")
                    report_lines.append(f"      Access: {details.get('access', 'N/A')}")
                
                # Show expected vs actual for storage rules
                if 'expected' in violation:
                    report_lines.append(f"   Expected: {violation.get('expected', 'N/A')}")
                    report_lines.append(f"   Actual: {violation.get('actual', 'N/A')}")
                
                report_lines.append("")
        
        # Summary recommendations
        report_lines.append("\n" + "=" * 80)
        report_lines.append("REMEDIATION RECOMMENDATIONS")
        report_lines.append("=" * 80)
        report_lines.append("")
        report_lines.append("1. CRITICAL violations should be remediated immediately")
        report_lines.append("2. HIGH violations should be addressed within 7 days")
        report_lines.append("3. MEDIUM violations should be addressed within 30 days")
        report_lines.append("4. Use Azure Policy or Terraform to enforce compliance automatically")
        report_lines.append("5. Schedule regular scans (daily/weekly) to catch new violations")
        report_lines.append("")
        
        # Join lines and save to file
        report_content = "\n".join(report_lines)
        
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(report_content)
            print(f"\n✓ Report saved to: {output_file.absolute()}")
        except IOError as e:
            print(f"\n✗ Failed to save report: {e}")
        
        return report_content


# WHY __main__ BLOCK:
# - Allows running scanner as standalone script for testing
# - Provides example usage for other developers
# - Enables quick manual testing without writing separate test scripts
if __name__ == "__main__":
    """
    Test the Azure scanner with credentials from environment variables.
    
    Required Environment Variables:
        AZURE_SUBSCRIPTION_ID: Azure subscription ID to scan
        AZURE_TENANT_ID: Azure AD tenant ID
        AZURE_CLIENT_ID: Service Principal application ID
        AZURE_CLIENT_SECRET: Service Principal secret
    
    WHY ENVIRONMENT VARIABLES:
    - Keeps secrets out of source code (security best practice)
    - Works with various secret management systems (Azure Key Vault, HashiCorp Vault)
    - Compatible with CI/CD pipelines (GitHub Actions, Azure DevOps)
    - Follows 12-factor app methodology for cloud-native applications
    
    Usage:
        # Set environment variables first
        export AZURE_SUBSCRIPTION_ID="your-sub-id"
        export AZURE_TENANT_ID="your-tenant-id"
        export AZURE_CLIENT_ID="your-client-id"
        export AZURE_CLIENT_SECRET="your-client-secret"
        
        # Run scanner
        python src/scanner.py
    """
    # Load credentials from environment
    subscription_id = os.getenv("AZURE_SUBSCRIPTION_ID")
    tenant_id = os.getenv("AZURE_TENANT_ID")
    client_id = os.getenv("AZURE_CLIENT_ID")
    client_secret = os.getenv("AZURE_CLIENT_SECRET")
    
    # Validate all required credentials are present
    missing_vars = []
    if not subscription_id:
        missing_vars.append("AZURE_SUBSCRIPTION_ID")
    if not tenant_id:
        missing_vars.append("AZURE_TENANT_ID")
    if not client_id:
        missing_vars.append("AZURE_CLIENT_ID")
    if not client_secret:
        missing_vars.append("AZURE_CLIENT_SECRET")
    
    if missing_vars:
        print("ERROR: Missing required environment variables:")
        for var in missing_vars:
            print(f"  - {var}")
        print("\nPlease set these variables before running the scanner.")
        print("Example:")
        print('  export AZURE_SUBSCRIPTION_ID="your-subscription-id"')
        sys.exit(1)
    
    try:
        # Initialize scanner
        print("Initializing Azure Scanner...")
        scanner = AzureScanner(
            subscription_id=subscription_id,
            tenant_id=tenant_id,
            client_id=client_id,
            client_secret=client_secret
        )
        
        # Run full compliance scan
        results = scanner.scan_all_resources()
        
        # Generate and save report
        report = scanner.generate_scan_report()
        
        # Print summary to console
        print("\n" + "=" * 80)
        print("SCAN SUMMARY")
        print("=" * 80)
        print(f"Total Violations: {results['total_violations']}")
        print(f"  CRITICAL: {results['violations_by_severity']['CRITICAL']}")
        print(f"  HIGH: {results['violations_by_severity']['HIGH']}")
        print(f"  MEDIUM: {results['violations_by_severity']['MEDIUM']}")
        print(f"  LOW: {results['violations_by_severity']['LOW']}")
        print("=" * 80)
        
        # Exit with error code if violations found (useful for CI/CD)
        # WHY: Allows pipeline to fail if compliance violations are detected
        if results['total_violations'] > 0:
            sys.exit(1)
        else:
            print("\n✓ No compliance violations found!")
            sys.exit(0)
            
    except FileNotFoundError as e:
        print(f"\nERROR: {e}")
        sys.exit(1)
    except AzureError as e:
        print(f"\nAzure API Error: {e}")
        print("\nPossible causes:")
        print("  - Invalid credentials")
        print("  - Insufficient permissions (Reader role required)")
        print("  - Network connectivity issues")
        print("  - Invalid subscription ID")
        sys.exit(1)
    except Exception as e:
        print(f"\nUnexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)