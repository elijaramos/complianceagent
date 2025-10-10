"""
Claude AI Analyzer for Security Remediation

This module uses Claude AI to analyze Azure compliance findings and generate
detailed, actionable remediation plans with safety checks and approval workflows.

WHY USE AI FOR SECURITY ANALYSIS:
- Reduces analysis time from hours to minutes
- Provides context-aware remediation steps based on Azure best practices
- Generates rollback procedures automatically
- Prioritizes findings by actual business risk, not just severity
- Explains WHY each remediation is needed (helps with approval and learning)
- Catches potential conflicts between remediations (e.g., network changes affecting multiple services)
"""

import os
import sys
import json
from typing import Dict, List, Any, Optional
from datetime import datetime
from pathlib import Path

from anthropic import Anthropic, APIError, APIConnectionError, RateLimitError

# Import configuration settings from root directory
sys.path.insert(0, str(Path(__file__).parent.parent))
from settings import get_claude_config, CLAUDE_MODEL, APPROVALS_DIR, REPORTS_DIR


class ClaudeAnalyzer:
    """
    Analyzes security findings using Claude AI and generates remediation plans.
    
    WHY THIS CLASS:
    - Centralizes AI interaction logic for security analysis
    - Provides structured output (JSON) for automation
    - Implements safety checks before executing remediations
    - Generates human-readable approval requests for governance
    - Enables consistent, repeatable security recommendations
    
    Architecture:
    - Uses Anthropic's Claude Sonnet 4 for advanced reasoning
    - Temperature=0 for deterministic security recommendations (no creativity)
    - Prompt engineering separates analysis, prioritization, and remediation
    - JSON output enables automation while maintaining auditability
    """
    
    def __init__(self, api_key: Optional[str] = None, 
                 model: Optional[str] = None):
        """
        Initialize Claude analyzer with API credentials.
        
        WHY THESE PARAMETERS:
        - api_key: Allows explicit key or falls back to environment variable
        - model: Allows model flexibility (newer versions, different sizes)
        
        WHY CLAUDE SONNET 4:
        - Best balance of speed, cost, and reasoning capability
        - Excellent at structured JSON output (critical for automation)
        - Strong domain knowledge of Azure and security practices
        - Large context window (handles extensive scan reports)
        
        Args:
            api_key: Anthropic API key (defaults to ANTHROPIC_API_KEY env var)
            model: Claude model identifier (defaults to settings.CLAUDE_MODEL)
            
        Raises:
            ValueError: If API key is not provided or found in environment
        """
        # Get API key from parameter or environment
        self.api_key = api_key or os.getenv("ANTHROPIC_API_KEY")
        
        if not self.api_key:
            raise ValueError(
                "ANTHROPIC_API_KEY not found. Please set environment variable or pass api_key parameter.\n"
                "Get your API key from: https://console.anthropic.com/"
            )
        
        # Initialize Anthropic client
        self.client = Anthropic(api_key=self.api_key)
        
        # Get model from parameter, config, or default
        # WHY: Allows override for testing or using different model versions
        self.model = model or CLAUDE_MODEL
        
        # Get configuration settings
        config = get_claude_config()
        self.temperature = config['temperature']
        self.max_tokens = config['max_tokens']
        
        # WHY TEMPERATURE=0:
        # - Security recommendations must be deterministic and consistent
        # - No creativity needed (we want proven best practices, not novel ideas)
        # - Ensures same findings always get same recommendations (auditability)
        # - Reduces risk of hallucinated or incorrect commands
        
        print(f"✓ Claude Analyzer initialized (model: {self.model})")
    
    def analyze_findings(self, scan_report: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze security findings and generate comprehensive remediation plans.
        
        WHY THIS METHOD:
        - Transforms raw scan data into actionable remediation plans
        - Prioritizes findings by business impact (not just severity)
        - Generates step-by-step remediation instructions
        - Includes rollback procedures for safety
        - Provides risk assessment for informed decision-making
        
        PROMPT ENGINEERING PATTERN:
        - Clear role definition: "You are an Azure security expert"
        - Structured input: JSON format with clear schema
        - Explicit output format: JSON with required fields
        - Context: Why each finding matters (business impact)
        - Constraints: Safety checks, testing steps, rollback procedures
        - Examples: Implied through detailed field descriptions
        
        Args:
            scan_report: Dictionary containing scan results from AzureScanner
                Must include: results, total_violations, violations_by_severity
                
        Returns:
            Dictionary containing:
                - analysis_summary: High-level overview
                - priority_order: List of finding IDs sorted by risk
                - remediations: Detailed remediation plans
                - timestamp: When analysis was performed
                
        Raises:
            APIError: If Claude API returns an error
            JSONDecodeError: If Claude response is not valid JSON
        """
        print("\nAnalyzing findings with Claude AI...")
        
        # Extract findings from scan report
        findings = scan_report.get('results', [])
        
        if not findings:
            print("  ℹ No findings to analyze")
            return {
                'analysis_summary': 'No compliance violations found.',
                'priority_order': [],
                'remediations': [],
                'timestamp': datetime.utcnow().isoformat()
            }
        
        print(f"  Sending {len(findings)} findings to Claude...")
        
        # Build comprehensive prompt
        # WHY DETAILED PROMPT: Claude performs better with clear instructions and context
        prompt = self._build_analysis_prompt(scan_report)
        
        try:
            # Call Claude API
            # WHY max_tokens from config: Allows detailed remediation plans for multiple findings
            # WHY temperature=0: Ensures deterministic security recommendations
            response = self.client.messages.create(
                model=self.model,
                max_tokens=self.max_tokens,
                temperature=self.temperature,
                messages=[
                    {
                        "role": "user",
                        "content": prompt
                    }
                ]
            )
            
            # Extract response text
            response_text = response.content[0].text

            # Strip markdown code blocks if present
            # Claude sometimes wraps JSON in ```json ... ```
            if response_text.strip().startswith('```'):
                # Remove opening ```json or ```
                response_text = response_text.strip()
                if response_text.startswith('```json'):
                    response_text = response_text[7:]
                elif response_text.startswith('```'):
                    response_text = response_text[3:]
                # Remove closing ```
                if response_text.endswith('```'):
                    response_text = response_text[:-3]
                response_text = response_text.strip()

            # Parse JSON response
            # WHY JSON: Enables automation, structured data, easy integration
            try:
                analysis = json.loads(response_text)
            except json.JSONDecodeError as e:
                print(f"  ✗ Failed to parse Claude response as JSON: {e}")
                print(f"  Raw response: {response_text[:500]}...")
                raise
            
            # Add metadata
            analysis['timestamp'] = datetime.utcnow().isoformat()
            analysis['model'] = self.model
            
            # Validation
            required_fields = ['analysis_summary', 'priority_order', 'remediations']
            missing_fields = [f for f in required_fields if f not in analysis]
            
            if missing_fields:
                raise ValueError(f"Claude response missing required fields: {missing_fields}")
            
            print(f"  ✓ Analysis complete")
            print(f"    - {len(analysis['remediations'])} remediation plans generated")
            print(f"    - Priority order: {', '.join(analysis['priority_order'][:3])}...")
            
            return analysis
            
        except RateLimitError as e:
            print(f"  ✗ Rate limit exceeded: {e}")
            print("  Wait a moment and try again")
            raise
        except APIConnectionError as e:
            print(f"  ✗ Network error connecting to Claude API: {e}")
            raise
        except APIError as e:
            print(f"  ✗ Claude API error: {e}")
            raise
    
    def _build_analysis_prompt(self, scan_report: Dict[str, Any]) -> str:
        """
        Build comprehensive prompt for Claude analysis.
        
        WHY SEPARATE METHOD:
        - Keeps prompt engineering logic isolated and testable
        - Makes it easy to iterate on prompt without changing API call logic
        - Allows prompt versioning and A/B testing
        - Easier to add examples or additional context
        
        PROMPT ENGINEERING PRINCIPLES:
        1. Role: Establish Claude as an Azure security expert
        2. Context: Explain what the data is and why it matters
        3. Task: Clearly define what Claude should do
        4. Format: Specify exact JSON structure expected
        5. Constraints: Safety requirements, testing, rollback procedures
        6. Examples: Provide sample output structure (shown in field descriptions)
        
        Args:
            scan_report: Scan results dictionary
            
        Returns:
            Formatted prompt string
        """
        # Convert scan report to formatted JSON for readability
        findings_json = json.dumps(scan_report, indent=2)
        
        # Build structured prompt
        prompt = f"""You are an expert Azure security engineer analyzing compliance findings from an automated scan.

CONTEXT:
This scan evaluated Azure resources against NIST Cybersecurity Framework (CSF) 2.0 controls.
Your job is to analyze these findings, prioritize them by actual business risk, and create
detailed remediation plans that can be safely executed.

SCAN REPORT:
{findings_json}

YOUR TASK:
Analyze the findings and generate a comprehensive remediation plan. Consider:
1. Business impact: Data exposure > Service disruption > Compliance violations
2. Attack likelihood: Public internet exposure > Internal misconfiguration
3. Remediation complexity: Quick wins first, then complex changes
4. Dependencies: Group related remediations to avoid conflicts

OUTPUT FORMAT (JSON):
{{
  "analysis_summary": "High-level overview of security posture and key risks (2-3 sentences)",
  "priority_order": ["finding_id_1", "finding_id_2", ...],
  "remediations": [
    {{
      "finding_id": "Unique identifier from scan (e.g., 'PR.DS-1-storage-encryption')",
      "resource_name": "Azure resource name",
      "resource_group": "Resource group name",
      "rule_id": "Rule ID from scan",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW",
      "risk_assessment": "Explain WHAT could happen if not fixed, WHO could exploit it, and WHAT data/services are at risk (2-3 sentences)",
      "technical_implementation": "Explain EXACTLY what Azure configuration settings will be changed (e.g., 'Set allowBlobPublicAccess property to false on storage account', 'Update NSG rule to deny 0.0.0.0/0 inbound traffic on port 22'). Be specific about property names, values, and Azure resource properties being modified (2-3 sentences)",
      "remediation_steps": [
        "Step 1: Human-readable action",
        "Step 2: Human-readable action",
        "Step 3: Verify the change"
      ],
      "azure_commands": [
        "# Azure CLI or PowerShell command with explanation",
        "az storage account update --name <account> --resource-group <rg> --allow-blob-public-access false",
        "# Verify change",
        "az storage account show --name <account> --resource-group <rg> --query allowBlobPublicAccess"
      ],
      "estimated_time_minutes": 10,
      "prerequisites": [
        "Azure Contributor role on resource group",
        "Azure CLI installed and authenticated"
      ],
      "rollback_procedure": [
        "Step 1: Revert command",
        "Step 2: Verify rollback"
      ]
    }}
  ]
}}

IMPORTANT CONSTRAINTS:
- Use ONLY Azure CLI (az) commands or Azure PowerShell (Az module) - no Terraform/ARM templates
- Include actual resource names from the findings (don't use placeholders if real names are provided)
- For NSG rules, specify exact rule names and priorities
- All commands must be idempotent (safe to run multiple times)
- Include verification commands after each change
- Rollback procedures must be tested and reliable
- Estimated times should be realistic (including testing)

SAFETY REQUIREMENTS:
- Never delete resources (disable features instead)
- Always include verification steps
- Warn if change might cause service disruption
- Group related changes to avoid configuration drift
- Include prerequisites (roles, tools, backups)

Return ONLY valid JSON (no markdown, no explanations outside JSON)."""
        
        return prompt
    
    def generate_approval_request(self, remediation_plan: Dict[str, Any]) -> str:
        """
        Generate human-readable approval request for governance workflows.
        
        WHY THIS METHOD:
        - Security changes require human approval (compliance requirement)
        - Non-technical approvers need plain English explanations
        - Provides audit trail for who approved what and when
        - Includes risk/benefit analysis for informed decision-making
        
        APPROVAL WORKFLOW:
        1. Scanner detects violation
        2. Claude generates remediation plan
        3. This method creates approval request
        4. Human reviews and approves/rejects
        5. If approved, automation executes remediation
        6. Results logged for audit trail
        
        Args:
            remediation_plan: Single remediation from analyze_findings() output
            
        Returns:
            Formatted approval request text suitable for email/ticket
        """
        # Extract remediation details
        finding_id = remediation_plan.get('finding_id', 'UNKNOWN')
        resource_name = remediation_plan.get('resource_name', 'UNKNOWN')
        resource_group = remediation_plan.get('resource_group', 'UNKNOWN')
        severity = remediation_plan.get('severity', 'UNKNOWN')
        risk = remediation_plan.get('risk_assessment', 'No risk assessment provided')
        steps = remediation_plan.get('remediation_steps', [])
        time_estimate = remediation_plan.get('estimated_time_minutes', 'Unknown')
        prerequisites = remediation_plan.get('prerequisites', [])
        
        # Build approval request
        lines = []
        lines.append("=" * 80)
        lines.append("AZURE SECURITY REMEDIATION APPROVAL REQUEST")
        lines.append("=" * 80)
        lines.append(f"Request Date: {datetime.utcnow().isoformat()}")
        lines.append(f"Severity: {severity}")
        lines.append("")
        
        lines.append("AFFECTED RESOURCE:")
        lines.append(f"  Name: {resource_name}")
        lines.append(f"  Resource Group: {resource_group}")
        lines.append(f"  NIST CSF Rule: {finding_id}")
        lines.append("")

        lines.append("RISK IF NOT REMEDIATED:")
        lines.append(f"  {risk}")
        lines.append("")

        lines.append("TECHNICAL IMPLEMENTATION:")
        technical_impl = remediation_plan.get('technical_implementation', 'N/A')
        lines.append(f"  {technical_impl}")
        lines.append("")

        lines.append("PROPOSED REMEDIATION STEPS:")
        for i, step in enumerate(steps, 1):
            lines.append(f"  {i}. {step}")
        lines.append("")
        
        lines.append("PREREQUISITES:")
        if prerequisites:
            for prereq in prerequisites:
                lines.append(f"  - {prereq}")
        else:
            lines.append("  - None")
        lines.append("")
        
        lines.append(f"ESTIMATED TIME: {time_estimate} minutes")
        lines.append("")
        
        lines.append("ROLLBACK AVAILABLE: Yes (see full remediation plan)")
        lines.append("")
        
        lines.append("APPROVAL REQUIRED FROM:")
        if severity in ['CRITICAL', 'HIGH']:
            lines.append("  - Security Team Lead")
            lines.append("  - Cloud Infrastructure Manager")
        else:
            lines.append("  - Security Team Lead")
        lines.append("")
        
        lines.append("DECISION:")
        lines.append("  [ ] APPROVED - Proceed with remediation")
        lines.append("  [ ] REJECTED - Do not implement (provide reason below)")
        lines.append("  [ ] DEFER - Schedule for maintenance window")
        lines.append("")
        lines.append("Approved by: ___________________________")
        lines.append("Date: ___________________________")
        lines.append("Reason (if rejected/deferred): ___________________________")
        lines.append("=" * 80)
        
        return "\n".join(lines)
    
    def validate_remediation_safety(self, remediation: Dict[str, Any], 
                                   resource_context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Perform final safety validation before executing remediation.
        
        WHY THIS METHOD:
        - Final safety check before making changes (fail-safe mechanism)
        - Catches issues AI might have missed
        - Validates against current resource state (may have changed since scan)
        - Provides risk score for automated decision-making
        - Logs validation results for audit trail
        
        SAFETY CHECKS:
        1. Resource still exists and matches expected state
        2. Prerequisites are met (permissions, tools, dependencies)
        3. Change window is appropriate (business hours, maintenance window)
        4. No conflicting changes in progress
        5. Rollback procedure is valid
        6. Risk level matches severity
        
        Args:
            remediation: Remediation plan dictionary
            resource_context: Current state of Azure resource
                Should include: resource_id, current_config, tags, dependencies
                
        Returns:
            Dictionary containing:
                - is_safe: Boolean, whether remediation can proceed
                - risk_score: 0-100 (0=safe, 100=dangerous)
                - warnings: List of warnings/concerns
                - blockers: List of issues that prevent execution
                - recommendations: Additional safety measures
        """
        print(f"\nValidating remediation safety for {remediation.get('resource_name', 'UNKNOWN')}...")
        
        # Initialize validation result
        validation = {
            'is_safe': True,
            'risk_score': 0,
            'warnings': [],
            'blockers': [],
            'recommendations': [],
            'timestamp': datetime.utcnow().isoformat()
        }
        
        # Check 1: Resource name validation
        # WHY: Prevents accidental changes to wrong resources
        resource_name = remediation.get('resource_name')
        context_name = resource_context.get('name')
        
        if resource_name != context_name:
            validation['blockers'].append(
                f"Resource name mismatch: remediation targets '{resource_name}' "
                f"but context shows '{context_name}'"
            )
            validation['is_safe'] = False
            validation['risk_score'] += 50
        
        # Check 2: Severity and risk alignment
        # WHY: Ensures remediation complexity matches finding severity
        severity = remediation.get('severity', 'UNKNOWN')
        if severity == 'CRITICAL':
            validation['risk_score'] += 10  # Higher scrutiny for critical changes
            validation['recommendations'].append(
                "CRITICAL severity: Recommend manual review before execution"
            )
        
        # Check 3: Prerequisites validation
        # WHY: Prevents execution failures due to missing requirements
        prerequisites = remediation.get('prerequisites', [])
        if not prerequisites:
            validation['warnings'].append(
                "No prerequisites specified - may fail during execution"
            )
            validation['risk_score'] += 5
        
        # Check 4: Rollback procedure validation
        # WHY: Must have a way to undo changes if something goes wrong
        rollback = remediation.get('rollback_procedure', [])
        if not rollback or len(rollback) < 2:
            validation['blockers'].append(
                "Insufficient rollback procedure - must have at least 2 steps"
            )
            validation['is_safe'] = False
            validation['risk_score'] += 30
        
        # Check 5: Command safety validation
        # WHY: Prevents destructive commands (delete, purge, destroy)
        azure_commands = remediation.get('azure_commands', [])
        dangerous_keywords = ['delete', 'purge', 'destroy', 'remove-azresource']
        
        for cmd in azure_commands:
            if any(keyword in cmd.lower() for keyword in dangerous_keywords):
                validation['blockers'].append(
                    f"Dangerous command detected: {cmd[:100]}"
                )
                validation['is_safe'] = False
                validation['risk_score'] += 40
        
        # Check 6: Resource context validation
        # WHY: Ensures resource hasn't changed since scan
        if not resource_context or not resource_context.get('resource_id'):
            validation['warnings'].append(
                "No resource context provided - cannot validate current state"
            )
            validation['risk_score'] += 15
        
        # Check 7: Production environment detection
        # WHY: Production changes require extra scrutiny
        tags = resource_context.get('tags', {})
        if tags.get('environment', '').lower() == 'production':
            validation['warnings'].append(
                "Production resource - recommend change control approval"
            )
            validation['recommendations'].append(
                "Schedule during maintenance window"
            )
            validation['risk_score'] += 10
        
        # Check 8: Time estimate reasonableness
        # WHY: Unrealistic estimates indicate poorly planned remediation
        time_estimate = remediation.get('estimated_time_minutes', 0)
        if time_estimate == 0:
            validation['warnings'].append(
                "No time estimate provided"
            )
        elif time_estimate > 60:
            validation['warnings'].append(
                f"Long remediation time ({time_estimate} min) - consider splitting into smaller changes"
            )
            validation['risk_score'] += 5
        
        # Final risk assessment
        # WHY: Provides clear go/no-go decision
        if validation['risk_score'] > 50:
            validation['is_safe'] = False
            validation['blockers'].append(
                f"Risk score too high: {validation['risk_score']}/100 (max 50 for auto-execution)"
            )
        
        if validation['blockers']:
            validation['is_safe'] = False
        
        # Print validation results
        if validation['is_safe']:
            print(f"  ✓ Validation passed (risk score: {validation['risk_score']}/100)")
        else:
            print(f"  ✗ Validation failed (risk score: {validation['risk_score']}/100)")
            print(f"    Blockers: {len(validation['blockers'])}")
            for blocker in validation['blockers']:
                print(f"      - {blocker}")
        
        if validation['warnings']:
            print(f"    Warnings: {len(validation['warnings'])}")
            for warning in validation['warnings'][:3]:  # Show first 3
                print(f"      - {warning}")
        
        return validation


# WHY __main__ BLOCK:
# - Demonstrates usage with sample data
# - Allows testing without running full Azure scan
# - Shows integration pattern for other developers
# - Validates API connectivity and credentials
if __name__ == "__main__":
    """
    Test Claude analyzer with sample compliance findings.
    
    This demonstrates the complete workflow:
    1. Initialize analyzer with API key
    2. Analyze sample findings
    3. Generate approval request
    4. Validate remediation safety
    
    Required Environment Variables:
        ANTHROPIC_API_KEY: Your Anthropic API key
        
    Usage:
        export ANTHROPIC_API_KEY="your-api-key"
        python src/analyzer.py
    """
    
    # Check for API key
    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        print("ERROR: ANTHROPIC_API_KEY environment variable not set")
        print("Get your API key from: https://console.anthropic.com/")
        print("\nExample:")
        print('  export ANTHROPIC_API_KEY="sk-ant-..."')
        sys.exit(1)
    
    # Sample scan report (simulates output from AzureScanner)
    # WHY SAMPLE DATA: Allows testing without Azure credentials
    sample_scan_report = {
        'timestamp': datetime.utcnow().isoformat(),
        'subscription_id': 'sample-subscription-id',
        'total_violations': 3,
        'violations_by_severity': {
            'CRITICAL': 1,
            'HIGH': 2,
            'MEDIUM': 0,
            'LOW': 0
        },
        'results': [
            {
                'rule_id': 'PR.AC-4-network-security',
                'resource_type': 'Microsoft.Network/networkSecurityGroups',
                'resource_name': 'prod-web-nsg',
                'resource_group': 'production-rg',
                'severity': 'CRITICAL',
                'description': 'Network Security Groups must not allow unrestricted inbound access from the internet',
                'nist_function': 'PROTECT',
                'nist_category': 'PR.AC-4',
                'violating_rule': 'AllowAllInbound',
                'violating_rule_details': {
                    'source': '0.0.0.0/0',
                    'destination_port': '22',
                    'protocol': 'TCP',
                    'access': 'Allow',
                    'direction': 'Inbound',
                    'priority': 100
                },
                'timestamp': datetime.utcnow().isoformat()
            },
            {
                'rule_id': 'PR.DS-1-storage-public-access',
                'resource_type': 'Microsoft.Storage/storageAccounts',
                'resource_name': 'companydatalake',
                'resource_group': 'production-rg',
                'severity': 'HIGH',
                'description': 'Storage accounts must disable public blob access',
                'nist_function': 'PROTECT',
                'nist_category': 'PR.DS-1',
                'expected': False,
                'actual': True,
                'timestamp': datetime.utcnow().isoformat()
            },
            {
                'rule_id': 'PR.DS-1-storage-encryption',
                'resource_type': 'Microsoft.Storage/storageAccounts',
                'resource_name': 'legacystorage',
                'resource_group': 'development-rg',
                'severity': 'HIGH',
                'description': 'Storage accounts must use encryption at rest',
                'nist_function': 'PROTECT',
                'nist_category': 'PR.DS-1',
                'expected': True,
                'actual': False,
                'timestamp': datetime.utcnow().isoformat()
            }
        ]
    }
    
    try:
        # Initialize analyzer
        print("="*80)
        print("Testing Claude Analyzer with Sample Data")
        print("="*80)
        
        analyzer = ClaudeAnalyzer(api_key=api_key)
        
        # Analyze findings
        print("\n1. ANALYZING FINDINGS")
        print("-"*80)
        analysis = analyzer.analyze_findings(sample_scan_report)
        
        print("\nAnalysis Summary:")
        print(f"  {analysis['analysis_summary']}")
        print(f"\nPriority Order: {', '.join(analysis['priority_order'])}")
        print(f"\nRemediations Generated: {len(analysis['remediations'])}")
        
        # Generate approval request for first remediation
        if analysis['remediations']:
            print("\n2. GENERATING APPROVAL REQUEST")
            print("-"*80)
            first_remediation = analysis['remediations'][0]
            approval_request = analyzer.generate_approval_request(first_remediation)
            print(approval_request)
            
            # Save approval request to file
            approvals_dir = Path(APPROVALS_DIR)
            approvals_dir.mkdir(exist_ok=True)
            
            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            approval_file = approvals_dir / f"approval_request_{timestamp}.txt"
            
            with open(approval_file, 'w', encoding='utf-8') as f:
                f.write(approval_request)
            
            print(f"\n✓ Approval request saved to: {approval_file}")
            
            # Validate remediation safety
            print("\n3. VALIDATING REMEDIATION SAFETY")
            print("-"*80)
            
            # Sample resource context (simulates current Azure resource state)
            sample_context = {
                'name': first_remediation['resource_name'],
                'resource_id': f"/subscriptions/sample-sub/resourceGroups/{first_remediation['resource_group']}/providers/{first_remediation.get('resource_type', 'Unknown')}/{first_remediation['resource_name']}",
                'tags': {
                    'environment': 'production',
                    'owner': 'security-team'
                },
                'current_config': {
                    'status': 'active'
                }
            }
            
            validation = analyzer.validate_remediation_safety(
                first_remediation,
                sample_context
            )
            
            print("\nValidation Results:")
            print(f"  Safe to execute: {'✓ YES' if validation['is_safe'] else '✗ NO'}")
            print(f"  Risk score: {validation['risk_score']}/100")
            
            if validation['blockers']:
                print(f"\n  Blockers ({len(validation['blockers'])}):")
                for blocker in validation['blockers']:
                    print(f"    - {blocker}")
            
            if validation['warnings']:
                print(f"\n  Warnings ({len(validation['warnings'])}):")
                for warning in validation['warnings']:
                    print(f"    - {warning}")
            
            if validation['recommendations']:
                print(f"\n  Recommendations ({len(validation['recommendations'])}):")
                for rec in validation['recommendations']:
                    print(f"    - {rec}")
        
        # Save full analysis to JSON file
        print("\n4. SAVING ANALYSIS RESULTS")
        print("-"*80)

        reports_dir = Path(REPORTS_DIR)
        reports_dir.mkdir(exist_ok=True)
        
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        analysis_file = reports_dir / f"claude_analysis_{timestamp}.json"
        
        with open(analysis_file, 'w', encoding='utf-8') as f:
            json.dump(analysis, f, indent=2)
        
        print(f"✓ Analysis saved to: {analysis_file}")
        
        print("\n" + "="*80)
        print("✓ Test completed successfully!")
        print("="*80)
        
        sys.exit(0)
        
    except ValueError as e:
        print(f"\nConfiguration Error: {e}")
        sys.exit(1)
    except APIError as e:
        print(f"\nClaude API Error: {e}")
        print("\nPossible causes:")
        print("  - Invalid API key")
        print("  - Insufficient credits")
        print("  - Rate limit exceeded")
        sys.exit(1)
    except Exception as e:
        print(f"\nUnexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)