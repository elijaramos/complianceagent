"""
Compliance Agent - Main Orchestrator

This module orchestrates the complete Azure compliance workflow: scanning resources,
analyzing findings with AI, requesting human approval, executing remediations, and
generating comprehensive reports.

WHY THIS EXISTS:
- Provides single entry point for complete compliance automation
- Implements human-in-the-loop approval for security changes
- Coordinates multiple systems (Azure SDK, Claude AI, file storage)
- Creates audit trail of all decisions and actions
- Enables repeatable, documented compliance processes
"""

import os
import sys
import json
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from pathlib import Path

from scanner import AzureScanner
from analyzer import ClaudeAnalyzer
from remediator import AzureRemediator

# Import configuration settings
sys.path.insert(0, str(Path(__file__).parent.parent))
from settings import APPROVALS_DIR, REPORTS_DIR, LOGS_DIR


class ComplianceAgent:
    """
    Orchestrates the complete Azure compliance workflow.
    
    WHY THIS CLASS:
    - Single responsibility: coordinate the compliance workflow
    - Maintains state across scan, analyze, remediate, verify cycle
    - Implements approval gates for governance
    - Creates comprehensive audit trail
    - Provides before/after comparison for measuring improvement
    
    Architecture Pattern: Orchestrator/Coordinator
    - Doesn't implement business logic (delegates to specialized classes)
    - Manages workflow state and transitions
    - Handles cross-cutting concerns (logging, reporting, approval)
    - Coordinates timing and sequencing of operations
    
    Workflow States:
    1. SCANNING - Discovering compliance violations
    2. ANALYZING - AI generating remediation plans
    3. PENDING_APPROVAL - Waiting for human decision
    4. EXECUTING - Running approved remediations
    5. VERIFYING - Confirming improvements
    6. COMPLETE - Final report generated
    """
    
    def __init__(self, azure_subscription_id: str, azure_tenant_id: str,
                 azure_client_id: str, azure_client_secret: str,
                 anthropic_api_key: str):
        """
        Initialize compliance agent with all required credentials.
        
        WHY CENTRALIZED INITIALIZATION:
        - Single point of credential management
        - Validates all prerequisites before starting workflow
        - Fails fast if any credential is missing
        - Simplifies error handling in main workflow
        
        Args:
            azure_subscription_id: Azure subscription to scan
            azure_tenant_id: Azure AD tenant ID
            azure_client_id: Service Principal application ID
            azure_client_secret: Service Principal secret
            anthropic_api_key: Claude API key
        """
        # Initialize components
        print("Initializing Compliance Agent...")
        print("="*80)
        
        # Azure Scanner - discovers compliance violations
        print("\n1. Initializing Azure Scanner...")
        self.scanner = AzureScanner(
            subscription_id=azure_subscription_id,
            tenant_id=azure_tenant_id,
            client_id=azure_client_id,
            client_secret=azure_client_secret
        )
        
        # Claude Analyzer - generates remediation plans
        print("\n2. Initializing Claude Analyzer...")
        self.analyzer = ClaudeAnalyzer(api_key=anthropic_api_key)
        
        # Azure Remediator - executes fixes
        print("\n3. Initializing Azure Remediator...")
        self.remediator = AzureRemediator(
            subscription_id=azure_subscription_id,
            tenant_id=azure_tenant_id,
            client_id=azure_client_id,
            client_secret=azure_client_secret
        )
        
        # Create output directories
        # WHY: Organized file storage for audit trail
        self.approvals_dir = Path(APPROVALS_DIR)
        self.reports_dir = Path(REPORTS_DIR)
        self.logs_dir = Path(LOGS_DIR)

        os.makedirs(self.approvals_dir, exist_ok=True)
        os.makedirs(self.reports_dir, exist_ok=True)
        os.makedirs(self.logs_dir, exist_ok=True)
        
        # Workflow state
        self.current_state = "INITIALIZED"
        self.workflow_id = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        
        print("\n" + "="*80)
        print("✓ Compliance Agent initialized successfully")
        print(f"  Workflow ID: {self.workflow_id}")
        print("="*80)
        
        # Log initialization
        self._log_event("INITIALIZED", {
            "workflow_id": self.workflow_id,
            "timestamp": datetime.utcnow().isoformat()
        })
    
    def run_full_cycle(self) -> Dict[str, Any]:
        """
        Execute complete compliance workflow from scan to final report.
        
        WHY THIS METHOD:
        - Single function call for complete automation
        - Implements human-in-the-loop approval pattern
        - Provides before/after comparison for measuring value
        - Creates comprehensive audit trail
        - Enables scheduling (cron, scheduled task, pipeline)
        
        WORKFLOW STEPS:
        1. SCAN - Discover compliance violations in Azure
        2. ANALYZE - Use Claude AI to generate remediation plans
        3. APPROVAL - Request human approval for changes
        4. EXECUTE - Run approved remediations
        5. VERIFY - Re-scan to measure improvement
        6. REPORT - Generate comprehensive final report
        
        Returns:
            Dictionary containing:
                - workflow_id: Unique identifier for this run
                - before_scan: Initial scan results
                - after_scan: Post-remediation scan results
                - analysis: Claude's remediation plans
                - execution_results: Results of each remediation
                - improvement_metrics: Before/after comparison
                - report_path: Location of final report
                
        WHY RETURN FULL STATE:
        - Enables programmatic processing of results
        - Supports integration with other systems
        - Facilitates testing and validation
        - Provides data for trending and analytics
        """
        print("\n" + "="*80)
        print("STARTING COMPLIANCE WORKFLOW")
        print("="*80)
        print(f"Workflow ID: {self.workflow_id}")
        print(f"Start Time: {datetime.utcnow().isoformat()}")
        print("="*80 + "\n")
        
        workflow_result = {
            'workflow_id': self.workflow_id,
            'start_time': datetime.utcnow().isoformat(),
            'status': 'IN_PROGRESS'
        }
        
        try:
            # STEP 1: Scan Azure environment for violations
            # WHY FIRST: Need to know what's broken before we can fix it
            print("\n" + "🔍 " + "="*76)
            print("STEP 1: SCANNING AZURE ENVIRONMENT")
            print("="*80)
            self.current_state = "SCANNING"
            self._log_event("SCAN_STARTED", {})
            
            before_scan = self.scanner.scan_all_resources()
            workflow_result['before_scan'] = before_scan
            
            self._log_event("SCAN_COMPLETED", {
                'total_violations': before_scan['total_violations'],
                'by_severity': before_scan['violations_by_severity']
            })
            
            # Early exit if no violations
            if before_scan['total_violations'] == 0:
                print("\n✓ No compliance violations found!")
                workflow_result['status'] = 'COMPLETE_NO_VIOLATIONS'
                workflow_result['end_time'] = datetime.utcnow().isoformat()
                
                # Generate report even with no violations (proves compliance)
                report_path = self._generate_final_report(before_scan, None, None)
                workflow_result['report_path'] = str(report_path)
                
                return workflow_result
            
            # STEP 2: Analyze findings with Claude AI
            # WHY: AI generates detailed remediation plans with context
            print("\n" + "🤖 " + "="*76)
            print("STEP 2: ANALYZING FINDINGS WITH CLAUDE AI")
            print("="*80)
            self.current_state = "ANALYZING"
            self._log_event("ANALYSIS_STARTED", {})
            
            analysis = self.analyzer.analyze_findings(before_scan)
            workflow_result['analysis'] = analysis
            
            self._log_event("ANALYSIS_COMPLETED", {
                'remediations_generated': len(analysis['remediations']),
                'priority_order': analysis['priority_order']
            })
            
            # STEP 3: Request human approval
            # WHY: Security changes require human oversight (governance)
            print("\n" + "👤 " + "="*76)
            print("STEP 3: REQUESTING HUMAN APPROVAL")
            print("="*80)
            self.current_state = "PENDING_APPROVAL"
            self._log_event("APPROVAL_REQUESTED", {})
            
            approved_remediations = self._request_approval(analysis)
            
            if not approved_remediations:
                print("\n⚠ No remediations approved - workflow cancelled")
                workflow_result['status'] = 'CANCELLED_BY_USER'
                workflow_result['end_time'] = datetime.utcnow().isoformat()
                
                self._log_event("WORKFLOW_CANCELLED", {
                    'reason': 'No remediations approved'
                })
                
                return workflow_result
            
            workflow_result['approved_remediations'] = len(approved_remediations)
            
            self._log_event("APPROVAL_GRANTED", {
                'approved_count': len(approved_remediations)
            })
            
            # STEP 4: Execute approved remediations
            # WHY: Actually fix the compliance violations
            print("\n" + "⚙️ " + "="*76)
            print("STEP 4: EXECUTING REMEDIATIONS")
            print("="*80)
            self.current_state = "EXECUTING"
            self._log_event("EXECUTION_STARTED", {})
            
            execution_results = self._execute_remediations(
                approved_remediations, 
                before_scan
            )
            workflow_result['execution_results'] = execution_results
            
            # Count successes and failures
            successes = sum(1 for r in execution_results if r['success'])
            failures = len(execution_results) - successes
            
            print(f"\n✓ Execution complete: {successes} succeeded, {failures} failed")
            
            self._log_event("EXECUTION_COMPLETED", {
                'total': len(execution_results),
                'successes': successes,
                'failures': failures
            })
            
            # STEP 5: Verify compliance improved
            # WHY: Measure effectiveness of remediations (before/after)
            print("\n" + "🔍 " + "="*76)
            print("STEP 5: VERIFYING COMPLIANCE IMPROVEMENT")
            print("="*80)
            self.current_state = "VERIFYING"
            self._log_event("VERIFICATION_STARTED", {})
            
            # Re-scan environment to see improvements
            after_scan = self.scanner.scan_all_resources()
            workflow_result['after_scan'] = after_scan
            
            # Display before/after comparison
            self._display_before_after(before_scan, after_scan)
            
            self._log_event("VERIFICATION_COMPLETED", {
                'before_violations': before_scan['total_violations'],
                'after_violations': after_scan['total_violations'],
                'violations_fixed': before_scan['total_violations'] - after_scan['total_violations']
            })
            
            # STEP 6: Generate final report
            # WHY: Creates audit trail and documentation
            print("\n" + "📄 " + "="*76)
            print("STEP 6: GENERATING FINAL REPORT")
            print("="*80)
            self.current_state = "REPORTING"
            
            report_path = self._generate_final_report(
                before_scan, 
                after_scan, 
                execution_results
            )
            workflow_result['report_path'] = str(report_path)
            
            # Workflow complete
            workflow_result['status'] = 'COMPLETE'
            workflow_result['end_time'] = datetime.utcnow().isoformat()
            
            self._log_event("WORKFLOW_COMPLETED", {
                'status': 'SUCCESS',
                'violations_fixed': before_scan['total_violations'] - after_scan['total_violations']
            })
            
            print("\n" + "="*80)
            print("✓ COMPLIANCE WORKFLOW COMPLETED SUCCESSFULLY")
            print("="*80)
            print(f"Workflow ID: {self.workflow_id}")
            print(f"Duration: {self._calculate_duration(workflow_result)}")
            print(f"Violations Fixed: {before_scan['total_violations'] - after_scan['total_violations']}")
            print(f"Report: {report_path}")
            print("="*80 + "\n")
            
            return workflow_result
            
        except KeyboardInterrupt:
            print("\n\n⚠ Workflow interrupted by user")
            workflow_result['status'] = 'INTERRUPTED'
            workflow_result['end_time'] = datetime.utcnow().isoformat()
            self._log_event("WORKFLOW_INTERRUPTED", {})
            return workflow_result
            
        except Exception as e:
            print(f"\n\n✗ Workflow failed with error: {str(e)}")
            workflow_result['status'] = 'FAILED'
            workflow_result['error'] = str(e)
            workflow_result['end_time'] = datetime.utcnow().isoformat()
            
            self._log_event("WORKFLOW_FAILED", {
                'error': str(e),
                'state': self.current_state
            })
            
            import traceback
            traceback.print_exc()
            
            return workflow_result
    
    def _request_approval(self, analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Request human approval for remediations via CLI interface.
        
        WHY THIS METHOD:
        - Implements human-in-the-loop pattern for governance
        - Allows review of AI recommendations before execution
        - Creates approval audit trail
        - Enables selective remediation (approve critical, defer others)
        
        APPROVAL OPTIONS:
        1. Approve all - Execute all remediations
        2. Select specific - Choose which remediations to execute
        3. Reject all - Cancel workflow
        
        Args:
            analysis: Claude analysis output with remediations
            
        Returns:
            List of approved remediation dictionaries
        """
        remediations = analysis.get('remediations', [])
        
        if not remediations:
            print("  No remediations to approve")
            return []
        
        print(f"\n{len(remediations)} remediation(s) proposed by Claude AI")
        print("\nSummary:")
        print(f"  {analysis.get('analysis_summary', 'N/A')}")
        print(f"\nPriority Order: {', '.join(analysis['priority_order'][:5])}")
        
        # Display each remediation for review
        print("\n" + "-"*80)
        print("REMEDIATION PLANS")
        print("-"*80)
        
        for i, remediation in enumerate(remediations, 1):
            print(f"\n{i}. {remediation.get('resource_name', 'Unknown')} "
                  f"({remediation.get('severity', 'N/A')})")
            print(f"   NIST CSF Rule: {remediation.get('rule_id', 'N/A')}")
            print(f"   Risk: {remediation.get('risk_assessment', 'N/A')[:100]}...")
            print(f"   Implementation: {remediation.get('technical_implementation', 'N/A')[:100]}...")
            print(f"   Time: ~{remediation.get('estimated_time_minutes', '?')} minutes")
            
            # Save individual approval request to file
            # WHY: Creates audit trail, can be forwarded to approvers
            approval_file = self.approvals_dir / f"{self.workflow_id}_remediation_{i}.txt"
            approval_text = self.analyzer.generate_approval_request(remediation)
            
            with open(approval_file, 'w', encoding='utf-8') as f:
                f.write(approval_text)
            
            print(f"   Approval request: {approval_file}")
        
        # Prompt for approval decision
        print("\n" + "="*80)
        print("APPROVAL DECISION")
        print("="*80)
        print("\nOptions:")
        print("  1. Approve all remediations")
        print("  2. Select specific remediations")
        print("  3. Reject all (cancel workflow)")
        print()
        
        while True:
            choice = input("Enter choice (1-3): ").strip()
            
            if choice == '1':
                # Approve all
                print(f"\n✓ Approved all {len(remediations)} remediations")
                self._log_event("APPROVAL_ALL", {
                    'count': len(remediations)
                })
                return remediations
            
            elif choice == '2':
                # Select specific remediations
                print("\nEnter remediation numbers to approve (comma-separated, e.g., 1,3,5):")
                selection = input("Numbers: ").strip()
                
                try:
                    # Parse selection
                    selected_indices = [int(x.strip()) - 1 for x in selection.split(',')]
                    selected_remediations = [
                        remediations[i] for i in selected_indices 
                        if 0 <= i < len(remediations)
                    ]
                    
                    if selected_remediations:
                        print(f"\n✓ Approved {len(selected_remediations)} remediation(s)")
                        self._log_event("APPROVAL_SELECTIVE", {
                            'count': len(selected_remediations),
                            'indices': selected_indices
                        })
                        return selected_remediations
                    else:
                        print("  ✗ Invalid selection, try again")
                        
                except (ValueError, IndexError) as e:
                    print(f"  ✗ Invalid input: {e}, try again")
            
            elif choice == '3':
                # Reject all
                print("\n✗ All remediations rejected")
                self._log_event("APPROVAL_REJECTED", {})
                return []
            
            else:
                print("  ✗ Invalid choice, please enter 1, 2, or 3")
    
    def _execute_remediations(self, remediations: List[Dict[str, Any]], 
                            scan_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Execute approved remediations in priority order.
        
        WHY THIS METHOD:
        - Implements the actual compliance fixes
        - Handles errors gracefully (continue on failure)
        - Creates rollback snapshots for safety
        - Validates each remediation before execution
        - Logs all actions for audit trail
        
        EXECUTION PATTERN:
        1. Get resource context from scan data
        2. Validate remediation safety
        3. Create rollback snapshot
        4. Execute remediation via SDK
        5. Log result (success/failure)
        6. Continue to next remediation
        
        Args:
            remediations: List of approved remediation plans
            scan_data: Original scan data for resource context
            
        Returns:
            List of execution result dictionaries
        """
        results = []
        
        print(f"\nExecuting {len(remediations)} remediation(s)...")
        print("-"*80)
        
        for i, remediation in enumerate(remediations, 1):
            print(f"\n[{i}/{len(remediations)}] Processing: {remediation.get('resource_name', 'Unknown')}")
            
            result = {
                'remediation_index': i,
                'finding_id': remediation.get('finding_id'),
                'rule_id': remediation.get('rule_id'),
                'resource_name': remediation.get('resource_name'),
                'resource_group': remediation.get('resource_group'),
                'severity': remediation.get('severity'),
                'timestamp': datetime.utcnow().isoformat(),
                'success': False,
                'message': '',
                'rollback_snapshot': None
            }
            
            try:
                # Get resource context from scan data
                resource_context = self._get_resource_context(
                    remediation.get('finding_id'),
                    scan_data
                )
                
                # Validate remediation safety
                print("  Validating safety...")
                validation = self.analyzer.validate_remediation_safety(
                    remediation,
                    resource_context
                )
                
                if not validation['is_safe']:
                    result['message'] = f"Safety validation failed: {', '.join(validation['blockers'])}"
                    result['validation'] = validation
                    print(f"  ✗ {result['message']}")
                    results.append(result)
                    self._log_event("REMEDIATION_BLOCKED", result)
                    continue
                
                # Create rollback snapshot
                print("  Creating rollback snapshot...")
                snapshot = self.remediator.create_rollback_snapshot({
                    'resource_name': remediation.get('resource_name'),
                    'resource_group': remediation.get('resource_group'),
                    'resource_type': resource_context.get('resource_type')
                })
                result['rollback_snapshot'] = snapshot.get('snapshot_file')
                
                # Execute remediation using SDK
                print("  Executing remediation via Azure SDK...")
                success, message = self.remediator.execute_remediation(
                    remediation.get('rule_id'),
                    {
                        'resource_name': remediation.get('resource_name'),
                        'resource_group': remediation.get('resource_group'),
                        'resource_type': resource_context.get('resource_type'),
                        'violating_rule_details': remediation.get('violating_rule_details')
                    }
                )
                
                result['success'] = success
                result['message'] = message
                
                if success:
                    print(f"  ✓ Success: {message}")
                    self._log_event("REMEDIATION_SUCCESS", result)
                else:
                    print(f"  ✗ Failed: {message}")
                    self._log_event("REMEDIATION_FAILED", result)
                
            except Exception as e:
                result['message'] = f"Unexpected error: {str(e)}"
                print(f"  ✗ {result['message']}")
                self._log_event("REMEDIATION_ERROR", result)
            
            results.append(result)
            print("-"*80)
        
        return results
    
    def _get_resource_context(self, finding_id: str, 
                            scan_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract resource context from scan data for a specific finding.
        
        WHY THIS METHOD:
        - Remediations need current resource state
        - Validates resource still exists
        - Provides tags, dependencies, configuration
        - Enables safety validation
        
        Args:
            finding_id: Finding identifier to look up
            scan_data: Original scan results
            
        Returns:
            Dictionary with resource context (name, type, tags, etc.)
        """
        # Find the specific finding in scan results
        findings = scan_data.get('results', [])
        
        for finding in findings:
            if finding.get('rule_id') == finding_id:
                return {
                    'name': finding.get('resource_name'),
                    'resource_id': f"/subscriptions/{scan_data.get('subscription_id')}/resourceGroups/{finding.get('resource_group')}/providers/{finding.get('resource_type')}/{finding.get('resource_name')}",
                    'resource_type': finding.get('resource_type'),
                    'resource_group': finding.get('resource_group'),
                    'tags': {},  # Would fetch from Azure in production
                    'current_config': finding  # Use finding data as current state
                }
        
        # Default context if not found
        return {
            'name': 'unknown',
            'resource_id': 'unknown',
            'resource_type': 'unknown',
            'resource_group': 'unknown',
            'tags': {},
            'current_config': {}
        }
    
    def _display_before_after(self, before: Dict[str, Any], 
                             after: Dict[str, Any]) -> None:
        """
        Display before/after compliance metrics to show improvement.
        
        WHY THIS METHOD:
        - Demonstrates value of remediation efforts
        - Provides immediate feedback on effectiveness
        - Helps prioritize future efforts
        - Creates visual representation of improvement
        
        Args:
            before: Scan results before remediation
            after: Scan results after remediation
        """
        print("\n" + "="*80)
        print("COMPLIANCE IMPROVEMENT")
        print("="*80)
        
        before_total = before['total_violations']
        after_total = after['total_violations']
        fixed = before_total - after_total
        
        # Overall metrics
        print(f"\nTotal Violations:")
        print(f"  Before:  {before_total}")
        print(f"  After:   {after_total}")
        print(f"  Fixed:   {fixed} ({self._calculate_percentage(fixed, before_total):.1f}%)")
        
        # By severity
        print(f"\nBy Severity:")
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            before_count = before['violations_by_severity'].get(severity, 0)
            after_count = after['violations_by_severity'].get(severity, 0)
            fixed_count = before_count - after_count
            
            if before_count > 0:
                symbol = "✓" if fixed_count > 0 else "○"
                print(f"  {symbol} {severity:8s}: {before_count} → {after_count} "
                      f"(fixed {fixed_count})")
        
        # Compliance score
        # WHY: Single number for executives and dashboards
        before_score = self._calculate_compliance_score(before)
        after_score = self._calculate_compliance_score(after)
        improvement = after_score - before_score
        
        print(f"\nCompliance Score (0-100):")
        print(f"  Before:      {before_score:.1f}")
        print(f"  After:       {after_score:.1f}")
        print(f"  Improvement: +{improvement:.1f}")
        
        print("="*80)
    
    def _generate_final_report(self, before: Dict[str, Any], 
                              after: Optional[Dict[str, Any]],
                              execution: Optional[List[Dict[str, Any]]]) -> Path:
        """
        Generate comprehensive final report with all workflow details.
        
        WHY THIS METHOD:
        - Creates audit trail for compliance frameworks
        - Documents decisions and actions taken
        - Provides evidence for auditors and management
        - Enables trending and analysis over time
        - Can be attached to change management tickets
        
        REPORT CONTENTS:
        - Executive summary
        - Before/after metrics
        - Remediation actions taken
        - Success/failure details
        - Recommendations for future cycles
        
        Args:
            before: Initial scan results
            after: Post-remediation scan results (None if no remediations)
            execution: Execution results (None if no remediations)
            
        Returns:
            Path to generated report file
        """
        print("\nGenerating comprehensive report...")
        
        lines = []
        
        # Header
        lines.append("="*80)
        lines.append("AZURE COMPLIANCE WORKFLOW REPORT")
        lines.append("="*80)
        lines.append(f"Workflow ID: {self.workflow_id}")
        lines.append(f"Generated: {datetime.utcnow().isoformat()}")
        lines.append(f"Subscription: {before.get('subscription_id', 'Unknown')}")
        lines.append("="*80)
        lines.append("")
        
        # Executive Summary
        lines.append("\nEXECUTIVE SUMMARY")
        lines.append("-"*80)
        
        if after:
            fixed = before['total_violations'] - after['total_violations']
            lines.append(f"Initial Violations: {before['total_violations']}")
            lines.append(f"Remaining Violations: {after['total_violations']}")
            lines.append(f"Violations Fixed: {fixed}")
            lines.append(f"Success Rate: {self._calculate_percentage(fixed, before['total_violations']):.1f}%")
        else:
            lines.append(f"Initial Violations: {before['total_violations']}")
            lines.append(f"Status: No remediations executed")
        
        lines.append("")
        
        # Before Scan Results
        lines.append("\n" + "="*80)
        lines.append("INITIAL SCAN RESULTS")
        lines.append("="*80)
        lines.append(f"Timestamp: {before.get('timestamp', 'Unknown')}")
        lines.append(f"Total Violations: {before['total_violations']}")
        lines.append("\nBy Severity:")
        for severity, count in before['violations_by_severity'].items():
            if count > 0:
                lines.append(f"  {severity}: {count}")
        
        # Detailed findings
        lines.append("\nDetailed Findings:")
        for i, finding in enumerate(before.get('results', []), 1):
            lines.append(f"\n{i}. {finding.get('description', 'N/A')}")
            lines.append(f"   Resource: {finding.get('resource_name', 'N/A')}")
            lines.append(f"   Resource Group: {finding.get('resource_group', 'N/A')}")
            lines.append(f"   Severity: {finding.get('severity', 'N/A')}")
            lines.append(f"   Rule ID: {finding.get('rule_id', 'N/A')}")
        
        # Remediation Actions (if any)
        if execution:
            lines.append("\n" + "="*80)
            lines.append("REMEDIATION ACTIONS")
            lines.append("="*80)
            
            successes = [r for r in execution if r['success']]
            failures = [r for r in execution if not r['success']]
            
            lines.append(f"Total Attempted: {len(execution)}")
            lines.append(f"Successful: {len(successes)}")
            lines.append(f"Failed: {len(failures)}")
            lines.append("")
            
            # Successful remediations
            if successes:
                lines.append("\nSuccessful Remediations:")
                for i, result in enumerate(successes, 1):
                    lines.append(f"\n{i}. {result['resource_name']} ({result['severity']})")
                    lines.append(f"   NIST CSF Rule: {result['rule_id']}")
                    lines.append(f"   Result: {result['message']}")
                    if result.get('rollback_snapshot'):
                        lines.append(f"   Rollback: {result['rollback_snapshot']}")

            # Failed remediations
            if failures:
                lines.append("\nFailed Remediations:")
                for i, result in enumerate(failures, 1):
                    lines.append(f"\n{i}. {result['resource_name']} ({result['severity']})")
                    lines.append(f"   NIST CSF Rule: {result['rule_id']}")
                    lines.append(f"   Error: {result['message']}")
        
        # After Scan Results (if available)
        if after:
            lines.append("\n" + "="*80)
            lines.append("POST-REMEDIATION SCAN RESULTS")
            lines.append("="*80)
            lines.append(f"Timestamp: {after.get('timestamp', 'Unknown')}")
            lines.append(f"Total Violations: {after['total_violations']}")
            lines.append("\nBy Severity:")
            for severity, count in after['violations_by_severity'].items():
                if count > 0:
                    lines.append(f"  {severity}: {count}")
            
            # Remaining violations
            if after['total_violations'] > 0:
                lines.append("\nRemaining Violations:")
                for i, finding in enumerate(after.get('results', []), 1):
                    lines.append(f"\n{i}. {finding.get('description', 'N/A')}")
                    lines.append(f"   Resource: {finding.get('resource_name', 'N/A')}")
                    lines.append(f"   Severity: {finding.get('severity', 'N/A')}")
        
        # Recommendations
        lines.append("\n" + "="*80)
        lines.append("RECOMMENDATIONS")
        lines.append("="*80)
        
        if after and after['total_violations'] > 0:
            lines.append("\n1. Schedule another remediation cycle for remaining violations")
            lines.append("2. Review failed remediations and address blockers")
            lines.append("3. Consider Azure Policy to prevent future violations")
        else:
            lines.append("\n1. Monitor environment continuously for new violations")
            lines.append("2. Implement Azure Policy for automated enforcement")
            lines.append("3. Schedule regular compliance scans (weekly recommended)")
        
        lines.append("4. Review and update NIST CSF rules as requirements evolve")
        lines.append("5. Integrate with change management process")
        lines.append("")
        
        # Save report
        report_content = "\n".join(lines)
        report_file = self.reports_dir / f"compliance_report_{self.workflow_id}.txt"
        
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(report_content)
        
        print(f"✓ Report saved to: {report_file}")
        
        return report_file
    
    def _log_event(self, event_type: str, data: Dict[str, Any]) -> None:
        """
        Log workflow event to audit trail.
        
        WHY THIS METHOD:
        - Creates detailed audit trail of all actions
        - Enables forensic analysis if issues occur
        - Required for compliance frameworks (SOX, HIPAA, etc.)
        - Facilitates troubleshooting and debugging
        - Provides data for process improvement
        
        LOG FORMAT:
        - Timestamp (ISO 8601)
        - Event type (SCAN_STARTED, REMEDIATION_SUCCESS, etc.)
        - Workflow ID (links events together)
        - Event-specific data
        
        Args:
            event_type: Type of event (e.g., 'SCAN_STARTED')
            data: Event-specific data dictionary
        """
        log_entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'workflow_id': self.workflow_id,
            'event_type': event_type,
            'state': self.current_state,
            'data': data
        }
        
        # Append to workflow log file
        log_file = self.logs_dir / f"workflow_{self.workflow_id}.jsonl"
        
        try:
            with open(log_file, 'a', encoding='utf-8') as f:
                f.write(json.dumps(log_entry) + '\n')
        except IOError as e:
            print(f"⚠ Failed to write log entry: {e}")
    
    def _calculate_percentage(self, value: int, total: int) -> float:
        """Calculate percentage with division-by-zero handling."""
        if total == 0:
            return 0.0
        return (value / total) * 100
    
    def _calculate_compliance_score(self, scan_results: Dict[str, Any]) -> float:
        """
        Calculate compliance score (0-100) based on violations and severity.
        
        WHY: Single metric for executives and dashboards
        
        Formula: 100 - (weighted violations / max possible violations * 100)
        Weights: CRITICAL=10, HIGH=5, MEDIUM=2, LOW=1
        """
        severity_weights = {
            'CRITICAL': 10,
            'HIGH': 5,
            'MEDIUM': 2,
            'LOW': 1
        }
        
        weighted_violations = sum(
            count * severity_weights.get(severity, 1)
            for severity, count in scan_results['violations_by_severity'].items()
        )
        
        # Assume max 50 violations for scoring (adjust based on environment)
        max_weighted = 50 * severity_weights['CRITICAL']
        
        if weighted_violations >= max_weighted:
            return 0.0
        
        return 100 - (weighted_violations / max_weighted * 100)
    
    def _calculate_duration(self, workflow_result: Dict[str, Any]) -> str:
        """Calculate human-readable workflow duration."""
        try:
            start = datetime.fromisoformat(workflow_result['start_time'])
            end = datetime.fromisoformat(workflow_result.get('end_time', datetime.utcnow().isoformat()))
            duration = end - start
            
            minutes = int(duration.total_seconds() / 60)
            seconds = int(duration.total_seconds() % 60)
            
            return f"{minutes}m {seconds}s"
        except:
            return "Unknown"


# WHY __main__ BLOCK:
# - Provides single-command execution of complete workflow
# - Validates all prerequisites before starting
# - Demonstrates usage pattern for automation
# - Enables scheduling (cron, Task Scheduler, pipeline)
if __name__ == "__main__":
    """
    Execute complete Azure compliance workflow.
    
    This is the main entry point for the compliance agent. It orchestrates
    the entire workflow: scan, analyze, approve, remediate, verify, report.
    
    Required Environment Variables:
        AZURE_SUBSCRIPTION_ID: Azure subscription to scan
        AZURE_TENANT_ID: Azure AD tenant ID
        AZURE_CLIENT_ID: Service Principal application ID
        AZURE_CLIENT_SECRET: Service Principal secret
        ANTHROPIC_API_KEY: Claude API key for analysis
        
    Usage:
        # Set environment variables
        export AZURE_SUBSCRIPTION_ID="your-subscription-id"
        export AZURE_TENANT_ID="your-tenant-id"
        export AZURE_CLIENT_ID="your-client-id"
        export AZURE_CLIENT_SECRET="your-client-secret"
        export ANTHROPIC_API_KEY="sk-ant-..."
        
        # Run complete workflow
        python src/agent.py
        
    Integration:
        # Schedule with cron (Linux/Mac)
        0 2 * * * cd /path/to/project && python src/agent.py
        
        # Schedule with Task Scheduler (Windows)
        schtasks /create /tn "ComplianceScan" /tr "python src/agent.py" /sc daily /st 02:00
        
        # Run in CI/CD pipeline (GitHub Actions, Azure DevOps)
        - name: Compliance Scan
          run: python src/agent.py
          env:
            AZURE_SUBSCRIPTION_ID: ${{ secrets.AZURE_SUBSCRIPTION_ID }}
            ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
    """
    
    print("="*80)
    print("AZURE COMPLIANCE AGENT")
    print("="*80)
    print("Automated compliance scanning, analysis, and remediation")
    print("Powered by Azure SDK and Claude AI")
    print("="*80 + "\n")
    
    # Load credentials from environment
    azure_subscription_id = os.getenv("AZURE_SUBSCRIPTION_ID")
    azure_tenant_id = os.getenv("AZURE_TENANT_ID")
    azure_client_id = os.getenv("AZURE_CLIENT_ID")
    azure_client_secret = os.getenv("AZURE_CLIENT_SECRET")
    anthropic_api_key = os.getenv("ANTHROPIC_API_KEY")
    
    # Validate all required credentials
    missing_vars = []
    if not azure_subscription_id:
        missing_vars.append("AZURE_SUBSCRIPTION_ID")
    if not azure_tenant_id:
        missing_vars.append("AZURE_TENANT_ID")
    if not azure_client_id:
        missing_vars.append("AZURE_CLIENT_ID")
    if not azure_client_secret:
        missing_vars.append("AZURE_CLIENT_SECRET")
    if not anthropic_api_key:
        missing_vars.append("ANTHROPIC_API_KEY")
    
    if missing_vars:
        print("ERROR: Missing required environment variables:")
        for var in missing_vars:
            print(f"  - {var}")
        print("\nPlease set these variables before running the agent.")
        print("\nExample:")
        print('  export AZURE_SUBSCRIPTION_ID="your-subscription-id"')
        print('  export ANTHROPIC_API_KEY="sk-ant-..."')
        sys.exit(1)
    
    try:
        # Initialize compliance agent
        agent = ComplianceAgent(
            azure_subscription_id=azure_subscription_id,
            azure_tenant_id=azure_tenant_id,
            azure_client_id=azure_client_id,
            azure_client_secret=azure_client_secret,
            anthropic_api_key=anthropic_api_key
        )
        
        # Run complete workflow
        result = agent.run_full_cycle()
        
        # Exit with appropriate code
        if result['status'] == 'COMPLETE':
            sys.exit(0)
        elif result['status'] == 'COMPLETE_NO_VIOLATIONS':
            sys.exit(0)
        else:
            sys.exit(1)
            
    except KeyboardInterrupt:
        print("\n\nWorkflow interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"\n\nFatal error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)