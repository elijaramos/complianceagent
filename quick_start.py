"""
Quick Start CLI - Azure Compliance Agent

User-friendly command-line interface for Azure compliance scanning and remediation.
Provides menu-driven access to all agent features with prerequisite checks and
helpful guidance.

WHY THIS EXISTS:
- Simplifies onboarding for new users
- Provides guided workflow for common tasks
- Tests connectivity before full workflows
- Shows recent results without re-scanning
- Reduces complexity of command-line arguments
"""

import sys
import os
from pathlib import Path
from datetime import datetime
from dotenv import load_dotenv

# Load environment variables from .env file
# WHY: Reads .env and sets environment variables
load_dotenv()

# Add src directory to Python path
# WHY: Allows importing modules from src/ without package installation
sys.path.insert(0, str(Path(__file__).parent / 'src'))

from agent import ComplianceAgent
from scanner import AzureScanner
from analyzer import ClaudeAnalyzer

# Import settings from root-level settings.py
from settings import (
    CLAUDE_MODEL,
    APPLICATION_VERSION,
    APPLICATION_NAME,
    COMPLIANCE_FRAMEWORK,
    REPORTS_DIR
)

def check_prerequisites() -> dict:
    """
    Verify all required environment variables are set.
    
    WHY THIS FUNCTION:
    - Fails fast if configuration is incomplete
    - Shows user exactly what's missing
    - Masks sensitive values for security
    - Validates before running expensive operations
    
    Returns:
        Dictionary with credentials (or None for missing values)
    """
    print("\n" + "="*80)
    print("🔍 CHECKING PREREQUISITES")
    print("="*80 + "\n")
    
    # Required environment variables
    required_vars = {
        'AZURE_SUBSCRIPTION_ID': 'Azure Subscription ID',
        'AZURE_TENANT_ID': 'Azure Tenant ID',
        'AZURE_CLIENT_ID': 'Service Principal Client ID',
        'AZURE_CLIENT_SECRET': 'Service Principal Secret',
        'ANTHROPIC_API_KEY': 'Claude API Key'
    }
    
    credentials = {}
    missing = []
    
    for var_name, description in required_vars.items():
        value = os.getenv(var_name)
        credentials[var_name] = value
        
        if value:
            # Mask sensitive values for display
            # WHY: Security best practice - don't display full secrets
            if 'SECRET' in var_name or 'KEY' in var_name:
                masked = value[:8] + '...' + value[-4:] if len(value) > 12 else '***'
            else:
                masked = value[:12] + '...' if len(value) > 12 else value
            
            print(f"  ✅ {description:35s} {masked}")
        else:
            print(f"  ❌ {description:35s} NOT SET")
            missing.append(var_name)
    
    print()
    
    if missing:
        print("⚠️  Missing required environment variables:")
        for var in missing:
            print(f"     - {var}")
        print("\n💡 Setup instructions:")
        print("     1. Copy .env.example to .env (if available)")
        print("     2. Fill in your credentials")
        print("     3. Load environment: source .env (Linux/Mac) or set commands (Windows)")
        print("\n   Or set directly:")
        print(f'     export {missing[0]}="your-value-here"')
        print()
        return None
    
    print("✅ All prerequisites satisfied!\n")
    return credentials


def menu() -> str:
    """
    Display main menu and get user choice.
    
    WHY MENU INTERFACE:
    - Easier than remembering command-line arguments
    - Guides users through available features
    - Provides descriptions for each option
    - Reduces errors from incorrect usage
    
    Returns:
        User's menu choice as string
    """
    print("\n" + "="*80)
    print("⚙️  AZURE COMPLIANCE AGENT - MAIN MENU")
    print("="*80)
    print("\n📋 Available Actions:\n")
    print("  1. 🔍 Scan Only (read-only compliance audit)")
    print("       - Discover violations without making changes")
    print("       - Safe to run anytime, no Azure modifications")
    print()
    print("  2. 🔄 Full Compliance Cycle (scan + AI analysis + remediation)")
    print("       - Complete workflow with human approval gates")
    print("       - WILL MODIFY Azure resources after approval")
    print()
    print("  3. 📊 View Last Report")
    print("       - Display most recent compliance report")
    print("       - No scanning required")
    print()
    print("  4. 🔌 Test Azure Connection")
    print("       - Verify Azure credentials and access")
    print("       - Lists accessible resource groups")
    print()
    print("  5. 🤖 Test Claude Connection")
    print("       - Verify Anthropic API connectivity")
    print("       - Simple test query")
    print()
    print("  6. 🚪 Exit")
    print()
    print("="*80)
    
    choice = input("Enter your choice (1-6): ").strip()
    return choice


def scan_only(credentials: dict) -> None:
    """
    Run read-only compliance scan without remediation.
    
    WHY THIS FUNCTION:
    - Safe way to assess current state
    - No risk of unintended changes
    - Quick compliance check
    - Generates report without AI analysis
    
    Args:
        credentials: Dictionary with Azure credentials
    """
    print("\n" + "="*80)
    print("🔍 STARTING READ-ONLY COMPLIANCE SCAN")
    print("="*80)
    print("\n⚠️  This will NOT modify any Azure resources")
    print("   It only reads current configuration and checks compliance.\n")
    
    input("Press Enter to continue or Ctrl+C to cancel...")
    
    try:
        # Initialize scanner
        print("\n📡 Connecting to Azure...")
        scanner = AzureScanner(
            subscription_id=credentials['AZURE_SUBSCRIPTION_ID'],
            tenant_id=credentials['AZURE_TENANT_ID'],
            client_id=credentials['AZURE_CLIENT_ID'],
            client_secret=credentials['AZURE_CLIENT_SECRET']
        )
        
        # Run scan
        print("\n🔍 Scanning Azure resources...")
        results = scanner.scan_all_resources()
        
        # Display results in user-friendly format
        print("\n" + "="*80)
        print("📊 SCAN RESULTS")
        print("="*80)
        
        total = results['total_violations']
        
        if total == 0:
            print("\n🎉 Congratulations! No compliance violations found!")
            print("   Your Azure environment meets all NIST CSF requirements.")
        else:
            print(f"\n⚠️  Found {total} compliance violation(s)\n")
            
            # Show breakdown by severity
            print("By Severity:")
            for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
                count = results['violations_by_severity'].get(severity, 0)
                if count > 0:
                    emoji = "🔴" if severity == "CRITICAL" else "🟡" if severity == "HIGH" else "🟠" if severity == "MEDIUM" else "⚪"
                    print(f"  {emoji} {severity:8s}: {count}")
            
            # Show sample violations
            print(f"\n📋 Violations (showing first 5):")
            for i, violation in enumerate(results['results'][:5], 1):
                severity_emoji = "🔴" if violation['severity'] == "CRITICAL" else "🟡"
                print(f"\n  {i}. {severity_emoji} {violation['description']}")
                print(f"     Resource: {violation['resource_name']}")
                print(f"     Group: {violation['resource_group']}")
                print(f"     Rule: {violation['rule_id']}")
            
            if total > 5:
                print(f"\n  ... and {total - 5} more violation(s)")
        
        # Generate detailed report
        print("\n📄 Generating detailed report...")
        report = scanner.generate_scan_report()

        print(f"\n✅ Scan complete!")
        print(f"   Detailed report saved to: {REPORTS_DIR}/compliance_report.txt")
        
    except KeyboardInterrupt:
        print("\n\n⚠️  Scan cancelled by user")
    except Exception as e:
        print(f"\n\n❌ Scan failed: {str(e)}")
        print(f"   Check your Azure credentials and permissions")
    
    print("\n" + "="*80)
    input("\nPress Enter to return to menu...")


def full_cycle(credentials: dict) -> None:
    """
    Run complete compliance cycle with AI analysis and remediation.
    
    WHY THIS FUNCTION:
    - Complete end-to-end automation
    - Includes human approval gates for safety
    - Measures improvement with before/after comparison
    - Creates comprehensive audit trail
    
    Args:
        credentials: Dictionary with all required credentials
    """
    print("\n" + "="*80)
    print("🔄 FULL COMPLIANCE CYCLE")
    print("="*80)
    
    print("\n⚠️  IMPORTANT: This workflow will:")
    print("   1. Scan your Azure environment for violations")
    print("   2. Use Claude AI to analyze findings and generate remediation plans")
    print("   3. Request your approval before making ANY changes")
    print("   4. Execute ONLY approved remediations")
    print("   5. Re-scan to verify improvements")
    print("   6. Generate comprehensive report")
    print("\n💡 You will have a chance to review and approve each change before execution.")
    print()
    
    confirm = input("Continue with full cycle? (yes/no): ").strip().lower()
    
    if confirm not in ['yes', 'y']:
        print("\n⚠️  Full cycle cancelled")
        input("\nPress Enter to return to menu...")
        return
    
    try:
        # Initialize agent
        print("\n🚀 Initializing Compliance Agent...")
        agent = ComplianceAgent(
            azure_subscription_id=credentials['AZURE_SUBSCRIPTION_ID'],
            azure_tenant_id=credentials['AZURE_TENANT_ID'],
            azure_client_id=credentials['AZURE_CLIENT_ID'],
            azure_client_secret=credentials['AZURE_CLIENT_SECRET'],
            anthropic_api_key=credentials['ANTHROPIC_API_KEY']
        )
        
        # Run complete workflow
        print("\n🔄 Starting workflow...")
        result = agent.run_full_cycle()
        
        # Check for errors/interruptions
        if result['status'] not in ['COMPLETE', 'COMPLETE_NO_VIOLATIONS']:
            print(f"\n⚠️  Workflow ended with status: {result['status']}")
        
    except KeyboardInterrupt:
        print("\n\n⚠️  Workflow interrupted by user")
    except Exception as e:
        print(f"\n\n❌ Workflow failed: {str(e)}")
        import traceback
        traceback.print_exc()
    
    print("\n" + "="*80)
    input("\nPress Enter to return to menu...")


def test_azure(credentials: dict) -> None:
    """
    Test Azure connection and list accessible resource groups.
    
    WHY THIS FUNCTION:
    - Validates credentials before running full scan
    - Shows what resources the service principal can access
    - Quick connectivity check
    - Helps diagnose permission issues
    
    Args:
        credentials: Dictionary with Azure credentials
    """
    print("\n" + "="*80)
    print("🔌 TESTING AZURE CONNECTION")
    print("="*80 + "\n")
    
    try:
        from azure.identity import ClientSecretCredential
        from azure.mgmt.resource import ResourceManagementClient
        
        print("📡 Authenticating...")
        credential = ClientSecretCredential(
            tenant_id=credentials['AZURE_TENANT_ID'],
            client_id=credentials['AZURE_CLIENT_ID'],
            client_secret=credentials['AZURE_CLIENT_SECRET']
        )
        
        print("🔍 Fetching resource groups...")
        resource_client = ResourceManagementClient(
            credential=credential,
            subscription_id=credentials['AZURE_SUBSCRIPTION_ID']
        )
        
        # List resource groups (proves we have access)
        rgs = list(resource_client.resource_groups.list())
        
        print(f"\n✅ Azure connection successful!")
        print(f"\n📦 Found {len(rgs)} resource group(s):")
        
        for i, rg in enumerate(rgs[:10], 1):  # Show first 10
            location_emoji = "🌍"
            print(f"   {i}. {location_emoji} {rg.name} ({rg.location})")
        
        if len(rgs) > 10:
            print(f"   ... and {len(rgs) - 10} more")
        
        if len(rgs) == 0:
            print("   ⚠️  No resource groups found")
            print("      The service principal may not have Reader access")
        
        print(f"\n💡 Service Principal has access to subscription")
        print(f"   Ready to scan for compliance violations!")
        
    except Exception as e:
        print(f"\n❌ Azure connection failed: {str(e)}")
        print("\n💡 Troubleshooting:")
        print("   - Verify credentials are correct")
        print("   - Ensure Service Principal has Reader role on subscription")
        print("   - Check tenant ID matches the subscription")
        print("   - Verify subscription ID is correct")
    
    print("\n" + "="*80)
    input("\nPress Enter to return to menu...")


def test_claude(credentials: dict) -> None:
    """
    Test Claude API connection with simple query.
    
    WHY THIS FUNCTION:
    - Validates Anthropic API key before analysis
    - Checks rate limits and quotas
    - Quick connectivity test
    - Helps diagnose API issues
    
    Args:
        credentials: Dictionary with Anthropic API key
    """
    print("\n" + "="*80)
    print("🤖 TESTING CLAUDE API CONNECTION")
    print("="*80 + "\n")
    
    try:
        from anthropic import Anthropic
        
        print("📡 Connecting to Claude API...")
        client = Anthropic(api_key=credentials['ANTHROPIC_API_KEY'])
        
        print(f"💬 Sending test query (using model: {CLAUDE_MODEL})...")
        response = client.messages.create(
            model=CLAUDE_MODEL,  # Use model from config
            max_tokens=100,
            temperature=0,
            messages=[
                {
                    "role": "user",
                    "content": "Say 'Azure Compliance Agent test successful' and nothing else."
                }
            ]
        )
        
        response_text = response.content[0].text
        
        print(f"\n✅ Claude API connection successful!")
        print(f"\n🤖 Claude's response:")
        print(f"   {response_text}")
        print(f"\n💡 Model: {response.model}")
        print(f"   Tokens used: {response.usage.input_tokens} in, {response.usage.output_tokens} out")
        print(f"\n   Ready to analyze compliance findings!")
        
    except Exception as e:
        print(f"\n❌ Claude API connection failed: {str(e)}")
        print("\n💡 Troubleshooting:")
        print("   - Verify API key is correct (starts with 'sk-ant-')")
        print("   - Check you have sufficient credits")
        print("   - Verify no rate limiting")
        print("   - Test at: https://console.anthropic.com/")
        print(f"   - Current model in config: {CLAUDE_MODEL}")
        print("   - Update model in config/settings.py if needed")
    
    print("\n" + "="*80)
    input("\nPress Enter to return to menu...")


def main():
    """
    Main program loop - displays menu and handles user choices.
    
    WHY THIS FUNCTION:
    - Single entry point for CLI interface
    - Maintains program state between operations
    - Handles exit gracefully
    - Provides consistent user experience
    """
    print("\n" + "="*80)
    print(f"🛡️  {APPLICATION_NAME.upper()}")
    print("="*80)
    print("\nAutomated Azure compliance scanning and remediation")
    print("Powered by Azure SDK and Claude AI")
    print(f"\nVersion: {APPLICATION_VERSION}")
    print(f"Framework: {COMPLIANCE_FRAMEWORK}")
    print("="*80)
    
    # Check prerequisites on startup
    credentials = check_prerequisites()
    
    if not credentials:
        print("❌ Cannot continue without required credentials")
        print("\nPlease set environment variables and try again.")
        sys.exit(1)
    
    # Main menu loop
    while True:
        try:
            choice = menu()
            
            if choice == '1':
                # Scan only
                scan_only(credentials)
            
            elif choice == '2':
                # Full compliance cycle
                full_cycle(credentials)
            
            elif choice == '3':
                # View last report
                view_last_report()
            
            elif choice == '4':
                # Test Azure connection
                test_azure(credentials)
            
            elif choice == '5':
                # Test Claude connection
                test_claude(credentials)
            
            elif choice == '6':
                # Exit
                print("\n👋 Thank you for using Azure Compliance Agent!")
                print("   Stay compliant! 🛡️\n")
                sys.exit(0)
            
            else:
                print("\n❌ Invalid choice. Please enter 1-6.")
                input("Press Enter to continue...")
        
        except KeyboardInterrupt:
            print("\n\n👋 Goodbye!")
            sys.exit(0)
        
        except Exception as e:
            print(f"\n❌ Unexpected error: {str(e)}")
            import traceback
            traceback.print_exc()
            input("\nPress Enter to continue...")


if __name__ == "__main__":
    """
    Entry point for Quick Start CLI.
    
    This provides a user-friendly interface to all compliance agent features.
    No command-line arguments required - everything is menu-driven.
    
    Usage:
        python quick_start.py
    """
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n👋 Goodbye!")
        sys.exit(0)
    except Exception as e:
        print(f"\n\n❌ Fatal error: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)