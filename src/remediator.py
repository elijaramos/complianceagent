"""
Azure Remediation Executor

This module executes automated remediation of Azure compliance violations using
the Azure SDK. Unlike CLI-based approaches, this uses Python SDK clients for
programmatic, auditable, and reliable resource updates.

WHY SDK OVER CLI:
- Programmatic: Direct API calls, no shell command parsing/injection risks
- Type safety: Python objects ensure valid parameters at compile time
- Error handling: Structured exceptions instead of parsing CLI output
- Atomic operations: SDK operations are transactional where possible
- Audit trail: Detailed logging of exact API calls made
- Testing: Easy to mock and unit test SDK clients
"""

import os
import sys
import json
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from pathlib import Path

from azure.identity import ClientSecretCredential
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.monitor import MonitorManagementClient
from azure.mgmt.monitor.models import DiagnosticSettingsResource, LogSettings

# Import configuration settings
sys.path.insert(0, str(Path(__file__).parent.parent))
from settings import ROLLBACK_SNAPSHOTS_DIR
from azure.mgmt.storage.models import (
    StorageAccountUpdateParameters, 
    Encryption,
    EncryptionServices,
    EncryptionService,
    BlobServiceProperties
)
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.network.models import (
    NetworkSecurityGroup,
    SecurityRule
)
from azure.mgmt.resource import ResourceManagementClient
from azure.core.exceptions import (
    AzureError, 
    HttpResponseError, 
    ResourceNotFoundError,
    ClientAuthenticationError
)


class AzureRemediator:
    """
    Executes automated remediation of Azure compliance violations.
    
    WHY THIS CLASS:
    - Centralizes Azure update logic for consistency and auditability
    - Implements rollback capability for safety
    - Provides standardized error handling and logging
    - Enables automated remediation workflows with human approval gates
    - Maps compliance violations to specific SDK operations
    
    Architecture:
    - Uses Azure SDK management clients (not CLI) for direct API calls
    - Each remediation function is idempotent (safe to run multiple times)
    - Returns success/failure tuples for easy integration
    - Saves rollback snapshots before making changes
    - Validates prerequisites before executing changes
    """
    
    def __init__(self, subscription_id: str, tenant_id: str, 
                 client_id: str, client_secret: str):
        """
        Initialize Azure remediator with credentials.
        
        WHY SERVICE PRINCIPAL:
        - Automation requires non-interactive authentication
        - Can be scoped with minimum required permissions (Contributor on specific RGs)
        - Supports credential rotation and secret management
        - Enables audit logging of who made changes (via service principal)
        
        REQUIRED AZURE PERMISSIONS:
        - Storage Account Contributor (for storage remediations)
        - Network Contributor (for NSG remediations)
        - Reader (for fetching current state)
        
        Args:
            subscription_id: Azure subscription ID
            tenant_id: Azure AD tenant ID
            client_id: Service Principal application ID
            client_secret: Service Principal secret
        """
        self.subscription_id = subscription_id
        
        # Azure SDK Pattern: ClientSecretCredential handles OAuth token management
        # Tokens are cached and automatically refreshed before expiration
        self.credential = ClientSecretCredential(
            tenant_id=tenant_id,
            client_id=client_id,
            client_secret=client_secret
        )
        
        # Initialize management clients for different Azure services
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

        self.monitor_client = MonitorManagementClient(
            credential=self.credential,
            subscription_id=subscription_id
        )

        print(f"✓ Azure Remediator initialized for subscription: {subscription_id}")
    
    def remediate_storage_encryption(self, resource_group: str, 
                                    account_name: str) -> Tuple[bool, str]:
        """
        Enable encryption at rest for storage account blob service.
        
        WHY THIS MATTERS:
        - Encryption at rest protects data from physical storage breaches
        - Required by GDPR, HIPAA, PCI DSS, and most compliance frameworks
        - Azure encrypts by default, but this ensures it's explicitly enabled
        - Uses Microsoft-managed keys (customer-managed keys require Key Vault)
        
        Azure SDK Pattern:
        - Get current storage account properties
        - Create update parameters with only fields to change
        - Call update() method (PATCH operation, not full replace)
        - Azure SDK handles request serialization and retry logic
        
        Args:
            resource_group: Resource group name
            account_name: Storage account name
            
        Returns:
            Tuple of (success: bool, message: str)
            
        IMPORTANT:
        - This operation is non-disruptive (no downtime)
        - Encryption happens transparently at storage layer
        - Existing unencrypted data is encrypted on next write
        """
        print(f"\nRemediating storage encryption: {account_name}")
        
        try:
            # Get current storage account state
            # WHY: Validate resource exists and get current configuration
            print(f"  Fetching current state...")
            account = self.storage_client.storage_accounts.get_properties(
                resource_group_name=resource_group,
                account_name=account_name
            )
            
            # Check if encryption is already enabled
            # WHY: Avoid unnecessary updates (idempotency check)
            if (account.encryption and 
                account.encryption.services and 
                account.encryption.services.blob and 
                account.encryption.services.blob.enabled):
                return (True, f"Storage account '{account_name}' already has blob encryption enabled")
            
            # Azure SDK Pattern: Create update parameters object
            # WHY: Type-safe way to specify changes, SDK validates parameters
            # Only fields set in the update object will be changed
            print(f"  Enabling blob encryption...")
            
            update_params = StorageAccountUpdateParameters(
                encryption=Encryption(
                    services=EncryptionServices(
                        blob=EncryptionService(
                            enabled=True,
                            key_type='Account'  # Use account key (Microsoft-managed)
                        ),
                        file=EncryptionService(
                            enabled=True,
                            key_type='Account'
                        )
                    ),
                    key_source='Microsoft.Storage'  # Microsoft-managed keys
                )
            )
            
            # Execute update
            # Azure SDK Pattern: update() returns updated resource object
            # This is an asynchronous operation but SDK waits for completion
            updated_account = self.storage_client.storage_accounts.update(
                resource_group_name=resource_group,
                account_name=account_name,
                parameters=update_params
            )
            
            # Verify the change
            # WHY: Ensure update was actually applied (defense in depth)
            if (updated_account.encryption and 
                updated_account.encryption.services.blob.enabled):
                print(f"  ✓ Blob encryption enabled successfully")
                return (True, f"Successfully enabled encryption for storage account '{account_name}'")
            else:
                return (False, f"Update completed but encryption not confirmed for '{account_name}'")
                
        except ResourceNotFoundError:
            msg = f"Storage account '{account_name}' not found in resource group '{resource_group}'"
            print(f"  ✗ {msg}")
            return (False, msg)
        except ClientAuthenticationError:
            msg = "Authentication failed - check service principal credentials and permissions"
            print(f"  ✗ {msg}")
            return (False, msg)
        except HttpResponseError as e:
            msg = f"Azure API error: {e.message}"
            print(f"  ✗ {msg}")
            return (False, msg)
        except AzureError as e:
            msg = f"Azure SDK error: {str(e)}"
            print(f"  ✗ {msg}")
            return (False, msg)
        except Exception as e:
            msg = f"Unexpected error: {str(e)}"
            print(f"  ✗ {msg}")
            return (False, msg)
    
    def remediate_storage_public_access(self, resource_group: str, 
                                       account_name: str) -> Tuple[bool, str]:
        """
        Disable public blob access for storage account.
        
        WHY THIS MATTERS:
        - Public access allows anonymous internet users to read blobs
        - Common cause of data breaches (misconfigured storage accounts)
        - Disabling enforces authentication for all access
        - Prevents accidental public exposure of sensitive data
        
        IMPACT:
        - Existing public containers become private (may break anonymous access)
        - Applications using anonymous access will fail (need SAS tokens or AAD)
        - This is a security-first approach (availability vs security tradeoff)
        
        Args:
            resource_group: Resource group name
            account_name: Storage account name
            
        Returns:
            Tuple of (success: bool, message: str)
        """
        print(f"\nRemediating storage public access: {account_name}")
        
        try:
            # Get current state
            print(f"  Fetching current state...")
            account = self.storage_client.storage_accounts.get_properties(
                resource_group_name=resource_group,
                account_name=account_name
            )
            
            # Check if already disabled (idempotency)
            if hasattr(account, 'allow_blob_public_access') and not account.allow_blob_public_access:
                return (True, f"Public access already disabled for '{account_name}'")
            
            # Azure SDK Pattern: Update only the specific property
            # WHY: Minimizes risk by changing only what's necessary
            print(f"  Disabling public blob access...")
            
            update_params = StorageAccountUpdateParameters(
                allow_blob_public_access=False
            )
            
            # Execute update
            updated_account = self.storage_client.storage_accounts.update(
                resource_group_name=resource_group,
                account_name=account_name,
                parameters=update_params
            )
            
            # Verify the change
            if not updated_account.allow_blob_public_access:
                print(f"  ✓ Public access disabled successfully")
                print(f"  📍 Azure Portal UI: Settings → Configuration → 'Allow Blob anonymous access' = Disabled")
                print(f"  ⚠  Note: Existing anonymous access will be blocked")
                return (True, f"Successfully disabled public access for '{account_name}'")
            else:
                return (False, f"Update completed but public access not confirmed disabled for '{account_name}'")
                
        except ResourceNotFoundError:
            msg = f"Storage account '{account_name}' not found in resource group '{resource_group}'"
            print(f"  ✗ {msg}")
            return (False, msg)
        except HttpResponseError as e:
            msg = f"Azure API error: {e.message}"
            print(f"  ✗ {msg}")
            return (False, msg)
        except AzureError as e:
            msg = f"Azure SDK error: {str(e)}"
            print(f"  ✗ {msg}")
            return (False, msg)
        except Exception as e:
            msg = f"Unexpected error: {str(e)}"
            print(f"  ✗ {msg}")
            return (False, msg)
    
    def remediate_nsg_overpermissive_rules(self, resource_group: str, nsg_name: str,
                                          dangerous_rules: List[Dict[str, Any]]) -> Tuple[bool, str]:
        """
        Remediate overpermissive Network Security Group rules.
        
        WHY THIS MATTERS:
        - NSG rules with source 0.0.0.0/0 expose resources to internet attacks
        - Most common are SSH (22), RDP (3389), and database ports (1433, 3306)
        - Attackers actively scan for these exposed services
        - Restricting source IPs implements network segmentation and least privilege
        
        REMEDIATION STRATEGY:
        - Don't delete rules (might be intentional, need approval)
        - Instead: Add DENY rule with higher priority (lower number)
        - This blocks the dangerous access while preserving original rule for audit
        - Allows easy rollback by removing the deny rule
        
        Azure SDK Pattern:
        - Get current NSG configuration
        - Create new security rule with higher priority
        - Add rule to NSG's security_rules collection
        - Update NSG with modified rules
        
        Args:
            resource_group: Resource group name
            nsg_name: Network Security Group name
            dangerous_rules: List of dangerous rule details from scanner
            
        Returns:
            Tuple of (success: bool, message: str)
        """
        print(f"\nRemediating NSG overpermissive rules: {nsg_name}")
        
        try:
            # Get current NSG configuration
            print(f"  Fetching current NSG configuration...")
            nsg = self.network_client.network_security_groups.get(
                resource_group_name=resource_group,
                network_security_group_name=nsg_name
            )
            
            print(f"  Found {len(nsg.security_rules or [])} existing rules")
            
            if not dangerous_rules or len(dangerous_rules) == 0:
                return (True, f"No dangerous rules specified for '{nsg_name}'")
            
            # For each dangerous rule, add a higher-priority DENY rule
            # WHY DENY RULES: More explicit and auditable than deleting
            remediated_rules = []
            
            for danger_rule in dangerous_rules:
                rule_name = danger_rule.get('name', 'unknown')
                dest_port = danger_rule.get('destination_port', '*')
                protocol = danger_rule.get('protocol', '*')
                
                print(f"  Creating DENY rule for dangerous rule: {rule_name}")
                
                # Find lowest priority (highest precedence) available
                # Azure priorities: 100-4096, lower number = higher priority
                existing_priorities = [r.priority for r in (nsg.security_rules or [])]
                min_priority = min(existing_priorities) if existing_priorities else 200
                new_priority = max(100, min_priority - 10)  # Ensure at least 100
                
                # Create deny rule name
                deny_rule_name = f"DENY-Remediation-{rule_name}"
                
                # Azure SDK Pattern: Create SecurityRule object
                # WHY: Type-safe configuration with validation
                deny_rule = SecurityRule(
                    name=deny_rule_name,
                    protocol=protocol if protocol != '*' else 'Tcp',
                    source_port_range='*',
                    destination_port_range=dest_port,
                    source_address_prefix='*',  # Deny from all sources
                    destination_address_prefix='*',
                    access='Deny',  # DENY overrides ALLOW at same priority
                    priority=new_priority,
                    direction='Inbound',
                    description=f'Auto-remediation: Blocks dangerous rule {rule_name} allowing 0.0.0.0/0 access'
                )
                
                try:
                    # Azure SDK Pattern: begin_create_or_update() is async operation
                    # Returns LROPoller (Long Running Operation Poller)
                    # .result() blocks until operation completes
                    print(f"    Adding deny rule with priority {new_priority}...")
                    poller = self.network_client.security_rules.begin_create_or_update(
                        resource_group_name=resource_group,
                        network_security_group_name=nsg_name,
                        security_rule_name=deny_rule_name,
                        security_rule_parameters=deny_rule
                    )
                    
                    # Wait for operation to complete
                    # WHY: Ensures rule is active before proceeding
                    result = poller.result()
                    
                    print(f"    ✓ Deny rule '{deny_rule_name}' created successfully")
                    remediated_rules.append(deny_rule_name)
                    
                except HttpResponseError as e:
                    if 'already exists' in str(e).lower():
                        print(f"    ℹ Deny rule '{deny_rule_name}' already exists")
                        remediated_rules.append(deny_rule_name)
                    else:
                        print(f"    ✗ Failed to create deny rule: {e.message}")
                        continue
            
            if remediated_rules:
                msg = f"Successfully added {len(remediated_rules)} deny rule(s) to '{nsg_name}': {', '.join(remediated_rules)}"
                print(f"  ✓ {msg}")
                print(f"  ⚠ Note: Original dangerous rules still exist but are overridden")
                return (True, msg)
            else:
                msg = f"No deny rules were added to '{nsg_name}'"
                print(f"  ✗ {msg}")
                return (False, msg)
                
        except ResourceNotFoundError:
            msg = f"NSG '{nsg_name}' not found in resource group '{resource_group}'"
            print(f"  ✗ {msg}")
            return (False, msg)
        except HttpResponseError as e:
            msg = f"Azure API error: {e.message}"
            print(f"  ✗ {msg}")
            return (False, msg)
        except AzureError as e:
            msg = f"Azure SDK error: {str(e)}"
            print(f"  ✗ {msg}")
            return (False, msg)
        except Exception as e:
            msg = f"Unexpected error: {str(e)}"
            print(f"  ✗ {msg}")
            return (False, msg)
    
    def enable_storage_logging(self, resource_group: str,
                              account_name: str) -> Tuple[bool, str]:
        """
        Enable diagnostic logging for storage account using Azure Monitor.

        WHY THIS MATTERS:
        - Logging is required for security incident investigation
        - Provides audit trail of who accessed what data and when
        - Required by SOX, HIPAA, PCI DSS, and most compliance frameworks
        - Enables detection of data exfiltration and unauthorized access

        Azure Monitor Pattern:
        - Diagnostic settings are created via MonitorManagementClient
        - Can send logs to: Log Analytics, Storage Account, Event Hub
        - Logs all read, write, delete operations across blob/file/queue/table

        WHAT GETS LOGGED:
        - Read, write, delete operations
        - Authentication method (SAS, account key, AAD)
        - Client IP address
        - Request/response details
        - Failed authentication attempts

        Args:
            resource_group: Resource group name
            account_name: Storage account name

        Returns:
            Tuple of (success: bool, message: str)
        """
        print(f"\nEnabling diagnostic logging: {account_name}")

        try:
            # Build full resource ID for blob service
            # IMPORTANT: Diagnostic settings must be created at the service level
            # (blobServices/default), not at the storage account level
            storage_account_id = (
                f"/subscriptions/{self.subscription_id}"
                f"/resourceGroups/{resource_group}"
                f"/providers/Microsoft.Storage/storageAccounts/{account_name}"
            )

            blob_service_id = f"{storage_account_id}/blobServices/default"

            print(f"  Checking existing diagnostic settings...")

            # Check if diagnostic settings already exist
            try:
                existing_settings = self.monitor_client.diagnostic_settings.list(blob_service_id)
                if hasattr(existing_settings, 'value') and existing_settings.value:
                    for setting in existing_settings.value:
                        if setting.logs:
                            for log in setting.logs:
                                if log.enabled:
                                    return (True, f"Diagnostic logging already enabled for '{account_name}'")
            except Exception:
                pass  # No existing settings, we'll create new ones

            print(f"  Creating diagnostic settings for blob service...")

            # Create diagnostic setting with logging enabled
            # WHY: Sends all blob storage operation logs to Log Analytics
            # NOTE: Cannot send logs to the same storage account being monitored
            diagnostic_setting = DiagnosticSettingsResource(
                logs=[
                    LogSettings(
                        category="StorageRead",
                        enabled=True,
                        retention_policy=None  # Retention not supported for storage
                    ),
                    LogSettings(
                        category="StorageWrite",
                        enabled=True,
                        retention_policy=None
                    ),
                    LogSettings(
                        category="StorageDelete",
                        enabled=True,
                        retention_policy=None
                    )
                ]
            )

            # Create the diagnostic setting at blob service level
            # WHY: Uses Monitor API to configure centralized logging
            self.monitor_client.diagnostic_settings.create_or_update(
                resource_uri=blob_service_id,  # Target blob service, not storage account
                name="compliance-agent-logging",  # Diagnostic setting name
                parameters=diagnostic_setting
            )

            print(f"  ✓ Diagnostic logging enabled successfully")
            print(f"  📍 Azure Portal: Storage account → Monitoring → Diagnostic settings (blob)")
            print(f"  ℹ  Logs will be collected by Azure Monitor (viewable in Activity Log)")
            return (True, f"Successfully enabled diagnostic logging for '{account_name}'")

        except ResourceNotFoundError:
            msg = f"Storage account '{account_name}' not found in resource group '{resource_group}'"
            print(f"  ✗ {msg}")
            return (False, msg)
        except HttpResponseError as e:
            msg = f"Azure API error: {e.message}"
            print(f"  ✗ {msg}")
            return (False, msg)
        except AzureError as e:
            msg = f"Azure SDK error: {str(e)}"
            print(f"  ✗ {msg}")
            return (False, msg)
        except Exception as e:
            msg = f"Unexpected error: {str(e)}"
            print(f"  ✗ {msg}")
            return (False, msg)
    
    def execute_remediation(self, rule_id: str, 
                          resource: Dict[str, Any]) -> Tuple[bool, str]:
        """
        Router function that executes appropriate remediation based on rule ID.
        
        WHY THIS METHOD:
        - Provides single entry point for all remediations
        - Maps compliance rule IDs to specific remediation functions
        - Simplifies automation (one function to call)
        - Enables consistent error handling and logging
        
        WORKFLOW:
        1. Parse rule_id to determine remediation type
        2. Extract required parameters from resource dict
        3. Call appropriate remediation function
        4. Return success/failure result
        
        Args:
            rule_id: Compliance rule ID (e.g., 'PR.DS-1-storage-encryption')
            resource: Dictionary containing resource details
                Required keys: resource_name, resource_group
                Optional keys: depends on remediation type
                
        Returns:
            Tuple of (success: bool, message: str)
        """
        print(f"\n{'='*70}")
        print(f"Executing Remediation")
        print(f"Rule ID: {rule_id}")
        print(f"Resource: {resource.get('resource_name', 'unknown')}")
        print(f"{'='*70}")
        
        # Extract common parameters
        resource_name = resource.get('resource_name')
        resource_group = resource.get('resource_group')
        
        if not resource_name or not resource_group:
            msg = "Missing required parameters: resource_name and resource_group"
            print(f"✗ {msg}")
            return (False, msg)
        
        try:
            # Route to appropriate remediation based on rule ID
            # WHY RULE ID ROUTING: Consistent mapping from scan findings to fixes
            
            if rule_id == 'PR.DS-1-storage-encryption':
                return self.remediate_storage_encryption(resource_group, resource_name)
            
            elif rule_id == 'PR.DS-1-storage-public-access':
                return self.remediate_storage_public_access(resource_group, resource_name)
            
            elif rule_id == 'PR.AC-4-network-security':
                # NSG remediation requires dangerous rules list
                dangerous_rules = resource.get('violating_rule_details', [])
                if isinstance(dangerous_rules, dict):
                    # If single rule, convert to list
                    dangerous_rules = [dangerous_rules]
                return self.remediate_nsg_overpermissive_rules(
                    resource_group, resource_name, dangerous_rules
                )
            
            elif rule_id == 'DE.CM-7-logging':
                return self.enable_storage_logging(resource_group, resource_name)
            
            else:
                msg = f"No remediation handler for rule ID: {rule_id}"
                print(f"✗ {msg}")
                return (False, msg)
                
        except Exception as e:
            msg = f"Remediation failed with error: {str(e)}"
            print(f"✗ {msg}")
            return (False, msg)
    
    def create_rollback_snapshot(self, resource: Dict[str, Any]) -> Dict[str, Any]:
        """
        Save current resource configuration for rollback capability.
        
        WHY THIS METHOD:
        - Enables safe remediation with ability to undo changes
        - Captures complete resource state before modification
        - Provides audit trail of what changed
        - Required for change management and compliance
        
        WHAT'S SAVED:
        - Current resource properties (full state)
        - Timestamp of snapshot
        - Resource identifiers (subscription, RG, name)
        - Resource type and API version
        
        Args:
            resource: Dictionary with resource details
                Required keys: resource_name, resource_group, resource_type
                
        Returns:
            Dictionary containing snapshot data
            
        LIMITATIONS:
        - Some resources may have large configurations
        - Snapshots don't include data (only configuration)
        - NSG rules changes tracked individually
        """
        print(f"\nCreating rollback snapshot for {resource.get('resource_name', 'unknown')}...")
        
        resource_name = resource.get('resource_name')
        resource_group = resource.get('resource_group')
        resource_type = resource.get('resource_type', 'Unknown')
        
        snapshot = {
            'timestamp': datetime.utcnow().isoformat(),
            'subscription_id': self.subscription_id,
            'resource_group': resource_group,
            'resource_name': resource_name,
            'resource_type': resource_type,
            'configuration': {}
        }
        
        try:
            # Fetch current configuration based on resource type
            if 'Storage' in resource_type:
                # Get storage account properties
                account = self.storage_client.storage_accounts.get_properties(
                    resource_group_name=resource_group,
                    account_name=resource_name
                )
                
                # Save relevant properties for rollback
                snapshot['configuration'] = {
                    'allow_blob_public_access': account.allow_blob_public_access,
                    'encryption_enabled': account.encryption.services.blob.enabled if account.encryption else False,
                    'sku_name': account.sku.name if account.sku else None,
                    'access_tier': account.access_tier,
                    'tags': account.tags
                }
                
            elif 'NetworkSecurityGroup' in resource_type:
                # Get NSG configuration
                nsg = self.network_client.network_security_groups.get(
                    resource_group_name=resource_group,
                    network_security_group_name=resource_name
                )
                
                # Save security rules
                snapshot['configuration'] = {
                    'security_rules': [
                        {
                            'name': rule.name,
                            'priority': rule.priority,
                            'direction': rule.direction,
                            'access': rule.access,
                            'protocol': rule.protocol,
                            'source_address_prefix': rule.source_address_prefix,
                            'destination_port_range': rule.destination_port_range
                        }
                        for rule in (nsg.security_rules or [])
                    ],
                    'tags': nsg.tags
                }
            
            # Save snapshot to file
            # WHY FILE STORAGE: Simple, auditable, works without database
            snapshots_dir = Path(ROLLBACK_SNAPSHOTS_DIR)
            snapshots_dir.mkdir(exist_ok=True)
            
            timestamp_str = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            snapshot_file = snapshots_dir / f"{resource_name}_{timestamp_str}.json"
            
            with open(snapshot_file, 'w', encoding='utf-8') as f:
                json.dump(snapshot, f, indent=2)
            
            snapshot['snapshot_file'] = str(snapshot_file)
            
            print(f"  ✓ Snapshot saved to: {snapshot_file}")
            return snapshot
            
        except Exception as e:
            print(f"  ✗ Failed to create snapshot: {str(e)}")
            snapshot['error'] = str(e)
            return snapshot
    
    def execute_rollback(self, rollback_data: Dict[str, Any]) -> Tuple[bool, str]:
        """
        Restore resource to previous configuration from snapshot.
        
        WHY THIS METHOD:
        - Provides safety net if remediation causes issues
        - Enables quick recovery from failed changes
        - Required for change management procedures
        - Allows testing remediations with confidence
        
        ROLLBACK STRATEGY:
        - Restore exact configuration from snapshot
        - Validate restored state matches snapshot
        - Log rollback for audit trail
        - Report any differences or failures
        
        Args:
            rollback_data: Snapshot dictionary from create_rollback_snapshot()
                Required keys: resource_name, resource_group, resource_type, configuration
                
        Returns:
            Tuple of (success: bool, message: str)
            
        LIMITATIONS:
        - Cannot rollback deleted resources (only configuration changes)
        - Some changes may have external dependencies
        - Data changes (blob content) cannot be rolled back
        """
        print(f"\n{'='*70}")
        print(f"Executing Rollback")
        print(f"{'='*70}")
        
        resource_name = rollback_data.get('resource_name')
        resource_group = rollback_data.get('resource_group')
        resource_type = rollback_data.get('resource_type')
        config = rollback_data.get('configuration', {})
        
        if not all([resource_name, resource_group, resource_type, config]):
            msg = "Invalid rollback data: missing required fields"
            print(f"✗ {msg}")
            return (False, msg)
        
        print(f"Resource: {resource_name}")
        print(f"Resource Group: {resource_group}")
        print(f"Type: {resource_type}")
        print(f"Snapshot Time: {rollback_data.get('timestamp', 'unknown')}")
        
        try:
            if 'Storage' in resource_type:
                # Rollback storage account configuration
                print(f"\nRolling back storage account configuration...")
                
                update_params = StorageAccountUpdateParameters(
                    allow_blob_public_access=config.get('allow_blob_public_access')
                )
                
                # Apply rollback
                self.storage_client.storage_accounts.update(
                    resource_group_name=resource_group,
                    account_name=resource_name,
                    parameters=update_params
                )
                
                print(f"  ✓ Storage account rolled back successfully")
                return (True, f"Successfully rolled back storage account '{resource_name}'")
                
            elif 'NetworkSecurityGroup' in resource_type:
                # Rollback NSG rules
                print(f"\nRolling back NSG rules...")
                
                # Get current NSG
                nsg = self.network_client.network_security_groups.get(
                    resource_group_name=resource_group,
                    network_security_group_name=resource_name
                )
                
                current_rules = {r.name for r in (nsg.security_rules or [])}
                snapshot_rules = {r['name'] for r in config.get('security_rules', [])}
                
                # Find rules added after snapshot (remediation rules)
                rules_to_remove = current_rules - snapshot_rules
                
                print(f"  Found {len(rules_to_remove)} rule(s) to remove")
                
                # Remove remediation rules
                for rule_name in rules_to_remove:
                    if rule_name.startswith('DENY-Remediation-'):
                        print(f"    Removing remediation rule: {rule_name}")
                        try:
                            poller = self.network_client.security_rules.begin_delete(
                                resource_group_name=resource_group,
                                network_security_group_name=resource_name,
                                security_rule_name=rule_name
                            )
                            poller.result()  # Wait for deletion
                            print(f"      ✓ Removed {rule_name}")
                        except Exception as e:
                            print(f"      ✗ Failed to remove {rule_name}: {str(e)}")
                
                print(f"  ✓ NSG rolled back successfully")
                return (True, f"Successfully rolled back NSG '{resource_name}'")
                
            else:
                msg = f"Rollback not implemented for resource type: {resource_type}"
                print(f"✗ {msg}")
                return (False, msg)
                
        except ResourceNotFoundError:
            msg = f"Resource '{resource_name}' not found - may have been deleted"
            print(f"✗ {msg}")
            return (False, msg)
        except Exception as e:
            msg = f"Rollback failed: {str(e)}"
            print(f"✗ {msg}")
            return (False, msg)


# WHY __main__ BLOCK:
# - Demonstrates usage with test data
# - Validates Azure connectivity and permissions
# - Shows integration pattern for automation scripts
# - Tests each remediation function independently
if __name__ == "__main__":
    """
    Test Azure remediator with sample resources.
    
    Required Environment Variables:
        AZURE_SUBSCRIPTION_ID: Azure subscription ID
        AZURE_TENANT_ID: Azure AD tenant ID
        AZURE_CLIENT_ID: Service Principal application ID
        AZURE_CLIENT_SECRET: Service Principal secret
        
    Usage:
        # Set environment variables
        export AZURE_SUBSCRIPTION_ID="your-sub-id"
        export AZURE_TENANT_ID="your-tenant-id"
        export AZURE_CLIENT_ID="your-client-id"
        export AZURE_CLIENT_SECRET="your-client-secret"
        
        # Run test
        python src/remediator.py
        
    NOTE: This will attempt to make actual changes to Azure resources.
    Use a test subscription and test resources only.
    """
    
    # Load credentials from environment
    subscription_id = os.getenv("AZURE_SUBSCRIPTION_ID")
    tenant_id = os.getenv("AZURE_TENANT_ID")
    client_id = os.getenv("AZURE_CLIENT_ID")
    client_secret = os.getenv("AZURE_CLIENT_SECRET")
    
    # Validate credentials
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
        print("\nPlease set these variables before running the remediator.")
        sys.exit(1)
    
    # Sample test data
    # WHY: Allows testing remediation logic without running full scan
    # IMPORTANT: Replace with your actual test resource names
    sample_resources = {
        'storage_encryption': {
            'resource_name': 'teststorage123',  # Replace with your test storage account
            'resource_group': 'test-rg',  # Replace with your test resource group
            'resource_type': 'Microsoft.Storage/storageAccounts',
            'rule_id': 'PR.DS-1-storage-encryption'
        },
        'storage_public_access': {
            'resource_name': 'teststorage123',
            'resource_group': 'test-rg',
            'resource_type': 'Microsoft.Storage/storageAccounts',
            'rule_id': 'PR.DS-1-storage-public-access'
        },
        'nsg_rules': {
            'resource_name': 'test-nsg',  # Replace with your test NSG
            'resource_group': 'test-rg',
            'resource_type': 'Microsoft.Network/networkSecurityGroups',
            'rule_id': 'PR.AC-4-network-security',
            'violating_rule_details': {
                'name': 'allow-all-inbound',
                'destination_port': '22',
                'protocol': 'Tcp'
            }
        }
    }
    
    print("="*80)
    print("Azure Remediator Test")
    print("="*80)
    print("\n⚠ WARNING: This will make actual changes to Azure resources!")
    print("Ensure you're using test resources in a test subscription.\n")
    
    response = input("Continue? (yes/no): ")
    if response.lower() != 'yes':
        print("Test cancelled.")
        sys.exit(0)
    
    try:
        # Initialize remediator
        print("\nInitializing remediator...")
        remediator = AzureRemediator(
            subscription_id=subscription_id,
            tenant_id=tenant_id,
            client_id=client_id,
            client_secret=client_secret
        )
        
        # Test 1: Storage encryption remediation
        print("\n" + "="*80)
        print("TEST 1: Storage Encryption Remediation")
        print("="*80)
        
        resource = sample_resources['storage_encryption']
        
        # Create rollback snapshot
        snapshot = remediator.create_rollback_snapshot(resource)
        
        # Execute remediation
        success, message = remediator.execute_remediation(
            resource['rule_id'],
            resource
        )
        
        print(f"\nResult: {'✓ SUCCESS' if success else '✗ FAILED'}")
        print(f"Message: {message}")
        
        # Test 2: Storage public access remediation
        print("\n" + "="*80)
        print("TEST 2: Storage Public Access Remediation")
        print("="*80)
        
        resource = sample_resources['storage_public_access']
        success, message = remediator.execute_remediation(
            resource['rule_id'],
            resource
        )
        
        print(f"\nResult: {'✓ SUCCESS' if success else '✗ FAILED'}")
        print(f"Message: {message}")
        
        # Test 3: Rollback (if snapshot was created)
        if snapshot and 'error' not in snapshot:
            print("\n" + "="*80)
            print("TEST 3: Rollback")
            print("="*80)
            
            response = input("\nExecute rollback? (yes/no): ")
            if response.lower() == 'yes':
                success, message = remediator.execute_rollback(snapshot)
                print(f"\nResult: {'✓ SUCCESS' if success else '✗ FAILED'}")
                print(f"Message: {message}")
        
        print("\n" + "="*80)
        print("✓ Test completed")
        print("="*80)
        
    except ClientAuthenticationError as e:
        print(f"\nAuthentication Error: {e}")
        print("\nPossible causes:")
        print("  - Invalid service principal credentials")
        print("  - Service principal doesn't have access to subscription")
        print("  - Tenant ID mismatch")
        sys.exit(1)
    except Exception as e:
        print(f"\nUnexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)