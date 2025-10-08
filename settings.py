"""
Application Configuration Settings

This file stores dynamic configuration values that may change over time,
such as API model versions, limits, and other parameters.

WHY THIS EXISTS:
- Centralized location for all configurable values
- Easy to update when new model versions are released
- Prevents breaking changes when APIs evolve
- Makes testing easier (can override values)
- Documents available configuration options
"""

# =============================================================================
# CLAUDE AI CONFIGURATION
# =============================================================================

# Claude Model Configuration
# WHY: Model versions change regularly. Centralizing here prevents breaking changes.
# 
# Available Models (as of October 2025):
# - claude-sonnet-4-20250514: Latest Claude Sonnet 4 (recommended for production)
# - claude-opus-4-20250514: Most capable Claude 4 (slower, more expensive)
# - claude-3-5-sonnet-20241022: Previous generation Claude 3.5 Sonnet (still supported)
# - claude-3-5-sonnet-20240620: Earlier Claude 3.5 Sonnet
# - claude-3-opus-20240229: Claude 3 Opus (slower, more expensive)
# - claude-3-haiku-20240307: Fastest and most economical
#
# Update this when new versions are released: https://docs.anthropic.com/en/docs/about-claude/models
CLAUDE_MODEL = "claude-sonnet-4-20250514"

# Alternative: Use model aliases (points to latest version, but less predictable)
# CLAUDE_MODEL = "claude-sonnet-4-latest"

# Claude API Configuration
CLAUDE_MAX_TOKENS = 4096  # Maximum tokens for AI responses
CLAUDE_TEMPERATURE = 0    # Temperature for AI responses (0 = deterministic, 1 = creative)
CLAUDE_TIMEOUT = 120      # API timeout in seconds

# WHY TEMPERATURE=0 for Security:
# - Security recommendations must be deterministic and consistent
# - No creativity needed (we want proven best practices)
# - Ensures same findings always get same recommendations (auditability)
# - Reduces risk of hallucinated or incorrect commands


# =============================================================================
# AZURE CONFIGURATION
# =============================================================================

# Azure API timeouts and retries
AZURE_TIMEOUT = 60        # API timeout in seconds
AZURE_MAX_RETRIES = 3     # Number of retry attempts for failed API calls

# Resource scanning limits
MAX_RESOURCES_PER_SCAN = 1000  # Limit to prevent excessive API calls


# =============================================================================
# REPORTING CONFIGURATION
# =============================================================================

# Report output settings
REPORTS_DIR = "reports"
APPROVALS_DIR = "approvals"
LOGS_DIR = "logs"
ROLLBACK_SNAPSHOTS_DIR = "rollback_snapshots"
MAX_VIOLATIONS_IN_SUMMARY = 10  # Number of violations to show in summary


# =============================================================================
# WORKFLOW CONFIGURATION
# =============================================================================

# Approval workflow settings
REQUIRE_APPROVAL = True    # Whether to require human approval before remediation
AUTO_APPROVE_LOW_RISK = False  # Auto-approve low-risk changes (not recommended)

# Retry settings for failed remediations
MAX_REMEDIATION_RETRIES = 2
RETRY_DELAY_SECONDS = 5


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def get_claude_model() -> str:
    """
    Get the current Claude model identifier.
    
    This function allows for future enhancements like:
    - Environment-specific models (dev vs prod)
    - Feature flags for A/B testing
    - Cost optimization by model selection
    
    Returns:
        Model identifier string
    """
    return CLAUDE_MODEL


def get_claude_config() -> dict:
    """
    Get complete Claude configuration as dictionary.
    
    Returns:
        Dictionary with all Claude settings
    """
    return {
        'model': CLAUDE_MODEL,
        'max_tokens': CLAUDE_MAX_TOKENS,
        'temperature': CLAUDE_TEMPERATURE,
        'timeout': CLAUDE_TIMEOUT
    }


def get_azure_config() -> dict:
    """
    Get complete Azure configuration as dictionary.
    
    Returns:
        Dictionary with all Azure settings
    """
    return {
        'timeout': AZURE_TIMEOUT,
        'max_retries': AZURE_MAX_RETRIES,
        'max_resources_per_scan': MAX_RESOURCES_PER_SCAN
    }


# =============================================================================
# VERSION INFORMATION
# =============================================================================

APPLICATION_VERSION = "1.0.0"
APPLICATION_NAME = "Azure Compliance Agent"
COMPLIANCE_FRAMEWORK = "NIST Cybersecurity Framework (CSF) 2.0"
CONFIG_VERSION = "1.0.0"
LAST_UPDATED = "2025-10-06"