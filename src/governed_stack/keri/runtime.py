# -*- encoding: utf-8 -*-
"""
KERI Runtime Provider - Delegating to keri-runtime singleton.

This module is a thin wrapper around keri-runtime. All KERI singleton
management is handled by the shared keri-runtime package to prevent
singleton fracturing across projects.

Usage:
    from governed_stack.keri import get_keri_runtime

    runtime = get_keri_runtime()
    if runtime.available:
        # KERI is ready - use TEL-anchored operations
        pass

Note:
    This module delegates to keri_runtime. The keri-runtime package
    is the single source of truth for KERI infrastructure.
"""

import logging
from typing import Any, Optional

# Re-export from keri_runtime
from keri_runtime import (
    KeriRuntime,
    get_runtime,
    initialize_runtime as _initialize_runtime,
    reset_runtime,
    ensure_keri_available,
)

logger = logging.getLogger(__name__)


def get_keri_runtime(auto_initialize: bool = True) -> KeriRuntime:
    """
    Get the KERI runtime, auto-initializing if possible.

    This is an alias for keri_runtime.get_runtime() with
    governed-stack naming convention.

    Args:
        auto_initialize: If True, try to initialize from infrastructure

    Returns:
        KeriRuntime with available=True if KERI is ready, False otherwise
    """
    return get_runtime(auto_initialize=auto_initialize)


def initialize_runtime(
    hby: Optional[Any] = None,
    rgy: Optional[Any] = None,
    hab: Optional[Any] = None,
    session_id: Optional[str] = None,
) -> KeriRuntime:
    """
    Initialize the KERI runtime with explicit infrastructure.

    Delegates to keri_runtime.initialize_runtime().
    """
    return _initialize_runtime(hby=hby, rgy=rgy, hab=hab, session_id=session_id)


# =============================================================================
# Convenience accessors (ai-orchestrator specific)
# =============================================================================

def get_daid_manager_from_runtime():
    """
    Get DAIDManager using runtime infrastructure.

    Returns:
        DAIDManager if KERI available, None otherwise
    """
    runtime = get_keri_runtime()
    if not runtime.available:
        return None

    try:
        # This import only works with ai-orchestrator
        from agents.daid_manager import get_daid_manager
        return get_daid_manager(hby=runtime.hby, rgy=runtime.rgy)
    except ImportError:
        logger.debug("DAIDManager not available (ai-orchestrator not in path)")
    except Exception as e:
        logger.error(f"Failed to get DAIDManager: {e}")
    return None


def get_credential_service_from_runtime():
    """
    Get CredentialService using runtime infrastructure.

    Returns:
        CredentialService if KERI available, None otherwise
    """
    runtime = get_keri_runtime()
    if not runtime.available:
        return None

    try:
        # This import only works with ai-orchestrator
        from agents.credential_service import get_credential_service
        return get_credential_service(hby=runtime.hby, rgy=runtime.rgy)
    except ImportError:
        logger.debug("CredentialService not available (ai-orchestrator not in path)")
    except Exception as e:
        logger.error(f"Failed to get CredentialService: {e}")
    return None
