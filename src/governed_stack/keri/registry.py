# -*- encoding: utf-8 -*-
"""
KERI Consumer Registry - Delegating to keri-runtime singleton.

This module is a thin wrapper around keri-runtime. All fracture detection
is handled by the shared keri-runtime package.

Usage:
    from governed_stack.keri import register_keri_consumer, check_for_fractures

    # Register your component as a KERI consumer
    register_keri_consumer("my_module", runtime.hby)

    # Check if multiple Habery instances exist (indicates fracture)
    fractures = check_for_fractures()
    if fractures.fractured:
        logger.warning(f"KERI fractures detected: {fractures}")

Note:
    This module delegates to keri_runtime.registry. The keri-runtime package
    is the single source of truth for fracture detection.
"""

# Re-export everything from keri_runtime.registry
from keri_runtime.registry import (
    KeriConsumer,
    FractureReport,
    register_keri_consumer,
    get_registered_consumers,
    check_for_fractures,
    reset_registry,
)

__all__ = [
    "KeriConsumer",
    "FractureReport",
    "register_keri_consumer",
    "get_registered_consumers",
    "check_for_fractures",
    "reset_registry",
]
