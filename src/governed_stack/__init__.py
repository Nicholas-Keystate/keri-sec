# -*- encoding: utf-8 -*-
"""
Governed Stack - KERI-Governed Dependency Management

HYPER-EXPERIMENTAL: This package is in early development.
API may change without notice. Use at your own risk.

Provides cryptographic source of truth for version constraints using KERI primitives.
Bridges governance with execution (UV, pip) without compromising security.

Key Insight:
    UV/pip are EXECUTION tools - they install packages fast.
    Governed Stack is the GOVERNANCE layer - it answers:
      - WHY is this version required?
      - WHO approved it?
      - WHEN can we change it?
      - WHAT's the audit trail?

Architecture:
    ┌─────────────────────────────────────────────────────────┐
    │                   Stack Registry                        │
    │  Constraint SAIDs with controller AIDs and audit trail  │
    └──────────────────────┬──────────────────────────────────┘
                           │
                           ▼
    ┌─────────────────────────────────────────────────────────┐
    │             StackManager                                │
    │  - Defines stacks with cryptographic SAIDs              │
    │  - Verifies environment compliance                      │
    │  - Generates pyproject.toml / requirements.txt          │
    │  - Invokes UV/pip for installation                      │
    └──────────────────────┬──────────────────────────────────┘
                           │
                           ▼
    ┌─────────────────────────────────────────────────────────┐
    │              UV / pip                                   │
    │  Actually installs the governed versions                │
    └─────────────────────────────────────────────────────────┘

Usage:
    from governed_stack import StackManager, KERI_PRODUCTION_STACK

    # Create manager
    sm = StackManager()

    # Define a governed stack
    stack = sm.define_stack(
        name="my-project",
        controller_aid="BMASTER_AID...",
        constraints=KERI_PRODUCTION_STACK,
        rationale="Production KERI deployment",
    )

    # Check compliance
    result = sm.check_compliance(stack.said)
    if not result.compliant:
        sm.install_with_uv(stack.said)

    # Generate pyproject.toml
    toml = sm.generate_pyproject(stack.said)
"""

__version__ = "0.1.0"

from governed_stack.manager import (
    StackManager,
    ConstraintType,
    Constraint,
    StackProfile,
    ComplianceResult,
    ConstraintCheck,
    get_stack_manager,
    reset_stack_manager,
)

from governed_stack.stacks import (
    KERI_PRODUCTION_STACK,
    KERI_DEV_STACK,
    KGQL_STACK,
    AI_ORCHESTRATOR_STACK,
    WITNESS_STACK,
    MINIMAL_STACK,
)

__all__ = [
    # Manager
    "StackManager",
    "ConstraintType",
    "Constraint",
    "StackProfile",
    "ComplianceResult",
    "ConstraintCheck",
    "get_stack_manager",
    "reset_stack_manager",
    # Pre-defined stacks
    "KERI_PRODUCTION_STACK",
    "KERI_DEV_STACK",
    "KGQL_STACK",
    "AI_ORCHESTRATOR_STACK",
    "WITNESS_STACK",
    "MINIMAL_STACK",
]
