# -*- encoding: utf-8 -*-
"""
Staleness policies and policy algebra for GAID-governed test suites.

Policies define what happens when staleness is detected. They are composable
via a formal lattice algebra:

    BLOCK              (absorbing: BLOCK + X = BLOCK)
      |
    CASCADE_REVOKE     (dominates actions below)
      |
    RE_EXECUTE         (triggers full re-run)
      |
    SELECTIVE_RETEST   (optimized partial re-run)
      |
    WARN               (transparent: X + WARN = X + advisory)

Policies are bound to subtree paths and compose when multiple policies
apply to the same changed subtree.

Four unifications: policies ARE credentials (ACDC structure).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

from keri.core.coring import Diger, MtrDex


# ---------------------------------------------------------------------------
# Policy types
# ---------------------------------------------------------------------------


class PolicyType(Enum):
    """Staleness policy types, ordered by severity (highest first)."""

    BLOCK = "block"
    CASCADE_REVOKE = "cascade_revoke"
    RE_EXECUTE = "re_execute"
    SELECTIVE_RETEST = "selective_retest"
    WARN = "warn"


# Severity ranking: lower number = higher severity
_SEVERITY: Dict[PolicyType, int] = {
    PolicyType.BLOCK: 0,
    PolicyType.CASCADE_REVOKE: 1,
    PolicyType.RE_EXECUTE: 2,
    PolicyType.SELECTIVE_RETEST: 3,
    PolicyType.WARN: 4,
}


def policy_severity(policy_type: PolicyType) -> int:
    """Return severity rank (0 = most severe)."""
    return _SEVERITY[policy_type]


# ---------------------------------------------------------------------------
# Policy credential (ACDC structure)
# ---------------------------------------------------------------------------


def _compute_said(data: dict) -> str:
    ser = json.dumps(data, sort_keys=True, separators=(",", ":")).encode()
    return Diger(ser=ser, code=MtrDex.Blake3_256).qb64


@dataclass
class PolicyCredential:
    """A staleness policy bound to a subtree path.

    This is the ACDC credential structure. Each policy declares:
    - What type of action to take on staleness
    - Which subtree path it governs
    - Optional parameters (e.g., max staleness depth before escalation)
    - Priority for disambiguation when multiple policies of same type exist

    Attributes:
        policy_type: The action to take when staleness is detected
        subtree_path: The subtree this policy governs (e.g., "source/keri_sec")
        parameters: Additional policy parameters
        priority: Higher priority wins among same-type policies (default 0)
        issuer: AID prefix of the policy issuer
        description: Human-readable description
    """

    policy_type: PolicyType
    subtree_path: str
    parameters: Dict[str, Any] = field(default_factory=dict)
    priority: int = 0
    issuer: Optional[str] = None
    description: Optional[str] = None
    _said: Optional[str] = field(default=None, repr=False)

    @property
    def said(self) -> str:
        if self._said is None:
            self._said = _compute_said(self.to_dict())
        return self._said

    def to_dict(self) -> dict:
        d: Dict[str, Any] = {
            "policy_type": self.policy_type.value,
            "subtree_path": self.subtree_path,
        }
        if self.parameters:
            d["parameters"] = self.parameters
        if self.priority != 0:
            d["priority"] = self.priority
        if self.issuer is not None:
            d["issuer"] = self.issuer
        if self.description is not None:
            d["description"] = self.description
        return d


# ---------------------------------------------------------------------------
# Policy actions and verdicts
# ---------------------------------------------------------------------------


@dataclass
class PolicyAction:
    """A concrete action resulting from policy evaluation."""

    action_type: PolicyType
    subtree_path: str
    source_policy_said: str
    parameters: Dict[str, Any] = field(default_factory=dict)
    reason: Optional[str] = None


@dataclass
class PolicyVerdict:
    """The composed result of evaluating all applicable policies.

    Attributes:
        blocked: True if any BLOCK policy fired
        actions: Ordered list of actions to take (most severe first)
        warnings: Advisory messages from WARN policies
        effective_type: The most severe policy type that fired
        verdict_said: SAID of the verdict for audit trail
    """

    blocked: bool
    actions: List[PolicyAction]
    warnings: List[str]
    effective_type: PolicyType
    _verdict_said: Optional[str] = field(default=None, repr=False)

    @property
    def verdict_said(self) -> str:
        if self._verdict_said is None:
            d = {
                "blocked": self.blocked,
                "effective_type": self.effective_type.value,
                "action_count": len(self.actions),
                "warning_count": len(self.warnings),
            }
            self._verdict_said = _compute_said(d)
        return self._verdict_said

    @property
    def requires_action(self) -> bool:
        """True if any non-WARN action is needed."""
        return self.blocked or any(
            a.action_type != PolicyType.WARN for a in self.actions
        )


# ---------------------------------------------------------------------------
# Policy algebra
# ---------------------------------------------------------------------------


class PolicyAlgebra:
    """Composes multiple policies into a single verdict.

    Composition rules (lattice):
    1. BLOCK + X = BLOCK (absorbing element)
    2. CASCADE_REVOKE + RE_EXECUTE = CASCADE_REVOKE (dominates)
    3. SELECTIVE_RETEST + RE_EXECUTE = both emitted, ordered by severity
    4. X + WARN = X + [advisory] (transparent element)

    Subtree inheritance: if a subtree has no explicit policy, it inherits
    from the nearest ancestor. If no ancestor has a policy, the suite's
    default_staleness_policy applies.
    """

    @staticmethod
    def compose(policies: List[PolicyCredential], changed_paths: List[str]) -> PolicyVerdict:
        """Compose multiple policies into a verdict.

        Args:
            policies: All applicable PolicyCredentials (already resolved
                      via inheritance/matching)
            changed_paths: Subtree paths that actually changed

        Returns:
            PolicyVerdict with composed actions
        """
        if not policies:
            return PolicyVerdict(
                blocked=False,
                actions=[],
                warnings=[],
                effective_type=PolicyType.WARN,
            )

        # Sort by severity (most severe first)
        sorted_policies = sorted(
            policies, key=lambda p: (_SEVERITY[p.policy_type], -p.priority)
        )

        blocked = False
        actions: List[PolicyAction] = []
        warnings: List[str] = []
        seen_types: set = set()

        for policy in sorted_policies:
            ptype = policy.policy_type

            if ptype == PolicyType.BLOCK:
                blocked = True
                actions.append(PolicyAction(
                    action_type=PolicyType.BLOCK,
                    subtree_path=policy.subtree_path,
                    source_policy_said=policy.said,
                    parameters=policy.parameters,
                    reason=f"BLOCK policy on {policy.subtree_path}",
                ))
                # BLOCK is absorbing — skip all lower-severity actions
                break

            if ptype == PolicyType.WARN:
                msg = policy.description or f"Stale: {policy.subtree_path}"
                warnings.append(msg)
                continue

            # For action policies, apply dominance rules
            if ptype == PolicyType.CASCADE_REVOKE:
                # CASCADE_REVOKE subsumes RE_EXECUTE (remove if already added)
                seen_types.add(PolicyType.RE_EXECUTE)
                actions = [a for a in actions if a.action_type != PolicyType.RE_EXECUTE]

            # Skip if this type (or a dominated type) already handled
            if ptype in seen_types:
                continue

            seen_types.add(ptype)
            actions.append(PolicyAction(
                action_type=ptype,
                subtree_path=policy.subtree_path,
                source_policy_said=policy.said,
                parameters=policy.parameters,
                reason=f"{ptype.value} on {policy.subtree_path}",
            ))

        effective = sorted_policies[0].policy_type

        return PolicyVerdict(
            blocked=blocked,
            actions=actions,
            warnings=warnings,
            effective_type=effective,
        )

    @staticmethod
    def dominates(a: PolicyType, b: PolicyType) -> bool:
        """Return True if policy type `a` dominates (is more severe than) `b`."""
        return _SEVERITY[a] < _SEVERITY[b]
