# -*- encoding: utf-8 -*-
"""
Policy engine for GAID-governed test suites.

The PolicyEngine is the governance gate. It:
1. Maintains a registry of PolicyCredentials bound to subtree paths
2. Resolves which policies apply to changed subtrees (with inheritance)
3. Composes policies via PolicyAlgebra into a PolicyVerdict
4. Returns actionable verdict for the test runner

Usage:
    engine = PolicyEngine(suite)
    engine.register_policy(PolicyType.BLOCK, "source/keri_sec/keri")
    engine.register_policy(PolicyType.WARN, "tests")

    verdict = engine.evaluate(staleness_info)
    if verdict.blocked:
        raise RuntimeError("Pipeline blocked by staleness policy")
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from keri_sec.testing.policies import (
    PolicyAlgebra,
    PolicyCredential,
    PolicyType,
    PolicyVerdict,
)
from keri_sec.testing.staleness import StalenessInfo
from keri_sec.testing.suite_gaid import TestSuiteGAID


# ---------------------------------------------------------------------------
# Policy registry
# ---------------------------------------------------------------------------


class PolicyRegistry:
    """Index of PolicyCredentials by subtree path.

    Supports exact match and ancestor inheritance: if no policy exists
    for a specific subtree path, walks up path components to find the
    nearest ancestor policy.
    """

    def __init__(self):
        self._policies: Dict[str, List[PolicyCredential]] = {}
        self._all_policies: List[PolicyCredential] = []

    def register(self, policy: PolicyCredential) -> None:
        """Register a policy for a subtree path."""
        path = policy.subtree_path
        if path not in self._policies:
            self._policies[path] = []
        self._policies[path].append(policy)
        self._all_policies.append(policy)

    def lookup(self, subtree_path: str) -> List[PolicyCredential]:
        """Find policies for a subtree path (exact match only)."""
        return list(self._policies.get(subtree_path, []))

    def lookup_with_inheritance(self, subtree_path: str) -> List[PolicyCredential]:
        """Find policies for a subtree path, walking up ancestors.

        Tries exact match first, then progressively shorter prefixes.
        Returns policies from the nearest ancestor that has any.
        """
        # Exact match
        exact = self.lookup(subtree_path)
        if exact:
            return exact

        # Walk up path components
        parts = subtree_path.split("/")
        for i in range(len(parts) - 1, 0, -1):
            ancestor = "/".join(parts[:i])
            policies = self.lookup(ancestor)
            if policies:
                return policies

        # Root-level policies (empty string or "root")
        for root_key in ("", "root"):
            policies = self.lookup(root_key)
            if policies:
                return policies

        return []

    @property
    def all_policies(self) -> List[PolicyCredential]:
        return list(self._all_policies)

    @property
    def paths(self) -> List[str]:
        return list(self._policies.keys())


# ---------------------------------------------------------------------------
# Policy engine
# ---------------------------------------------------------------------------


class PolicyEngine:
    """The governance gate for test execution.

    Evaluates staleness against registered policies and produces
    a PolicyVerdict that the test runner can act on.
    """

    def __init__(
        self,
        suite: TestSuiteGAID,
        registry: Optional[PolicyRegistry] = None,
    ):
        self._suite = suite
        self._registry = registry or PolicyRegistry()

    @property
    def registry(self) -> PolicyRegistry:
        return self._registry

    def register_policy(
        self,
        policy_type: PolicyType,
        subtree_path: str,
        parameters: Optional[Dict] = None,
        priority: int = 0,
        issuer: Optional[str] = None,
        description: Optional[str] = None,
    ) -> PolicyCredential:
        """Create and register a policy credential.

        Returns the created PolicyCredential.
        """
        policy = PolicyCredential(
            policy_type=policy_type,
            subtree_path=subtree_path,
            parameters=parameters or {},
            priority=priority,
            issuer=issuer,
            description=description,
        )
        self._registry.register(policy)
        return policy

    def evaluate(self, staleness: StalenessInfo) -> PolicyVerdict:
        """Evaluate staleness against registered policies.

        If not stale, returns a clean verdict (no actions).
        If stale, resolves applicable policies for each changed subtree
        and composes them via PolicyAlgebra.

        Args:
            staleness: StalenessInfo from StalenessDetector

        Returns:
            PolicyVerdict with composed actions
        """
        if not staleness.is_stale:
            return PolicyVerdict(
                blocked=False,
                actions=[],
                warnings=[],
                effective_type=PolicyType.WARN,
            )

        # Collect applicable policies for all changed subtrees
        applicable: List[PolicyCredential] = []
        changed_paths: List[str] = []

        if staleness.changed_subtrees:
            for cs in staleness.changed_subtrees:
                changed_paths.append(cs.path)
                policies = self._registry.lookup_with_inheritance(cs.path)
                applicable.extend(policies)
        else:
            # No detailed diff available — use root-level policies
            changed_paths.append("root")
            applicable = self._resolve_default_policies()

        # Deduplicate by SAID
        seen_saids: set = set()
        unique: List[PolicyCredential] = []
        for p in applicable:
            if p.said not in seen_saids:
                seen_saids.add(p.said)
                unique.append(p)

        # If no policies found but stale, apply fail-closed behavior
        if not unique and self._suite.governance_rules.fail_closed:
            default_type = _parse_default_policy(
                self._suite.governance_rules.default_staleness_policy
            )
            unique.append(PolicyCredential(
                policy_type=default_type,
                subtree_path="root",
                description=f"Default staleness policy: {default_type.value}",
            ))

        return PolicyAlgebra.compose(unique, changed_paths)

    def _resolve_default_policies(self) -> List[PolicyCredential]:
        """Get root-level or default policies."""
        root_policies = self._registry.lookup_with_inheritance("root")
        if root_policies:
            return root_policies
        return []


def _parse_default_policy(policy_str: str) -> PolicyType:
    """Parse a default staleness policy string to PolicyType."""
    mapping = {
        "BLOCK": PolicyType.BLOCK,
        "WARN": PolicyType.WARN,
        "RE_EXECUTE": PolicyType.RE_EXECUTE,
        "CASCADE_REVOKE": PolicyType.CASCADE_REVOKE,
        "SELECTIVE_RETEST": PolicyType.SELECTIVE_RETEST,
    }
    return mapping.get(policy_str.upper(), PolicyType.WARN)
