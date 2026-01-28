# -*- encoding: utf-8 -*-
"""
TestSuiteGAID: Governed test suite identity.

A stable DAID for a test suite. Content rotates when the TestSmithTree
changes (sn:N -> sn:N+1). GovernanceRules constrain what constitutes
valid test execution.

Staleness = attestation.tree_root_said != suite.current_tree_root_said
This is equivalent to DAID content rotation detection.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from keri.core.coring import Diger, MtrDex


# ---------------------------------------------------------------------------
# Governance Rules
# ---------------------------------------------------------------------------


@dataclass
class TestSuiteGovernanceRules:
    """
    Governance rules for a test suite.

    These constrain what constitutes a valid test execution and what
    policies fire when staleness is detected.
    """

    min_coverage_percent: Optional[float] = None
    required_test_categories: List[str] = field(default_factory=list)
    max_stale_duration_hours: Optional[int] = None
    required_env_gaid: Optional[str] = None
    allowed_runners: List[str] = field(default_factory=list)  # AID prefixes
    fail_closed: bool = True
    default_staleness_policy: str = "WARN"

    def to_dict(self) -> dict:
        d: Dict[str, Any] = {}
        if self.min_coverage_percent is not None:
            d["min_coverage_percent"] = self.min_coverage_percent
        if self.required_test_categories:
            d["required_test_categories"] = self.required_test_categories
        if self.max_stale_duration_hours is not None:
            d["max_stale_duration_hours"] = self.max_stale_duration_hours
        if self.required_env_gaid is not None:
            d["required_env_gaid"] = self.required_env_gaid
        if self.allowed_runners:
            d["allowed_runners"] = self.allowed_runners
        d["fail_closed"] = self.fail_closed
        d["default_staleness_policy"] = self.default_staleness_policy
        return d

    @classmethod
    def from_dict(cls, d: dict) -> TestSuiteGovernanceRules:
        return cls(
            min_coverage_percent=d.get("min_coverage_percent"),
            required_test_categories=d.get("required_test_categories", []),
            max_stale_duration_hours=d.get("max_stale_duration_hours"),
            required_env_gaid=d.get("required_env_gaid"),
            allowed_runners=d.get("allowed_runners", []),
            fail_closed=d.get("fail_closed", True),
            default_staleness_policy=d.get("default_staleness_policy", "WARN"),
        )

    def check_coverage(self, actual_percent: float) -> Optional[str]:
        """Return violation message if coverage too low, else None."""
        if self.min_coverage_percent is not None:
            if actual_percent < self.min_coverage_percent:
                return (
                    f"Coverage {actual_percent:.1f}% below minimum "
                    f"{self.min_coverage_percent:.1f}%"
                )
        return None

    def check_runner(self, runner_aid: str) -> Optional[str]:
        """Return violation message if runner not allowed, else None."""
        if self.allowed_runners:
            if not any(runner_aid.startswith(p) for p in self.allowed_runners):
                return f"Runner {runner_aid[:12]}... not in allowed_runners"
        return None

    def check_env_gaid(self, actual_env_gaid: str) -> Optional[str]:
        """Return violation message if env GAID doesn't match, else None."""
        if self.required_env_gaid is not None:
            if actual_env_gaid != self.required_env_gaid:
                return (
                    f"Environment GAID mismatch: expected "
                    f"{self.required_env_gaid[:12]}..., "
                    f"got {actual_env_gaid[:12]}..."
                )
        return None


# ---------------------------------------------------------------------------
# Version chain
# ---------------------------------------------------------------------------


@dataclass
class TestSuiteVersion:
    """A version of the test suite (one per tree root change)."""

    sequence: int  # sn
    tree_root_said: str
    timestamp: str
    change_summary: Optional[str] = None
    credential_said: Optional[str] = None  # TEL-anchored credential

    def to_dict(self) -> dict:
        return {
            "sequence": self.sequence,
            "tree_root_said": self.tree_root_said,
            "timestamp": self.timestamp,
            "change_summary": self.change_summary,
            "credential_said": self.credential_said,
        }


# ---------------------------------------------------------------------------
# TestSuiteGAID
# ---------------------------------------------------------------------------


def _compute_said(data: dict) -> str:
    """Compute SAID for a dict."""
    ser = json.dumps(data, sort_keys=True, separators=(",", ":")).encode()
    return Diger(ser=ser, code=MtrDex.Blake3_256).qb64


class TestSuiteGAID:
    """
    Governed test suite with stable DAID identity.

    The GAID (prefix) is computed from inception data and never changes.
    Each TestSmithTree root change = content rotation (sn:N -> sn:N+1).
    The version chain is append-only.
    """

    def __init__(
        self,
        name: str,
        governance_rules: TestSuiteGovernanceRules,
        initial_tree_root_said: str,
    ):
        # Compute stable GAID from inception
        inception = {
            "name": name,
            "initial_tree_root_said": initial_tree_root_said,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        self._gaid = _compute_said(inception)
        self._name = name
        self._governance_rules = governance_rules
        self._versions: List[TestSuiteVersion] = []

        # Record initial version (sn=0)
        self._versions.append(
            TestSuiteVersion(
                sequence=0,
                tree_root_said=initial_tree_root_said,
                timestamp=inception["created_at"],
                change_summary="Initial version",
            )
        )

    @property
    def gaid(self) -> str:
        """Stable identifier (never changes)."""
        return self._gaid

    @property
    def name(self) -> str:
        return self._name

    @property
    def governance_rules(self) -> TestSuiteGovernanceRules:
        return self._governance_rules

    @property
    def current_sn(self) -> int:
        """Current sequence number."""
        return self._versions[-1].sequence

    @property
    def current_tree_root_said(self) -> str:
        """Current tree root SAID."""
        return self._versions[-1].tree_root_said

    @property
    def current_version(self) -> TestSuiteVersion:
        return self._versions[-1]

    @property
    def versions(self) -> List[TestSuiteVersion]:
        return list(self._versions)

    def rotate(
        self,
        new_tree_root_said: str,
        change_summary: Optional[str] = None,
    ) -> TestSuiteVersion:
        """
        Content rotation: register a new tree root (sn:N+1).

        The GAID stays the same. The tree root changes.
        All prior test attestations referencing the old root are now stale.

        Args:
            new_tree_root_said: Root SAID of the updated TestSmithTree
            change_summary: Human-readable description of what changed

        Returns:
            The new TestSuiteVersion

        Raises:
            ValueError: If the new root is the same as current (no-op rotation)
        """
        if new_tree_root_said == self.current_tree_root_said:
            raise ValueError(
                "Cannot rotate to the same tree root SAID. "
                "No content change detected."
            )

        new_sn = self.current_sn + 1
        version = TestSuiteVersion(
            sequence=new_sn,
            tree_root_said=new_tree_root_said,
            timestamp=datetime.now(timezone.utc).isoformat(),
            change_summary=change_summary,
        )
        self._versions.append(version)
        return version

    def is_stale(self, tree_root_said: str) -> bool:
        """
        Check if a tree root SAID is stale (not current).

        This is the core staleness check: if the attestation references
        a different tree root than current, it's stale.
        """
        return tree_root_said != self.current_tree_root_said

    def stale_since(self, tree_root_said: str) -> Optional[int]:
        """
        Return the sn gap between the given root and current.

        Returns None if the root was never part of this suite.
        Returns 0 if the root is current (not stale).
        Returns positive int for how many rotations behind.
        """
        for version in self._versions:
            if version.tree_root_said == tree_root_said:
                return self.current_sn - version.sequence
        return None

    def version_at_sn(self, sn: int) -> Optional[TestSuiteVersion]:
        """Get the version at a specific sequence number."""
        for v in self._versions:
            if v.sequence == sn:
                return v
        return None

    def summary(self) -> dict:
        return {
            "gaid": self._gaid,
            "name": self._name,
            "current_sn": self.current_sn,
            "current_tree_root_said": self.current_tree_root_said,
            "total_versions": len(self._versions),
            "governance_rules": self._governance_rules.to_dict(),
        }
