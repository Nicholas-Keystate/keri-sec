# -*- encoding: utf-8 -*-
"""
Staleness detection for GAID-governed test suites.

Staleness = DAID content rotation. When the TestSmithTree root changes
(sn:N -> sn:N+1), all prior test attestations referencing sn:N are stale.

This module provides:
- StalenessInfo: structured result of staleness detection
- StalenessDetector: compares an attestation's tree root against current state
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from keri_sec.testing.smith_tree import ChangedSubtree, TestSmithTree, TreeDiff
from keri_sec.testing.suite_gaid import TestSuiteGAID


# ---------------------------------------------------------------------------
# Staleness result
# ---------------------------------------------------------------------------


@dataclass
class StalenessInfo:
    """Structured result of staleness detection.

    Attributes:
        is_stale: True if the attested root != current root
        staleness_depth: Number of rotations behind (0 = current, None = unknown)
        attested_sn: The sn referenced by the attestation
        current_sn: The suite's current sn
        attested_tree_root_said: Tree root SAID from the attestation
        current_tree_root_said: Current tree root SAID
        tree_diff: Detailed diff if both trees are available
        env_changed: Whether the runtime environment leaf changed
        changed_subtrees: Subtrees that changed between attested and current
    """

    is_stale: bool
    staleness_depth: Optional[int]
    attested_sn: Optional[int]
    current_sn: int
    attested_tree_root_said: str
    current_tree_root_said: str
    tree_diff: Optional[TreeDiff] = None
    env_changed: bool = False
    changed_subtrees: List[ChangedSubtree] = field(default_factory=list)

    @property
    def is_current(self) -> bool:
        return not self.is_stale

    @property
    def summary(self) -> str:
        if not self.is_stale:
            return f"Current (sn:{self.current_sn})"
        depth = self.staleness_depth
        depth_str = f"{depth} rotation(s)" if depth is not None else "unknown depth"
        return (
            f"Stale by {depth_str}: "
            f"attested sn:{self.attested_sn} vs current sn:{self.current_sn}"
        )


# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------


class StalenessDetector:
    """Detects staleness by comparing attested tree root against suite state.

    Usage:
        detector = StalenessDetector(suite_gaid)
        info = detector.detect(attested_tree_root_said="ERoot_old...")
        if info.is_stale:
            print(info.summary)
    """

    def __init__(self, suite: TestSuiteGAID):
        self._suite = suite

    def detect(
        self,
        attested_tree_root_said: str,
        current_tree: Optional[TestSmithTree] = None,
        attested_tree: Optional[TestSmithTree] = None,
    ) -> StalenessInfo:
        """Detect staleness for a given attested tree root SAID.

        Args:
            attested_tree_root_said: The tree root SAID from a test attestation
            current_tree: Current TestSmithTree (for detailed diff)
            attested_tree: The tree at attestation time (for detailed diff)

        Returns:
            StalenessInfo with detection results
        """
        is_stale = self._suite.is_stale(attested_tree_root_said)
        depth = self._suite.stale_since(attested_tree_root_said)

        # Resolve the attested sn
        attested_sn = None
        if depth is not None:
            attested_sn = self._suite.current_sn - depth

        # Compute tree diff if both trees provided
        tree_diff = None
        env_changed = False
        changed_subtrees: List[ChangedSubtree] = []

        if current_tree is not None and attested_tree is not None:
            tree_diff = current_tree.diff(attested_tree)
            env_changed = tree_diff.env_changed
            changed_subtrees = tree_diff.changed_subtrees

        return StalenessInfo(
            is_stale=is_stale,
            staleness_depth=depth,
            attested_sn=attested_sn,
            current_sn=self._suite.current_sn,
            attested_tree_root_said=attested_tree_root_said,
            current_tree_root_said=self._suite.current_tree_root_said,
            tree_diff=tree_diff,
            env_changed=env_changed,
            changed_subtrees=changed_subtrees,
        )
