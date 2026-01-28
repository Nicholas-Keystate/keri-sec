# -*- encoding: utf-8 -*-
"""Tests for staleness detection."""

import pytest

from keri_sec.testing.staleness import StalenessDetector, StalenessInfo
from keri_sec.testing.suite_gaid import (
    TestSuiteGAID,
    TestSuiteGovernanceRules,
)


@pytest.fixture
def rules():
    return TestSuiteGovernanceRules(
        min_coverage_percent=80.0,
        fail_closed=True,
        default_staleness_policy="WARN",
    )


@pytest.fixture
def suite(rules):
    return TestSuiteGAID(
        name="staleness-test-suite",
        governance_rules=rules,
        initial_tree_root_said="EInitRoot_000000000000000000000000000000000",
    )


@pytest.fixture
def detector(suite):
    return StalenessDetector(suite)


class TestStalenessDetection:
    def test_current_root_not_stale(self, detector, suite):
        info = detector.detect(suite.current_tree_root_said)
        assert not info.is_stale
        assert info.is_current
        assert info.staleness_depth == 0
        assert info.attested_sn == suite.current_sn

    def test_old_root_is_stale(self, detector, suite):
        old_root = suite.current_tree_root_said
        suite.rotate("ENewRoot_000000000000000000000000000000000000")
        info = detector.detect(old_root)
        assert info.is_stale
        assert not info.is_current
        assert info.staleness_depth == 1
        assert info.attested_sn == 0
        assert info.current_sn == 1

    def test_staleness_depth_multiple_rotations(self, detector, suite):
        old_root = suite.current_tree_root_said
        for i in range(5):
            suite.rotate(f"ERoot_{i}_00000000000000000000000000000000000")
        info = detector.detect(old_root)
        assert info.staleness_depth == 5
        assert info.attested_sn == 0
        assert info.current_sn == 5

    def test_unknown_root_returns_none_depth(self, detector):
        info = detector.detect("ENeverExistedRoot")
        assert info.is_stale
        assert info.staleness_depth is None
        assert info.attested_sn is None


class TestStalenessInfoSummary:
    def test_current_summary(self, detector, suite):
        info = detector.detect(suite.current_tree_root_said)
        assert "Current" in info.summary

    def test_stale_summary(self, detector, suite):
        old_root = suite.current_tree_root_said
        suite.rotate("ENewRoot_000000000000000000000000000000000000")
        info = detector.detect(old_root)
        assert "Stale" in info.summary
        assert "1 rotation" in info.summary

    def test_unknown_root_summary(self, detector):
        info = detector.detect("ENeverExistedRoot")
        assert "unknown depth" in info.summary


class TestStalenessWithTreeDiff:
    def test_no_diff_without_trees(self, detector, suite):
        old_root = suite.current_tree_root_said
        suite.rotate("ENewRoot_000000000000000000000000000000000000")
        info = detector.detect(old_root)
        assert info.tree_diff is None
        assert info.changed_subtrees == []
        assert not info.env_changed
