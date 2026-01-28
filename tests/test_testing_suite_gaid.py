# -*- encoding: utf-8 -*-
"""Tests for TestSuiteGAID: governed test suite identity."""

import pytest

from keri_sec.testing.suite_gaid import (
    TestSuiteGAID,
    TestSuiteGovernanceRules,
    TestSuiteVersion,
)


@pytest.fixture
def rules():
    return TestSuiteGovernanceRules(
        min_coverage_percent=80.0,
        required_test_categories=["unit", "integration"],
        fail_closed=True,
        default_staleness_policy="WARN",
    )


@pytest.fixture
def suite(rules):
    return TestSuiteGAID(
        name="keri-sec-tests",
        governance_rules=rules,
        initial_tree_root_said="EInitialRootSAID000000000000000000000000000",
    )


class TestGAIDStability:
    def test_gaid_is_stable(self, suite):
        """GAID prefix computed at inception, never changes."""
        gaid = suite.gaid
        assert gaid.startswith("E")
        # Rotate content
        suite.rotate("ENewRoot1_000000000000000000000000000000000")
        assert suite.gaid == gaid

    def test_gaid_stable_through_multiple_rotations(self, suite):
        gaid = suite.gaid
        for i in range(5):
            suite.rotate(f"ERoot_{i}_00000000000000000000000000000000000")
        assert suite.gaid == gaid

    def test_different_suites_different_gaids(self, rules):
        s1 = TestSuiteGAID("suite-a", rules, "ERoot_A")
        s2 = TestSuiteGAID("suite-b", rules, "ERoot_B")
        assert s1.gaid != s2.gaid


class TestVersionChain:
    def test_initial_version(self, suite):
        assert suite.current_sn == 0
        assert suite.current_tree_root_said == "EInitialRootSAID000000000000000000000000000"

    def test_rotate_increments_sn(self, suite):
        suite.rotate("ENewRoot_000000000000000000000000000000000000")
        assert suite.current_sn == 1

    def test_rotate_updates_tree_root(self, suite):
        new_root = "ENewRoot_000000000000000000000000000000000000"
        suite.rotate(new_root)
        assert suite.current_tree_root_said == new_root

    def test_version_chain_append_only(self, suite):
        roots = ["EInitialRootSAID000000000000000000000000000"]
        for i in range(3):
            root = f"ERoot_{i}_00000000000000000000000000000000000"
            suite.rotate(root)
            roots.append(root)
        assert len(suite.versions) == 4
        for i, v in enumerate(suite.versions):
            assert v.sequence == i
            assert v.tree_root_said == roots[i]

    def test_rotate_same_root_raises(self, suite):
        with pytest.raises(ValueError, match="Cannot rotate to the same"):
            suite.rotate("EInitialRootSAID000000000000000000000000000")

    def test_version_has_timestamp(self, suite):
        v = suite.rotate("ENewRoot_000000000000000000000000000000000000")
        assert v.timestamp is not None
        assert "T" in v.timestamp  # ISO format

    def test_change_summary(self, suite):
        v = suite.rotate("ENewRoot_000000000000000000000000000000000000",
                         change_summary="Modified core.py")
        assert v.change_summary == "Modified core.py"

    def test_version_at_sn(self, suite):
        suite.rotate("ERoot1_0000000000000000000000000000000000000")
        suite.rotate("ERoot2_0000000000000000000000000000000000000")
        v = suite.version_at_sn(1)
        assert v is not None
        assert v.tree_root_said == "ERoot1_0000000000000000000000000000000000000"
        assert suite.version_at_sn(99) is None


class TestStaleness:
    def test_current_root_not_stale(self, suite):
        assert not suite.is_stale(suite.current_tree_root_said)

    def test_old_root_is_stale(self, suite):
        old_root = suite.current_tree_root_said
        suite.rotate("ENewRoot_000000000000000000000000000000000000")
        assert suite.is_stale(old_root)

    def test_stale_since_current(self, suite):
        assert suite.stale_since(suite.current_tree_root_said) == 0

    def test_stale_since_one_rotation(self, suite):
        old_root = suite.current_tree_root_said
        suite.rotate("ENewRoot_000000000000000000000000000000000000")
        assert suite.stale_since(old_root) == 1

    def test_stale_since_multiple_rotations(self, suite):
        old_root = suite.current_tree_root_said
        for i in range(5):
            suite.rotate(f"ERoot_{i}_00000000000000000000000000000000000")
        assert suite.stale_since(old_root) == 5

    def test_stale_since_unknown_root(self, suite):
        assert suite.stale_since("ENeverExisted") is None


class TestGovernanceRules:
    def test_coverage_check_passes(self, rules):
        assert rules.check_coverage(85.0) is None

    def test_coverage_check_fails(self, rules):
        msg = rules.check_coverage(70.0)
        assert msg is not None
        assert "70.0%" in msg

    def test_runner_check_passes(self):
        rules = TestSuiteGovernanceRules(allowed_runners=["BAbc", "BDef"])
        assert rules.check_runner("BAbcXYZ123") is None

    def test_runner_check_fails(self):
        rules = TestSuiteGovernanceRules(allowed_runners=["BAbc"])
        msg = rules.check_runner("BUnknownRunner")
        assert msg is not None

    def test_runner_check_empty_allows_all(self):
        rules = TestSuiteGovernanceRules(allowed_runners=[])
        assert rules.check_runner("BAnyRunner") is None

    def test_env_gaid_check_passes(self):
        rules = TestSuiteGovernanceRules(required_env_gaid="EEnvGAID123")
        assert rules.check_env_gaid("EEnvGAID123") is None

    def test_env_gaid_check_fails(self):
        rules = TestSuiteGovernanceRules(required_env_gaid="EEnvGAID123")
        msg = rules.check_env_gaid("EDifferentGAID")
        assert msg is not None

    def test_rules_serialization(self, rules):
        d = rules.to_dict()
        restored = TestSuiteGovernanceRules.from_dict(d)
        assert restored.min_coverage_percent == rules.min_coverage_percent
        assert restored.fail_closed == rules.fail_closed
        assert restored.default_staleness_policy == rules.default_staleness_policy

    def test_summary(self, suite):
        s = suite.summary()
        assert s["name"] == "keri-sec-tests"
        assert s["current_sn"] == 0
        assert "governance_rules" in s
