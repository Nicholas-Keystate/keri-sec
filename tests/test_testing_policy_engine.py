# -*- encoding: utf-8 -*-
"""Tests for the policy engine and registry."""

import pytest

from keri_sec.testing.policies import PolicyCredential, PolicyType
from keri_sec.testing.policy_engine import PolicyEngine, PolicyRegistry
from keri_sec.testing.staleness import StalenessDetector, StalenessInfo
from keri_sec.testing.smith_tree import ChangedSubtree
from keri_sec.testing.suite_gaid import (
    TestSuiteGAID,
    TestSuiteGovernanceRules,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def rules():
    return TestSuiteGovernanceRules(
        fail_closed=True,
        default_staleness_policy="WARN",
    )


@pytest.fixture
def suite(rules):
    return TestSuiteGAID(
        name="engine-test-suite",
        governance_rules=rules,
        initial_tree_root_said="EInitRoot_000000000000000000000000000000000",
    )


@pytest.fixture
def engine(suite):
    return PolicyEngine(suite)


def _make_stale_info(
    suite: TestSuiteGAID,
    attested_root: str = "EOldRoot_000000000000000000000000000000000",
    changed_paths: list = None,
) -> StalenessInfo:
    """Helper to create a StalenessInfo for testing."""
    changed = []
    if changed_paths:
        for p in changed_paths:
            changed.append(ChangedSubtree(
                path=p,
                previous_said="EPrev",
                current_said="ECurr",
                changed_files=[f"{p}/file.py"],
                subtree_type="source_module",
            ))
    return StalenessInfo(
        is_stale=True,
        staleness_depth=1,
        attested_sn=0,
        current_sn=1,
        attested_tree_root_said=attested_root,
        current_tree_root_said=suite.current_tree_root_said,
        changed_subtrees=changed,
    )


# ---------------------------------------------------------------------------
# PolicyRegistry tests
# ---------------------------------------------------------------------------


class TestPolicyRegistry:
    def test_register_and_lookup(self):
        reg = PolicyRegistry()
        p = PolicyCredential(PolicyType.BLOCK, "source/keri_sec")
        reg.register(p)
        found = reg.lookup("source/keri_sec")
        assert len(found) == 1
        assert found[0].said == p.said

    def test_lookup_miss(self):
        reg = PolicyRegistry()
        assert reg.lookup("nonexistent") == []

    def test_inheritance_exact_match_first(self):
        reg = PolicyRegistry()
        parent = PolicyCredential(PolicyType.WARN, "source")
        child = PolicyCredential(PolicyType.BLOCK, "source/keri_sec")
        reg.register(parent)
        reg.register(child)
        found = reg.lookup_with_inheritance("source/keri_sec")
        assert len(found) == 1
        assert found[0].policy_type == PolicyType.BLOCK

    def test_inheritance_falls_to_parent(self):
        reg = PolicyRegistry()
        parent = PolicyCredential(PolicyType.RE_EXECUTE, "source")
        reg.register(parent)
        found = reg.lookup_with_inheritance("source/keri_sec/attestation")
        assert len(found) == 1
        assert found[0].policy_type == PolicyType.RE_EXECUTE

    def test_inheritance_falls_to_root(self):
        reg = PolicyRegistry()
        root = PolicyCredential(PolicyType.WARN, "root")
        reg.register(root)
        found = reg.lookup_with_inheritance("source/deep/nested/path")
        assert len(found) == 1
        assert found[0].policy_type == PolicyType.WARN

    def test_inheritance_no_match(self):
        reg = PolicyRegistry()
        # Register for unrelated path
        reg.register(PolicyCredential(PolicyType.BLOCK, "other"))
        found = reg.lookup_with_inheritance("source/keri_sec")
        assert found == []

    def test_all_policies(self):
        reg = PolicyRegistry()
        reg.register(PolicyCredential(PolicyType.BLOCK, "a"))
        reg.register(PolicyCredential(PolicyType.WARN, "b"))
        assert len(reg.all_policies) == 2

    def test_paths(self):
        reg = PolicyRegistry()
        reg.register(PolicyCredential(PolicyType.BLOCK, "source"))
        reg.register(PolicyCredential(PolicyType.WARN, "tests"))
        assert set(reg.paths) == {"source", "tests"}


# ---------------------------------------------------------------------------
# PolicyEngine tests
# ---------------------------------------------------------------------------


class TestPolicyEngineNotStale:
    def test_not_stale_returns_clean_verdict(self, engine, suite):
        info = StalenessInfo(
            is_stale=False,
            staleness_depth=0,
            attested_sn=0,
            current_sn=0,
            attested_tree_root_said=suite.current_tree_root_said,
            current_tree_root_said=suite.current_tree_root_said,
        )
        verdict = engine.evaluate(info)
        assert not verdict.blocked
        assert len(verdict.actions) == 0
        assert len(verdict.warnings) == 0


class TestPolicyEngineStale:
    def test_block_policy_fires(self, engine, suite):
        engine.register_policy(PolicyType.BLOCK, "source/keri_sec")
        info = _make_stale_info(suite, changed_paths=["source/keri_sec"])
        verdict = engine.evaluate(info)
        assert verdict.blocked
        assert verdict.effective_type == PolicyType.BLOCK

    def test_warn_policy_fires(self, engine, suite):
        engine.register_policy(
            PolicyType.WARN, "tests",
            description="Test files changed",
        )
        info = _make_stale_info(suite, changed_paths=["tests"])
        verdict = engine.evaluate(info)
        assert not verdict.blocked
        assert len(verdict.warnings) == 1

    def test_re_execute_policy(self, engine, suite):
        engine.register_policy(PolicyType.RE_EXECUTE, "source")
        info = _make_stale_info(suite, changed_paths=["source"])
        verdict = engine.evaluate(info)
        assert not verdict.blocked
        assert verdict.requires_action
        assert verdict.actions[0].action_type == PolicyType.RE_EXECUTE

    def test_selective_retest_policy(self, engine, suite):
        engine.register_policy(PolicyType.SELECTIVE_RETEST, "source/utils")
        info = _make_stale_info(suite, changed_paths=["source/utils"])
        verdict = engine.evaluate(info)
        assert not verdict.blocked
        assert verdict.actions[0].action_type == PolicyType.SELECTIVE_RETEST

    def test_multiple_policies_compose(self, engine, suite):
        engine.register_policy(PolicyType.CASCADE_REVOKE, "source/keri_sec")
        engine.register_policy(PolicyType.WARN, "tests", description="Tests stale")
        info = _make_stale_info(
            suite, changed_paths=["source/keri_sec", "tests"]
        )
        verdict = engine.evaluate(info)
        assert not verdict.blocked
        assert verdict.effective_type == PolicyType.CASCADE_REVOKE
        assert len(verdict.warnings) == 1

    def test_inherited_policy_applies(self, engine, suite):
        engine.register_policy(PolicyType.RE_EXECUTE, "source")
        info = _make_stale_info(suite, changed_paths=["source/keri_sec/deep"])
        verdict = engine.evaluate(info)
        assert verdict.actions[0].action_type == PolicyType.RE_EXECUTE


class TestPolicyEngineFailClosed:
    def test_fail_closed_default_policy(self, suite):
        """When stale with no registered policies, fail_closed applies default."""
        engine = PolicyEngine(suite)
        info = _make_stale_info(suite, changed_paths=["source/unknown"])
        verdict = engine.evaluate(info)
        # Default is WARN, applied via fail_closed
        assert verdict.effective_type == PolicyType.WARN
        assert len(verdict.actions) == 0  # WARN has no actions, only warnings

    def test_fail_closed_block_default(self):
        """Suite with default_staleness_policy=BLOCK blocks on unknown staleness."""
        rules = TestSuiteGovernanceRules(
            fail_closed=True,
            default_staleness_policy="BLOCK",
        )
        suite = TestSuiteGAID("block-suite", rules, "ERoot_000000000000000000000000000000000000")
        engine = PolicyEngine(suite)
        suite.rotate("ENewRoot_0000000000000000000000000000000000000")
        info = _make_stale_info(suite, changed_paths=["source/unknown"])
        verdict = engine.evaluate(info)
        assert verdict.blocked

    def test_no_fail_closed_no_default(self):
        """Without fail_closed, no policies means clean pass."""
        rules = TestSuiteGovernanceRules(
            fail_closed=False,
            default_staleness_policy="WARN",
        )
        suite = TestSuiteGAID("open-suite", rules, "ERoot_000000000000000000000000000000000000")
        engine = PolicyEngine(suite)
        suite.rotate("ENewRoot_0000000000000000000000000000000000000")
        info = _make_stale_info(suite, changed_paths=["source/anything"])
        verdict = engine.evaluate(info)
        # No policies, no fail_closed → empty compose
        assert not verdict.blocked
        assert len(verdict.actions) == 0

    def test_no_changed_subtrees_uses_root(self, engine, suite):
        """When staleness has no detailed diff, root policies apply."""
        engine.register_policy(PolicyType.RE_EXECUTE, "root")
        info = StalenessInfo(
            is_stale=True,
            staleness_depth=1,
            attested_sn=0,
            current_sn=1,
            attested_tree_root_said="EOld",
            current_tree_root_said=suite.current_tree_root_said,
        )
        verdict = engine.evaluate(info)
        assert verdict.actions[0].action_type == PolicyType.RE_EXECUTE


class TestPolicyEngineRegistration:
    def test_register_policy_returns_credential(self, engine):
        p = engine.register_policy(PolicyType.BLOCK, "source")
        assert p.policy_type == PolicyType.BLOCK
        assert p.said.startswith("E")

    def test_registered_policy_in_registry(self, engine):
        engine.register_policy(PolicyType.WARN, "tests")
        assert len(engine.registry.all_policies) == 1
