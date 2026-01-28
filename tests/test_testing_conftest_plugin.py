# -*- encoding: utf-8 -*-
"""Tests for the GAID pytest plugin."""

import pytest
from pathlib import Path

from keri_sec.testing.conftest_plugin import (
    KeriTestConfig,
    KeriTestPlugin,
    ResultCollector,
    _path_overlaps_changes,
)
from keri_sec.testing.policies import PolicyType
from keri_sec.testing.policy_engine import PolicyEngine
from keri_sec.testing.smith_tree import ChangedSubtree, TestSmithTree
from keri_sec.testing.staleness import StalenessInfo
from keri_sec.testing.suite_gaid import TestSuiteGAID, TestSuiteGovernanceRules


FIXED_TIMESTAMP = "2026-01-28T12:00:00+00:00"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def sample_project(tmp_path):
    src = tmp_path / "src" / "mylib"
    src.mkdir(parents=True)
    (src / "__init__.py").write_text("")
    (src / "core.py").write_text("def hello(): return 'world'")
    (src / "utils.py").write_text("def add(a, b): return a + b")

    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "test_core.py").write_text("def test_hello(): pass")
    (tests / "test_utils.py").write_text("def test_add(): pass")

    return tmp_path


@pytest.fixture
def config(sample_project):
    return KeriTestConfig(
        suite_name="test-plugin-suite",
        source_dirs=["src"],
        test_dirs=["tests"],
        project_root=str(sample_project),
        default_policy="warn",
        fail_closed=True,
    )


@pytest.fixture
def plugin(config):
    return KeriTestPlugin(config)


# ---------------------------------------------------------------------------
# KeriTestConfig
# ---------------------------------------------------------------------------


class TestKeriTestConfig:
    def test_defaults(self):
        cfg = KeriTestConfig()
        assert cfg.suite_name == "default-suite"
        assert cfg.source_dirs == ["src"]
        assert cfg.fail_closed is True

    def test_from_dict(self):
        d = {
            "suite_name": "my-suite",
            "source_dirs": ["lib"],
            "default_policy": "block",
            "min_coverage_percent": 90.0,
        }
        cfg = KeriTestConfig.from_dict(d)
        assert cfg.suite_name == "my-suite"
        assert cfg.source_dirs == ["lib"]
        assert cfg.default_policy == "block"
        assert cfg.min_coverage_percent == 90.0


# ---------------------------------------------------------------------------
# ResultCollector
# ---------------------------------------------------------------------------


class TestResultCollector:
    def test_empty_results(self):
        rc = ResultCollector()
        r = rc.to_results()
        assert r.total == 0
        assert r.passed == 0

    def test_record_outcomes(self):
        rc = ResultCollector()
        rc.record("test_a", passed=True, failed=False, skipped=False)
        rc.record("test_b", passed=False, failed=True, skipped=False)
        rc.record("test_c", passed=False, failed=False, skipped=True)
        r = rc.to_results()
        assert r.total == 3
        assert r.passed == 1
        assert r.failed == 1
        assert r.skipped == 1

    def test_duration(self):
        rc = ResultCollector()
        rc.set_start(100.0)
        rc.set_end(112.5)
        r = rc.to_results()
        assert r.duration_seconds == 12.5

    def test_coverage_passthrough(self):
        rc = ResultCollector()
        r = rc.to_results(coverage_percent=85.0)
        assert r.coverage_percent == 85.0


# ---------------------------------------------------------------------------
# Plugin: tree building
# ---------------------------------------------------------------------------


class TestPluginTreeBuilding:
    def test_builds_tree(self, plugin):
        assert plugin.tree.root_said is not None
        assert plugin.tree.root_said.startswith("E")

    def test_tree_has_leaves(self, plugin):
        assert plugin.tree.leaf_count() == 5  # 3 src + 2 tests


# ---------------------------------------------------------------------------
# Plugin: configure (staleness + policy evaluation)
# ---------------------------------------------------------------------------


class TestPluginConfigure:
    def test_no_staleness_on_first_run(self, plugin):
        verdict = plugin.configure()
        assert not verdict.blocked
        assert plugin.staleness is not None
        assert not plugin.staleness.is_stale

    def test_stale_with_old_root(self, config):
        plugin = KeriTestPlugin(config)
        # Simulate rotation
        plugin.suite.rotate("ENewRoot_000000000000000000000000000000000000")
        old_root = "EInitRoot_that_no_longer_matches"
        verdict = plugin.configure(attested_tree_root_said=old_root)
        # old_root was never in the suite, so staleness_depth is None
        assert plugin.staleness.is_stale

    def test_block_policy_blocks(self, config):
        plugin = KeriTestPlugin(config)
        plugin.engine.register_policy(PolicyType.BLOCK, "root")
        # Rotate to create staleness
        plugin.suite.rotate("ENewRoot_000000000000000000000000000000000000")
        # Use a root that was in the suite (the initial one)
        initial_root = plugin.suite.versions[0].tree_root_said
        verdict = plugin.configure(attested_tree_root_said=initial_root)
        assert verdict.blocked


# ---------------------------------------------------------------------------
# Plugin: SELECTIVE_RETEST filtering
# ---------------------------------------------------------------------------


class TestPluginSelectiveRetest:
    def test_no_filter_when_not_stale(self, plugin):
        plugin.configure()
        items = ["tests/test_core.py::test_hello", "tests/test_utils.py::test_add"]
        selected, deselected = plugin.filter_items(items)
        assert selected == items
        assert deselected == []

    def test_no_filter_without_selective_policy(self, config):
        plugin = KeriTestPlugin(config)
        plugin.engine.register_policy(PolicyType.RE_EXECUTE, "root")
        plugin.suite.rotate("ENewRoot_000000000000000000000000000000000000")
        initial_root = plugin.suite.versions[0].tree_root_said

        # Manually set staleness with changed subtrees
        plugin._staleness = StalenessInfo(
            is_stale=True,
            staleness_depth=1,
            attested_sn=0,
            current_sn=1,
            attested_tree_root_said=initial_root,
            current_tree_root_said=plugin.suite.current_tree_root_said,
            changed_subtrees=[ChangedSubtree(
                path="source/mylib",
                previous_said="EPrev",
                current_said="ECurr",
                changed_files=["src/mylib/core.py"],
                subtree_type="source_module",
            )],
        )
        plugin._verdict = plugin.engine.evaluate(plugin._staleness)

        items = ["tests/test_core.py::test_hello", "tests/test_utils.py::test_add"]
        selected, deselected = plugin.filter_items(items)
        # RE_EXECUTE doesn't filter, runs everything
        assert selected == items


class TestPluginSelectiveRetestFiltering:
    def test_selective_retest_filters_unchanged(self):
        """SELECTIVE_RETEST deselects tests for unchanged modules."""
        config = KeriTestConfig(suite_name="selective-suite")
        rules = TestSuiteGovernanceRules(
            fail_closed=True,
            default_staleness_policy="SELECTIVE_RETEST",
        )
        suite = TestSuiteGAID("selective-suite", rules, "EInitRoot")
        engine = PolicyEngine(suite)
        engine.register_policy(PolicyType.SELECTIVE_RETEST, "root")

        plugin = KeriTestPlugin(config, suite=suite, engine=engine)
        suite.rotate("ENewRoot_000000000000000000000000000000000000")

        # Manually set staleness with specific changed files
        plugin._staleness = StalenessInfo(
            is_stale=True,
            staleness_depth=1,
            attested_sn=0,
            current_sn=1,
            attested_tree_root_said="EInitRoot",
            current_tree_root_said=suite.current_tree_root_said,
            changed_subtrees=[ChangedSubtree(
                path="source/mylib",
                previous_said="EPrev",
                current_said="ECurr",
                changed_files=["src/mylib/core.py"],
                subtree_type="source_module",
            )],
        )
        plugin._verdict = engine.evaluate(plugin._staleness)

        items = [
            "tests/test_core.py::test_hello",
            "tests/test_utils.py::test_add",
        ]
        selected, deselected = plugin.filter_items(items)
        # Only test_core.py should remain (core.py changed)
        assert len(selected) == 1
        assert "test_core" in selected[0]
        assert len(deselected) == 1
        assert "test_utils" in deselected[0]


# ---------------------------------------------------------------------------
# Plugin: session finish (credential issuance)
# ---------------------------------------------------------------------------


class TestPluginFinish:
    def test_issues_credential(self, plugin):
        plugin.configure()
        plugin.collector.record("test_a", passed=True, failed=False, skipped=False)
        plugin.collector.record("test_b", passed=True, failed=False, skipped=False)
        cred = plugin.finish(timestamp=FIXED_TIMESTAMP)
        assert cred.said.startswith("E")
        assert cred.results.total == 2
        assert cred.results.passed == 2
        assert cred.tree_root_said == plugin.tree.root_said

    def test_credential_chains_to_previous(self, config):
        plugin = KeriTestPlugin(
            config,
            previous_run_said="EPreviousRun_SAID",
        )
        plugin.configure()
        plugin.collector.record("test_a", passed=True, failed=False, skipped=False)
        cred = plugin.finish(timestamp=FIXED_TIMESTAMP)
        assert cred.is_chained
        assert cred.edges.previous_run_said == "EPreviousRun_SAID"

    def test_credential_references_suite_gaid(self, plugin):
        plugin.configure()
        cred = plugin.finish(timestamp=FIXED_TIMESTAMP)
        assert cred.edges.test_suite_gaid == plugin.suite.gaid

    def test_credential_includes_coverage(self, plugin):
        plugin.configure()
        cred = plugin.finish(coverage_percent=92.5, timestamp=FIXED_TIMESTAMP)
        assert cred.results.coverage_percent == 92.5


# ---------------------------------------------------------------------------
# Path overlap helper
# ---------------------------------------------------------------------------


class TestPathOverlaps:
    def test_direct_match(self):
        assert _path_overlaps_changes(
            "tests/test_core.py",
            {"tests/test_core.py"},
        )

    def test_module_name_match(self):
        assert _path_overlaps_changes(
            "tests/test_core.py",
            {"src/mylib/core.py"},
        )

    def test_no_match(self):
        assert not _path_overlaps_changes(
            "tests/test_core.py",
            {"src/mylib/utils.py"},
        )

    def test_non_test_prefix(self):
        assert _path_overlaps_changes(
            "tests/conftest.py",
            {"src/mylib/conftest.py"},
        )
