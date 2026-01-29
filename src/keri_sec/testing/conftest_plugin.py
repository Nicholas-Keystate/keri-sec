# -*- encoding: utf-8 -*-
"""
pytest plugin for GAID-governed test attestation.

Hooks into pytest lifecycle to:
1. pytest_configure: Build TestSmithTree, detect staleness, evaluate policies
2. pytest_collection_modifyitems: SELECTIVE_RETEST deselects unchanged modules
3. pytest_runtest_logreport: Track per-test results
4. pytest_sessionfinish: Issue TestExecutionCredential

Configuration via pyproject.toml [tool.keri-test] or pytest ini options.

Usage:
    # In conftest.py:
    from keri_sec.testing.conftest_plugin import KeriTestPlugin
    plugin = KeriTestPlugin(config)
    # Or register as a pytest plugin
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

from keri_sec.testing.execution_credential import (
    TestExecutionCredential,
    TestExecutionIssuer,
    TestResults,
)
from keri_sec.testing.policies import PolicyType, PolicyVerdict
from keri_sec.testing.policy_engine import PolicyEngine
from keri_sec.testing.smith_tree import TestSmithTree
from keri_sec.testing.staleness import StalenessDetector, StalenessInfo
from keri_sec.testing.suite_gaid import TestSuiteGAID, TestSuiteGovernanceRules


# ---------------------------------------------------------------------------
# Plugin configuration
# ---------------------------------------------------------------------------


@dataclass
class KeriTestConfig:
    """Configuration for the GAID test plugin.

    Can be loaded from pyproject.toml [tool.keri-test] section.
    """

    suite_name: str = "default-suite"
    source_dirs: List[str] = field(default_factory=lambda: ["src"])
    test_dirs: List[str] = field(default_factory=lambda: ["tests"])
    file_extensions: List[str] = field(default_factory=lambda: [".py"])
    project_root: Optional[str] = None
    default_policy: str = "warn"
    fail_closed: bool = True
    min_coverage_percent: Optional[float] = None
    runner_aid: Optional[str] = None
    tel_enabled: bool = False
    schema_said: Optional[str] = None
    policy_schema_said: Optional[str] = None

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> KeriTestConfig:
        return cls(
            suite_name=d.get("suite_name", "default-suite"),
            source_dirs=d.get("source_dirs", ["src"]),
            test_dirs=d.get("test_dirs", ["tests"]),
            file_extensions=d.get("file_extensions", [".py"]),
            project_root=d.get("project_root"),
            default_policy=d.get("default_policy", "warn"),
            fail_closed=d.get("fail_closed", True),
            min_coverage_percent=d.get("min_coverage_percent"),
            runner_aid=d.get("runner_aid"),
            tel_enabled=d.get("tel_enabled", False),
            schema_said=d.get("schema_said"),
            policy_schema_said=d.get("policy_schema_said"),
        )


# ---------------------------------------------------------------------------
# Result collector
# ---------------------------------------------------------------------------


@dataclass
class _TestOutcome:
    """Outcome of a single test."""

    nodeid: str
    passed: bool
    failed: bool
    skipped: bool


class ResultCollector:
    """Collects per-test results during pytest session."""

    def __init__(self):
        self._outcomes: List[_TestOutcome] = []
        self._start_time: Optional[float] = None
        self._end_time: Optional[float] = None

    def record(self, nodeid: str, passed: bool, failed: bool, skipped: bool) -> None:
        self._outcomes.append(_TestOutcome(
            nodeid=nodeid,
            passed=passed,
            failed=failed,
            skipped=skipped,
        ))

    def set_start(self, time: float) -> None:
        self._start_time = time

    def set_end(self, time: float) -> None:
        self._end_time = time

    def to_results(self, coverage_percent: Optional[float] = None) -> TestResults:
        total = len(self._outcomes)
        passed = sum(1 for o in self._outcomes if o.passed)
        failed = sum(1 for o in self._outcomes if o.failed)
        skipped = sum(1 for o in self._outcomes if o.skipped)
        errors = total - passed - failed - skipped

        duration = 0.0
        if self._start_time is not None and self._end_time is not None:
            duration = self._end_time - self._start_time

        return TestResults(
            total=total,
            passed=passed,
            failed=failed,
            skipped=skipped,
            errors=errors,
            duration_seconds=duration,
            coverage_percent=coverage_percent,
        )

    @property
    def outcomes(self) -> List[_TestOutcome]:
        return list(self._outcomes)


# ---------------------------------------------------------------------------
# Plugin core
# ---------------------------------------------------------------------------


class KeriTestPlugin:
    """Core plugin logic for GAID-governed test attestation.

    This is intentionally decoupled from pytest's hook API so it can be
    tested without a full pytest session. The conftest.py glue code
    calls these methods from the appropriate hooks.
    """

    def __init__(
        self,
        config: KeriTestConfig,
        suite: Optional[TestSuiteGAID] = None,
        engine: Optional[PolicyEngine] = None,
        previous_tree: Optional[TestSmithTree] = None,
        previous_run_said: Optional[str] = None,
        input_deck: Optional[Any] = None,
        output_deck: Optional[Any] = None,
    ):
        self._config = config
        self._collector = ResultCollector()
        self._previous_tree = previous_tree
        self._previous_run_said = previous_run_said
        self._input_deck = input_deck
        self._output_deck = output_deck

        # Build current tree
        self._tree = TestSmithTree.build(
            source_dirs=config.source_dirs,
            test_dirs=config.test_dirs,
            project_root=config.project_root,
            file_extensions=config.file_extensions,
        )

        # Set up suite and engine
        if suite is not None:
            self._suite = suite
        else:
            rules = TestSuiteGovernanceRules(
                min_coverage_percent=config.min_coverage_percent,
                fail_closed=config.fail_closed,
                default_staleness_policy=config.default_policy.upper(),
            )
            self._suite = TestSuiteGAID(
                name=config.suite_name,
                governance_rules=rules,
                initial_tree_root_said=self._tree.root_said,
            )

        self._engine = engine or PolicyEngine(self._suite)
        self._staleness: Optional[StalenessInfo] = None
        self._verdict: Optional[PolicyVerdict] = None
        self._credential: Optional[TestExecutionCredential] = None
        self._deselected_items: List[str] = []

    @property
    def tree(self) -> TestSmithTree:
        return self._tree

    @property
    def suite(self) -> TestSuiteGAID:
        return self._suite

    @property
    def engine(self) -> PolicyEngine:
        return self._engine

    @property
    def staleness(self) -> Optional[StalenessInfo]:
        return self._staleness

    @property
    def verdict(self) -> Optional[PolicyVerdict]:
        return self._verdict

    @property
    def credential(self) -> Optional[TestExecutionCredential]:
        return self._credential

    @property
    def collector(self) -> ResultCollector:
        return self._collector

    @property
    def deselected_items(self) -> List[str]:
        return list(self._deselected_items)

    # -- Phase: configure (build tree, detect staleness, evaluate policies) --

    def configure(self, attested_tree_root_said: Optional[str] = None) -> PolicyVerdict:
        """Run staleness detection and policy evaluation.

        Args:
            attested_tree_root_said: Tree root SAID from last attestation.
                If None, uses the suite's initial root (no staleness).

        Returns:
            PolicyVerdict from the policy engine
        """
        root = attested_tree_root_said or self._suite.current_tree_root_said

        detector = StalenessDetector(self._suite)
        self._staleness = detector.detect(
            attested_tree_root_said=root,
            current_tree=self._tree,
            attested_tree=self._previous_tree,
        )

        self._verdict = self._engine.evaluate(self._staleness)
        return self._verdict

    # -- Phase: collection_modifyitems (SELECTIVE_RETEST) --

    def filter_items(
        self,
        item_nodeids: List[str],
    ) -> tuple:
        """Filter test items based on SELECTIVE_RETEST policy.

        If the verdict includes SELECTIVE_RETEST, only keep tests
        whose module paths overlap with changed subtrees.

        Args:
            item_nodeids: List of pytest node IDs (e.g., "tests/test_foo.py::test_bar")

        Returns:
            (selected_nodeids, deselected_nodeids)
        """
        if self._verdict is None or not self._staleness or not self._staleness.is_stale:
            return item_nodeids, []

        # Check if SELECTIVE_RETEST is in the verdict
        has_selective = any(
            a.action_type == PolicyType.SELECTIVE_RETEST
            for a in self._verdict.actions
        )
        if not has_selective:
            return item_nodeids, []

        # Get changed file paths from staleness info
        changed_files: Set[str] = set()
        if self._staleness.changed_subtrees:
            for cs in self._staleness.changed_subtrees:
                changed_files.update(cs.changed_files)

        if not changed_files:
            return item_nodeids, []

        # Select tests whose module overlaps with changed files
        selected = []
        deselected = []
        for nodeid in item_nodeids:
            module_path = nodeid.split("::")[0]  # e.g., "tests/test_foo.py"
            if _path_overlaps_changes(module_path, changed_files):
                selected.append(nodeid)
            else:
                deselected.append(nodeid)

        self._deselected_items = deselected
        return selected, deselected

    # -- Phase: sessionfinish (issue credential) --

    def finish(
        self,
        coverage_percent: Optional[float] = None,
        timestamp: Optional[str] = None,
    ) -> TestExecutionCredential:
        """Issue a TestExecutionCredential for this session.

        When ``tel_enabled`` is True and an ``input_deck`` is attached,
        the credential is also pushed to the TestAttestationDoer for
        real TEL anchoring. Otherwise, the SAID-only fast path is used.

        Args:
            coverage_percent: Coverage percentage if available
            timestamp: Override timestamp for deterministic tests

        Returns:
            TestExecutionCredential with computed SAID
        """
        results = self._collector.to_results(coverage_percent=coverage_percent)

        issuer = TestExecutionIssuer(
            suite_gaid=self._suite.gaid,
            suite_sn=self._suite.current_sn,
            runner_aid=self._config.runner_aid,
        )
        # Set chain to previous run if available
        if self._previous_run_said is not None:
            issuer._last_said = self._previous_run_said

        self._credential = issuer.issue(
            tree_root_said=self._tree.root_said,
            results=results,
            timestamp=timestamp,
        )

        # TEL anchoring: push to Doer if enabled
        if self._config.tel_enabled and self._input_deck is not None:
            from keri_sec.testing.test_attestation_doer import TestAttestationRequest
            request = TestAttestationRequest(
                request_id=f"session-{self._credential.said[:12]}",
                credential=self._credential,
                suite_gaid=self._suite.gaid,
                suite_sn=self._suite.current_sn,
            )
            self._input_deck.push(request)

        return self._credential


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _path_overlaps_changes(module_path: str, changed_files: Set[str]) -> bool:
    """Check if a test module path overlaps with any changed source file.

    Simple heuristic: a test module "tests/test_foo.py" relates to
    changes in source files containing "foo" in their path.
    Also matches if the test file itself changed.
    """
    # Direct match: the test file itself changed
    if module_path in changed_files:
        return True

    # Extract module name from test path
    # e.g., "tests/test_core.py" -> "core"
    import os

    basename = os.path.basename(module_path)
    if basename.startswith("test_"):
        module_name = basename[5:].replace(".py", "")
    else:
        module_name = basename.replace(".py", "")

    # Check if any changed file contains this module name
    for changed in changed_files:
        changed_base = os.path.basename(changed).replace(".py", "")
        if module_name == changed_base:
            return True

    return False
