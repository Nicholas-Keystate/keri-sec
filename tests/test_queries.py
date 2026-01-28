# -*- encoding: utf-8 -*-
"""Tests for KGQL query templates: substitution and syntax validation."""

import pytest
from string import Template

from keri_sec.testing.queries import TestQueryTemplates


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

FAKE_SCHEMA = "ELJm6sOw-eZmeTGgLrO0p614JPcJLX5RhWIw9WzvoaDV"
FAKE_POLICY_SCHEMA = "EKJm7tPx-fAmfUHhMsP1q725KQdKMY6RiWJx0XbwpbEW"
FAKE_GAID = "EGAID_test_suite_000000000000000000000"
FAKE_ROOT = "ETreeRoot_00000000000000000000000000000000"
FAKE_RUNNER = "ERunnerAid_0000000000000000000000000000000"
FAKE_CRED = "ECredSaid_00000000000000000000000000000000"
FAKE_AID = "EAid_000000000000000000000000000000000000"


# ---------------------------------------------------------------------------
# Template resolution tests
# ---------------------------------------------------------------------------


class TestStaleExecutions:
    def test_substitutes_all_params(self):
        q = TestQueryTemplates.STALE_EXECUTIONS.substitute(
            schema_said=FAKE_SCHEMA,
            current_root=FAKE_ROOT,
            suite_gaid=FAKE_GAID,
        )
        assert FAKE_SCHEMA in q
        assert FAKE_ROOT in q
        assert FAKE_GAID in q

    def test_contains_match(self):
        q = TestQueryTemplates.STALE_EXECUTIONS.substitute(
            schema_said=FAKE_SCHEMA,
            current_root=FAKE_ROOT,
            suite_gaid=FAKE_GAID,
        )
        assert "MATCH" in q

    def test_contains_where(self):
        q = TestQueryTemplates.STALE_EXECUTIONS.substitute(
            schema_said=FAKE_SCHEMA,
            current_root=FAKE_ROOT,
            suite_gaid=FAKE_GAID,
        )
        assert "WHERE" in q
        assert "!=" in q


class TestExecutionChain:
    def test_substitutes_all_params(self):
        q = TestQueryTemplates.EXECUTION_CHAIN.substitute(
            schema_said=FAKE_SCHEMA,
            credential_said=FAKE_CRED,
        )
        assert FAKE_SCHEMA in q
        assert FAKE_CRED in q
        assert "previousRun" in q

    def test_contains_path_traversal(self):
        q = TestQueryTemplates.EXECUTION_CHAIN.substitute(
            schema_said=FAKE_SCHEMA,
            credential_said=FAKE_CRED,
        )
        assert "path" in q
        assert "*" in q  # Variable-length path


class TestExecutionsByRunner:
    def test_substitutes_all_params(self):
        q = TestQueryTemplates.EXECUTIONS_BY_RUNNER.substitute(
            schema_said=FAKE_SCHEMA,
            runner_aid=FAKE_RUNNER,
        )
        assert FAKE_RUNNER in q
        assert "runnerAid" in q


class TestExecutionsForRoot:
    def test_substitutes_all_params(self):
        q = TestQueryTemplates.EXECUTIONS_FOR_ROOT.substitute(
            schema_said=FAKE_SCHEMA,
            tree_root_said=FAKE_ROOT,
            suite_gaid=FAKE_GAID,
        )
        assert FAKE_ROOT in q
        assert FAKE_GAID in q
        assert "treeRootSaid" in q


class TestVerifyRunner:
    def test_contains_proof(self):
        q = TestQueryTemplates.VERIFY_RUNNER.substitute(
            schema_said=FAKE_SCHEMA,
            credential_said=FAKE_CRED,
        )
        assert "PROOF" in q


class TestPolicyBySubtree:
    def test_substitutes_all_params(self):
        q = TestQueryTemplates.POLICY_BY_SUBTREE.substitute(
            policy_schema_said=FAKE_POLICY_SCHEMA,
            subtree_path="source/core",
            suite_gaid=FAKE_GAID,
        )
        assert FAKE_POLICY_SCHEMA in q
        assert "source/core" in q
        assert "policyType" in q
        assert "priority" in q


class TestExecutionAtKeystate:
    def test_substitutes_all_params(self):
        q = TestQueryTemplates.EXECUTION_AT_KEYSTATE.substitute(
            aid=FAKE_AID,
            seq=5,
            schema_said=FAKE_SCHEMA,
            suite_gaid=FAKE_GAID,
        )
        assert "AT KEYSTATE" in q
        assert FAKE_AID in q
        assert "5" in q


class TestSuiteLatestExecution:
    def test_substitutes_all_params(self):
        q = TestQueryTemplates.SUITE_LATEST_EXECUTION.substitute(
            schema_said=FAKE_SCHEMA,
            suite_gaid=FAKE_GAID,
        )
        assert "ORDER BY" in q
        assert "LIMIT 1" in q
        assert FAKE_GAID in q


# ---------------------------------------------------------------------------
# No unresolved placeholders
# ---------------------------------------------------------------------------


class TestNoUnresolvedPlaceholders:
    """Verify that all templates resolve without leftover $var placeholders."""

    FULL_PARAMS = dict(
        schema_said=FAKE_SCHEMA,
        policy_schema_said=FAKE_POLICY_SCHEMA,
        suite_gaid=FAKE_GAID,
        tree_root_said=FAKE_ROOT,
        runner_aid=FAKE_RUNNER,
        credential_said=FAKE_CRED,
        subtree_path="root",
        aid=FAKE_AID,
        seq=0,
        current_root=FAKE_ROOT,
    )

    @pytest.mark.parametrize("name", [
        "STALE_EXECUTIONS",
        "EXECUTION_CHAIN",
        "EXECUTIONS_BY_RUNNER",
        "EXECUTIONS_FOR_ROOT",
        "VERIFY_RUNNER",
        "POLICY_BY_SUBTREE",
        "EXECUTION_AT_KEYSTATE",
        "SUITE_LATEST_EXECUTION",
    ])
    def test_no_dollar_vars_remain(self, name):
        template = getattr(TestQueryTemplates, name)
        q = template.substitute(**self.FULL_PARAMS)
        assert "$" not in q, f"Unresolved placeholder in {name}: {q}"

    @pytest.mark.parametrize("name", [
        "STALE_EXECUTIONS",
        "EXECUTION_CHAIN",
        "EXECUTIONS_BY_RUNNER",
        "EXECUTIONS_FOR_ROOT",
        "VERIFY_RUNNER",
        "POLICY_BY_SUBTREE",
        "EXECUTION_AT_KEYSTATE",
        "SUITE_LATEST_EXECUTION",
    ])
    def test_is_template_instance(self, name):
        template = getattr(TestQueryTemplates, name)
        assert isinstance(template, Template)
