# -*- encoding: utf-8 -*-
"""Tests for TestExecutionCredential and issuer."""

import pytest

from keri_sec.testing.execution_credential import (
    CredentialEdges,
    TestExecutionCredential,
    TestExecutionIssuer,
    TestResults,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

FIXED_TIMESTAMP = "2026-01-28T12:00:00+00:00"


@pytest.fixture
def results():
    return TestResults(
        total=42,
        passed=40,
        failed=1,
        skipped=1,
        errors=0,
        duration_seconds=12.5,
        coverage_percent=87.3,
    )


@pytest.fixture
def passing_results():
    return TestResults(
        total=42,
        passed=42,
        failed=0,
        skipped=0,
        errors=0,
        duration_seconds=10.0,
    )


@pytest.fixture
def edges():
    return CredentialEdges(
        test_suite_gaid="EGAID_000000000000000000000000000000000000",
        test_suite_sn=0,
        previous_run_said=None,
        code_under_test_said="ECodeRoot_00000000000000000000000000000000",
        runtime_env_said="EEnvSAID_000000000000000000000000000000000",
    )


# ---------------------------------------------------------------------------
# TestResults
# ---------------------------------------------------------------------------


class TestTestResults:
    def test_success_when_no_failures(self, passing_results):
        assert passing_results.success

    def test_not_success_with_failures(self, results):
        assert not results.success

    def test_not_success_with_errors(self):
        r = TestResults(total=10, passed=10, failed=0, skipped=0, errors=1)
        assert not r.success

    def test_to_dict(self, results):
        d = results.to_dict()
        assert d["total"] == 42
        assert d["passed"] == 40
        assert d["failed"] == 1
        assert d["coverage_percent"] == 87.3

    def test_to_dict_no_coverage(self, passing_results):
        d = passing_results.to_dict()
        assert "coverage_percent" not in d


# ---------------------------------------------------------------------------
# CredentialEdges
# ---------------------------------------------------------------------------


class TestCredentialEdges:
    def test_to_dict_minimal(self):
        e = CredentialEdges(
            test_suite_gaid="EGAID",
            test_suite_sn=0,
        )
        d = e.to_dict()
        assert d["test_suite_gaid"] == "EGAID"
        assert "previous_run_said" not in d

    def test_to_dict_full(self, edges):
        d = edges.to_dict()
        assert "code_under_test_said" in d
        assert "runtime_env_said" in d


# ---------------------------------------------------------------------------
# TestExecutionCredential
# ---------------------------------------------------------------------------


class TestExecutionCredential_:
    def test_said_deterministic(self, results, edges):
        c1 = TestExecutionCredential(
            tree_root_said="ERoot",
            results=results,
            edges=edges,
            timestamp=FIXED_TIMESTAMP,
        )
        c2 = TestExecutionCredential(
            tree_root_said="ERoot",
            results=results,
            edges=edges,
            timestamp=FIXED_TIMESTAMP,
        )
        assert c1.said == c2.said
        assert c1.said.startswith("E")

    def test_said_changes_with_results(self, edges):
        r1 = TestResults(total=10, passed=10, failed=0, skipped=0)
        r2 = TestResults(total=10, passed=9, failed=1, skipped=0)
        c1 = TestExecutionCredential("ERoot", r1, edges, timestamp=FIXED_TIMESTAMP)
        c2 = TestExecutionCredential("ERoot", r2, edges, timestamp=FIXED_TIMESTAMP)
        assert c1.said != c2.said

    def test_said_changes_with_tree_root(self, results, edges):
        c1 = TestExecutionCredential("ERoot1", results, edges, timestamp=FIXED_TIMESTAMP)
        c2 = TestExecutionCredential("ERoot2", results, edges, timestamp=FIXED_TIMESTAMP)
        assert c1.said != c2.said

    def test_is_chained_false_for_first(self, results, edges):
        c = TestExecutionCredential("ERoot", results, edges, timestamp=FIXED_TIMESTAMP)
        assert not c.is_chained

    def test_is_chained_true_with_previous(self, results):
        e = CredentialEdges(
            test_suite_gaid="EGAID",
            test_suite_sn=1,
            previous_run_said="EPrevSAID",
        )
        c = TestExecutionCredential("ERoot", results, e, timestamp=FIXED_TIMESTAMP)
        assert c.is_chained

    def test_success_delegates_to_results(self, passing_results, edges):
        c = TestExecutionCredential("ERoot", passing_results, edges, timestamp=FIXED_TIMESTAMP)
        assert c.success

    def test_to_dict_includes_said(self, results, edges):
        c = TestExecutionCredential("ERoot", results, edges, timestamp=FIXED_TIMESTAMP)
        d = c.to_dict()
        assert "said" in d
        assert d["said"] == c.said
        assert d["tree_root_said"] == "ERoot"


# ---------------------------------------------------------------------------
# TestExecutionIssuer
# ---------------------------------------------------------------------------


class TestExecutionIssuerBasic:
    def test_issue_returns_credential(self):
        issuer = TestExecutionIssuer(
            suite_gaid="EGAID",
            suite_sn=0,
        )
        cred = issuer.issue(
            tree_root_said="ERoot",
            results=TestResults(total=5, passed=5, failed=0, skipped=0),
            timestamp=FIXED_TIMESTAMP,
        )
        assert cred.said.startswith("E")
        assert cred.tree_root_said == "ERoot"

    def test_first_issue_no_chain(self):
        issuer = TestExecutionIssuer(suite_gaid="EGAID", suite_sn=0)
        cred = issuer.issue(
            tree_root_said="ERoot",
            results=TestResults(total=1, passed=1, failed=0, skipped=0),
            timestamp=FIXED_TIMESTAMP,
        )
        assert not cred.is_chained
        assert cred.edges.previous_run_said is None

    def test_second_issue_chains_to_first(self):
        issuer = TestExecutionIssuer(suite_gaid="EGAID", suite_sn=0)
        c1 = issuer.issue(
            tree_root_said="ERoot1",
            results=TestResults(total=1, passed=1, failed=0, skipped=0),
            timestamp=FIXED_TIMESTAMP,
        )
        c2 = issuer.issue(
            tree_root_said="ERoot2",
            results=TestResults(total=2, passed=2, failed=0, skipped=0),
            timestamp="2026-01-28T13:00:00+00:00",
        )
        assert c2.is_chained
        assert c2.edges.previous_run_said == c1.said

    def test_chain_across_multiple_runs(self):
        issuer = TestExecutionIssuer(suite_gaid="EGAID", suite_sn=0)
        creds = []
        for i in range(5):
            c = issuer.issue(
                tree_root_said=f"ERoot_{i}",
                results=TestResults(total=1, passed=1, failed=0, skipped=0),
                timestamp=f"2026-01-28T{12+i:02d}:00:00+00:00",
            )
            creds.append(c)

        # Each chains to previous
        assert not creds[0].is_chained
        for i in range(1, 5):
            assert creds[i].edges.previous_run_said == creds[i - 1].said

    def test_issued_count(self):
        issuer = TestExecutionIssuer(suite_gaid="EGAID", suite_sn=0)
        assert issuer.issued_count == 0
        issuer.issue(
            tree_root_said="ERoot",
            results=TestResults(total=1, passed=1, failed=0, skipped=0),
            timestamp=FIXED_TIMESTAMP,
        )
        assert issuer.issued_count == 1

    def test_last_said_tracks(self):
        issuer = TestExecutionIssuer(suite_gaid="EGAID", suite_sn=0)
        assert issuer.last_said is None
        c = issuer.issue(
            tree_root_said="ERoot",
            results=TestResults(total=1, passed=1, failed=0, skipped=0),
            timestamp=FIXED_TIMESTAMP,
        )
        assert issuer.last_said == c.said

    def test_runner_aid_included(self):
        issuer = TestExecutionIssuer(
            suite_gaid="EGAID",
            suite_sn=0,
            runner_aid="BRunner_AID_prefix",
        )
        cred = issuer.issue(
            tree_root_said="ERoot",
            results=TestResults(total=1, passed=1, failed=0, skipped=0),
            timestamp=FIXED_TIMESTAMP,
        )
        assert cred.runner_aid == "BRunner_AID_prefix"
        d = cred.to_dict()
        assert d["runner_aid"] == "BRunner_AID_prefix"

    def test_chain_property(self):
        issuer = TestExecutionIssuer(suite_gaid="EGAID", suite_sn=0)
        issuer.issue(
            tree_root_said="ERoot1",
            results=TestResults(total=1, passed=1, failed=0, skipped=0),
            timestamp=FIXED_TIMESTAMP,
        )
        issuer.issue(
            tree_root_said="ERoot2",
            results=TestResults(total=1, passed=1, failed=0, skipped=0),
            timestamp="2026-01-28T13:00:00+00:00",
        )
        assert len(issuer.chain) == 2


class TestExecutionIssuerEdges:
    def test_code_and_env_edges(self):
        issuer = TestExecutionIssuer(suite_gaid="EGAID", suite_sn=0)
        cred = issuer.issue(
            tree_root_said="ERoot",
            results=TestResults(total=1, passed=1, failed=0, skipped=0),
            code_under_test_said="ECodeRoot",
            runtime_env_said="EEnvSAID",
            timestamp=FIXED_TIMESTAMP,
        )
        assert cred.edges.code_under_test_said == "ECodeRoot"
        assert cred.edges.runtime_env_said == "EEnvSAID"
