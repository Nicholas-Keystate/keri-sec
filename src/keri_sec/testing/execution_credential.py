# -*- encoding: utf-8 -*-
"""
TestExecutionCredential: per-run test attestation.

Each test execution produces a credential with:
- Subject: tree root SAID, env manifest SAID, test results, coverage
- Edges: test suite GAID, previous run, code-under-test, runtime env
- SAID: deterministic from subject content
- TEL anchoring: fast-path SAID return, background anchoring

This is the ACDC credential that proves a test run actually happened
against a specific dependency surface.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from keri.core.coring import Diger, MtrDex


# ---------------------------------------------------------------------------
# SAID computation
# ---------------------------------------------------------------------------


def _compute_said(data: dict) -> str:
    ser = json.dumps(data, sort_keys=True, separators=(",", ":")).encode()
    return Diger(ser=ser, code=MtrDex.Blake3_256).qb64


# ---------------------------------------------------------------------------
# Test results
# ---------------------------------------------------------------------------


@dataclass
class TestResults:
    """Aggregated test execution results."""

    total: int
    passed: int
    failed: int
    skipped: int
    errors: int = 0
    duration_seconds: float = 0.0
    coverage_percent: Optional[float] = None

    @property
    def success(self) -> bool:
        return self.failed == 0 and self.errors == 0

    def to_dict(self) -> dict:
        d: Dict[str, Any] = {
            "total": self.total,
            "passed": self.passed,
            "failed": self.failed,
            "skipped": self.skipped,
            "errors": self.errors,
            "duration_seconds": self.duration_seconds,
        }
        if self.coverage_percent is not None:
            d["coverage_percent"] = self.coverage_percent
        return d


# ---------------------------------------------------------------------------
# Credential edges
# ---------------------------------------------------------------------------


@dataclass
class CredentialEdges:
    """ACDC edges linking this credential to its context.

    Attributes:
        test_suite_gaid: GAID of the test suite
        test_suite_sn: Sequence number of the suite at execution time
        previous_run_said: SAID of the previous execution credential (chain)
        code_under_test_said: Tree root SAID of the source subtree
        runtime_env_said: RuntimeManifest SAID (env leaf)
    """

    test_suite_gaid: str
    test_suite_sn: int
    previous_run_said: Optional[str] = None
    code_under_test_said: Optional[str] = None
    runtime_env_said: Optional[str] = None

    def to_dict(self) -> dict:
        d: Dict[str, Any] = {
            "test_suite_gaid": self.test_suite_gaid,
            "test_suite_sn": self.test_suite_sn,
        }
        if self.previous_run_said is not None:
            d["previous_run_said"] = self.previous_run_said
        if self.code_under_test_said is not None:
            d["code_under_test_said"] = self.code_under_test_said
        if self.runtime_env_said is not None:
            d["runtime_env_said"] = self.runtime_env_said
        return d


# ---------------------------------------------------------------------------
# Execution credential
# ---------------------------------------------------------------------------


@dataclass
class TestExecutionCredential:
    """ACDC credential attesting to a test execution.

    Subject:
        - tree_root_said: Smith tree root at execution time
        - results: aggregated test outcomes
        - timestamp: ISO 8601 execution time

    Edges:
        - test_suite_gaid: the governed suite identity
        - previous_run_said: chain to prior execution
        - code_under_test_said: source subtree root
        - runtime_env_said: environment manifest

    The SAID is computed deterministically from the subject + edges,
    making the credential content-addressable and verifiable.
    """

    tree_root_said: str
    results: TestResults
    edges: CredentialEdges
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    runner_aid: Optional[str] = None
    _said: Optional[str] = field(default=None, repr=False)

    @property
    def said(self) -> str:
        if self._said is None:
            self._said = _compute_said(self._canonical())
        return self._said

    def _canonical(self) -> dict:
        """Canonical dict for SAID computation (deterministic)."""
        return {
            "tree_root_said": self.tree_root_said,
            "results": self.results.to_dict(),
            "edges": self.edges.to_dict(),
            "timestamp": self.timestamp,
            "runner_aid": self.runner_aid,
        }

    def to_dict(self) -> dict:
        """Full serialization including computed SAID."""
        d = self._canonical()
        d["said"] = self.said
        return d

    @property
    def is_chained(self) -> bool:
        """True if this credential chains to a previous run."""
        return self.edges.previous_run_said is not None

    @property
    def success(self) -> bool:
        return self.results.success


# ---------------------------------------------------------------------------
# Credential issuer (fast-path pattern)
# ---------------------------------------------------------------------------


class TestExecutionIssuer:
    """Issues TestExecutionCredentials with chaining.

    Follows the fast-path pattern: returns SAID immediately,
    TEL anchoring happens in background (not implemented here,
    that's the HIO Doer's job in Phase 5).

    Usage:
        issuer = TestExecutionIssuer(suite_gaid="EGAID...", suite_sn=0)
        cred = issuer.issue(
            tree_root_said="ERoot...",
            results=TestResults(total=10, passed=10, failed=0, skipped=0),
        )
        # cred.said available immediately
        # cred.edges.previous_run_said chains to prior execution
    """

    def __init__(
        self,
        suite_gaid: str,
        suite_sn: int,
        runner_aid: Optional[str] = None,
    ):
        self._suite_gaid = suite_gaid
        self._suite_sn = suite_sn
        self._runner_aid = runner_aid
        self._last_said: Optional[str] = None
        self._issued: List[TestExecutionCredential] = []

    @property
    def last_said(self) -> Optional[str]:
        """SAID of the most recently issued credential."""
        return self._last_said

    @property
    def issued_count(self) -> int:
        return len(self._issued)

    @property
    def chain(self) -> List[TestExecutionCredential]:
        """All issued credentials in order."""
        return list(self._issued)

    def issue(
        self,
        tree_root_said: str,
        results: TestResults,
        code_under_test_said: Optional[str] = None,
        runtime_env_said: Optional[str] = None,
        timestamp: Optional[str] = None,
    ) -> TestExecutionCredential:
        """Issue a new execution credential.

        Automatically chains to the previous credential via edges.

        Args:
            tree_root_said: Smith tree root at execution time
            results: Test execution results
            code_under_test_said: Source subtree root SAID
            runtime_env_said: Environment manifest SAID
            timestamp: Override timestamp (for deterministic tests)

        Returns:
            TestExecutionCredential with computed SAID
        """
        edges = CredentialEdges(
            test_suite_gaid=self._suite_gaid,
            test_suite_sn=self._suite_sn,
            previous_run_said=self._last_said,
            code_under_test_said=code_under_test_said,
            runtime_env_said=runtime_env_said,
        )

        ts = timestamp or datetime.now(timezone.utc).isoformat()

        cred = TestExecutionCredential(
            tree_root_said=tree_root_said,
            results=results,
            edges=edges,
            timestamp=ts,
            runner_aid=self._runner_aid,
        )

        self._last_said = cred.said
        self._issued.append(cred)
        return cred
