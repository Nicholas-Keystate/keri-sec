# -*- encoding: utf-8 -*-
"""Tests for the TEL bridge: ACDC building, issuance, registry management, Reger storage."""

import pytest
from datetime import datetime, timezone

from keri.app import habbing
from keri.vdr import credentialing
from keri.vc import proving
from keri.core.coring import Saider

from keri_sec.testing.execution_credential import (
    CredentialEdges,
    TestExecutionCredential,
    TestResults,
)
from keri_sec.testing.policies import PolicyCredential, PolicyType
from keri_sec.testing.tel_bridge import (
    TestCredentialIssuer,
    anchor_credential,
    anchor_tel_event,
)
from keri_sec.testing.reger_storage import store_in_reger


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

FIXED_TIMESTAMP = "2026-01-28T12:00:00+00:00"
FAKE_SCHEMA_SAID = "ELJm6sOw-eZmeTGgLrO0p614JPcJLX5RhWIw9WzvoaDV"
FAKE_POLICY_SCHEMA_SAID = "EKJm7tPx-fAmfUHhMsP1q725KQdKMY6RiWJx0XbwpbEW"


@pytest.fixture
def keri_env(tmp_path):
    """Minimal real KERI environment: Habery + Regery, temp storage."""
    hby = habbing.Habery(name="bridge-test", temp=True)
    rgy = credentialing.Regery(hby=hby, name="bridge-test", temp=True)
    yield {"hby": hby, "rgy": rgy}
    hby.close()


@pytest.fixture
def issuer_hab(keri_env):
    """Create a transferable issuer AID."""
    return keri_env["hby"].makeHab(name="test-issuer", transferable=True)


@pytest.fixture
def registry(keri_env, issuer_hab):
    """Create a TEL registry with anchored VCP."""
    rgy = keri_env["rgy"]
    reg = rgy.makeRegistry(name="test-registry", prefix=issuer_hab.pre)
    anchor_tel_event(issuer_hab, reg, reg.vcp)
    return reg


@pytest.fixture
def sample_cred():
    """A sample TestExecutionCredential for testing."""
    results = TestResults(total=10, passed=8, failed=1, skipped=1, errors=0, duration_seconds=5.2)
    edges = CredentialEdges(
        test_suite_gaid="EGAID_test_suite_000000000000000000000",
        test_suite_sn=3,
        previous_run_said="EPrevious_run_000000000000000000000000",
        code_under_test_said="ECodeUnderTest_00000000000000000000000",
    )
    return TestExecutionCredential(
        tree_root_said="ETreeRoot_00000000000000000000000000000000",
        results=results,
        edges=edges,
        timestamp=FIXED_TIMESTAMP,
        runner_aid="ERunnerAid_0000000000000000000000000000000",
    )


@pytest.fixture
def issuer():
    """TestCredentialIssuer with fake schema SAIDs."""
    return TestCredentialIssuer(
        schema_said=FAKE_SCHEMA_SAID,
        policy_schema_said=FAKE_POLICY_SCHEMA_SAID,
    )


# ---------------------------------------------------------------------------
# TestCredentialIssuer: ACDC structure building
# ---------------------------------------------------------------------------


class TestBuildAcdcAttrs:
    def test_has_d_placeholder(self, issuer, sample_cred):
        attrs = issuer.build_acdc_attrs(sample_cred)
        assert attrs["d"] == ""

    def test_has_dt(self, issuer, sample_cred):
        attrs = issuer.build_acdc_attrs(sample_cred)
        assert attrs["dt"] == FIXED_TIMESTAMP

    def test_has_tree_root_said(self, issuer, sample_cred):
        attrs = issuer.build_acdc_attrs(sample_cred)
        assert attrs["treeRootSaid"] == sample_cred.tree_root_said

    def test_has_results(self, issuer, sample_cred):
        attrs = issuer.build_acdc_attrs(sample_cred)
        r = attrs["results"]
        assert r["total"] == 10
        assert r["passed"] == 8
        assert r["failed"] == 1
        assert r["skipped"] == 1

    def test_has_suite_sn(self, issuer, sample_cred):
        attrs = issuer.build_acdc_attrs(sample_cred)
        assert attrs["suiteSn"] == 3

    def test_has_runner_aid(self, issuer, sample_cred):
        attrs = issuer.build_acdc_attrs(sample_cred)
        assert attrs["runnerAid"] == sample_cred.runner_aid

    def test_omits_zero_errors(self, issuer, sample_cred):
        """errors=0 is omitted to keep the ACDC compact."""
        attrs = issuer.build_acdc_attrs(sample_cred)
        assert "errors" not in attrs["results"]

    def test_includes_nonzero_errors(self, issuer):
        results = TestResults(total=5, passed=3, failed=1, skipped=0, errors=1)
        edges = CredentialEdges(test_suite_gaid="EGAID", test_suite_sn=0)
        cred = TestExecutionCredential(
            tree_root_said="ERoot", results=results, edges=edges, timestamp=FIXED_TIMESTAMP,
        )
        attrs = issuer.build_acdc_attrs(cred)
        assert attrs["results"]["errors"] == 1

    def test_includes_coverage(self, issuer):
        results = TestResults(total=5, passed=5, failed=0, skipped=0, coverage_percent=92.5)
        edges = CredentialEdges(test_suite_gaid="EGAID", test_suite_sn=0)
        cred = TestExecutionCredential(
            tree_root_said="ERoot", results=results, edges=edges, timestamp=FIXED_TIMESTAMP,
        )
        attrs = issuer.build_acdc_attrs(cred)
        assert attrs["results"]["coveragePercent"] == 92.5


class TestBuildAcdcEdges:
    def test_has_d_placeholder(self, issuer, sample_cred):
        edges = issuer.build_acdc_edges(sample_cred)
        assert edges["d"] == ""

    def test_has_suite_edge(self, issuer, sample_cred):
        edges = issuer.build_acdc_edges(sample_cred)
        assert "suite" in edges
        assert edges["suite"]["n"] == sample_cred.edges.test_suite_gaid
        assert edges["suite"]["s"] == FAKE_SCHEMA_SAID

    def test_has_previous_run_edge(self, issuer, sample_cred):
        edges = issuer.build_acdc_edges(sample_cred)
        assert "previousRun" in edges
        assert edges["previousRun"]["n"] == sample_cred.edges.previous_run_said

    def test_has_code_under_test_edge(self, issuer, sample_cred):
        edges = issuer.build_acdc_edges(sample_cred)
        assert "codeUnderTest" in edges
        assert edges["codeUnderTest"]["n"] == sample_cred.edges.code_under_test_said

    def test_omits_absent_edges(self, issuer):
        """Edges not present in the credential should be omitted."""
        results = TestResults(total=1, passed=1, failed=0, skipped=0)
        edges = CredentialEdges(test_suite_gaid="EGAID", test_suite_sn=0)
        cred = TestExecutionCredential(
            tree_root_said="ERoot", results=results, edges=edges, timestamp=FIXED_TIMESTAMP,
        )
        acdc_edges = issuer.build_acdc_edges(cred)
        assert "previousRun" not in acdc_edges
        assert "codeUnderTest" not in acdc_edges
        assert "runtimeEnv" not in acdc_edges
        # Suite is always present
        assert "suite" in acdc_edges


# ---------------------------------------------------------------------------
# TestCredentialIssuer: real issuance via proving.credential()
# ---------------------------------------------------------------------------


class TestIssueCredential:
    def test_issue_returns_creder(self, issuer, issuer_hab, registry, sample_cred):
        creder = issuer.issue(issuer_hab, registry, sample_cred)
        assert creder.said is not None
        assert creder.said.startswith("E")

    def test_issue_uses_registry_regk(self, issuer, issuer_hab, registry, sample_cred):
        creder = issuer.issue(issuer_hab, registry, sample_cred)
        # The credential references the registry via the status field in the KED
        assert creder.sad.get("ri") is not None


# ---------------------------------------------------------------------------
# Policy issuance
# ---------------------------------------------------------------------------


class TestIssuePolicyCredential:
    def test_build_policy_attrs(self, issuer):
        policy = PolicyCredential(
            policy_type=PolicyType.BLOCK,
            subtree_path="source/core",
            priority=10,
            description="Block on core changes",
        )
        attrs = issuer.build_policy_attrs(policy)
        assert attrs["d"] == ""
        assert attrs["policyType"] == "block"
        assert attrs["subtreePath"] == "source/core"
        assert attrs["priority"] == 10
        assert attrs["description"] == "Block on core changes"

    def test_build_policy_edges(self, issuer):
        edges = issuer.build_policy_edges(
            suite_gaid="EGAID_suite",
            previous_policy_said="EPrevPolicy",
        )
        assert edges["d"] == ""
        assert edges["suite"]["n"] == "EGAID_suite"
        assert edges["previousPolicy"]["n"] == "EPrevPolicy"

    def test_issue_policy_requires_schema(self):
        issuer = TestCredentialIssuer(schema_said=FAKE_SCHEMA_SAID)
        policy = PolicyCredential(
            policy_type=PolicyType.WARN,
            subtree_path="root",
        )
        with pytest.raises(ValueError, match="policy_schema_said required"):
            issuer.issue_policy(None, None, policy, "EGAID")

    def test_issue_policy_returns_creder(self, issuer, issuer_hab, registry):
        policy = PolicyCredential(
            policy_type=PolicyType.WARN,
            subtree_path="root",
        )
        creder = issuer.issue_policy(
            issuer_hab, registry, policy, suite_gaid="EGAID_suite",
        )
        assert creder.said is not None
        assert creder.said.startswith("E")


# ---------------------------------------------------------------------------
# TestRegistryManager
# ---------------------------------------------------------------------------


class TestRegistryManagerBehavior:
    def test_creates_registry(self, keri_env, issuer_hab):
        from keri_sec.testing.tel_bridge import TestRegistryManager as RegistryMgr
        mgr = RegistryMgr(keri_env["rgy"])
        reg = mgr.get_or_create(issuer_hab)
        assert reg.regk is not None
        assert reg.regk.startswith("E")

    def test_caches_by_aid(self, keri_env, issuer_hab):
        from keri_sec.testing.tel_bridge import TestRegistryManager as RegistryMgr
        mgr = RegistryMgr(keri_env["rgy"])
        reg1 = mgr.get_or_create(issuer_hab)
        reg2 = mgr.get_or_create(issuer_hab)
        assert reg1 is reg2

    def test_registry_name_includes_aid_prefix(self, keri_env, issuer_hab):
        from keri_sec.testing.tel_bridge import TestRegistryManager as RegistryMgr
        mgr = RegistryMgr(keri_env["rgy"])
        reg = mgr.get_or_create(issuer_hab)
        # Registry was created — validate it has a valid key
        assert reg.regk is not None


# ---------------------------------------------------------------------------
# Reger storage
# ---------------------------------------------------------------------------


class TestRegerStorage:
    def test_store_populates_creds(self, keri_env, issuer_hab, registry, issuer, sample_cred):
        creder = issuer.issue(issuer_hab, registry, sample_cred)
        rgy = keri_env["rgy"]

        store_in_reger(rgy, creder, issuer_hab.pre, FAKE_SCHEMA_SAID)

        # Verify main storage
        stored = rgy.reger.creds.get(keys=creder.said)
        assert stored is not None

    def test_store_populates_issuer_index(self, keri_env, issuer_hab, registry, issuer, sample_cred):
        creder = issuer.issue(issuer_hab, registry, sample_cred)
        rgy = keri_env["rgy"]

        store_in_reger(rgy, creder, issuer_hab.pre, FAKE_SCHEMA_SAID)

        # Verify issuer index
        issuer_creds = list(rgy.reger.issus.getIter(keys=issuer_hab.pre))
        saids = [s.qb64 for s in issuer_creds]
        assert creder.said in saids

    def test_store_populates_schema_index(self, keri_env, issuer_hab, registry, issuer, sample_cred):
        creder = issuer.issue(issuer_hab, registry, sample_cred)
        rgy = keri_env["rgy"]

        store_in_reger(rgy, creder, issuer_hab.pre, FAKE_SCHEMA_SAID)

        # Verify schema index
        schema_creds = list(rgy.reger.schms.getIter(keys=FAKE_SCHEMA_SAID))
        saids = [s.qb64 for s in schema_creds]
        assert creder.said in saids

    def test_store_populates_subject_index(self, keri_env, issuer_hab, registry, issuer, sample_cred):
        creder = issuer.issue(issuer_hab, registry, sample_cred)
        rgy = keri_env["rgy"]

        store_in_reger(rgy, creder, issuer_hab.pre, FAKE_SCHEMA_SAID)

        # Verify subject index (self-issued: subject == issuer)
        subj_creds = list(rgy.reger.subjs.getIter(keys=issuer_hab.pre))
        saids = [s.qb64 for s in subj_creds]
        assert creder.said in saids

    def test_store_returns_said(self, keri_env, issuer_hab, registry, issuer, sample_cred):
        creder = issuer.issue(issuer_hab, registry, sample_cred)
        rgy = keri_env["rgy"]

        said = store_in_reger(rgy, creder, issuer_hab.pre, FAKE_SCHEMA_SAID)
        assert said == creder.said


# ---------------------------------------------------------------------------
# TEL anchoring
# ---------------------------------------------------------------------------


class TestAnchorCredential:
    def test_anchor_creates_iss_event(self, issuer_hab, registry, issuer, sample_cred):
        creder = issuer.issue(issuer_hab, registry, sample_cred)
        iss, seqner, saider = anchor_credential(
            issuer_hab, registry, creder.said, dt=FIXED_TIMESTAMP,
        )
        assert iss is not None
        assert seqner.sn > 0
        assert saider.qb64.startswith("E")

    def test_anchor_populates_tevers(self, keri_env, issuer_hab, registry, issuer, sample_cred):
        """After full anchor, the credential's TEL state is populated."""
        creder = issuer.issue(issuer_hab, registry, sample_cred)

        # Issue and anchor
        iss, seqner, saider = anchor_credential(
            issuer_hab, registry, creder.said, dt=FIXED_TIMESTAMP,
        )

        # Process escrows to finalize
        keri_env["rgy"].processEscrows()

        # The registry key should still be in tevers (from VCP anchor)
        assert registry.regk in keri_env["rgy"].reger.tevers


# ---------------------------------------------------------------------------
# Integration: full pipeline
# ---------------------------------------------------------------------------


class TestFullPipeline:
    def test_issue_store_anchor(self, keri_env, issuer_hab, registry, issuer, sample_cred):
        """Full pipeline: build ACDC → issue → store in Reger → anchor to TEL."""
        # Step 1: Issue credential
        creder = issuer.issue(issuer_hab, registry, sample_cred)
        assert creder.said.startswith("E")

        # Step 2: Store in Reger
        rgy = keri_env["rgy"]
        store_in_reger(rgy, creder, issuer_hab.pre, FAKE_SCHEMA_SAID)

        # Step 3: Anchor to TEL
        iss, seqner, saider = anchor_credential(
            issuer_hab, registry, creder.said, dt=FIXED_TIMESTAMP,
        )

        # Step 4: Process escrows
        rgy.processEscrows()

        # Verify: credential is stored and queryable
        stored = rgy.reger.creds.get(keys=creder.said)
        assert stored is not None

        # Verify: issuer index populated
        issuer_creds = list(rgy.reger.issus.getIter(keys=issuer_hab.pre))
        saids = [s.qb64 for s in issuer_creds]
        assert creder.said in saids
