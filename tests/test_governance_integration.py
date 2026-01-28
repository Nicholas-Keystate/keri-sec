# -*- encoding: utf-8 -*-
"""
Integration tests: KGQL + keri-governance + keri-sec infrastructure.

Tasks #20 and #21 from Phase 3:
- Real Habery for DAID-signed credentials
- KEL attestation verification
- Governance enforcement with production-grade infrastructure

These tests demonstrate production readiness by using keri-sec's
KeriInfrastructure rather than mocking KERI operations.
"""

import pytest
import tempfile
from pathlib import Path
from unittest.mock import Mock

from keri_sec.keri.infrastructure import (
    KeriInfrastructure,
    reset_infrastructure,
)

from keri_governance.primitives import (
    EdgeOperator,
    StrengthLevel,
    LoALevel,
    operator_satisfies,
    loa_satisfies,
    loa_to_strength,
)
from keri_governance.schema import (
    GovernanceFramework,
    ConstraintRule,
    CredentialMatrixEntry,
    RuleEnforcement,
)
from keri_governance.checker import ConstraintChecker, CheckResult


class TestGovernanceWithRealHabery:
    """Integration tests using real Habery from keri-sec."""

    @pytest.fixture
    def keri_infra(self):
        """Create temporary KERI infrastructure for testing."""
        reset_infrastructure()
        with tempfile.TemporaryDirectory() as tmpdir:
            infra = KeriInfrastructure(
                base_path=Path(tmpdir),
                passcode="test-governance-key",
                temp=True,
            )
            infra.enter()
            yield infra
            infra.exit()
            reset_infrastructure()

    @pytest.fixture
    def issuer_aid(self, keri_infra):
        """Create a real issuer AID."""
        return keri_infra.create_aid("test-issuer", transferable=True)

    @pytest.fixture
    def holder_aid(self, keri_infra):
        """Create a real holder AID."""
        return keri_infra.create_aid("test-holder", transferable=False)

    @pytest.fixture
    def delegated_aid(self, keri_infra, issuer_aid):
        """Create a delegated AID."""
        return keri_infra.create_delegated_aid(
            alias="delegated-issuer",
            delegator_alias="test-issuer",
            transferable=True,
        )

    @pytest.fixture
    def governance_framework(self):
        """Create a test governance framework."""
        return GovernanceFramework(
            said="ETEST_FRAMEWORK_SAID",
            name="Test Governance Framework",
            rules=[
                ConstraintRule(
                    name="iss_requires_di2i",
                    applies_to="iss",
                    required_operator=EdgeOperator.DI2I,
                    enforcement=RuleEnforcement.STRICT,
                ),
                ConstraintRule(
                    name="acdc_requires_i2i",
                    applies_to="acdc",
                    required_operator=EdgeOperator.I2I,
                    enforcement=RuleEnforcement.STRICT,
                ),
                ConstraintRule(
                    name="att_allows_ni2i",
                    applies_to="att",
                    required_operator=EdgeOperator.NI2I,
                    enforcement=RuleEnforcement.ADVISORY,
                ),
            ],
            credential_matrix=[
                CredentialMatrixEntry(
                    action="issue",
                    role="QVI",
                    allowed=True,
                    required_operator=EdgeOperator.I2I,
                ),
                CredentialMatrixEntry(
                    action="issue",
                    role="LE",
                    allowed=True,
                    required_operator=EdgeOperator.DI2I,
                ),
                CredentialMatrixEntry(
                    action="revoke",
                    role="QVI",
                    allowed=True,
                    required_operator=EdgeOperator.I2I,
                ),
                CredentialMatrixEntry(
                    action="query",
                    role="public",
                    allowed=True,
                    required_operator=EdgeOperator.ANY,
                ),
            ],
        )

    def test_real_aid_creation(self, keri_infra, issuer_aid, holder_aid):
        """Test that real AIDs are created with KERI prefixes."""
        assert issuer_aid.startswith(("B", "D", "E"))
        assert holder_aid.startswith(("B", "D", "E"))
        assert issuer_aid != holder_aid

    def test_delegated_aid_chain(self, keri_infra, issuer_aid, delegated_aid):
        """Test delegation chain exists."""
        assert delegated_aid.startswith(("B", "D", "E"))
        assert delegated_aid != issuer_aid

        # Verify delegation is recorded
        sessions = keri_infra._read_registry()
        delegations = sessions.get("delegations", {})
        assert delegated_aid in delegations
        assert delegations[delegated_aid]["delegator"] == issuer_aid

    def test_constraint_checker_with_real_framework(self, governance_framework):
        """Test ConstraintChecker with real framework."""
        checker = ConstraintChecker(governance_framework)

        # I2I satisfies DI2I requirement (stronger)
        result = checker.check_edge("iss", EdgeOperator.I2I)
        assert result.allowed
        assert len(result.violations) == 0

        # DI2I satisfies DI2I requirement (equal)
        result = checker.check_edge("iss", EdgeOperator.DI2I)
        assert result.allowed

        # NI2I does NOT satisfy DI2I requirement (weaker)
        result = checker.check_edge("iss", EdgeOperator.NI2I)
        assert not result.allowed
        assert len(result.violations) == 1
        assert "requires @DI2I" in result.violations[0].message

    def test_action_matrix_enforcement(self, governance_framework):
        """Test credential matrix action enforcement."""
        checker = ConstraintChecker(governance_framework)

        # QVI can issue with I2I
        result = checker.check_action("issue", "QVI", EdgeOperator.I2I)
        assert result.allowed

        # QVI cannot issue with DI2I (too weak)
        result = checker.check_action("issue", "QVI", EdgeOperator.DI2I)
        assert not result.allowed

        # LE can issue with DI2I
        result = checker.check_action("issue", "LE", EdgeOperator.DI2I)
        assert result.allowed

        # LE can issue with I2I (stronger than required)
        result = checker.check_action("issue", "LE", EdgeOperator.I2I)
        assert result.allowed

    def test_loa_integration_with_credentials(self, governance_framework):
        """Test LoA constraint checking."""
        checker = ConstraintChecker(governance_framework)

        # Credential with LoA 2
        cred = {
            "d": "ESAID_LOA2_CRED",
            "a": {
                "d": "EATTR_SAID",
                "loa": 2,
                "name": "Test Org",
            }
        }

        # LoA 2 satisfies LoA 2
        result = checker.check_loa(cred, LoALevel.LOA_2)
        assert result.allowed

        # LoA 2 satisfies LoA 1 (lower)
        result = checker.check_loa(cred, LoALevel.LOA_1)
        assert result.allowed

        # LoA 2 does NOT satisfy LoA 3 (higher)
        result = checker.check_loa(cred, LoALevel.LOA_3)
        assert not result.allowed
        assert "does not satisfy" in result.violations[0].message

    def test_loa_chain_with_multiple_credentials(self, governance_framework):
        """Test LoA chain checking."""
        checker = ConstraintChecker(governance_framework)

        # Chain with varying LoA levels
        creds = [
            {"d": "ECRED1", "a": {"loa": 3}},  # Gold
            {"d": "ECRED2", "a": {"loa": 3}},  # Gold
            {"d": "ECRED3", "a": {"loa": 4}},  # vLEI
        ]

        # All satisfy LoA 3
        result = checker.check_loa_chain(creds, LoALevel.LOA_3)
        assert result.allowed

        # Chain with weak link
        weak_chain = [
            {"d": "ECRED1", "a": {"loa": 3}},
            {"d": "ECRED2", "a": {"loa": 1}},  # Too weak!
            {"d": "ECRED3", "a": {"loa": 3}},
        ]

        result = checker.check_loa_chain(weak_chain, LoALevel.LOA_2)
        assert not result.allowed
        assert "position 1" in result.violations[0].message

    def test_delegation_depth_limits(self, governance_framework):
        """Test delegation depth constraint enforcement."""
        # Add depth limit rule
        framework = GovernanceFramework(
            said="ETEST_DEPTH_FRAMEWORK",
            name="Depth Limited Framework",
            rules=[
                ConstraintRule(
                    name="iss_max_depth_3",
                    applies_to="iss",
                    required_operator=EdgeOperator.DI2I,
                    max_delegation_depth=3,
                    enforcement=RuleEnforcement.STRICT,
                ),
            ],
        )

        checker = ConstraintChecker(framework)

        # Depth 2 is OK
        result = checker.check_delegation_depth("iss", 2)
        assert result.allowed

        # Depth 3 is OK (exactly at limit)
        result = checker.check_delegation_depth("iss", 3)
        assert result.allowed

        # Depth 4 exceeds limit
        result = checker.check_delegation_depth("iss", 4)
        assert not result.allowed
        assert "exceeds maximum" in result.violations[0].message


class TestKELAttestation:
    """Tests for KEL attestation and verification (Task #21)."""

    @pytest.fixture
    def keri_infra(self):
        """Create temporary KERI infrastructure for testing."""
        reset_infrastructure()
        with tempfile.TemporaryDirectory() as tmpdir:
            infra = KeriInfrastructure(
                base_path=Path(tmpdir),
                passcode="test-kel-attest-key",
                temp=True,
            )
            infra.enter()
            yield infra
            infra.exit()
            reset_infrastructure()

    @pytest.fixture
    def issuer_hab(self, keri_infra):
        """Get the actual Hab for the issuer."""
        aid = keri_infra.create_aid("kel-test-issuer", transferable=True)
        return keri_infra._get_hab_by_alias("kel-test-issuer")

    def test_hab_has_kel(self, issuer_hab):
        """Test that created Hab has a KEL."""
        assert issuer_hab is not None
        assert issuer_hab.pre is not None

        # KEL is accessible via kever
        assert hasattr(issuer_hab, "kever")
        kever = issuer_hab.kever
        assert kever is not None

        # KEL has inception event
        assert kever.serder is not None
        assert kever.sn == 0  # Inception is sequence 0

    def test_hab_signature_verification(self, keri_infra, issuer_hab):
        """Test that we can sign and verify with the Hab."""
        # Sign some data
        data = b"test data to sign"

        # Sign the data using hab.sign()
        sigers = issuer_hab.sign(ser=data)
        assert len(sigers) > 0

        # Verify signature against public key
        verfer = issuer_hab.kever.verfers[0]
        verified = verfer.verify(sig=sigers[0].raw, ser=data)
        assert verified

    def test_content_said_anchoring(self, keri_infra):
        """Test that content can be anchored via SAID."""
        content = {
            "type": "attestation",
            "subject": "test-subject",
            "claim": "test-claim",
        }

        # Store content and get SAID
        said = keri_infra.store_content(content)
        assert said.startswith("E")

        # Retrieve and verify
        retrieved = keri_infra.get_content(said)
        assert retrieved == content

        # SAID is deterministic
        said2 = keri_infra.compute_content_said(content)
        assert said == said2

    def test_delegated_signing(self, keri_infra):
        """Test delegated AID can sign."""
        # Create delegator and delegate
        delegator_aid = keri_infra.create_aid("delegator", transferable=True)
        delegate_aid = keri_infra.create_delegated_aid(
            alias="delegate",
            delegator_alias="delegator",
            transferable=True,
        )

        delegate_hab = keri_infra._get_hab_by_alias("delegate")
        assert delegate_hab is not None

        # Delegate can sign
        data = b"delegate signed data"
        sigers = delegate_hab.sign(ser=data)
        assert len(sigers) > 0

        # Verify signature
        verfer = delegate_hab.kever.verfers[0]
        verified = verfer.verify(sig=sigers[0].raw, ser=data)
        assert verified


class TestLoAToStrengthMapping:
    """Test LoA level to KERI strength level mapping."""

    def test_loa_0_maps_to_any(self):
        """LoA 0 (Identifier Affidavit) maps to ANY strength."""
        assert loa_to_strength(LoALevel.LOA_0) == StrengthLevel.ANY

    def test_loa_1_maps_to_said_only(self):
        """LoA 1 (Bronze Vet) maps to SAID_ONLY strength."""
        assert loa_to_strength(LoALevel.LOA_1) == StrengthLevel.SAID_ONLY

    def test_loa_2_maps_to_kel_anchored(self):
        """LoA 2 (Silver Vet) maps to KEL_ANCHORED strength."""
        assert loa_to_strength(LoALevel.LOA_2) == StrengthLevel.KEL_ANCHORED

    def test_loa_3_maps_to_tel_anchored(self):
        """LoA 3 (Gold Vet) maps to TEL_ANCHORED strength."""
        assert loa_to_strength(LoALevel.LOA_3) == StrengthLevel.TEL_ANCHORED

    def test_vlei_maps_to_tel_anchored(self):
        """vLEI (full compliance) maps to TEL_ANCHORED strength."""
        assert loa_to_strength(LoALevel.VLEI) == StrengthLevel.TEL_ANCHORED


class TestOperatorPartialOrder:
    """Verify operator partial order: I2I > DI2I > NI2I > ANY."""

    @pytest.mark.parametrize("actual,required,expected", [
        # I2I satisfies everything
        (EdgeOperator.I2I, EdgeOperator.I2I, True),
        (EdgeOperator.I2I, EdgeOperator.DI2I, True),
        (EdgeOperator.I2I, EdgeOperator.NI2I, True),
        (EdgeOperator.I2I, EdgeOperator.ANY, True),
        # DI2I satisfies DI2I, NI2I, ANY
        (EdgeOperator.DI2I, EdgeOperator.I2I, False),
        (EdgeOperator.DI2I, EdgeOperator.DI2I, True),
        (EdgeOperator.DI2I, EdgeOperator.NI2I, True),
        (EdgeOperator.DI2I, EdgeOperator.ANY, True),
        # NI2I satisfies NI2I, ANY
        (EdgeOperator.NI2I, EdgeOperator.I2I, False),
        (EdgeOperator.NI2I, EdgeOperator.DI2I, False),
        (EdgeOperator.NI2I, EdgeOperator.NI2I, True),
        (EdgeOperator.NI2I, EdgeOperator.ANY, True),
        # ANY only satisfies ANY
        (EdgeOperator.ANY, EdgeOperator.I2I, False),
        (EdgeOperator.ANY, EdgeOperator.DI2I, False),
        (EdgeOperator.ANY, EdgeOperator.NI2I, False),
        (EdgeOperator.ANY, EdgeOperator.ANY, True),
    ])
    def test_operator_satisfies(self, actual, required, expected):
        """Parametrized test for operator partial order."""
        assert operator_satisfies(actual, required) == expected


class TestLoAPartialOrder:
    """Verify LoA partial order: vLEI > LOA_3 > LOA_2 > LOA_1 > LOA_0."""

    @pytest.mark.parametrize("actual,required,expected", [
        # vLEI satisfies everything
        (LoALevel.VLEI, LoALevel.VLEI, True),
        (LoALevel.VLEI, LoALevel.LOA_3, True),
        (LoALevel.VLEI, LoALevel.LOA_2, True),
        (LoALevel.VLEI, LoALevel.LOA_1, True),
        (LoALevel.VLEI, LoALevel.LOA_0, True),
        # LOA_3 satisfies LOA_3 and below
        (LoALevel.LOA_3, LoALevel.VLEI, False),
        (LoALevel.LOA_3, LoALevel.LOA_3, True),
        (LoALevel.LOA_3, LoALevel.LOA_2, True),
        # LOA_2 satisfies LOA_2 and below
        (LoALevel.LOA_2, LoALevel.LOA_3, False),
        (LoALevel.LOA_2, LoALevel.LOA_2, True),
        (LoALevel.LOA_2, LoALevel.LOA_1, True),
        # LOA_1 satisfies LOA_1 and below
        (LoALevel.LOA_1, LoALevel.LOA_2, False),
        (LoALevel.LOA_1, LoALevel.LOA_1, True),
        (LoALevel.LOA_1, LoALevel.LOA_0, True),
        # LOA_0 only satisfies LOA_0
        (LoALevel.LOA_0, LoALevel.LOA_1, False),
        (LoALevel.LOA_0, LoALevel.LOA_0, True),
    ])
    def test_loa_satisfies(self, actual, required, expected):
        """Parametrized test for LoA partial order."""
        assert loa_satisfies(actual, required) == expected
