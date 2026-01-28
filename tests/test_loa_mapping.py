# -*- encoding: utf-8 -*-
"""
Tests for LoA mapping module.

Tests Hardman's Level of Assurance mapping and KERI strength levels.
"""

import pytest

from keri_sec.crosswalk.loa_mapping import (
    LoALevel,
    StrengthLevel,
    LoARequirements,
    LoADimensionScore,
    get_loa_requirements,
    map_loa_to_strength,
    map_strength_to_loa,
    loa_satisfies,
    strength_satisfies,
    can_strengthen,
    get_next_loa,
    get_loa_chain,
    get_derivation_losses,
    LOA_REQUIREMENTS,
)


class TestLoALevel:
    """Tests for LoALevel enum."""

    def test_loa_values(self):
        """Test LoA level integer values."""
        assert LoALevel.LOA_0 == 0
        assert LoALevel.LOA_1 == 1
        assert LoALevel.LOA_2 == 2
        assert LoALevel.LOA_3 == 3
        assert LoALevel.VLEI == 4

    def test_loa_comparison(self):
        """Test LoA levels are comparable."""
        assert LoALevel.LOA_0 < LoALevel.LOA_1
        assert LoALevel.LOA_2 < LoALevel.VLEI
        assert LoALevel.VLEI > LoALevel.LOA_3

    def test_loa_human_names(self):
        """Test human-readable names."""
        assert LoALevel.LOA_0.name_human == "Identifier Affidavit"
        assert LoALevel.LOA_1.name_human == "Bronze Vet Credential"
        assert LoALevel.LOA_2.name_human == "Silver Vet Credential"
        assert LoALevel.LOA_3.name_human == "Gold Vet Credential"
        assert LoALevel.VLEI.name_human == "Full vLEI"

    def test_loa_credential_types(self):
        """Test credential type identifiers."""
        assert LoALevel.LOA_0.credential_type == "eLEI"
        assert LoALevel.LOA_1.credential_type == "pre-vLEI1"
        assert LoALevel.LOA_2.credential_type == "pre-vLEI2"
        assert LoALevel.LOA_3.credential_type == "pre-vLEI3"
        assert LoALevel.VLEI.credential_type == "vLEI"


class TestStrengthLevel:
    """Tests for StrengthLevel enum."""

    def test_strength_values(self):
        """Test strength level integer values."""
        assert StrengthLevel.ANY == 0
        assert StrengthLevel.SAID == 1
        assert StrengthLevel.KEL == 2
        assert StrengthLevel.TEL == 3

    def test_strength_comparison(self):
        """Test strength levels are comparable."""
        assert StrengthLevel.ANY < StrengthLevel.SAID
        assert StrengthLevel.KEL < StrengthLevel.TEL


class TestLoARequirements:
    """Tests for LoARequirements dataclass."""

    def test_all_loa_levels_have_requirements(self):
        """Test all LoA levels have defined requirements."""
        for level in LoALevel:
            reqs = get_loa_requirements(level)
            assert reqs.level == level
            assert isinstance(reqs, LoARequirements)

    def test_loa_0_requirements(self):
        """Test LoA 0 requirements match Hardman spec."""
        reqs = get_loa_requirements(LoALevel.LOA_0)
        assert "LEI identifier exists" in reqs.tech_requirements
        assert "Organization not defunct" in reqs.tech_requirements
        assert len(reqs.prerequisites) == 0  # LoA 0 has no prerequisites

    def test_loa_1_prerequisites(self):
        """Test LoA 1 has LoA 0 as prerequisite."""
        reqs = get_loa_requirements(LoALevel.LOA_1)
        assert "Satisfy LoA 0" in reqs.prerequisites

    def test_loa_3_requirements(self):
        """Test LoA 3 requires DARs/LARs and multisig."""
        reqs = get_loa_requirements(LoALevel.LOA_3)
        assert "DARs/LARs configured" in reqs.tech_requirements
        assert "Multisig in place" in reqs.tech_requirements

    def test_vlei_egf_compliance(self):
        """Test vLEI requires EGF compliance."""
        reqs = get_loa_requirements(LoALevel.VLEI)
        assert "Full EGF compliance" in reqs.tech_requirements


class TestLoAToStrengthMapping:
    """Tests for LoA to strength mapping."""

    def test_loa_0_maps_to_any(self):
        """Test LoA 0 maps to ANY strength."""
        assert map_loa_to_strength(LoALevel.LOA_0) == StrengthLevel.ANY

    def test_loa_1_maps_to_said(self):
        """Test LoA 1 maps to SAID strength."""
        assert map_loa_to_strength(LoALevel.LOA_1) == StrengthLevel.SAID

    def test_loa_2_maps_to_kel(self):
        """Test LoA 2 maps to KEL strength."""
        assert map_loa_to_strength(LoALevel.LOA_2) == StrengthLevel.KEL

    def test_loa_3_and_vlei_map_to_tel(self):
        """Test LoA 3 and vLEI map to TEL strength."""
        assert map_loa_to_strength(LoALevel.LOA_3) == StrengthLevel.TEL
        assert map_loa_to_strength(LoALevel.VLEI) == StrengthLevel.TEL


class TestStrengthToLoAMapping:
    """Tests for strength to LoA mapping."""

    def test_any_maps_to_loa_0(self):
        """Test ANY strength maps to minimum LoA 0."""
        assert map_strength_to_loa(StrengthLevel.ANY) == LoALevel.LOA_0

    def test_said_maps_to_loa_1(self):
        """Test SAID strength maps to minimum LoA 1."""
        assert map_strength_to_loa(StrengthLevel.SAID) == LoALevel.LOA_1

    def test_kel_maps_to_loa_2(self):
        """Test KEL strength maps to minimum LoA 2."""
        assert map_strength_to_loa(StrengthLevel.KEL) == LoALevel.LOA_2

    def test_tel_maps_to_loa_3(self):
        """Test TEL strength maps to minimum LoA 3."""
        assert map_strength_to_loa(StrengthLevel.TEL) == LoALevel.LOA_3


class TestLoASatisfies:
    """Tests for LoA satisfaction checking."""

    def test_equal_levels_satisfy(self):
        """Test equal levels satisfy requirement."""
        assert loa_satisfies(LoALevel.LOA_2, LoALevel.LOA_2)

    def test_higher_satisfies_lower(self):
        """Test higher levels satisfy lower requirements."""
        assert loa_satisfies(LoALevel.VLEI, LoALevel.LOA_0)
        assert loa_satisfies(LoALevel.LOA_3, LoALevel.LOA_1)

    def test_lower_does_not_satisfy_higher(self):
        """Test lower levels do not satisfy higher requirements."""
        assert not loa_satisfies(LoALevel.LOA_0, LoALevel.LOA_1)
        assert not loa_satisfies(LoALevel.LOA_2, LoALevel.VLEI)


class TestStrengthSatisfies:
    """Tests for strength satisfaction checking."""

    def test_equal_strengths_satisfy(self):
        """Test equal strengths satisfy requirement."""
        assert strength_satisfies(StrengthLevel.KEL, StrengthLevel.KEL)

    def test_higher_satisfies_lower(self):
        """Test higher strengths satisfy lower requirements."""
        assert strength_satisfies(StrengthLevel.TEL, StrengthLevel.ANY)
        assert strength_satisfies(StrengthLevel.KEL, StrengthLevel.SAID)

    def test_lower_does_not_satisfy_higher(self):
        """Test lower strengths do not satisfy higher requirements."""
        assert not strength_satisfies(StrengthLevel.ANY, StrengthLevel.SAID)
        assert not strength_satisfies(StrengthLevel.KEL, StrengthLevel.TEL)


class TestCanStrengthen:
    """Tests for strengthening validation."""

    def test_can_strengthen_to_higher(self):
        """Test can strengthen to higher level."""
        assert can_strengthen(LoALevel.LOA_0, LoALevel.LOA_1)
        assert can_strengthen(LoALevel.LOA_2, LoALevel.VLEI)

    def test_cannot_strengthen_to_same(self):
        """Test cannot strengthen to same level."""
        assert not can_strengthen(LoALevel.LOA_1, LoALevel.LOA_1)

    def test_cannot_weaken(self):
        """Test cannot weaken (monotonic ratchet)."""
        assert not can_strengthen(LoALevel.LOA_2, LoALevel.LOA_1)
        assert not can_strengthen(LoALevel.VLEI, LoALevel.LOA_3)


class TestGetNextLoA:
    """Tests for getting next LoA level."""

    def test_next_loa_increments(self):
        """Test next LoA increments by one."""
        assert get_next_loa(LoALevel.LOA_0) == LoALevel.LOA_1
        assert get_next_loa(LoALevel.LOA_1) == LoALevel.LOA_2
        assert get_next_loa(LoALevel.LOA_2) == LoALevel.LOA_3
        assert get_next_loa(LoALevel.LOA_3) == LoALevel.VLEI

    def test_next_loa_at_vlei_is_none(self):
        """Test vLEI has no next level."""
        assert get_next_loa(LoALevel.VLEI) is None


class TestGetLoAChain:
    """Tests for getting LoA chain."""

    def test_chain_to_loa_0(self):
        """Test chain to LoA 0 is just LoA 0."""
        chain = get_loa_chain(LoALevel.LOA_0)
        assert chain == [LoALevel.LOA_0]

    def test_chain_to_loa_2(self):
        """Test chain to LoA 2 includes 0, 1, 2."""
        chain = get_loa_chain(LoALevel.LOA_2)
        assert chain == [LoALevel.LOA_0, LoALevel.LOA_1, LoALevel.LOA_2]

    def test_chain_to_vlei(self):
        """Test chain to vLEI includes all levels."""
        chain = get_loa_chain(LoALevel.VLEI)
        assert len(chain) == 5
        assert chain[0] == LoALevel.LOA_0
        assert chain[-1] == LoALevel.VLEI


class TestLoADimensionScore:
    """Tests for LoADimensionScore dataclass."""

    def test_preservation_ratio_all_preserved(self):
        """Test preservation ratio when all preserved."""
        score = LoADimensionScore(
            dimension="tech",
            preserved=["a", "b", "c"],
            degraded=[],
            lost=[],
        )
        assert score.preservation_ratio == 1.0

    def test_preservation_ratio_half_lost(self):
        """Test preservation ratio when half lost."""
        score = LoADimensionScore(
            dimension="tech",
            preserved=["a"],
            degraded=[],
            lost=["b"],
        )
        assert score.preservation_ratio == 0.5

    def test_preservation_ratio_all_lost(self):
        """Test preservation ratio when all lost."""
        score = LoADimensionScore(
            dimension="tech",
            preserved=[],
            degraded=[],
            lost=["a", "b"],
        )
        assert score.preservation_ratio == 0.0

    def test_loss_severity_minimal(self):
        """Test minimal loss severity."""
        score = LoADimensionScore(
            dimension="tech",
            preserved=["a", "b", "c", "d"],
            degraded=[],
            lost=["e"],
        )
        assert score.loss_severity == "minimal"

    def test_loss_severity_severe(self):
        """Test severe loss severity."""
        score = LoADimensionScore(
            dimension="tech",
            preserved=["a"],
            degraded=[],
            lost=["b", "c", "d", "e", "f"],
        )
        assert score.loss_severity == "severe"


class TestDerivationLosses:
    """Tests for derivation loss retrieval."""

    def test_w3c_vc_losses(self):
        """Test W3C VC losses are returned."""
        losses = get_derivation_losses("w3c_vc")
        assert "tech" in losses
        assert "governance" in losses
        assert "holder" in losses
        assert "vetting" in losses

    def test_x509_losses(self):
        """Test x509 losses are returned."""
        losses = get_derivation_losses("x509")
        assert "tech" in losses
        assert losses["tech"].dimension == "tech"

    def test_unknown_format_defaults_to_w3c(self):
        """Test unknown format defaults to W3C VC losses."""
        losses = get_derivation_losses("unknown_format")
        w3c_losses = get_derivation_losses("w3c_vc")
        assert losses == w3c_losses
