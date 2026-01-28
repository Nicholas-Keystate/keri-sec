# -*- encoding: utf-8 -*-
"""
Tests for loss report infrastructure.

Tests LossReport, LossItem, and related functions.
"""

import pytest

from keri_sec.crosswalk.loa_mapping import LoALevel, StrengthLevel
from keri_sec.crosswalk.loss_report import (
    LossSeverity,
    LossCategory,
    LossItem,
    LossReport,
    create_loss_report,
    assess_derivation_viability,
    get_mitigation_recommendations,
    STANDARD_LOSSES,
)


class TestLossItem:
    """Tests for LossItem dataclass."""

    def test_loss_item_creation(self):
        """Test creating a loss item."""
        item = LossItem(
            name="test_loss",
            category=LossCategory.TECH,
            severity=LossSeverity.MODERATE,
            description="Test loss description",
        )
        assert item.name == "test_loss"
        assert item.category == LossCategory.TECH
        assert item.severity == LossSeverity.MODERATE

    def test_loss_item_is_total_loss(self):
        """Test is_total_loss property."""
        total_loss = LossItem(
            name="lost",
            category=LossCategory.TECH,
            severity=LossSeverity.SEVERE,
            description="Completely lost",
        )
        assert total_loss.is_total_loss

        degraded = LossItem(
            name="degraded",
            category=LossCategory.TECH,
            severity=LossSeverity.MINIMAL,
            description="Degraded",
            target_representation="some representation",
        )
        assert not degraded.is_total_loss


class TestLossReport:
    """Tests for LossReport dataclass."""

    def test_empty_report(self):
        """Test empty loss report."""
        report = LossReport(
            source_said="ESAID123",
            source_loa=LoALevel.LOA_2,
            target_format="w3c_vc",
        )
        report.finalize()
        assert report.overall_severity == LossSeverity.NONE
        assert report.total_losses == 0

    def test_add_losses(self):
        """Test adding losses to report."""
        report = LossReport(
            source_said="ESAID123",
            source_loa=LoALevel.LOA_2,
            target_format="w3c_vc",
        )
        report.add_loss(LossItem(
            name="loss1",
            category=LossCategory.TECH,
            severity=LossSeverity.MODERATE,
            description="Test",
        ))
        report.add_loss(LossItem(
            name="loss2",
            category=LossCategory.STRUCTURAL,
            severity=LossSeverity.SEVERE,
            description="Test",
        ))
        assert len(report.losses) == 2

    def test_finalize_computes_severity(self):
        """Test finalize computes overall severity."""
        report = LossReport(
            source_said="ESAID123",
            source_loa=LoALevel.LOA_2,
            target_format="w3c_vc",
        )
        report.add_loss(LossItem(
            name="minor",
            category=LossCategory.TECH,
            severity=LossSeverity.MINIMAL,
            description="Minor loss",
        ))
        report.add_loss(LossItem(
            name="major",
            category=LossCategory.STRUCTURAL,
            severity=LossSeverity.SEVERE,
            description="Major loss",
        ))
        report.finalize()
        # Overall should be SEVERE (worst)
        assert report.overall_severity == LossSeverity.SEVERE

    def test_finalize_computes_effective_strength(self):
        """Test finalize computes effective strength."""
        report = LossReport(
            source_said="ESAID123",
            source_loa=LoALevel.LOA_3,  # Maps to TEL
            target_format="w3c_vc",
        )
        report.add_loss(LossItem(
            name="severe",
            category=LossCategory.STRUCTURAL,
            severity=LossSeverity.SEVERE,
            description="Severe loss",
        ))
        report.finalize()
        # Severe loss reduces strength
        assert report.effective_strength < StrengthLevel.TEL

    def test_by_category_filter(self):
        """Test filtering losses by category."""
        report = LossReport(
            source_said="ESAID123",
            source_loa=LoALevel.LOA_0,
            target_format="w3c_vc",
        )
        report.add_loss(LossItem(
            name="tech1",
            category=LossCategory.TECH,
            severity=LossSeverity.MODERATE,
            description="Tech loss",
        ))
        report.add_loss(LossItem(
            name="gov1",
            category=LossCategory.GOVERNANCE,
            severity=LossSeverity.MODERATE,
            description="Governance loss",
        ))
        report.add_loss(LossItem(
            name="tech2",
            category=LossCategory.TECH,
            severity=LossSeverity.MINIMAL,
            description="Tech loss 2",
        ))

        tech_losses = report.by_category(LossCategory.TECH)
        assert len(tech_losses) == 2

        gov_losses = report.by_category(LossCategory.GOVERNANCE)
        assert len(gov_losses) == 1

    def test_by_severity_filter(self):
        """Test filtering losses by severity."""
        report = LossReport(
            source_said="ESAID123",
            source_loa=LoALevel.LOA_0,
            target_format="w3c_vc",
        )
        report.add_loss(LossItem(
            name="severe1",
            category=LossCategory.TECH,
            severity=LossSeverity.SEVERE,
            description="Severe",
        ))
        report.add_loss(LossItem(
            name="minimal1",
            category=LossCategory.TECH,
            severity=LossSeverity.MINIMAL,
            description="Minimal",
        ))

        severe = report.by_severity(LossSeverity.SEVERE)
        assert len(severe) == 1
        assert severe[0].name == "severe1"

    def test_to_dict_serialization(self):
        """Test report serializes to dict."""
        report = LossReport(
            source_said="ESAID123",
            source_loa=LoALevel.LOA_2,
            target_format="w3c_vc",
        )
        report.add_loss(LossItem(
            name="test",
            category=LossCategory.TECH,
            severity=LossSeverity.MODERATE,
            description="Test",
        ))
        report.finalize()

        d = report.to_dict()
        assert d["source_said"] == "ESAID123"
        assert d["source_loa"] == "LOA_2"
        assert d["target_format"] == "w3c_vc"
        assert len(d["losses"]) == 1


class TestCreateLossReport:
    """Tests for create_loss_report function."""

    def test_create_w3c_vc_report(self):
        """Test creating W3C VC loss report."""
        report = create_loss_report(
            source_said="ESAID123",
            source_loa=LoALevel.LOA_2,
            target_format="w3c_vc",
        )
        # Should have dimension scores
        assert "tech" in report.dimension_scores
        # Should have losses populated from dimension scores
        assert len(report.losses) > 0

    def test_create_x509_report(self):
        """Test creating x509 loss report."""
        report = create_loss_report(
            source_said="ESAID123",
            source_loa=LoALevel.LOA_3,
            target_format="x509",
        )
        assert report.target_format == "x509"
        assert len(report.losses) > 0


class TestAssessDerivationViability:
    """Tests for assess_derivation_viability function."""

    def test_viable_derivation(self):
        """Test viable derivation assessment."""
        viable, msg = assess_derivation_viability(
            source_loa=LoALevel.VLEI,
            target_format="w3c_vc",
            required_strength=StrengthLevel.ANY,
        )
        assert viable
        assert "viable" in msg.lower()

    def test_not_viable_derivation(self):
        """Test non-viable derivation assessment."""
        viable, msg = assess_derivation_viability(
            source_loa=LoALevel.LOA_0,
            target_format="x509",
            required_strength=StrengthLevel.TEL,
        )
        assert not viable
        assert "NOT viable" in msg


class TestGetMitigationRecommendations:
    """Tests for get_mitigation_recommendations function."""

    def test_recommendations_for_losses(self):
        """Test recommendations are generated for losses."""
        report = create_loss_report(
            source_said="ESAID123",
            source_loa=LoALevel.LOA_3,
            target_format="w3c_vc",
        )
        report.finalize()

        recommendations = get_mitigation_recommendations(report)
        assert len(recommendations) > 0

    def test_no_recommendations_for_clean_report(self):
        """Test minimal recommendations for report with no severe losses."""
        report = LossReport(
            source_said="ESAID123",
            source_loa=LoALevel.LOA_0,
            target_format="w3c_vc",
        )
        report.finalize()

        recommendations = get_mitigation_recommendations(report)
        assert any("no significant" in r.lower() for r in recommendations)


class TestStandardLosses:
    """Tests for STANDARD_LOSSES constants."""

    def test_edge_section_loss_exists(self):
        """Test edge_section standard loss exists."""
        assert "edge_section" in STANDARD_LOSSES
        loss = STANDARD_LOSSES["edge_section"]
        assert loss.severity == LossSeverity.SEVERE

    def test_edge_operators_loss_exists(self):
        """Test edge_operators standard loss exists."""
        assert "edge_operators" in STANDARD_LOSSES
        loss = STANDARD_LOSSES["edge_operators"]
        assert loss.category == LossCategory.STRUCTURAL

    def test_said_to_id_is_minimal(self):
        """Test SAID to id mapping is minimal loss."""
        assert "said_to_id" in STANDARD_LOSSES
        loss = STANDARD_LOSSES["said_to_id"]
        assert loss.severity == LossSeverity.MINIMAL
        assert loss.target_representation  # Has representation (not total loss)
