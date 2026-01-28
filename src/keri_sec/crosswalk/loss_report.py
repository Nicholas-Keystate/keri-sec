# -*- encoding: utf-8 -*-
"""
Loss Report Infrastructure for Credential Crosswalk.

Provides structured reporting of what semantic content is preserved,
degraded, or lost when deriving from ACDC to other credential formats.

Key concepts:
    - Derivation is lossy (ACDC → other format)
    - Translation is lossless (ACDC ↔ ACDC)
    - Loss reports document exactly what is lost and why
    - Severity levels categorize the impact of losses
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from .loa_mapping import (
    LoALevel,
    StrengthLevel,
    LoADimensionScore,
    get_derivation_losses,
    map_loa_to_strength,
)


class LossSeverity(str, Enum):
    """
    Severity classification for derivation losses.

    Based on impact to credential utility and verifiability.
    """
    NONE = "none"           # No loss - full preservation
    MINIMAL = "minimal"     # Minor formatting changes, no semantic loss
    MODERATE = "moderate"   # Some semantic loss, credential still useful
    SIGNIFICANT = "significant"  # Major semantic loss, reduced assurance
    SEVERE = "severe"       # Critical loss, credential validity questionable


class LossCategory(str, Enum):
    """
    Categories of loss in credential derivation.

    Maps to Hardman's four LoA dimensions plus structural losses.
    """
    TECH = "tech"           # Technical primitives (crypto, identifiers)
    GOVERNANCE = "governance"  # Framework rules, constraints
    HOLDER = "holder"       # Subject attributes, claims
    VETTING = "vetting"     # Process rigor, chain of vetting
    STRUCTURAL = "structural"  # Graph structure, edges, relationships


@dataclass
class LossItem:
    """
    Single item lost or degraded in derivation.

    Represents one specific piece of semantic content that could not
    be fully preserved in the target format.
    """
    name: str                       # What was lost (e.g., "edge_section")
    category: LossCategory          # Which dimension
    severity: LossSeverity          # How bad is this loss
    description: str                # Human explanation
    source_path: str = ""           # JSON path in source ACDC
    target_representation: str = "" # How it's represented in target (if degraded)
    mitigation: str = ""            # How to work around this loss

    @property
    def is_total_loss(self) -> bool:
        """Check if this is a complete loss (not degraded)."""
        return not self.target_representation


@dataclass
class LossReport:
    """
    Complete loss report for a credential derivation.

    Documents all losses, their severity, and provides overall
    assessment of the derivation quality.
    """
    source_said: str                # SAID of source ACDC
    source_loa: LoALevel            # LoA level of source
    target_format: str              # Target format (e.g., "w3c_vc")
    derived_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    # Categorized losses
    losses: list[LossItem] = field(default_factory=list)

    # Dimension scores (from loa_mapping)
    dimension_scores: dict[str, LoADimensionScore] = field(default_factory=dict)

    # Computed fields (set by finalize())
    overall_severity: LossSeverity = LossSeverity.NONE
    effective_strength: StrengthLevel = StrengthLevel.ANY
    preservation_ratio: float = 1.0
    warning_summary: str = ""

    def add_loss(self, item: LossItem) -> None:
        """Add a loss item to the report."""
        self.losses.append(item)

    def finalize(self) -> "LossReport":
        """
        Compute derived fields after all losses are added.

        Should be called once after populating losses and dimension_scores.
        """
        # Compute overall severity from worst loss
        if self.losses:
            severities = [l.severity for l in self.losses]
            severity_order = [
                LossSeverity.NONE,
                LossSeverity.MINIMAL,
                LossSeverity.MODERATE,
                LossSeverity.SIGNIFICANT,
                LossSeverity.SEVERE,
            ]
            self.overall_severity = max(severities, key=lambda s: severity_order.index(s))
        else:
            self.overall_severity = LossSeverity.NONE

        # Compute preservation ratio from dimension scores
        if self.dimension_scores:
            ratios = [score.preservation_ratio for score in self.dimension_scores.values()]
            self.preservation_ratio = sum(ratios) / len(ratios)
        else:
            self.preservation_ratio = 1.0

        # Compute effective strength (downgraded from source based on losses)
        source_strength = map_loa_to_strength(self.source_loa)
        strength_penalties = {
            LossSeverity.NONE: 0,
            LossSeverity.MINIMAL: 0,
            LossSeverity.MODERATE: 1,
            LossSeverity.SIGNIFICANT: 2,
            LossSeverity.SEVERE: 3,
        }
        penalty = strength_penalties.get(self.overall_severity, 0)
        new_strength_value = max(0, source_strength.value - penalty)
        self.effective_strength = StrengthLevel(new_strength_value)

        # Generate warning summary
        self.warning_summary = self._generate_warning_summary()

        return self

    def _generate_warning_summary(self) -> str:
        """Generate human-readable warning summary."""
        if self.overall_severity == LossSeverity.NONE:
            return "No losses detected."

        severe_losses = [l for l in self.losses if l.severity == LossSeverity.SEVERE]
        significant_losses = [l for l in self.losses if l.severity == LossSeverity.SIGNIFICANT]

        parts = []
        if severe_losses:
            names = ", ".join(l.name for l in severe_losses[:3])
            parts.append(f"SEVERE: {names}")
        if significant_losses:
            names = ", ".join(l.name for l in significant_losses[:3])
            parts.append(f"SIGNIFICANT: {names}")

        if self.effective_strength < map_loa_to_strength(self.source_loa):
            parts.append(
                f"Strength reduced from {map_loa_to_strength(self.source_loa).name} "
                f"to {self.effective_strength.name}"
            )

        return "; ".join(parts) if parts else "Minor losses detected."

    @property
    def total_losses(self) -> int:
        """Count of total loss items."""
        return len([l for l in self.losses if l.is_total_loss])

    @property
    def degraded_items(self) -> int:
        """Count of degraded (not totally lost) items."""
        return len([l for l in self.losses if not l.is_total_loss])

    def by_category(self, category: LossCategory) -> list[LossItem]:
        """Get losses filtered by category."""
        return [l for l in self.losses if l.category == category]

    def by_severity(self, severity: LossSeverity) -> list[LossItem]:
        """Get losses filtered by severity."""
        return [l for l in self.losses if l.severity == severity]

    def to_dict(self) -> dict:
        """Serialize report to dictionary."""
        return {
            "source_said": self.source_said,
            "source_loa": self.source_loa.name,
            "target_format": self.target_format,
            "derived_at": self.derived_at.isoformat(),
            "overall_severity": self.overall_severity.value,
            "effective_strength": self.effective_strength.name,
            "preservation_ratio": round(self.preservation_ratio, 3),
            "warning_summary": self.warning_summary,
            "total_losses": self.total_losses,
            "degraded_items": self.degraded_items,
            "losses": [
                {
                    "name": l.name,
                    "category": l.category.value,
                    "severity": l.severity.value,
                    "description": l.description,
                    "source_path": l.source_path,
                    "target_representation": l.target_representation,
                    "mitigation": l.mitigation,
                }
                for l in self.losses
            ],
            "dimension_scores": {
                dim: {
                    "preserved": score.preserved,
                    "degraded": score.degraded,
                    "lost": score.lost,
                    "preservation_ratio": round(score.preservation_ratio, 3),
                    "loss_severity": score.loss_severity,
                }
                for dim, score in self.dimension_scores.items()
            },
        }


# Standard loss items for common derivation scenarios
STANDARD_LOSSES = {
    "edge_section": LossItem(
        name="edge_section",
        category=LossCategory.STRUCTURAL,
        severity=LossSeverity.SEVERE,
        description="ACDC edge section ('e' block) cannot be represented in target format",
        source_path="$.e",
        mitigation="Include edge references as linked credentials or out-of-band",
    ),
    "edge_operators": LossItem(
        name="edge_operators",
        category=LossCategory.STRUCTURAL,
        severity=LossSeverity.SEVERE,
        description="Edge operators (I2I, DI2I, NI2I) have no equivalent in target format",
        source_path="$.e.*.o",
        mitigation="Document operator semantics in credential metadata",
    ),
    "graduated_disclosure": LossItem(
        name="graduated_disclosure",
        category=LossCategory.TECH,
        severity=LossSeverity.SIGNIFICANT,
        description="Graduated disclosure (compact/partial/full SAID) not supported",
        source_path="$._disclosure",
        mitigation="Use target-native selective disclosure if available",
    ),
    "tel_status": LossItem(
        name="tel_status",
        category=LossCategory.TECH,
        severity=LossSeverity.SIGNIFICANT,
        description="TEL (Transaction Event Log) credential status not supported",
        source_path="$.ri",
        mitigation="Include revocation status via target's status method",
    ),
    "progressive_chain": LossItem(
        name="progressive_chain",
        category=LossCategory.VETTING,
        severity=LossSeverity.SIGNIFICANT,
        description="Progressive assurance chain (e.previousLevel) not representable",
        source_path="$.e.previousLevel",
        mitigation="Reference prior credentials via linked data",
    ),
    "cardinal_rules": LossItem(
        name="cardinal_rules",
        category=LossCategory.GOVERNANCE,
        severity=LossSeverity.MODERATE,
        description="ACDC rules section constraint algebra not portable",
        source_path="$.r",
        mitigation="Reference governance framework by URL",
    ),
    "monotonic_ratchet": LossItem(
        name="monotonic_ratchet",
        category=LossCategory.GOVERNANCE,
        severity=LossSeverity.MODERATE,
        description="Monotonic assurance ratchet semantics not enforceable",
        mitigation="Document ratchet policy in governance framework",
    ),
    "said_to_id": LossItem(
        name="said_to_id",
        category=LossCategory.TECH,
        severity=LossSeverity.MINIMAL,
        description="SAID mapped to 'id' field with urn:said: scheme",
        source_path="$.d",
        target_representation="id: urn:said:<SAID>",
    ),
    "aid_to_did": LossItem(
        name="aid_to_did",
        category=LossCategory.TECH,
        severity=LossSeverity.MINIMAL,
        description="AID mapped to did:keri: DID method",
        source_path="$.i",
        target_representation="issuer: did:keri:<AID>",
    ),
    "rules_to_terms": LossItem(
        name="rules_to_terms",
        category=LossCategory.GOVERNANCE,
        severity=LossSeverity.MINIMAL,
        description="Rules section mapped to termsOfUse",
        source_path="$.r",
        target_representation="termsOfUse array",
    ),
}


def create_loss_report(
    source_said: str,
    source_loa: LoALevel,
    target_format: str,
) -> LossReport:
    """
    Create a loss report for a derivation with standard losses.

    Populates the report with standard losses for the target format
    based on the predefined dimension scores.

    Args:
        source_said: SAID of the source ACDC
        source_loa: LoA level of the source credential
        target_format: Target format (w3c_vc, sd_jwt, x509, jwt)

    Returns:
        Populated LossReport ready for finalization
    """
    report = LossReport(
        source_said=source_said,
        source_loa=source_loa,
        target_format=target_format,
    )

    # Get standard dimension scores for this target
    report.dimension_scores = get_derivation_losses(target_format)

    # Add loss items based on dimension scores
    for dim_name, score in report.dimension_scores.items():
        category = _map_dimension_to_category(dim_name)

        # Add losses for items in the 'lost' list
        for lost_item in score.lost:
            if lost_item in STANDARD_LOSSES:
                report.add_loss(STANDARD_LOSSES[lost_item])
            else:
                report.add_loss(LossItem(
                    name=lost_item,
                    category=category,
                    severity=LossSeverity.SIGNIFICANT,
                    description=f"{lost_item} not supported in {target_format}",
                ))

        # Add degraded items as minimal losses
        for degraded_item in score.degraded:
            if degraded_item in STANDARD_LOSSES:
                report.add_loss(STANDARD_LOSSES[degraded_item])
            else:
                report.add_loss(LossItem(
                    name=degraded_item,
                    category=category,
                    severity=LossSeverity.MINIMAL,
                    description=f"{degraded_item} degraded in {target_format}",
                ))

    return report


def _map_dimension_to_category(dimension: str) -> LossCategory:
    """Map LoA dimension name to LossCategory."""
    mapping = {
        "tech": LossCategory.TECH,
        "governance": LossCategory.GOVERNANCE,
        "holder": LossCategory.HOLDER,
        "vetting": LossCategory.VETTING,
    }
    return mapping.get(dimension, LossCategory.STRUCTURAL)


def assess_derivation_viability(
    source_loa: LoALevel,
    target_format: str,
    required_strength: StrengthLevel,
) -> tuple[bool, str]:
    """
    Assess whether a derivation will meet strength requirements.

    Checks if the expected effective strength after derivation losses
    will satisfy the required strength level.

    Args:
        source_loa: LoA level of source credential
        target_format: Target format
        required_strength: Minimum required strength

    Returns:
        Tuple of (viable, explanation)
    """
    # Create a hypothetical report to check
    report = create_loss_report("hypothetical", source_loa, target_format)
    report.finalize()

    if report.effective_strength >= required_strength:
        return True, (
            f"Derivation viable: {source_loa.name_human} → {target_format} "
            f"yields {report.effective_strength.name} strength (>= {required_strength.name})"
        )
    else:
        return False, (
            f"Derivation NOT viable: {source_loa.name_human} → {target_format} "
            f"yields only {report.effective_strength.name} strength "
            f"(required: {required_strength.name})"
        )


def get_mitigation_recommendations(report: LossReport) -> list[str]:
    """
    Get mitigation recommendations for losses in a report.

    Returns actionable recommendations for addressing significant losses.

    Args:
        report: Finalized loss report

    Returns:
        List of mitigation recommendation strings
    """
    recommendations = []

    # Group by severity
    severe = report.by_severity(LossSeverity.SEVERE)
    significant = report.by_severity(LossSeverity.SIGNIFICANT)

    if severe:
        recommendations.append(
            "CRITICAL: The following cannot be preserved and require alternative approaches:"
        )
        for loss in severe:
            if loss.mitigation:
                recommendations.append(f"  - {loss.name}: {loss.mitigation}")
            else:
                recommendations.append(f"  - {loss.name}: No known mitigation")

    if significant:
        recommendations.append(
            "IMPORTANT: The following are significantly degraded:"
        )
        for loss in significant:
            if loss.mitigation:
                recommendations.append(f"  - {loss.name}: {loss.mitigation}")

    if report.effective_strength < map_loa_to_strength(report.source_loa):
        recommendations.append(
            f"NOTE: Effective strength reduced from {map_loa_to_strength(report.source_loa).name} "
            f"to {report.effective_strength.name}. Consider keeping ACDC as authoritative source."
        )

    if not recommendations:
        recommendations.append("No significant mitigations needed for this derivation.")

    return recommendations
