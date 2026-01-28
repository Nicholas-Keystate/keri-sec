# -*- encoding: utf-8 -*-
"""
LoA Mapping Module - Hardman's Level of Assurance mapping.

Maps between Hardman's 5-stage LoA ladder for organizational identity
and our KERI strength levels (ANY, SAID, KEL, TEL).

Reference: Daniel Hardman (Provenant), "Org Vet as a Credential Type", May 2025

Hardman's Progressive Assurance Ladder:
    LoA 0 (Identifier Affidavit): LEI exists, org not defunct, metadata verified
    LoA 1 (Bronze): + domain control, DNS binding to crypto ID
    LoA 2 (Silver): + legal identity of requester, delegated authority, 1+ witness
    LoA 3 (Gold): + DARs/LARs, multisig, no-MITM ceremony, sufficient witnesses
    vLEI: Full EGF compliance — gold standard

Each level is CUMULATIVE — higher levels assert everything lower levels did, plus more.
The ratchet is MONOTONIC — strengthen only, never weaken.

Four LoA Dimensions (from Hardman):
    1. Tech primitives: identifier, data format, commitment, crypto
    2. Governance: practicalities, incentives, safeguards, processes
    3. Holder attributes: what the credential subject has proved
    4. Vetting processes/rules: rigor of the vetting procedure
"""

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Optional


class LoALevel(IntEnum):
    """
    Hardman's Level of Assurance levels.

    IntEnum allows comparison: LoA_2 > LoA_1 is True.
    """
    LOA_0 = 0  # Identifier Affidavit (eLEI)
    LOA_1 = 1  # Bronze Vet Cred (pre-vLEI1)
    LOA_2 = 2  # Silver Vet Cred (pre-vLEI2)
    LOA_3 = 3  # Gold Vet Cred (pre-vLEI3)
    VLEI = 4   # Full vLEI (EGF compliance)

    @property
    def name_human(self) -> str:
        """Human-readable name for the LoA level."""
        names = {
            LoALevel.LOA_0: "Identifier Affidavit",
            LoALevel.LOA_1: "Bronze Vet Credential",
            LoALevel.LOA_2: "Silver Vet Credential",
            LoALevel.LOA_3: "Gold Vet Credential",
            LoALevel.VLEI: "Full vLEI",
        }
        return names.get(self, "Unknown")

    @property
    def credential_type(self) -> str:
        """Credential type identifier for this LoA level."""
        types = {
            LoALevel.LOA_0: "eLEI",
            LoALevel.LOA_1: "pre-vLEI1",
            LoALevel.LOA_2: "pre-vLEI2",
            LoALevel.LOA_3: "pre-vLEI3",
            LoALevel.VLEI: "vLEI",
        }
        return types.get(self, "unknown")


class StrengthLevel(IntEnum):
    """
    KERI verification strength levels.

    Our internal strength classification for cryptographic verification.
    """
    ANY = 0   # No verification required
    SAID = 1  # Content integrity via SAID
    KEL = 2   # Key state anchored in KEL
    TEL = 3   # Credential state in TEL (full verifiability)


@dataclass(frozen=True)
class LoARequirements:
    """
    Requirements for a specific LoA level.

    Documents what must be proved at each level per Hardman's specification.
    """
    level: LoALevel
    prerequisites: tuple[str, ...] = field(default_factory=tuple)
    tech_requirements: tuple[str, ...] = field(default_factory=tuple)
    governance_requirements: tuple[str, ...] = field(default_factory=tuple)
    holder_requirements: tuple[str, ...] = field(default_factory=tuple)
    vetting_requirements: tuple[str, ...] = field(default_factory=tuple)


# LoA level requirements from Hardman's specification
LOA_REQUIREMENTS = {
    LoALevel.LOA_0: LoARequirements(
        level=LoALevel.LOA_0,
        prerequisites=(),
        tech_requirements=(
            "LEI identifier exists",
            "Organization not defunct",
            "Metadata verified",
        ),
        governance_requirements=(
            "LEI registration authority validation",
        ),
        holder_requirements=(
            "Entity has LEI",
        ),
        vetting_requirements=(
            "Human check",
            "Org lookup",
            "Confirm not defunct",
        ),
    ),
    LoALevel.LOA_1: LoARequirements(
        level=LoALevel.LOA_1,
        prerequisites=("Satisfy LoA 0",),
        tech_requirements=(
            "Domain ownership proved",
            "DNS binding to crypto ID Z",
            "Email in domain verified",
        ),
        governance_requirements=(
            "Domain validation process",
        ),
        holder_requirements=(
            "Controls domain",
            "Has crypto identifier",
        ),
        vetting_requirements=(
            "Prove domain ownership",
            "Verify email in domain",
            "DNS record claims Z",
        ),
    ),
    LoALevel.LOA_2: LoARequirements(
        level=LoALevel.LOA_2,
        prerequisites=("Satisfy LoA 1",),
        tech_requirements=(
            "Legal identity of requester R verified",
            "Delegation from org X to R proved",
            "At least 1 witness attestation",
        ),
        governance_requirements=(
            "Identity verification process (NIST IAL2 or VC)",
            "Delegation chain validation",
        ),
        holder_requirements=(
            "R has verified legal identity",
            "R is delegated by org",
        ),
        vetting_requirements=(
            "Prove R's legal identity",
            "Prove delegation from X to R",
            "Obtain witness attestation",
        ),
    ),
    LoALevel.LOA_3: LoARequirements(
        level=LoALevel.LOA_3,
        prerequisites=("Satisfy LoA 2",),
        tech_requirements=(
            "DARs/LARs configured",
            "Multisig in place",
            "No-MITM ceremony completed",
            "Sufficient witnesses",
        ),
        governance_requirements=(
            "DAR/LAR role definition",
            "Multisig threshold policy",
            "Witness sufficiency rules",
        ),
        holder_requirements=(
            "Has authorized representatives",
            "Uses multisig protection",
        ),
        vetting_requirements=(
            "Check DARs/LARs",
            "Verify multisig",
            "Prove no MITM",
            "Require enough witnesses",
        ),
    ),
    LoALevel.VLEI: LoARequirements(
        level=LoALevel.VLEI,
        prerequisites=("Satisfy LoA 3",),
        tech_requirements=(
            "Full EGF compliance",
            "QVI vetting completed",
            "All vLEI infrastructure requirements",
        ),
        governance_requirements=(
            "EGF framework compliance",
            "QVI relationship established",
        ),
        holder_requirements=(
            "Fully vetted organization",
            "Active vLEI credential",
        ),
        vetting_requirements=(
            "Full QVI vetting per EGF",
        ),
    ),
}


def get_loa_requirements(level: LoALevel) -> LoARequirements:
    """
    Get requirements for a specific LoA level.

    Args:
        level: LoA level to get requirements for

    Returns:
        LoARequirements dataclass with all requirements
    """
    return LOA_REQUIREMENTS.get(level, LOA_REQUIREMENTS[LoALevel.LOA_0])


def map_loa_to_strength(loa: LoALevel) -> StrengthLevel:
    """
    Map Hardman LoA level to KERI strength level.

    The mapping is approximate since LoA focuses on process rigor
    while strength focuses on cryptographic anchoring.

    Args:
        loa: Hardman LoA level

    Returns:
        Corresponding KERI strength level

    Mapping:
        LoA 0 → ANY (identifier exists, no crypto verification)
        LoA 1 → SAID (domain binding adds content integrity)
        LoA 2 → KEL (witness attestation requires key state)
        LoA 3, vLEI → TEL (full credential lifecycle tracking)
    """
    mapping = {
        LoALevel.LOA_0: StrengthLevel.ANY,
        LoALevel.LOA_1: StrengthLevel.SAID,
        LoALevel.LOA_2: StrengthLevel.KEL,
        LoALevel.LOA_3: StrengthLevel.TEL,
        LoALevel.VLEI: StrengthLevel.TEL,
    }
    return mapping.get(loa, StrengthLevel.ANY)


def map_strength_to_loa(strength: StrengthLevel) -> LoALevel:
    """
    Map KERI strength level to minimum Hardman LoA level.

    Returns the minimum LoA that would typically require this strength.
    This is a lower bound — actual LoA may be higher.

    Args:
        strength: KERI strength level

    Returns:
        Minimum corresponding LoA level

    Mapping:
        ANY → LoA 0 (no crypto verification needed)
        SAID → LoA 1 (content integrity)
        KEL → LoA 2 (key state verification)
        TEL → LoA 3 (full credential state)
    """
    mapping = {
        StrengthLevel.ANY: LoALevel.LOA_0,
        StrengthLevel.SAID: LoALevel.LOA_1,
        StrengthLevel.KEL: LoALevel.LOA_2,
        StrengthLevel.TEL: LoALevel.LOA_3,
    }
    return mapping.get(strength, LoALevel.LOA_0)


def loa_satisfies(actual: LoALevel, required: LoALevel) -> bool:
    """
    Check if actual LoA level satisfies required level.

    LoA is monotonic — higher levels satisfy lower requirements.

    Args:
        actual: The LoA level we have
        required: The LoA level we need

    Returns:
        True if actual >= required
    """
    return actual >= required


def strength_satisfies(actual: StrengthLevel, required: StrengthLevel) -> bool:
    """
    Check if actual strength level satisfies required level.

    Strength is monotonic — higher levels satisfy lower requirements.

    Args:
        actual: The strength level we have
        required: The strength level we need

    Returns:
        True if actual >= required
    """
    return actual >= required


def can_strengthen(current: LoALevel, target: LoALevel) -> bool:
    """
    Check if strengthening from current to target LoA is valid.

    The ratchet is monotonic — can only strengthen, never weaken.

    Args:
        current: Current LoA level
        target: Target LoA level

    Returns:
        True if target > current (valid strengthening)
    """
    return target > current


def get_next_loa(current: LoALevel) -> Optional[LoALevel]:
    """
    Get the next LoA level in the progressive ladder.

    Args:
        current: Current LoA level

    Returns:
        Next LoA level, or None if already at vLEI
    """
    if current == LoALevel.VLEI:
        return None

    return LoALevel(current.value + 1)


def get_loa_chain(target: LoALevel) -> list[LoALevel]:
    """
    Get the full LoA chain from LoA 0 to target.

    Each level in the chain represents a credential that would
    be issued with an e.previousLevel edge to the prior.

    Args:
        target: Target LoA level

    Returns:
        List of LoA levels from 0 to target (inclusive)
    """
    return [LoALevel(i) for i in range(target.value + 1)]


@dataclass
class LoADimensionScore:
    """
    Score for a single LoA dimension.

    Represents what's preserved, degraded, or lost when
    deriving from ACDC to another format.
    """
    dimension: str  # "tech", "governance", "holder", "vetting"
    preserved: list[str] = field(default_factory=list)
    degraded: list[str] = field(default_factory=list)
    lost: list[str] = field(default_factory=list)

    @property
    def preservation_ratio(self) -> float:
        """Calculate ratio of preserved items to total."""
        total = len(self.preserved) + len(self.degraded) + len(self.lost)
        if total == 0:
            return 1.0
        return len(self.preserved) / total

    @property
    def loss_severity(self) -> str:
        """Categorize overall loss severity."""
        ratio = self.preservation_ratio
        if ratio >= 0.8:
            return "minimal"
        elif ratio >= 0.5:
            return "moderate"
        elif ratio >= 0.2:
            return "significant"
        else:
            return "severe"


# Standard LoA dimension scores for common derivation targets
W3C_VC_DIMENSION_LOSSES = {
    "tech": LoADimensionScore(
        dimension="tech",
        preserved=["issuer_identifier", "subject_attributes", "schema_reference", "timestamp"],
        degraded=["rules_to_termsOfUse", "SAID_to_id", "AID_to_did_keri"],
        lost=["edge_section", "edge_operators", "graduated_disclosure", "TEL_status", "progressive_chain"],
    ),
    "governance": LoADimensionScore(
        dimension="governance",
        preserved=["framework_reference_as_link"],
        degraded=[],
        lost=["formal_constraint_algebra", "monotonic_ratchet", "cardinal_rules"],
    ),
    "holder": LoADimensionScore(
        dimension="holder",
        preserved=["all_subject_attributes"],
        degraded=[],
        lost=["LoA_level_semantics"],
    ),
    "vetting": LoADimensionScore(
        dimension="vetting",
        preserved=["issuer_identity", "issuance_date"],
        degraded=[],
        lost=["cumulative_vet_chain", "vetting_process_rigor"],
    ),
}

X509_DIMENSION_LOSSES = {
    "tech": LoADimensionScore(
        dimension="tech",
        preserved=["issuer_identity_partial", "timestamp"],
        degraded=["AID_to_DN"],
        lost=["edge_section", "all_graph_structure", "self_certifying_property", "schema", "rules"],
    ),
    "governance": LoADimensionScore(
        dimension="governance",
        preserved=[],
        degraded=["framework_to_policy_oid"],
        lost=["all_governance_semantics"],
    ),
    "holder": LoADimensionScore(
        dimension="holder",
        preserved=["lei_in_subject_dn"],
        degraded=["attributes_to_dn_fields"],
        lost=["rich_attribute_structure"],
    ),
    "vetting": LoADimensionScore(
        dimension="vetting",
        preserved=["issuer_as_ca"],
        degraded=["loa_to_ev_policy"],
        lost=["vet_chain", "vetting_process_details"],
    ),
}


def get_derivation_losses(target_format: str) -> dict[str, LoADimensionScore]:
    """
    Get standard LoA dimension losses for a derivation target.

    Args:
        target_format: Target format ("w3c_vc", "x509", "sd_jwt", "jwt")

    Returns:
        Dict mapping dimension name to LoADimensionScore
    """
    losses = {
        "w3c_vc": W3C_VC_DIMENSION_LOSSES,
        "x509": X509_DIMENSION_LOSSES,
        # SD-JWT and JWT have similar losses to W3C VC
        "sd_jwt": W3C_VC_DIMENSION_LOSSES,
        "jwt": W3C_VC_DIMENSION_LOSSES,
    }
    return losses.get(target_format, W3C_VC_DIMENSION_LOSSES)
