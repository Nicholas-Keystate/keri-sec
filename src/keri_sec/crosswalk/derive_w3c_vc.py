# -*- encoding: utf-8 -*-
"""
ACDC to W3C Verifiable Credential 2.0 Derivation.

Derives a W3C VC 2.0 from an ACDC credential, tracking all semantic
losses in the derivation process.

W3C VC 2.0 Specification: https://www.w3.org/TR/vc-data-model-2.0/

Key mappings:
    ACDC.d → VC.id (urn:said:<SAID>)
    ACDC.i → VC.issuer (did:keri:<AID>)
    ACDC.s → VC.credentialSchema
    ACDC.a → VC.credentialSubject
    ACDC.r → VC.termsOfUse (degraded)
    ACDC.e → LOST (no equivalent in VC 2.0)
    ACDC.ri → VC.credentialStatus (if available)

Losses:
    - Edge section ('e') completely lost
    - Edge operators (I2I, DI2I, NI2I) lost
    - Graduated disclosure lost (VC 2.0 has different selective disclosure)
    - TEL status degraded to simpler credentialStatus
    - Rules section algebra lost (only URL reference preserved)
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

from .loa_mapping import LoALevel
from .loss_report import (
    LossReport,
    LossItem,
    LossCategory,
    LossSeverity,
    create_loss_report,
    STANDARD_LOSSES,
)


# W3C VC 2.0 context URLs
W3C_VC_CONTEXT = "https://www.w3.org/ns/credentials/v2"
W3C_VC_TYPE = "VerifiableCredential"

# URN schemes for KERI identifiers
SAID_URN_PREFIX = "urn:said:"
DID_KERI_PREFIX = "did:keri:"


@dataclass
class W3CVC:
    """
    W3C Verifiable Credential 2.0 structure.

    This is a data class representation - actual JSON-LD serialization
    may require additional processing.
    """
    context: list[str] = field(default_factory=lambda: [W3C_VC_CONTEXT])
    id: str = ""
    type: list[str] = field(default_factory=lambda: [W3C_VC_TYPE])
    issuer: str = ""
    valid_from: Optional[str] = None
    valid_until: Optional[str] = None
    credential_subject: dict[str, Any] = field(default_factory=dict)
    credential_schema: Optional[dict[str, Any]] = None
    credential_status: Optional[dict[str, Any]] = None
    terms_of_use: Optional[list[dict[str, Any]]] = None
    evidence: Optional[list[dict[str, Any]]] = None

    # Metadata about derivation (not part of VC spec)
    derived_from_said: str = ""
    derivation_timestamp: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialize to W3C VC 2.0 JSON structure."""
        vc = {
            "@context": self.context,
            "id": self.id,
            "type": self.type,
            "issuer": self.issuer,
            "credentialSubject": self.credential_subject,
        }

        if self.valid_from:
            vc["validFrom"] = self.valid_from
        if self.valid_until:
            vc["validUntil"] = self.valid_until
        if self.credential_schema:
            vc["credentialSchema"] = self.credential_schema
        if self.credential_status:
            vc["credentialStatus"] = self.credential_status
        if self.terms_of_use:
            vc["termsOfUse"] = self.terms_of_use
        if self.evidence:
            vc["evidence"] = self.evidence

        return vc


@dataclass
class DerivationResult:
    """
    Result of deriving a W3C VC from an ACDC.

    Contains both the derived credential and the loss report documenting
    what was lost in the derivation.
    """
    vc: W3CVC
    loss_report: LossReport
    success: bool = True
    error: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "vc": self.vc.to_dict(),
            "loss_report": self.loss_report.to_dict(),
            "success": self.success,
            "error": self.error,
        }


def derive_w3c_vc(
    acdc: dict[str, Any],
    source_loa: LoALevel = LoALevel.LOA_0,
    additional_context: Optional[list[str]] = None,
    additional_types: Optional[list[str]] = None,
    include_derivation_metadata: bool = True,
) -> DerivationResult:
    """
    Derive a W3C VC 2.0 from an ACDC credential.

    Args:
        acdc: ACDC credential as dictionary
        source_loa: LoA level of the source ACDC
        additional_context: Additional JSON-LD context URLs to include
        additional_types: Additional VC types to include
        include_derivation_metadata: Include metadata about derivation source

    Returns:
        DerivationResult containing the VC and loss report
    """
    # Validate required ACDC fields
    if "d" not in acdc:
        return DerivationResult(
            vc=W3CVC(),
            loss_report=LossReport(
                source_said="",
                source_loa=source_loa,
                target_format="w3c_vc",
            ),
            success=False,
            error="ACDC missing required 'd' (SAID) field",
        )

    said = acdc["d"]

    # Initialize loss report
    report = create_loss_report(said, source_loa, "w3c_vc")

    # Build W3C VC
    vc = W3CVC()

    # Set context
    if additional_context:
        vc.context = [W3C_VC_CONTEXT] + additional_context

    # Map SAID to id with URN scheme
    vc.id = f"{SAID_URN_PREFIX}{said}"
    # Add loss item for SAID mapping (degradation, not total loss)
    if "said_to_id" in STANDARD_LOSSES:
        report.add_loss(STANDARD_LOSSES["said_to_id"])

    # Map issuer AID to did:keri:
    if "i" in acdc:
        vc.issuer = f"{DID_KERI_PREFIX}{acdc['i']}"
        if "aid_to_did" in STANDARD_LOSSES:
            report.add_loss(STANDARD_LOSSES["aid_to_did"])
    else:
        report.add_loss(LossItem(
            name="missing_issuer",
            category=LossCategory.TECH,
            severity=LossSeverity.SEVERE,
            description="ACDC missing issuer field",
        ))

    # Set types
    if additional_types:
        vc.type = [W3C_VC_TYPE] + additional_types

    # Map schema
    if "s" in acdc:
        vc.credential_schema = {
            "id": f"{SAID_URN_PREFIX}{acdc['s']}",
            "type": "JsonSchema",
        }

    # Map attributes to credentialSubject
    if "a" in acdc:
        vc.credential_subject = _map_attributes(acdc["a"], report)

    # Map rules to termsOfUse (degraded)
    if "r" in acdc:
        vc.terms_of_use = _map_rules(acdc["r"], report)

    # Map registry to credentialStatus (degraded)
    if "ri" in acdc:
        vc.credential_status = _map_status(acdc["ri"], acdc.get("d", ""), report)

    # Handle edge section (LOST)
    if "e" in acdc:
        _report_edge_losses(acdc["e"], report)

    # Set timestamps
    now = datetime.now(timezone.utc).isoformat()
    vc.valid_from = acdc.get("dt", now)

    # Derivation metadata
    if include_derivation_metadata:
        vc.derived_from_said = said
        vc.derivation_timestamp = now

    # Finalize report
    report.finalize()

    return DerivationResult(
        vc=vc,
        loss_report=report,
        success=True,
    )


def _map_attributes(
    attributes: dict[str, Any],
    report: LossReport,
) -> dict[str, Any]:
    """
    Map ACDC attribute section to VC credentialSubject.

    Most attributes map directly. Special handling for:
    - Nested SAIDs
    - KERI-specific fields
    """
    subject = {}

    for key, value in attributes.items():
        # Skip ACDC-specific fields
        if key in ("d", "i", "dt"):
            continue

        # Handle nested objects with SAIDs
        if isinstance(value, dict) and "d" in value:
            # Nested SAID - reference it
            subject[key] = {
                "id": f"{SAID_URN_PREFIX}{value['d']}",
                **{k: v for k, v in value.items() if k != "d"},
            }
        else:
            subject[key] = value

    return subject


def _map_rules(
    rules: dict[str, Any] | list[dict[str, Any]],
    report: LossReport,
) -> list[dict[str, Any]]:
    """
    Map ACDC rules section to VC termsOfUse.

    Rules section algebra cannot be preserved - only references
    to governance frameworks are kept.
    """
    terms = []

    # Report degradation
    if "rules_to_terms" in STANDARD_LOSSES:
        report.add_loss(STANDARD_LOSSES["rules_to_terms"])
    if "cardinal_rules" in STANDARD_LOSSES:
        report.add_loss(STANDARD_LOSSES["cardinal_rules"])

    if isinstance(rules, dict):
        rules_list = [rules]
    else:
        rules_list = rules

    for rule in rules_list:
        term = {"type": "GovernanceFramework"}

        # Extract framework reference if present
        if "d" in rule:
            term["id"] = f"{SAID_URN_PREFIX}{rule['d']}"

        # Extract any URL references
        for key in ("url", "ref", "framework"):
            if key in rule:
                term["url"] = rule[key]
                break

        terms.append(term)

    return terms


def _map_status(
    registry_id: str,
    said: str,
    report: LossReport,
) -> dict[str, Any]:
    """
    Map ACDC registry to VC credentialStatus.

    TEL (Transaction Event Log) provides more functionality than
    simple credentialStatus - this is a degradation.
    """
    # Report TEL status loss
    if "tel_status" in STANDARD_LOSSES:
        report.add_loss(STANDARD_LOSSES["tel_status"])

    return {
        "id": f"{SAID_URN_PREFIX}{registry_id}#{said}",
        "type": "KeriCredentialStatus",
        "statusPurpose": "revocation",
    }


def _report_edge_losses(
    edges: dict[str, Any],
    report: LossReport,
) -> None:
    """
    Report losses from ACDC edge section.

    Edge section has no equivalent in W3C VC 2.0.
    """
    # Report edge section loss
    if "edge_section" in STANDARD_LOSSES:
        report.add_loss(STANDARD_LOSSES["edge_section"])

    # Check for operators
    has_operators = False
    for key, value in edges.items():
        if key == "d":
            continue
        if isinstance(value, dict) and "o" in value:
            has_operators = True
            break

    if has_operators:
        if "edge_operators" in STANDARD_LOSSES:
            report.add_loss(STANDARD_LOSSES["edge_operators"])

    # Check for progressive chain
    if "previousLevel" in edges:
        if "progressive_chain" in STANDARD_LOSSES:
            report.add_loss(STANDARD_LOSSES["progressive_chain"])


def derive_w3c_vc_from_dict(
    acdc_dict: dict[str, Any],
    **kwargs,
) -> dict[str, Any]:
    """
    Convenience function that returns dict instead of dataclass.

    Args:
        acdc_dict: ACDC as dictionary
        **kwargs: Additional arguments passed to derive_w3c_vc

    Returns:
        Dictionary with 'vc' and 'loss_report' keys
    """
    result = derive_w3c_vc(acdc_dict, **kwargs)
    return result.to_dict()
