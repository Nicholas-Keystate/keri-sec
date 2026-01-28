# -*- encoding: utf-8 -*-
"""
ACDC to SD-JWT (Selective Disclosure JWT) Derivation.

Derives an SD-JWT from an ACDC credential, tracking all semantic
losses in the derivation process.

SD-JWT Specification: draft-ietf-oauth-selective-disclosure-jwt

SD-JWT structure:
    - JWT header (alg, typ)
    - JWT payload with _sd claims and _sd_alg
    - Disclosures (base64url-encoded JSON arrays)
    - Key binding JWT (optional)

Key mappings:
    ACDC.d → JWT.sub or custom claim
    ACDC.i → JWT.iss
    ACDC.s → JWT._sd_schema (custom)
    ACDC.a → JWT claims with selective disclosure
    ACDC.e → LOST (no equivalent)
    ACDC.r → LOST (no equivalent)

Losses:
    - Edge section completely lost
    - Rules section completely lost
    - SAID self-referential integrity degraded
    - TEL status lost (SD-JWT has no status mechanism)
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional
import hashlib
import json
import base64

from .loa_mapping import LoALevel
from .loss_report import (
    LossReport,
    LossItem,
    LossCategory,
    LossSeverity,
    create_loss_report,
    STANDARD_LOSSES,
)


@dataclass
class SDJWTClaim:
    """
    A claim in SD-JWT format.

    Claims can be selectively disclosable or always disclosed.
    """
    name: str
    value: Any
    selectively_disclosable: bool = True
    salt: str = ""  # Random salt for disclosure

    def to_disclosure(self) -> str:
        """
        Create disclosure for this claim.

        Returns base64url-encoded JSON array: [salt, name, value]
        """
        if not self.salt:
            # Generate deterministic salt for reproducibility
            # In production, use cryptographic random
            content = f"{self.name}:{json.dumps(self.value)}"
            self.salt = hashlib.sha256(content.encode()).hexdigest()[:16]

        disclosure_array = [self.salt, self.name, self.value]
        json_bytes = json.dumps(disclosure_array, separators=(",", ":")).encode()
        return base64.urlsafe_b64encode(json_bytes).rstrip(b"=").decode()

    def disclosure_hash(self, alg: str = "sha-256") -> str:
        """
        Compute hash of disclosure for _sd array.

        Uses the specified algorithm (default sha-256).
        """
        disclosure = self.to_disclosure()
        if alg == "sha-256":
            hash_bytes = hashlib.sha256(disclosure.encode()).digest()
        else:
            raise ValueError(f"Unsupported hash algorithm: {alg}")

        return base64.urlsafe_b64encode(hash_bytes).rstrip(b"=").decode()


@dataclass
class SDJWT:
    """
    SD-JWT structure.

    Contains the JWT payload and disclosures. The actual JWT encoding
    (header + signature) is left to the caller.
    """
    # JWT claims (non-selectively-disclosable)
    iss: str = ""  # Issuer
    sub: str = ""  # Subject
    iat: int = 0   # Issued at (Unix timestamp)
    exp: Optional[int] = None  # Expiration (optional)
    nbf: Optional[int] = None  # Not before (optional)

    # SD-JWT specific
    sd_alg: str = "sha-256"  # Hash algorithm for _sd
    sd_claims: list[SDJWTClaim] = field(default_factory=list)

    # Additional claims (always disclosed)
    additional_claims: dict[str, Any] = field(default_factory=dict)

    # Metadata about derivation
    derived_from_said: str = ""
    schema_said: str = ""

    def add_sd_claim(self, name: str, value: Any, selectively_disclosable: bool = True) -> None:
        """Add a claim, optionally as selectively disclosable."""
        self.sd_claims.append(SDJWTClaim(
            name=name,
            value=value,
            selectively_disclosable=selectively_disclosable,
        ))

    def to_payload(self) -> dict[str, Any]:
        """
        Generate JWT payload with _sd array.

        Returns the payload dict ready for JWT encoding.
        """
        payload = {
            "iss": self.iss,
            "iat": self.iat,
            "_sd_alg": self.sd_alg,
        }

        if self.sub:
            payload["sub"] = self.sub
        if self.exp:
            payload["exp"] = self.exp
        if self.nbf:
            payload["nbf"] = self.nbf

        # Add _sd array with hashes of selectively disclosable claims
        sd_hashes = []
        for claim in self.sd_claims:
            if claim.selectively_disclosable:
                sd_hashes.append(claim.disclosure_hash(self.sd_alg))
            else:
                # Non-SD claims go directly in payload
                payload[claim.name] = claim.value

        if sd_hashes:
            payload["_sd"] = sd_hashes

        # Add additional always-disclosed claims
        payload.update(self.additional_claims)

        # Add derivation metadata as custom claims
        if self.derived_from_said:
            payload["_acdc_said"] = self.derived_from_said
        if self.schema_said:
            payload["_acdc_schema"] = self.schema_said

        return payload

    def get_disclosures(self) -> list[str]:
        """Get all disclosures for selectively disclosable claims."""
        return [
            claim.to_disclosure()
            for claim in self.sd_claims
            if claim.selectively_disclosable
        ]

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary representation."""
        return {
            "payload": self.to_payload(),
            "disclosures": self.get_disclosures(),
            "sd_alg": self.sd_alg,
        }


@dataclass
class SDJWTDerivationResult:
    """
    Result of deriving an SD-JWT from an ACDC.
    """
    sd_jwt: SDJWT
    loss_report: LossReport
    success: bool = True
    error: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "sd_jwt": self.sd_jwt.to_dict(),
            "loss_report": self.loss_report.to_dict(),
            "success": self.success,
            "error": self.error,
        }


def derive_sd_jwt(
    acdc: dict[str, Any],
    source_loa: LoALevel = LoALevel.LOA_0,
    sd_fields: Optional[list[str]] = None,
    always_disclose: Optional[list[str]] = None,
    include_derivation_metadata: bool = True,
) -> SDJWTDerivationResult:
    """
    Derive an SD-JWT from an ACDC credential.

    Args:
        acdc: ACDC credential as dictionary
        source_loa: LoA level of the source ACDC
        sd_fields: List of attribute field names to make selectively disclosable
                  (default: all fields are SD)
        always_disclose: List of attribute field names to always disclose
        include_derivation_metadata: Include ACDC SAID in custom claims

    Returns:
        SDJWTDerivationResult containing the SD-JWT and loss report
    """
    # Validate required ACDC fields
    if "d" not in acdc:
        return SDJWTDerivationResult(
            sd_jwt=SDJWT(),
            loss_report=LossReport(
                source_said="",
                source_loa=source_loa,
                target_format="sd_jwt",
            ),
            success=False,
            error="ACDC missing required 'd' (SAID) field",
        )

    said = acdc["d"]
    always_disclose = always_disclose or []

    # Initialize loss report
    report = create_loss_report(said, source_loa, "sd_jwt")

    # Build SD-JWT
    sd_jwt = SDJWT()

    # Map issuer
    if "i" in acdc:
        sd_jwt.iss = f"did:keri:{acdc['i']}"
    else:
        report.add_loss(LossItem(
            name="missing_issuer",
            category=LossCategory.TECH,
            severity=LossSeverity.SEVERE,
            description="ACDC missing issuer field",
        ))

    # Set timestamps
    now = datetime.now(timezone.utc)
    sd_jwt.iat = int(now.timestamp())

    # Map SAID (degraded - not self-referential in SD-JWT)
    sd_jwt.sub = f"urn:said:{said}"
    report.add_loss(LossItem(
        name="said_integrity",
        category=LossCategory.TECH,
        severity=LossSeverity.MODERATE,
        description="SAID self-referential integrity lost in SD-JWT",
        source_path="$.d",
        target_representation="sub claim",
    ))

    # Store schema reference
    if "s" in acdc:
        sd_jwt.schema_said = acdc["s"]

    # Map attributes to claims
    if "a" in acdc:
        _map_attributes_to_claims(
            sd_jwt,
            acdc["a"],
            sd_fields,
            always_disclose,
            report,
        )

    # Handle edge section (LOST)
    if "e" in acdc:
        _report_edge_losses(acdc["e"], report)

    # Handle rules section (LOST)
    if "r" in acdc:
        report.add_loss(LossItem(
            name="rules_section",
            category=LossCategory.GOVERNANCE,
            severity=LossSeverity.SIGNIFICANT,
            description="ACDC rules section has no equivalent in SD-JWT",
            source_path="$.r",
            mitigation="Reference governance framework via external URL",
        ))

    # Handle TEL status (LOST)
    if "ri" in acdc:
        report.add_loss(LossItem(
            name="tel_status_sd_jwt",
            category=LossCategory.TECH,
            severity=LossSeverity.SIGNIFICANT,
            description="TEL credential status not supported in SD-JWT",
            source_path="$.ri",
            mitigation="Implement status list as separate mechanism",
        ))

    # Derivation metadata
    if include_derivation_metadata:
        sd_jwt.derived_from_said = said

    # Finalize report
    report.finalize()

    return SDJWTDerivationResult(
        sd_jwt=sd_jwt,
        loss_report=report,
        success=True,
    )


def _map_attributes_to_claims(
    sd_jwt: SDJWT,
    attributes: dict[str, Any],
    sd_fields: Optional[list[str]],
    always_disclose: list[str],
    report: LossReport,
) -> None:
    """
    Map ACDC attributes to SD-JWT claims.

    Args:
        sd_jwt: SD-JWT being built
        attributes: ACDC attribute section
        sd_fields: Fields to make SD (None = all)
        always_disclose: Fields to always disclose
        report: Loss report to update
    """
    for key, value in attributes.items():
        # Skip ACDC-specific fields
        if key in ("d", "i", "dt"):
            continue

        # Determine if this should be selectively disclosable
        if sd_fields is not None:
            is_sd = key in sd_fields and key not in always_disclose
        else:
            is_sd = key not in always_disclose

        # Handle nested objects
        if isinstance(value, dict) and "d" in value:
            # Nested SAID - flatten or reference
            flat_value = {
                "said": value["d"],
                **{k: v for k, v in value.items() if k != "d"},
            }
            sd_jwt.add_sd_claim(key, flat_value, is_sd)
        else:
            sd_jwt.add_sd_claim(key, value, is_sd)

    # Report graduated disclosure loss
    report.add_loss(LossItem(
        name="graduated_disclosure_sd_jwt",
        category=LossCategory.TECH,
        severity=LossSeverity.MODERATE,
        description="ACDC graduated disclosure (compact/partial/full) differs from SD-JWT model",
        mitigation="SD-JWT provides per-claim disclosure instead",
    ))


def _report_edge_losses(
    edges: dict[str, Any],
    report: LossReport,
) -> None:
    """Report losses from ACDC edge section."""
    if "edge_section" in STANDARD_LOSSES:
        report.add_loss(STANDARD_LOSSES["edge_section"])

    # Check for operators
    for key, value in edges.items():
        if key == "d":
            continue
        if isinstance(value, dict) and "o" in value:
            if "edge_operators" in STANDARD_LOSSES:
                report.add_loss(STANDARD_LOSSES["edge_operators"])
            break

    # Check for progressive chain
    if "previousLevel" in edges:
        if "progressive_chain" in STANDARD_LOSSES:
            report.add_loss(STANDARD_LOSSES["progressive_chain"])


def derive_sd_jwt_from_dict(
    acdc_dict: dict[str, Any],
    **kwargs,
) -> dict[str, Any]:
    """
    Convenience function that returns dict instead of dataclass.

    Args:
        acdc_dict: ACDC as dictionary
        **kwargs: Additional arguments passed to derive_sd_jwt

    Returns:
        Dictionary with 'sd_jwt' and 'loss_report' keys
    """
    result = derive_sd_jwt(acdc_dict, **kwargs)
    return result.to_dict()
