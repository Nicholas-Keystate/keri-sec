# -*- encoding: utf-8 -*-
"""
ACDC to JWT (JSON Web Token) / OIDC Derivation.

Derives a JWT from an ACDC credential, suitable for use in
OIDC (OpenID Connect) and OAuth 2.0 scenarios.

JWT is simpler than SD-JWT - no selective disclosure mechanism.
All claims are visible to any party with access to the token.

Key mappings:
    ACDC.d → JWT.jti (JWT ID)
    ACDC.i → JWT.iss
    ACDC.a.i → JWT.sub (subject identifier)
    ACDC.a.* → JWT claims
    ACDC.e → LOST
    ACDC.r → LOST

OIDC-specific claims:
    - sub: Subject identifier
    - iss: Issuer
    - aud: Audience
    - exp: Expiration
    - iat: Issued at
    - nonce: For replay protection
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
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


@dataclass
class JWTPayload:
    """
    JWT payload structure.

    Standard claims plus custom claims from ACDC attributes.
    """
    # Standard JWT claims (RFC 7519)
    iss: str = ""                    # Issuer
    sub: str = ""                    # Subject
    aud: Optional[str | list[str]] = None  # Audience
    exp: Optional[int] = None        # Expiration (Unix timestamp)
    nbf: Optional[int] = None        # Not before
    iat: int = 0                     # Issued at
    jti: str = ""                    # JWT ID

    # OIDC claims (optional)
    nonce: Optional[str] = None
    auth_time: Optional[int] = None
    acr: Optional[str] = None        # Authentication context class reference
    amr: Optional[list[str]] = None  # Authentication methods

    # Custom claims from ACDC
    custom_claims: dict[str, Any] = field(default_factory=dict)

    # Derivation metadata
    acdc_said: str = ""
    acdc_schema: str = ""

    def to_dict(self, include_metadata: bool = True) -> dict[str, Any]:
        """
        Serialize to JWT payload dictionary.

        Args:
            include_metadata: Include ACDC derivation metadata
        """
        payload = {
            "iss": self.iss,
            "sub": self.sub,
            "iat": self.iat,
            "jti": self.jti,
        }

        if self.aud:
            payload["aud"] = self.aud
        if self.exp:
            payload["exp"] = self.exp
        if self.nbf:
            payload["nbf"] = self.nbf
        if self.nonce:
            payload["nonce"] = self.nonce
        if self.auth_time:
            payload["auth_time"] = self.auth_time
        if self.acr:
            payload["acr"] = self.acr
        if self.amr:
            payload["amr"] = self.amr

        # Add custom claims
        payload.update(self.custom_claims)

        # Add derivation metadata
        if include_metadata:
            if self.acdc_said:
                payload["_acdc_said"] = self.acdc_said
            if self.acdc_schema:
                payload["_acdc_schema"] = self.acdc_schema

        return payload


@dataclass
class JWT:
    """
    JWT structure (payload only - signature handled externally).
    """
    header: dict[str, str] = field(default_factory=lambda: {"alg": "ES256", "typ": "JWT"})
    payload: JWTPayload = field(default_factory=JWTPayload)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary representation."""
        return {
            "header": self.header,
            "payload": self.payload.to_dict(),
        }


@dataclass
class JWTDerivationResult:
    """
    Result of deriving a JWT from an ACDC.
    """
    jwt: JWT
    loss_report: LossReport
    success: bool = True
    error: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "jwt": self.jwt.to_dict(),
            "loss_report": self.loss_report.to_dict(),
            "success": self.success,
            "error": self.error,
        }


def derive_jwt(
    acdc: dict[str, Any],
    source_loa: LoALevel = LoALevel.LOA_0,
    audience: Optional[str | list[str]] = None,
    expiration_seconds: int = 3600,
    nonce: Optional[str] = None,
    include_derivation_metadata: bool = True,
    claim_mapping: Optional[dict[str, str]] = None,
) -> JWTDerivationResult:
    """
    Derive a JWT from an ACDC credential.

    Args:
        acdc: ACDC credential as dictionary
        source_loa: LoA level of the source ACDC
        audience: JWT audience (aud claim)
        expiration_seconds: Token lifetime in seconds
        nonce: OIDC nonce for replay protection
        include_derivation_metadata: Include ACDC SAID in custom claims
        claim_mapping: Map ACDC attribute names to JWT claim names

    Returns:
        JWTDerivationResult containing the JWT and loss report
    """
    # Validate required ACDC fields
    if "d" not in acdc:
        return JWTDerivationResult(
            jwt=JWT(),
            loss_report=LossReport(
                source_said="",
                source_loa=source_loa,
                target_format="jwt",
            ),
            success=False,
            error="ACDC missing required 'd' (SAID) field",
        )

    said = acdc["d"]
    claim_mapping = claim_mapping or {}

    # Initialize loss report
    report = create_loss_report(said, source_loa, "jwt")

    # Build JWT
    jwt = JWT()
    payload = jwt.payload

    # Map SAID to jti
    payload.jti = f"urn:said:{said}"

    # Map issuer
    if "i" in acdc:
        payload.iss = f"did:keri:{acdc['i']}"
    else:
        report.add_loss(LossItem(
            name="missing_issuer",
            category=LossCategory.TECH,
            severity=LossSeverity.SEVERE,
            description="ACDC missing issuer field",
        ))

    # Set timestamps
    now = datetime.now(timezone.utc)
    payload.iat = int(now.timestamp())
    payload.exp = int((now + timedelta(seconds=expiration_seconds)).timestamp())

    # Set audience if provided
    if audience:
        payload.aud = audience

    # Set nonce for OIDC
    if nonce:
        payload.nonce = nonce

    # Map attributes to claims
    if "a" in acdc:
        _map_attributes_to_claims(
            payload,
            acdc["a"],
            claim_mapping,
            report,
        )

    # Map schema
    if "s" in acdc:
        payload.acdc_schema = acdc["s"]

    # Handle edge section (LOST)
    if "e" in acdc:
        _report_edge_losses(acdc["e"], report)

    # Handle rules section (LOST)
    if "r" in acdc:
        report.add_loss(LossItem(
            name="rules_section_jwt",
            category=LossCategory.GOVERNANCE,
            severity=LossSeverity.SIGNIFICANT,
            description="ACDC rules section has no equivalent in JWT",
            source_path="$.r",
            mitigation="Reference governance framework via external URL in claims",
        ))

    # Handle TEL status (LOST)
    if "ri" in acdc:
        report.add_loss(LossItem(
            name="tel_status_jwt",
            category=LossCategory.TECH,
            severity=LossSeverity.SIGNIFICANT,
            description="TEL credential status not supported in JWT",
            source_path="$.ri",
            mitigation="Use token introspection endpoint for status",
        ))

    # Report no selective disclosure
    report.add_loss(LossItem(
        name="no_selective_disclosure",
        category=LossCategory.TECH,
        severity=LossSeverity.MODERATE,
        description="JWT has no selective disclosure - all claims visible",
        mitigation="Use SD-JWT if selective disclosure needed",
    ))

    # Derivation metadata
    if include_derivation_metadata:
        payload.acdc_said = said

    # Finalize report
    report.finalize()

    return JWTDerivationResult(
        jwt=jwt,
        loss_report=report,
        success=True,
    )


def _map_attributes_to_claims(
    payload: JWTPayload,
    attributes: dict[str, Any],
    claim_mapping: dict[str, str],
    report: LossReport,
) -> None:
    """
    Map ACDC attributes to JWT claims.

    Args:
        payload: JWT payload being built
        attributes: ACDC attribute section
        claim_mapping: Custom attribute to claim name mapping
        report: Loss report to update
    """
    # Standard OIDC claim mappings
    oidc_mappings = {
        "name": "name",
        "given_name": "given_name",
        "family_name": "family_name",
        "email": "email",
        "email_verified": "email_verified",
        "phone_number": "phone_number",
        "address": "address",
        "birthdate": "birthdate",
        "picture": "picture",
        "locale": "locale",
        "zoneinfo": "zoneinfo",
    }

    for key, value in attributes.items():
        # Skip ACDC-specific fields
        if key in ("d", "dt"):
            continue

        # Handle subject identifier specially
        if key == "i":
            payload.sub = str(value)
            continue

        # Check for custom mapping
        if key in claim_mapping:
            target_key = claim_mapping[key]
        elif key in oidc_mappings:
            target_key = oidc_mappings[key]
        else:
            target_key = key

        # Handle nested objects
        if isinstance(value, dict) and "d" in value:
            # Nested SAID - flatten
            flat_value = {
                "said": value["d"],
                **{k: v for k, v in value.items() if k != "d"},
            }
            payload.custom_claims[target_key] = flat_value
        else:
            payload.custom_claims[target_key] = value

    # Set sub if not already set
    if not payload.sub:
        # Use SAID as subject if no 'i' in attributes
        payload.sub = payload.jti


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


def derive_oidc_id_token(
    acdc: dict[str, Any],
    source_loa: LoALevel = LoALevel.LOA_0,
    audience: str = "",
    nonce: str = "",
    auth_time: Optional[int] = None,
    acr: Optional[str] = None,
    **kwargs,
) -> JWTDerivationResult:
    """
    Derive an OIDC ID Token from an ACDC.

    Convenience wrapper for derive_jwt with OIDC-specific defaults.

    Args:
        acdc: ACDC credential as dictionary
        source_loa: LoA level of the source ACDC
        audience: Required for OIDC - the client_id
        nonce: Required for OIDC - replay protection
        auth_time: When authentication occurred
        acr: Authentication context class reference
        **kwargs: Additional arguments passed to derive_jwt

    Returns:
        JWTDerivationResult containing the ID Token and loss report
    """
    result = derive_jwt(
        acdc,
        source_loa=source_loa,
        audience=audience,
        nonce=nonce,
        **kwargs,
    )

    if result.success:
        # Add OIDC-specific claims
        if auth_time:
            result.jwt.payload.auth_time = auth_time
        if acr:
            result.jwt.payload.acr = acr

        # Map LoA to acr if not provided
        if not acr:
            loa_to_acr = {
                LoALevel.LOA_0: "urn:keri:loa:0",
                LoALevel.LOA_1: "urn:keri:loa:1",
                LoALevel.LOA_2: "urn:keri:loa:2",
                LoALevel.LOA_3: "urn:keri:loa:3",
                LoALevel.VLEI: "urn:keri:loa:vlei",
            }
            result.jwt.payload.acr = loa_to_acr.get(source_loa, "urn:keri:loa:0")

    return result


def derive_jwt_from_dict(
    acdc_dict: dict[str, Any],
    **kwargs,
) -> dict[str, Any]:
    """
    Convenience function that returns dict instead of dataclass.

    Args:
        acdc_dict: ACDC as dictionary
        **kwargs: Additional arguments passed to derive_jwt

    Returns:
        Dictionary with 'jwt' and 'loss_report' keys
    """
    result = derive_jwt(acdc_dict, **kwargs)
    return result.to_dict()
