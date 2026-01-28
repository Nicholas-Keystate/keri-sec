# -*- encoding: utf-8 -*-
"""
ACDC to X.509 Certificate Derivation.

Derives an X.509 certificate structure from an ACDC credential,
tracking all semantic losses. This is the MOST LOSSY derivation
in the crosswalk module.

X.509 has a rigid structure that cannot represent most ACDC concepts:
- No graph structure (edges completely lost)
- No rules/governance section
- Very limited attribute representation (DN only)
- No selective disclosure
- No self-certifying identifiers

Key mappings:
    ACDC.i → Issuer DN (O, CN)
    ACDC.a.* → Subject DN fields (very lossy)
    ACDC.d → Extension with custom OID
    ACDC.s → Extension with schema OID
    ACDC.e → LOST (no equivalent)
    ACDC.r → PolicyOID extension (degraded)

Use cases for x509 derivation:
- Legacy system interoperability
- TLS certificate generation
- PKI bridge scenarios
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


# Custom OIDs for KERI extensions (placeholder - real OIDs would need registration)
KERI_OID_ARC = "1.3.6.1.4.1.99999"  # Placeholder private enterprise arc
KERI_OID_SAID = f"{KERI_OID_ARC}.1"
KERI_OID_AID = f"{KERI_OID_ARC}.2"
KERI_OID_SCHEMA = f"{KERI_OID_ARC}.3"
KERI_OID_LOA = f"{KERI_OID_ARC}.4"


@dataclass
class DistinguishedName:
    """
    X.509 Distinguished Name (DN) representation.

    Maps ACDC attributes to standard DN fields where possible.
    """
    common_name: str = ""          # CN
    organization: str = ""         # O
    organizational_unit: str = ""  # OU
    country: str = ""              # C
    state: str = ""                # ST
    locality: str = ""             # L
    email: str = ""                # E or emailAddress
    serial_number: str = ""        # serialNumber (for LEI)

    # Custom attributes that don't fit standard DN
    custom_attributes: dict[str, str] = field(default_factory=dict)

    def to_string(self) -> str:
        """Convert to DN string format (RFC 4514)."""
        parts = []
        if self.common_name:
            parts.append(f"CN={self.common_name}")
        if self.organization:
            parts.append(f"O={self.organization}")
        if self.organizational_unit:
            parts.append(f"OU={self.organizational_unit}")
        if self.locality:
            parts.append(f"L={self.locality}")
        if self.state:
            parts.append(f"ST={self.state}")
        if self.country:
            parts.append(f"C={self.country}")
        if self.email:
            parts.append(f"emailAddress={self.email}")
        if self.serial_number:
            parts.append(f"serialNumber={self.serial_number}")

        return ", ".join(parts)

    def to_dict(self) -> dict[str, str]:
        """Convert to dictionary."""
        result = {}
        if self.common_name:
            result["CN"] = self.common_name
        if self.organization:
            result["O"] = self.organization
        if self.organizational_unit:
            result["OU"] = self.organizational_unit
        if self.country:
            result["C"] = self.country
        if self.state:
            result["ST"] = self.state
        if self.locality:
            result["L"] = self.locality
        if self.email:
            result["emailAddress"] = self.email
        if self.serial_number:
            result["serialNumber"] = self.serial_number
        if self.custom_attributes:
            result["custom"] = self.custom_attributes
        return result


@dataclass
class X509Extension:
    """
    X.509 certificate extension.
    """
    oid: str
    critical: bool = False
    value: Any = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "oid": self.oid,
            "critical": self.critical,
            "value": self.value,
        }


@dataclass
class X509Certificate:
    """
    X.509 certificate structure (data only, not cryptographic operations).

    This represents the certificate data that would be used to
    generate an actual X.509 certificate.
    """
    version: int = 3  # X.509 v3
    serial_number: str = ""
    issuer: DistinguishedName = field(default_factory=DistinguishedName)
    subject: DistinguishedName = field(default_factory=DistinguishedName)
    not_before: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    not_after: datetime = field(default_factory=lambda: datetime.now(timezone.utc) + timedelta(days=365))
    extensions: list[X509Extension] = field(default_factory=list)

    # Key usage flags
    key_usage: list[str] = field(default_factory=list)
    extended_key_usage: list[str] = field(default_factory=list)

    # Derivation metadata
    derived_from_said: str = ""

    def add_extension(self, oid: str, value: Any, critical: bool = False) -> None:
        """Add an extension to the certificate."""
        self.extensions.append(X509Extension(oid=oid, critical=critical, value=value))

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "version": self.version,
            "serialNumber": self.serial_number,
            "issuer": self.issuer.to_dict(),
            "subject": self.subject.to_dict(),
            "validity": {
                "notBefore": self.not_before.isoformat(),
                "notAfter": self.not_after.isoformat(),
            },
            "extensions": [ext.to_dict() for ext in self.extensions],
            "keyUsage": self.key_usage,
            "extendedKeyUsage": self.extended_key_usage,
        }


@dataclass
class X509DerivationResult:
    """
    Result of deriving an X.509 certificate from an ACDC.
    """
    certificate: X509Certificate
    loss_report: LossReport
    success: bool = True
    error: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "certificate": self.certificate.to_dict(),
            "loss_report": self.loss_report.to_dict(),
            "success": self.success,
            "error": self.error,
        }


def derive_x509(
    acdc: dict[str, Any],
    source_loa: LoALevel = LoALevel.LOA_0,
    validity_days: int = 365,
    key_usage: Optional[list[str]] = None,
    extended_key_usage: Optional[list[str]] = None,
    include_keri_extensions: bool = True,
) -> X509DerivationResult:
    """
    Derive an X.509 certificate structure from an ACDC credential.

    This is the most lossy derivation - X.509 cannot represent most
    ACDC concepts. Only use when legacy interoperability is required.

    Args:
        acdc: ACDC credential as dictionary
        source_loa: LoA level of the source ACDC
        validity_days: Certificate validity period
        key_usage: Key usage flags (digitalSignature, keyEncipherment, etc.)
        extended_key_usage: Extended key usage OIDs
        include_keri_extensions: Include custom KERI extensions with SAID/AID

    Returns:
        X509DerivationResult containing the certificate structure and loss report
    """
    # Validate required ACDC fields
    if "d" not in acdc:
        return X509DerivationResult(
            certificate=X509Certificate(),
            loss_report=LossReport(
                source_said="",
                source_loa=source_loa,
                target_format="x509",
            ),
            success=False,
            error="ACDC missing required 'd' (SAID) field",
        )

    said = acdc["d"]

    # Initialize loss report - x509 has the highest losses
    report = create_loss_report(said, source_loa, "x509")

    # Build certificate
    cert = X509Certificate()
    cert.derived_from_said = said

    # Use SAID as serial number (truncated for x509 compatibility)
    cert.serial_number = said[:20] if len(said) > 20 else said

    # Set validity
    now = datetime.now(timezone.utc)
    cert.not_before = now
    cert.not_after = now + timedelta(days=validity_days)

    # Map issuer AID to issuer DN
    if "i" in acdc:
        cert.issuer = _map_aid_to_dn(acdc["i"], "Issuer", report)
    else:
        report.add_loss(LossItem(
            name="missing_issuer",
            category=LossCategory.TECH,
            severity=LossSeverity.SEVERE,
            description="ACDC missing issuer field",
        ))

    # Map attributes to subject DN
    if "a" in acdc:
        cert.subject = _map_attributes_to_dn(acdc["a"], report)
    else:
        # Use SAID as CN if no attributes
        cert.subject.common_name = said[:64]

    # Add KERI extensions if requested
    if include_keri_extensions:
        cert.add_extension(KERI_OID_SAID, said, critical=False)
        if "i" in acdc:
            cert.add_extension(KERI_OID_AID, acdc["i"], critical=False)
        if "s" in acdc:
            cert.add_extension(KERI_OID_SCHEMA, acdc["s"], critical=False)
        cert.add_extension(KERI_OID_LOA, source_loa.value, critical=False)

    # Map rules to policy OID (very degraded)
    if "r" in acdc:
        _map_rules_to_policy(acdc["r"], cert, report)

    # Report edge section loss (most significant)
    if "e" in acdc:
        _report_edge_losses(acdc["e"], report)

    # Report TEL status loss
    if "ri" in acdc:
        report.add_loss(LossItem(
            name="tel_status_x509",
            category=LossCategory.TECH,
            severity=LossSeverity.SIGNIFICANT,
            description="TEL status has no X.509 equivalent",
            source_path="$.ri",
            mitigation="Use CRL or OCSP for revocation status",
        ))

    # Report schema loss
    if "s" in acdc and not include_keri_extensions:
        report.add_loss(LossItem(
            name="schema_x509",
            category=LossCategory.TECH,
            severity=LossSeverity.MODERATE,
            description="Schema reference lost without KERI extensions",
            source_path="$.s",
        ))

    # Report general x509 limitations
    report.add_loss(LossItem(
        name="self_certifying_lost",
        category=LossCategory.TECH,
        severity=LossSeverity.SEVERE,
        description="X.509 is not self-certifying - relies on CA hierarchy",
        mitigation="KERI AID stored in extension for verification",
    ))

    # Set key usage if provided
    if key_usage:
        cert.key_usage = key_usage
    if extended_key_usage:
        cert.extended_key_usage = extended_key_usage

    # Finalize report
    report.finalize()

    return X509DerivationResult(
        certificate=cert,
        loss_report=report,
        success=True,
    )


def _map_aid_to_dn(aid: str, role: str, report: LossReport) -> DistinguishedName:
    """
    Map KERI AID to Distinguished Name.

    This is a severe degradation - AID has no equivalent in DN.
    """
    dn = DistinguishedName()

    # Use AID prefix as org identifier
    dn.common_name = f"KERI {role}"
    dn.organization = f"AID:{aid[:16]}..."
    dn.serial_number = aid  # Full AID in serialNumber

    # Report the mapping loss
    report.add_loss(LossItem(
        name="aid_to_dn",
        category=LossCategory.TECH,
        severity=LossSeverity.SIGNIFICANT,
        description="AID mapped to DN serialNumber field - loses crypto binding",
        source_path="$.i",
        target_representation="serialNumber in Subject DN",
    ))

    return dn


def _map_attributes_to_dn(
    attributes: dict[str, Any],
    report: LossReport,
) -> DistinguishedName:
    """
    Map ACDC attributes to Subject DN.

    Most attributes cannot be represented in DN fields.
    """
    dn = DistinguishedName()

    # Standard field mappings
    field_mappings = {
        "name": "common_name",
        "cn": "common_name",
        "commonName": "common_name",
        "organization": "organization",
        "org": "organization",
        "o": "organization",
        "organizationalUnit": "organizational_unit",
        "ou": "organizational_unit",
        "country": "country",
        "c": "country",
        "state": "state",
        "st": "state",
        "province": "state",
        "locality": "locality",
        "l": "locality",
        "city": "locality",
        "email": "email",
        "emailAddress": "email",
        "lei": "serial_number",
        "LEI": "serial_number",
    }

    mapped_fields = set()
    unmapped_fields = []

    for key, value in attributes.items():
        if key in ("d", "i", "dt"):
            continue

        # Convert value to string
        if isinstance(value, dict):
            str_value = value.get("d", str(value))
        else:
            str_value = str(value)

        # Check for standard mapping
        if key.lower() in field_mappings or key in field_mappings:
            target_field = field_mappings.get(key.lower(), field_mappings.get(key))
            if target_field:
                setattr(dn, target_field, str_value[:64])  # DN field length limit
                mapped_fields.add(key)
        else:
            unmapped_fields.append(key)
            # Store in custom attributes
            dn.custom_attributes[key] = str_value[:64]

    # Report attribute mapping losses
    if unmapped_fields:
        report.add_loss(LossItem(
            name="attributes_to_dn",
            category=LossCategory.HOLDER,
            severity=LossSeverity.SIGNIFICANT,
            description=f"Attributes not mappable to DN: {', '.join(unmapped_fields[:5])}",
            source_path="$.a",
            target_representation="Lost or stored in custom extension",
        ))

    # If no CN was found, use first available value
    if not dn.common_name:
        for key in ("name", "label", "title", "id"):
            if key in attributes:
                dn.common_name = str(attributes[key])[:64]
                break

    return dn


def _map_rules_to_policy(
    rules: dict[str, Any] | list[dict[str, Any]],
    cert: X509Certificate,
    report: LossReport,
) -> None:
    """
    Map ACDC rules to X.509 certificate policy.

    Only a policy OID reference can be preserved.
    """
    # Report severe degradation
    report.add_loss(LossItem(
        name="rules_to_policy_oid",
        category=LossCategory.GOVERNANCE,
        severity=LossSeverity.SEVERE,
        description="ACDC rules algebra completely lost - only policy OID reference possible",
        source_path="$.r",
        target_representation="Certificate Policy extension",
        mitigation="Reference full governance framework via policy OID",
    ))

    # Add generic policy extension
    # In real implementation, this would map to registered policy OIDs
    policy_oid = "2.5.29.32"  # certificatePolicies
    cert.add_extension(policy_oid, {"policyOID": KERI_OID_ARC}, critical=False)


def _report_edge_losses(
    edges: dict[str, Any],
    report: LossReport,
) -> None:
    """Report losses from ACDC edge section."""
    # All edge losses apply to x509
    report.add_loss(LossItem(
        name="edge_section_x509",
        category=LossCategory.STRUCTURAL,
        severity=LossSeverity.SEVERE,
        description="X.509 has no graph structure - all edges completely lost",
        source_path="$.e",
        mitigation="X.509 cannot represent credential graphs",
    ))

    # Check for operators
    for key, value in edges.items():
        if key == "d":
            continue
        if isinstance(value, dict) and "o" in value:
            report.add_loss(LossItem(
                name="edge_operators_x509",
                category=LossCategory.STRUCTURAL,
                severity=LossSeverity.SEVERE,
                description="Edge operators (I2I, DI2I, NI2I) have no X.509 equivalent",
                source_path=f"$.e.{key}.o",
            ))
            break


def derive_x509_from_dict(
    acdc_dict: dict[str, Any],
    **kwargs,
) -> dict[str, Any]:
    """
    Convenience function that returns dict instead of dataclass.

    Args:
        acdc_dict: ACDC as dictionary
        **kwargs: Additional arguments passed to derive_x509

    Returns:
        Dictionary with 'certificate' and 'loss_report' keys
    """
    result = derive_x509(acdc_dict, **kwargs)
    return result.to_dict()
