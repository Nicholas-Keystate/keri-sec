# -*- encoding: utf-8 -*-
"""
W3C Verifiable Credential to ACDC Ingestion.

Ingests a W3C VC 2.0 and creates an ACDC credential structure.

IMPORTANT: Ingestion is fundamentally limited. You cannot recreate
information that was never present in the source. Ingested ACDCs:
- Have LoA 0 (no vetting chain)
- Have empty edge sections (no graph structure)
- Have placeholder/derived SAIDs
- Require re-vetting to strengthen

Key mappings:
    VC.id → ACDC.d (if urn:said:, else generate)
    VC.issuer → ACDC.i (if did:keri:, else placeholder)
    VC.credentialSubject → ACDC.a
    VC.credentialSchema → ACDC.s (if available)
    VC.termsOfUse → ACDC.r (partial)

What cannot be recovered:
    - Original edge structure ($.e)
    - Progressive assurance chain
    - TEL credential status
    - SAID self-referential integrity
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional
import hashlib

from .loa_mapping import LoALevel, StrengthLevel


# URN schemes
SAID_URN_PREFIX = "urn:said:"
DID_KERI_PREFIX = "did:keri:"


@dataclass
class IngestionWarning:
    """
    Warning generated during ingestion.

    Documents limitations and assumptions made during ingestion.
    """
    field: str          # Source field
    warning_type: str   # Type of warning
    message: str        # Human explanation
    value_used: Any = None  # What value was used


@dataclass
class ACDCFromVC:
    """
    ACDC structure created from W3C VC ingestion.

    Note: This is a data structure only. To create a proper ACDC with
    valid SAID, use keripy's proving.credential() with this data.
    """
    # Core ACDC fields
    v: str = "ACDC10JSON000000_"  # Version string (placeholder)
    d: str = ""                   # SAID (will be computed)
    i: str = ""                   # Issuer AID
    ri: str = ""                  # Registry identifier (optional)
    s: str = ""                   # Schema SAID

    # Attribute section
    a: dict[str, Any] = field(default_factory=dict)

    # Edge section (empty for ingested credentials)
    e: dict[str, Any] = field(default_factory=dict)

    # Rules section
    r: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to ACDC dictionary structure."""
        acdc = {
            "v": self.v,
            "d": self.d,
            "i": self.i,
            "s": self.s,
            "a": self.a,
        }

        if self.ri:
            acdc["ri"] = self.ri
        if self.e:
            acdc["e"] = self.e
        if self.r:
            acdc["r"] = self.r

        return acdc


@dataclass
class IngestionResult:
    """
    Result of ingesting a W3C VC into ACDC format.
    """
    acdc: ACDCFromVC
    warnings: list[IngestionWarning] = field(default_factory=list)
    inferred_loa: LoALevel = LoALevel.LOA_0
    inferred_strength: StrengthLevel = StrengthLevel.ANY
    success: bool = True
    error: Optional[str] = None

    # Source tracking
    source_id: str = ""
    source_format: str = "w3c_vc"
    ingested_at: str = ""

    def add_warning(
        self,
        field: str,
        warning_type: str,
        message: str,
        value_used: Any = None,
    ) -> None:
        """Add an ingestion warning."""
        self.warnings.append(IngestionWarning(
            field=field,
            warning_type=warning_type,
            message=message,
            value_used=value_used,
        ))

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "acdc": self.acdc.to_dict(),
            "warnings": [
                {
                    "field": w.field,
                    "warning_type": w.warning_type,
                    "message": w.message,
                    "value_used": w.value_used,
                }
                for w in self.warnings
            ],
            "inferred_loa": self.inferred_loa.name,
            "inferred_strength": self.inferred_strength.name,
            "success": self.success,
            "error": self.error,
            "source_id": self.source_id,
            "source_format": self.source_format,
            "ingested_at": self.ingested_at,
        }


def ingest_w3c_vc(
    vc: dict[str, Any],
    issuer_aid: Optional[str] = None,
    schema_said: Optional[str] = None,
    registry_id: Optional[str] = None,
) -> IngestionResult:
    """
    Ingest a W3C VC 2.0 and create an ACDC structure.

    IMPORTANT: Ingested ACDCs have LoA 0 by definition. They require
    re-vetting to establish a proper assurance level.

    Args:
        vc: W3C VC as dictionary
        issuer_aid: Override issuer AID (if known from KERI)
        schema_said: Override schema SAID (if known)
        registry_id: Registry ID for credential status

    Returns:
        IngestionResult with ACDC structure and warnings
    """
    result = IngestionResult(
        acdc=ACDCFromVC(),
        ingested_at=datetime.now(timezone.utc).isoformat(),
    )

    # Extract source ID for tracking
    result.source_id = vc.get("id", "")

    # Map VC.id to SAID
    _map_id(vc, result, issuer_aid)

    # Map issuer
    _map_issuer(vc, result, issuer_aid)

    # Map schema
    _map_schema(vc, result, schema_said)

    # Map credentialSubject to attributes
    _map_credential_subject(vc, result)

    # Map termsOfUse to rules (partial)
    _map_terms_of_use(vc, result)

    # Set registry if provided
    if registry_id:
        result.acdc.ri = registry_id

    # Handle credential status
    _handle_credential_status(vc, result)

    # Set inferred assurance levels
    result.inferred_loa = LoALevel.LOA_0
    result.inferred_strength = StrengthLevel.ANY

    # Add general ingestion warnings
    result.add_warning(
        field="",
        warning_type="ingestion_limitation",
        message="Ingested ACDCs have LoA 0 - require re-vetting to strengthen",
    )

    result.add_warning(
        field="$.e",
        warning_type="no_edges",
        message="Edge structure cannot be recovered from W3C VC",
    )

    return result


def _map_id(
    vc: dict[str, Any],
    result: IngestionResult,
    issuer_aid: Optional[str],
) -> None:
    """Map VC.id to ACDC SAID."""
    vc_id = vc.get("id", "")

    if vc_id.startswith(SAID_URN_PREFIX):
        # Extract SAID from URN
        result.acdc.d = vc_id[len(SAID_URN_PREFIX):]
        result.add_warning(
            field="id",
            warning_type="said_extracted",
            message="SAID extracted from urn:said: - verify matches content hash",
            value_used=result.acdc.d,
        )
    elif vc_id:
        # Generate deterministic placeholder SAID from VC ID
        result.acdc.d = _generate_placeholder_said(vc_id, issuer_aid or "")
        result.add_warning(
            field="id",
            warning_type="said_generated",
            message="SAID generated from VC ID - not a true self-referential SAID",
            value_used=result.acdc.d,
        )
    else:
        # No ID - generate from content
        content_hash = _hash_content(vc)
        result.acdc.d = f"E{content_hash[:43]}"  # SAID-like prefix
        result.add_warning(
            field="id",
            warning_type="said_missing",
            message="No VC ID - generated placeholder SAID from content hash",
            value_used=result.acdc.d,
        )


def _map_issuer(
    vc: dict[str, Any],
    result: IngestionResult,
    issuer_aid: Optional[str],
) -> None:
    """Map VC.issuer to ACDC issuer AID."""
    if issuer_aid:
        # Use provided AID
        result.acdc.i = issuer_aid
        return

    issuer = vc.get("issuer", "")

    # Handle issuer as string or object
    if isinstance(issuer, dict):
        issuer = issuer.get("id", "")

    if issuer.startswith(DID_KERI_PREFIX):
        # Extract AID from did:keri:
        result.acdc.i = issuer[len(DID_KERI_PREFIX):]
    elif issuer.startswith("did:"):
        # Other DID method - use as-is with warning
        result.acdc.i = issuer
        result.add_warning(
            field="issuer",
            warning_type="non_keri_did",
            message=f"Issuer uses non-KERI DID method: {issuer[:30]}...",
            value_used=issuer,
        )
    elif issuer:
        # URL or other identifier
        result.acdc.i = issuer
        result.add_warning(
            field="issuer",
            warning_type="non_did_issuer",
            message="Issuer is not a DID - cannot verify cryptographically",
            value_used=issuer,
        )
    else:
        result.add_warning(
            field="issuer",
            warning_type="missing_issuer",
            message="No issuer in VC - ACDC issuer field empty",
        )


def _map_schema(
    vc: dict[str, Any],
    result: IngestionResult,
    schema_said: Optional[str],
) -> None:
    """Map VC.credentialSchema to ACDC schema SAID."""
    if schema_said:
        result.acdc.s = schema_said
        return

    schema = vc.get("credentialSchema")
    if not schema:
        result.add_warning(
            field="credentialSchema",
            warning_type="missing_schema",
            message="No schema in VC - ACDC schema field empty",
        )
        return

    # Handle schema as object
    if isinstance(schema, dict):
        schema_id = schema.get("id", "")
    else:
        schema_id = str(schema)

    if schema_id.startswith(SAID_URN_PREFIX):
        result.acdc.s = schema_id[len(SAID_URN_PREFIX):]
    elif schema_id:
        # Non-SAID schema reference
        result.acdc.s = schema_id
        result.add_warning(
            field="credentialSchema",
            warning_type="non_said_schema",
            message="Schema is not a SAID - using URL reference",
            value_used=schema_id,
        )


def _map_credential_subject(
    vc: dict[str, Any],
    result: IngestionResult,
) -> None:
    """Map VC.credentialSubject to ACDC attributes."""
    subject = vc.get("credentialSubject", {})

    if not subject:
        result.add_warning(
            field="credentialSubject",
            warning_type="missing_subject",
            message="No credentialSubject in VC - attributes empty",
        )
        return

    # Handle subject as list (multi-subject VC)
    if isinstance(subject, list):
        if len(subject) == 1:
            subject = subject[0]
        else:
            result.add_warning(
                field="credentialSubject",
                warning_type="multi_subject",
                message="Multi-subject VC - using first subject only",
                value_used=len(subject),
            )
            subject = subject[0]

    # Build attribute section
    attributes = {"d": ""}  # Placeholder for attribute SAID

    for key, value in subject.items():
        if key == "id":
            # Subject ID becomes attribute 'i'
            if isinstance(value, str) and value.startswith(DID_KERI_PREFIX):
                attributes["i"] = value[len(DID_KERI_PREFIX):]
            else:
                attributes["i"] = value
        else:
            attributes[key] = value

    # Add issuance timestamp
    attributes["dt"] = vc.get("validFrom", datetime.now(timezone.utc).isoformat())

    result.acdc.a = attributes


def _map_terms_of_use(
    vc: dict[str, Any],
    result: IngestionResult,
) -> None:
    """Map VC.termsOfUse to ACDC rules section (partial)."""
    terms = vc.get("termsOfUse")
    if not terms:
        return

    if isinstance(terms, dict):
        terms = [terms]

    rules = {"d": ""}  # Placeholder for rules SAID

    for term in terms:
        term_type = term.get("type", "")
        if term_type == "GovernanceFramework" or "url" in term:
            rules["framework"] = term.get("url", term.get("id", ""))

    if rules.get("framework"):
        result.acdc.r = rules
        result.add_warning(
            field="termsOfUse",
            warning_type="partial_rules",
            message="Only framework reference preserved - constraint algebra lost",
        )


def _handle_credential_status(
    vc: dict[str, Any],
    result: IngestionResult,
) -> None:
    """Handle VC.credentialStatus."""
    status = vc.get("credentialStatus")
    if not status:
        return

    result.add_warning(
        field="credentialStatus",
        warning_type="status_not_preserved",
        message="credentialStatus cannot be converted to TEL - check status separately",
        value_used=status.get("type", "unknown"),
    )


def _generate_placeholder_said(vc_id: str, issuer: str) -> str:
    """Generate a placeholder SAID from VC ID and issuer."""
    content = f"{vc_id}:{issuer}"
    hash_bytes = hashlib.blake2b(content.encode(), digest_size=32).digest()
    # Use base64url-like encoding
    import base64
    b64 = base64.urlsafe_b64encode(hash_bytes).decode().rstrip("=")
    return f"E{b64[:43]}"


def _hash_content(content: dict) -> str:
    """Hash content for SAID generation."""
    import json
    content_str = json.dumps(content, sort_keys=True, separators=(",", ":"))
    hash_bytes = hashlib.blake2b(content_str.encode(), digest_size=32).digest()
    import base64
    return base64.urlsafe_b64encode(hash_bytes).decode().rstrip("=")


def ingest_w3c_vc_from_dict(
    vc_dict: dict[str, Any],
    **kwargs,
) -> dict[str, Any]:
    """
    Convenience function that returns dict instead of dataclass.

    Args:
        vc_dict: W3C VC as dictionary
        **kwargs: Additional arguments passed to ingest_w3c_vc

    Returns:
        Dictionary with 'acdc', 'warnings', and metadata
    """
    result = ingest_w3c_vc(vc_dict, **kwargs)
    return result.to_dict()
