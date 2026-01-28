# -*- encoding: utf-8 -*-
"""
KERI Credential Crosswalk Module.

Provides infrastructure for:
- Deriving credentials from ACDC to other formats (W3C VC, SD-JWT, x509, JWT)
- Ingesting credentials from other formats back to ACDC
- Tracking semantic losses in derivation
- Mapping between LoA levels and KERI strength levels

Key principle: ACDC is the lossless canonical source. All other formats
are lossy derivations. This module documents exactly what is preserved,
degraded, or lost in each derivation.

Hardman Model Reference:
    Daniel Hardman (Provenant), "Org Vet as a Credential Type", May 2025
    Progressive LoA ladder: LoA 0-3 + vLEI
    Four dimensions: tech, governance, holder, vetting
"""

from .loa_mapping import (
    # Enums
    LoALevel,
    StrengthLevel,
    # Dataclasses
    LoARequirements,
    LoADimensionScore,
    # Functions
    get_loa_requirements,
    map_loa_to_strength,
    map_strength_to_loa,
    loa_satisfies,
    strength_satisfies,
    can_strengthen,
    get_next_loa,
    get_loa_chain,
    get_derivation_losses,
    # Constants
    LOA_REQUIREMENTS,
    W3C_VC_DIMENSION_LOSSES,
    X509_DIMENSION_LOSSES,
)

from .loss_report import (
    # Enums
    LossSeverity,
    LossCategory,
    # Dataclasses
    LossItem,
    LossReport,
    # Functions
    create_loss_report,
    assess_derivation_viability,
    get_mitigation_recommendations,
    # Constants
    STANDARD_LOSSES,
)

from .derive_w3c_vc import (
    W3CVC,
    DerivationResult,
    derive_w3c_vc,
    derive_w3c_vc_from_dict,
)

from .derive_sd_jwt import (
    SDJWTClaim,
    SDJWT,
    SDJWTDerivationResult,
    derive_sd_jwt,
    derive_sd_jwt_from_dict,
)

from .derive_x509 import (
    DistinguishedName,
    X509Extension,
    X509Certificate,
    X509DerivationResult,
    derive_x509,
    derive_x509_from_dict,
)

from .derive_jwt import (
    JWTPayload,
    JWT,
    JWTDerivationResult,
    derive_jwt,
    derive_jwt_from_dict,
    derive_oidc_id_token,
)

from .ingest_w3c_vc import (
    IngestionWarning,
    ACDCFromVC,
    IngestionResult,
    ingest_w3c_vc,
    ingest_w3c_vc_from_dict,
)

__all__ = [
    # LoA Mapping
    "LoALevel",
    "StrengthLevel",
    "LoARequirements",
    "LoADimensionScore",
    "get_loa_requirements",
    "map_loa_to_strength",
    "map_strength_to_loa",
    "loa_satisfies",
    "strength_satisfies",
    "can_strengthen",
    "get_next_loa",
    "get_loa_chain",
    "get_derivation_losses",
    "LOA_REQUIREMENTS",
    "W3C_VC_DIMENSION_LOSSES",
    "X509_DIMENSION_LOSSES",
    # Loss Report
    "LossSeverity",
    "LossCategory",
    "LossItem",
    "LossReport",
    "create_loss_report",
    "assess_derivation_viability",
    "get_mitigation_recommendations",
    "STANDARD_LOSSES",
    # W3C VC Derivation
    "W3CVC",
    "DerivationResult",
    "derive_w3c_vc",
    "derive_w3c_vc_from_dict",
    # SD-JWT Derivation
    "SDJWTClaim",
    "SDJWT",
    "SDJWTDerivationResult",
    "derive_sd_jwt",
    "derive_sd_jwt_from_dict",
    # X.509 Derivation
    "DistinguishedName",
    "X509Extension",
    "X509Certificate",
    "X509DerivationResult",
    "derive_x509",
    "derive_x509_from_dict",
    # JWT/OIDC Derivation
    "JWTPayload",
    "JWT",
    "JWTDerivationResult",
    "derive_jwt",
    "derive_jwt_from_dict",
    "derive_oidc_id_token",
    # W3C VC Ingestion
    "IngestionWarning",
    "ACDCFromVC",
    "IngestionResult",
    "ingest_w3c_vc",
    "ingest_w3c_vc_from_dict",
]
