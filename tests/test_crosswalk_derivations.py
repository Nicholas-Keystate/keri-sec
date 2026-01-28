# -*- encoding: utf-8 -*-
"""
Tests for crosswalk derivation modules.

Tests ACDC to W3C VC, SD-JWT, x509, and JWT derivations.
"""

import pytest

from keri_sec.crosswalk.loa_mapping import LoALevel
from keri_sec.crosswalk.loss_report import LossSeverity

from keri_sec.crosswalk.derive_w3c_vc import (
    derive_w3c_vc,
    derive_w3c_vc_from_dict,
    W3CVC,
    DerivationResult,
)
from keri_sec.crosswalk.derive_sd_jwt import (
    derive_sd_jwt,
    derive_sd_jwt_from_dict,
    SDJWT,
    SDJWTClaim,
)
from keri_sec.crosswalk.derive_x509 import (
    derive_x509,
    derive_x509_from_dict,
    DistinguishedName,
)
from keri_sec.crosswalk.derive_jwt import (
    derive_jwt,
    derive_jwt_from_dict,
    derive_oidc_id_token,
)


@pytest.fixture
def sample_acdc():
    """Sample ACDC credential for testing."""
    return {
        "v": "ACDC10JSON000000_",
        "d": "ESAID1234567890ABCDEF",
        "i": "EAID_ISSUER_123456789",
        "ri": "EREGISTRY_123456789",
        "s": "ESCHEMA_123456789",
        "a": {
            "d": "EATTR_SAID_123",
            "i": "ESUBJECT_AID_123",
            "dt": "2026-01-28T00:00:00Z",
            "name": "Test Organization",
            "LEI": "5493001KJTIIGC8Y1R12",
        },
        "e": {
            "d": "EEDGE_SAID_123",
            "previousLevel": {
                "n": "EPREV_SAID_123",
                "o": "I2I",
            },
        },
        "r": {
            "d": "ERULE_SAID_123",
            "url": "https://governance.example.com/framework",
        },
    }


@pytest.fixture
def minimal_acdc():
    """Minimal ACDC with just required fields."""
    return {
        "d": "ESAID_MINIMAL_123",
        "i": "EAID_ISSUER_MIN",
        "a": {
            "name": "Minimal Test",
        },
    }


class TestDeriveW3CVC:
    """Tests for W3C VC derivation."""

    def test_derive_success(self, sample_acdc):
        """Test successful W3C VC derivation."""
        result = derive_w3c_vc(sample_acdc)
        assert result.success
        assert result.vc is not None

    def test_vc_has_context(self, sample_acdc):
        """Test VC has @context."""
        result = derive_w3c_vc(sample_acdc)
        assert "https://www.w3.org/ns/credentials/v2" in result.vc.context

    def test_vc_has_type(self, sample_acdc):
        """Test VC has type."""
        result = derive_w3c_vc(sample_acdc)
        assert "VerifiableCredential" in result.vc.type

    def test_said_maps_to_id(self, sample_acdc):
        """Test SAID maps to VC id with URN scheme."""
        result = derive_w3c_vc(sample_acdc)
        assert result.vc.id == f"urn:said:{sample_acdc['d']}"

    def test_aid_maps_to_issuer(self, sample_acdc):
        """Test AID maps to issuer with did:keri:."""
        result = derive_w3c_vc(sample_acdc)
        assert result.vc.issuer == f"did:keri:{sample_acdc['i']}"

    def test_attributes_map_to_subject(self, sample_acdc):
        """Test attributes map to credentialSubject."""
        result = derive_w3c_vc(sample_acdc)
        assert "name" in result.vc.credential_subject
        assert result.vc.credential_subject["name"] == "Test Organization"

    def test_loss_report_generated(self, sample_acdc):
        """Test loss report is generated."""
        result = derive_w3c_vc(sample_acdc)
        assert result.loss_report is not None
        assert len(result.loss_report.losses) > 0

    def test_edge_loss_reported(self, sample_acdc):
        """Test edge section loss is reported."""
        result = derive_w3c_vc(sample_acdc)
        edge_losses = [l for l in result.loss_report.losses if "edge" in l.name.lower()]
        assert len(edge_losses) > 0

    def test_missing_said_fails(self):
        """Test derivation fails without SAID."""
        acdc = {"i": "EAID123", "a": {"name": "Test"}}
        result = derive_w3c_vc(acdc)
        assert not result.success
        assert "SAID" in result.error

    def test_to_dict_serialization(self, sample_acdc):
        """Test result serializes to dict."""
        result = derive_w3c_vc(sample_acdc)
        d = result.to_dict()
        assert "vc" in d
        assert "loss_report" in d
        assert "@context" in d["vc"]

    def test_dict_convenience_function(self, sample_acdc):
        """Test derive_w3c_vc_from_dict returns dict."""
        result = derive_w3c_vc_from_dict(sample_acdc)
        assert isinstance(result, dict)
        assert "vc" in result


class TestDeriveSDJWT:
    """Tests for SD-JWT derivation."""

    def test_derive_success(self, sample_acdc):
        """Test successful SD-JWT derivation."""
        result = derive_sd_jwt(sample_acdc)
        assert result.success
        assert result.sd_jwt is not None

    def test_issuer_mapped(self, sample_acdc):
        """Test issuer is mapped."""
        result = derive_sd_jwt(sample_acdc)
        assert result.sd_jwt.iss == f"did:keri:{sample_acdc['i']}"

    def test_claims_created(self, sample_acdc):
        """Test claims are created from attributes."""
        result = derive_sd_jwt(sample_acdc)
        claim_names = [c.name for c in result.sd_jwt.sd_claims]
        assert "name" in claim_names

    def test_sd_claims_have_disclosures(self, sample_acdc):
        """Test SD claims have disclosures."""
        result = derive_sd_jwt(sample_acdc)
        disclosures = result.sd_jwt.get_disclosures()
        assert len(disclosures) > 0

    def test_payload_has_sd_hashes(self, sample_acdc):
        """Test payload has _sd array with hashes."""
        result = derive_sd_jwt(sample_acdc)
        payload = result.sd_jwt.to_payload()
        assert "_sd" in payload
        assert len(payload["_sd"]) > 0

    def test_always_disclose_fields(self, sample_acdc):
        """Test always_disclose fields are not in _sd."""
        result = derive_sd_jwt(sample_acdc, always_disclose=["name"])
        payload = result.sd_jwt.to_payload()
        # 'name' should be directly in payload, not in disclosures
        assert "name" in payload

    def test_loss_report_includes_edge_loss(self, sample_acdc):
        """Test loss report includes edge section loss."""
        result = derive_sd_jwt(sample_acdc)
        loss_names = [l.name for l in result.loss_report.losses]
        assert any("edge" in name.lower() for name in loss_names)

    def test_missing_said_fails(self):
        """Test derivation fails without SAID."""
        acdc = {"i": "EAID123", "a": {"name": "Test"}}
        result = derive_sd_jwt(acdc)
        assert not result.success


class TestDeriveX509:
    """Tests for X.509 derivation."""

    def test_derive_success(self, sample_acdc):
        """Test successful x509 derivation."""
        result = derive_x509(sample_acdc)
        assert result.success
        assert result.certificate is not None

    def test_certificate_has_dn(self, sample_acdc):
        """Test certificate has distinguished names."""
        result = derive_x509(sample_acdc)
        assert result.certificate.issuer is not None
        assert result.certificate.subject is not None

    def test_lei_maps_to_serial_number(self, sample_acdc):
        """Test LEI maps to DN serialNumber."""
        result = derive_x509(sample_acdc)
        assert result.certificate.subject.serial_number == "5493001KJTIIGC8Y1R12"

    def test_keri_extensions_added(self, sample_acdc):
        """Test KERI extensions are added."""
        result = derive_x509(sample_acdc, include_keri_extensions=True)
        ext_oids = [e.oid for e in result.certificate.extensions]
        # Should have SAID extension
        assert any("99999" in oid for oid in ext_oids)

    def test_no_keri_extensions_option(self, sample_acdc):
        """Test can disable KERI extensions."""
        result = derive_x509(sample_acdc, include_keri_extensions=False)
        ext_oids = [e.oid for e in result.certificate.extensions]
        # Should not have KERI-specific extensions (except policy)
        keri_exts = [oid for oid in ext_oids if "99999" in oid]
        assert len(keri_exts) == 0

    def test_high_loss_severity(self, sample_acdc):
        """Test x509 derivation has high loss severity."""
        result = derive_x509(sample_acdc)
        result.loss_report.finalize()
        # x509 should have severe losses
        severe = result.loss_report.by_severity(LossSeverity.SEVERE)
        assert len(severe) > 0

    def test_custom_validity(self, sample_acdc):
        """Test custom validity period."""
        result = derive_x509(sample_acdc, validity_days=730)
        delta = result.certificate.not_after - result.certificate.not_before
        assert delta.days == 730


class TestDeriveJWT:
    """Tests for JWT derivation."""

    def test_derive_success(self, sample_acdc):
        """Test successful JWT derivation."""
        result = derive_jwt(sample_acdc)
        assert result.success
        assert result.jwt is not None

    def test_jwt_has_standard_claims(self, sample_acdc):
        """Test JWT has standard claims."""
        result = derive_jwt(sample_acdc)
        payload = result.jwt.payload.to_dict()
        assert "iss" in payload
        assert "iat" in payload
        assert "jti" in payload

    def test_said_maps_to_jti(self, sample_acdc):
        """Test SAID maps to JWT ID."""
        result = derive_jwt(sample_acdc)
        assert f"urn:said:{sample_acdc['d']}" in result.jwt.payload.jti

    def test_expiration_set(self, sample_acdc):
        """Test expiration is set."""
        result = derive_jwt(sample_acdc, expiration_seconds=7200)
        payload = result.jwt.payload.to_dict()
        assert "exp" in payload
        assert payload["exp"] > payload["iat"]

    def test_audience_set(self, sample_acdc):
        """Test audience is set."""
        result = derive_jwt(sample_acdc, audience="https://api.example.com")
        payload = result.jwt.payload.to_dict()
        assert payload["aud"] == "https://api.example.com"

    def test_custom_claim_mapping(self, sample_acdc):
        """Test custom claim mapping."""
        result = derive_jwt(sample_acdc, claim_mapping={"name": "organization_name"})
        payload = result.jwt.payload.to_dict()
        assert "organization_name" in payload

    def test_no_selective_disclosure_loss(self, sample_acdc):
        """Test no selective disclosure loss is reported."""
        result = derive_jwt(sample_acdc)
        loss_names = [l.name for l in result.loss_report.losses]
        assert any("selective" in name.lower() for name in loss_names)


class TestDeriveOIDCIdToken:
    """Tests for OIDC ID Token derivation."""

    def test_oidc_token_success(self, sample_acdc):
        """Test OIDC ID token derivation."""
        result = derive_oidc_id_token(
            sample_acdc,
            audience="client123",
            nonce="nonce456",
        )
        assert result.success

    def test_oidc_has_nonce(self, sample_acdc):
        """Test OIDC token has nonce."""
        result = derive_oidc_id_token(
            sample_acdc,
            audience="client123",
            nonce="nonce456",
        )
        payload = result.jwt.payload.to_dict()
        assert payload["nonce"] == "nonce456"

    def test_oidc_has_acr(self, sample_acdc):
        """Test OIDC token has acr claim."""
        result = derive_oidc_id_token(
            sample_acdc,
            audience="client123",
            nonce="nonce456",
            source_loa=LoALevel.LOA_2,
        )
        assert result.jwt.payload.acr is not None
        assert "keri:loa:2" in result.jwt.payload.acr


class TestDistinguishedName:
    """Tests for DistinguishedName dataclass."""

    def test_dn_to_string(self):
        """Test DN to string conversion."""
        dn = DistinguishedName(
            common_name="Test Org",
            organization="Test Inc",
            country="US",
        )
        dn_str = dn.to_string()
        assert "CN=Test Org" in dn_str
        assert "O=Test Inc" in dn_str
        assert "C=US" in dn_str

    def test_dn_to_dict(self):
        """Test DN to dict conversion."""
        dn = DistinguishedName(
            common_name="Test",
            email="test@example.com",
        )
        d = dn.to_dict()
        assert d["CN"] == "Test"
        assert d["emailAddress"] == "test@example.com"


class TestSDJWTClaim:
    """Tests for SDJWTClaim dataclass."""

    def test_disclosure_generation(self):
        """Test disclosure is generated."""
        claim = SDJWTClaim(
            name="email",
            value="test@example.com",
            selectively_disclosable=True,
        )
        disclosure = claim.to_disclosure()
        assert disclosure  # Base64-encoded
        # Should be decodable
        import base64
        decoded = base64.urlsafe_b64decode(disclosure + "==")
        assert b"email" in decoded

    def test_disclosure_hash(self):
        """Test disclosure hash computation."""
        claim = SDJWTClaim(
            name="test",
            value="value",
            selectively_disclosable=True,
        )
        hash_val = claim.disclosure_hash()
        assert hash_val  # Should be non-empty base64url string
        assert "=" not in hash_val  # Should be base64url without padding
