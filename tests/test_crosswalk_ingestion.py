# -*- encoding: utf-8 -*-
"""
Tests for crosswalk ingestion module.

Tests W3C VC to ACDC ingestion.
"""

import pytest

from keri_sec.crosswalk.loa_mapping import LoALevel, StrengthLevel
from keri_sec.crosswalk.ingest_w3c_vc import (
    ingest_w3c_vc,
    ingest_w3c_vc_from_dict,
    IngestionWarning,
    ACDCFromVC,
    IngestionResult,
)


@pytest.fixture
def sample_w3c_vc():
    """Sample W3C VC for testing."""
    return {
        "@context": [
            "https://www.w3.org/ns/credentials/v2",
        ],
        "id": "urn:said:ESAID1234567890ABCDEF",
        "type": ["VerifiableCredential"],
        "issuer": "did:keri:EAID_ISSUER_123456789",
        "validFrom": "2026-01-28T00:00:00Z",
        "credentialSubject": {
            "id": "did:keri:ESUBJECT_AID_123",
            "name": "Test Organization",
            "LEI": "5493001KJTIIGC8Y1R12",
        },
        "credentialSchema": {
            "id": "urn:said:ESCHEMA_123456789",
            "type": "JsonSchema",
        },
        "termsOfUse": [
            {
                "type": "GovernanceFramework",
                "url": "https://governance.example.com/framework",
            }
        ],
    }


@pytest.fixture
def minimal_w3c_vc():
    """Minimal W3C VC with just required fields."""
    return {
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "type": ["VerifiableCredential"],
        "issuer": "https://issuer.example.com",
        "credentialSubject": {
            "name": "Minimal Test",
        },
    }


class TestIngestW3CVC:
    """Tests for W3C VC ingestion."""

    def test_ingest_success(self, sample_w3c_vc):
        """Test successful ingestion."""
        result = ingest_w3c_vc(sample_w3c_vc)
        assert result.success
        assert result.acdc is not None

    def test_said_extracted_from_urn(self, sample_w3c_vc):
        """Test SAID is extracted from urn:said: id."""
        result = ingest_w3c_vc(sample_w3c_vc)
        assert result.acdc.d == "ESAID1234567890ABCDEF"

    def test_said_generated_for_non_urn_id(self, minimal_w3c_vc):
        """Test SAID is generated when id is not urn:said:."""
        minimal_w3c_vc["id"] = "https://example.com/credential/123"
        result = ingest_w3c_vc(minimal_w3c_vc)
        assert result.acdc.d.startswith("E")  # SAID-like prefix

    def test_said_generated_for_missing_id(self, minimal_w3c_vc):
        """Test SAID is generated when id is missing."""
        result = ingest_w3c_vc(minimal_w3c_vc)
        assert result.acdc.d.startswith("E")

    def test_issuer_extracted_from_did_keri(self, sample_w3c_vc):
        """Test issuer AID extracted from did:keri:."""
        result = ingest_w3c_vc(sample_w3c_vc)
        assert result.acdc.i == "EAID_ISSUER_123456789"

    def test_issuer_warning_for_non_keri_did(self, minimal_w3c_vc):
        """Test warning for non-KERI DID issuer."""
        minimal_w3c_vc["issuer"] = "did:web:example.com"
        result = ingest_w3c_vc(minimal_w3c_vc)
        warnings = [w for w in result.warnings if w.warning_type == "non_keri_did"]
        assert len(warnings) > 0

    def test_issuer_override(self, sample_w3c_vc):
        """Test issuer AID can be overridden."""
        result = ingest_w3c_vc(sample_w3c_vc, issuer_aid="EOVERRIDE_AID_123")
        assert result.acdc.i == "EOVERRIDE_AID_123"

    def test_schema_extracted_from_urn(self, sample_w3c_vc):
        """Test schema SAID extracted from urn:said:."""
        result = ingest_w3c_vc(sample_w3c_vc)
        assert result.acdc.s == "ESCHEMA_123456789"

    def test_schema_override(self, sample_w3c_vc):
        """Test schema SAID can be overridden."""
        result = ingest_w3c_vc(sample_w3c_vc, schema_said="EOVERRIDE_SCHEMA_123")
        assert result.acdc.s == "EOVERRIDE_SCHEMA_123"

    def test_attributes_mapped(self, sample_w3c_vc):
        """Test credentialSubject maps to attributes."""
        result = ingest_w3c_vc(sample_w3c_vc)
        assert result.acdc.a["name"] == "Test Organization"
        assert result.acdc.a["LEI"] == "5493001KJTIIGC8Y1R12"

    def test_subject_id_maps_to_attribute_i(self, sample_w3c_vc):
        """Test subject id maps to attribute 'i'."""
        result = ingest_w3c_vc(sample_w3c_vc)
        assert result.acdc.a["i"] == "ESUBJECT_AID_123"

    def test_terms_of_use_maps_to_rules(self, sample_w3c_vc):
        """Test termsOfUse maps to rules section."""
        result = ingest_w3c_vc(sample_w3c_vc)
        assert "framework" in result.acdc.r
        assert result.acdc.r["framework"] == "https://governance.example.com/framework"

    def test_edge_section_empty(self, sample_w3c_vc):
        """Test edge section is empty (cannot be recovered)."""
        result = ingest_w3c_vc(sample_w3c_vc)
        assert result.acdc.e == {} or not result.acdc.e

    def test_inferred_loa_is_zero(self, sample_w3c_vc):
        """Test inferred LoA is always 0 for ingested credentials."""
        result = ingest_w3c_vc(sample_w3c_vc)
        assert result.inferred_loa == LoALevel.LOA_0

    def test_inferred_strength_is_any(self, sample_w3c_vc):
        """Test inferred strength is always ANY for ingested credentials."""
        result = ingest_w3c_vc(sample_w3c_vc)
        assert result.inferred_strength == StrengthLevel.ANY

    def test_warnings_generated(self, sample_w3c_vc):
        """Test warnings are generated."""
        result = ingest_w3c_vc(sample_w3c_vc)
        assert len(result.warnings) > 0

    def test_ingestion_limitation_warning(self, sample_w3c_vc):
        """Test ingestion limitation warning is present."""
        result = ingest_w3c_vc(sample_w3c_vc)
        warnings = [w for w in result.warnings if w.warning_type == "ingestion_limitation"]
        assert len(warnings) > 0

    def test_no_edges_warning(self, sample_w3c_vc):
        """Test no edges warning is present."""
        result = ingest_w3c_vc(sample_w3c_vc)
        warnings = [w for w in result.warnings if w.warning_type == "no_edges"]
        assert len(warnings) > 0


class TestIngestionEdgeCases:
    """Tests for ingestion edge cases."""

    def test_multi_subject_vc(self, sample_w3c_vc):
        """Test multi-subject VC uses first subject."""
        sample_w3c_vc["credentialSubject"] = [
            {"name": "First Subject"},
            {"name": "Second Subject"},
        ]
        result = ingest_w3c_vc(sample_w3c_vc)
        assert result.acdc.a["name"] == "First Subject"
        warnings = [w for w in result.warnings if w.warning_type == "multi_subject"]
        assert len(warnings) > 0

    def test_issuer_as_object(self, minimal_w3c_vc):
        """Test issuer as object with id."""
        minimal_w3c_vc["issuer"] = {
            "id": "did:keri:EAID_OBJECT_123",
            "name": "Issuer Name",
        }
        result = ingest_w3c_vc(minimal_w3c_vc)
        assert result.acdc.i == "EAID_OBJECT_123"

    def test_missing_credential_subject(self, minimal_w3c_vc):
        """Test missing credentialSubject generates warning."""
        del minimal_w3c_vc["credentialSubject"]
        result = ingest_w3c_vc(minimal_w3c_vc)
        warnings = [w for w in result.warnings if w.warning_type == "missing_subject"]
        assert len(warnings) > 0

    def test_missing_issuer(self, minimal_w3c_vc):
        """Test missing issuer generates warning."""
        del minimal_w3c_vc["issuer"]
        result = ingest_w3c_vc(minimal_w3c_vc)
        warnings = [w for w in result.warnings if w.warning_type == "missing_issuer"]
        assert len(warnings) > 0

    def test_registry_id_set(self, sample_w3c_vc):
        """Test registry ID can be set."""
        result = ingest_w3c_vc(sample_w3c_vc, registry_id="EREGISTRY_123")
        assert result.acdc.ri == "EREGISTRY_123"

    def test_credential_status_warning(self, sample_w3c_vc):
        """Test credentialStatus generates warning."""
        sample_w3c_vc["credentialStatus"] = {
            "id": "https://example.com/status/123",
            "type": "StatusList2021Entry",
        }
        result = ingest_w3c_vc(sample_w3c_vc)
        warnings = [w for w in result.warnings if w.warning_type == "status_not_preserved"]
        assert len(warnings) > 0


class TestIngestionSerialization:
    """Tests for ingestion result serialization."""

    def test_acdc_to_dict(self, sample_w3c_vc):
        """Test ACDC serializes to dict."""
        result = ingest_w3c_vc(sample_w3c_vc)
        acdc_dict = result.acdc.to_dict()
        assert "v" in acdc_dict
        assert "d" in acdc_dict
        assert "i" in acdc_dict
        assert "a" in acdc_dict

    def test_result_to_dict(self, sample_w3c_vc):
        """Test result serializes to dict."""
        result = ingest_w3c_vc(sample_w3c_vc)
        d = result.to_dict()
        assert "acdc" in d
        assert "warnings" in d
        assert "inferred_loa" in d
        assert "success" in d

    def test_dict_convenience_function(self, sample_w3c_vc):
        """Test ingest_w3c_vc_from_dict returns dict."""
        result = ingest_w3c_vc_from_dict(sample_w3c_vc)
        assert isinstance(result, dict)
        assert "acdc" in result


class TestIngestionWarning:
    """Tests for IngestionWarning dataclass."""

    def test_warning_creation(self):
        """Test warning creation."""
        warning = IngestionWarning(
            field="issuer",
            warning_type="non_keri_did",
            message="Test message",
            value_used="did:web:example.com",
        )
        assert warning.field == "issuer"
        assert warning.warning_type == "non_keri_did"
        assert warning.value_used == "did:web:example.com"
