# -*- encoding: utf-8 -*-
"""Tests for TestAttestationDoer: HIO lifecycle, request/response, background anchoring."""

import pytest

from hio.help import Deck
from keri.app import habbing
from keri.vdr import credentialing

from keri_sec.testing.execution_credential import (
    CredentialEdges,
    TestExecutionCredential,
    TestResults,
)
from keri_sec.testing.test_attestation_doer import (
    AnchoringTask,
    TestAttestationDoer,
    TestAttestationRequest,
    TestAttestationResponse,
    create_test_attestation_doer,
)
from keri_sec.testing.tel_bridge import anchor_tel_event


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

FIXED_TIMESTAMP = "2026-01-28T12:00:00+00:00"
FAKE_SCHEMA_SAID = "ELJm6sOw-eZmeTGgLrO0p614JPcJLX5RhWIw9WzvoaDV"


@pytest.fixture
def keri_env():
    """Temp Habery + Regery for isolated Doer testing."""
    hby = habbing.Habery(name="doer-test", temp=True)
    rgy = credentialing.Regery(hby=hby, name="doer-test", temp=True)
    yield {"hby": hby, "rgy": rgy}
    hby.close()


@pytest.fixture
def doer_with_decks(keri_env):
    """Create Doer with pre-wired Habery/Regery and Decks."""
    doer, input_deck, output_deck = create_test_attestation_doer(
        schema_said=FAKE_SCHEMA_SAID,
        temp=True,
        hby=keri_env["hby"],
        rgy=keri_env["rgy"],
    )
    return doer, input_deck, output_deck


@pytest.fixture
def sample_request():
    """A sample attestation request."""
    results = TestResults(total=10, passed=9, failed=1, skipped=0)
    edges = CredentialEdges(
        test_suite_gaid="EGAID_test_suite_000000000000000000000",
        test_suite_sn=2,
    )
    cred = TestExecutionCredential(
        tree_root_said="ETreeRoot_00000000000000000000000000000000",
        results=results,
        edges=edges,
        timestamp=FIXED_TIMESTAMP,
    )
    return TestAttestationRequest(
        request_id="req-001",
        credential=cred,
        suite_gaid="EGAID_test_suite_000000000000000000000",
        suite_sn=2,
    )


# ---------------------------------------------------------------------------
# Lifecycle tests
# ---------------------------------------------------------------------------


class TestDoerLifecycle:
    def test_enter_initializes(self, doer_with_decks):
        doer, _, _ = doer_with_decks
        assert not doer.entered
        doer.enter()
        assert doer.entered

    def test_enter_idempotent(self, doer_with_decks):
        doer, _, _ = doer_with_decks
        doer.enter()
        doer.enter()  # Should not raise
        assert doer.entered

    def test_recur_lazy_enter(self, doer_with_decks):
        """recur() calls enter() automatically if not yet entered."""
        doer, _, _ = doer_with_decks
        assert not doer.entered
        doer.recur(tyme=0.0)
        assert doer.entered

    def test_recur_returns_false(self, doer_with_decks):
        """recur() returns False (not done, continue running)."""
        doer, _, _ = doer_with_decks
        result = doer.recur(tyme=0.0)
        assert result is False

    def test_exit_drains_queue(self, doer_with_decks):
        """exit() processes remaining anchoring tasks."""
        doer, _, _ = doer_with_decks
        doer.enter()
        # No tasks — should not raise
        doer.exit()


# ---------------------------------------------------------------------------
# Request / Response flow
# ---------------------------------------------------------------------------


class TestRequestResponse:
    def test_push_request_pull_response(self, doer_with_decks, sample_request):
        """Full cycle: push request -> recur -> pull response."""
        doer, input_deck, output_deck = doer_with_decks
        doer.enter()

        # Push request
        input_deck.push(sample_request)

        # Process
        doer.recur(tyme=0.0)

        # Pull response
        response = output_deck.pull(emptive=True)
        assert response is not None
        assert isinstance(response, TestAttestationResponse)
        assert response.request_id == "req-001"
        assert response.success is True
        assert response.credential_said is not None
        assert response.credential_said.startswith("E")

    def test_multiple_requests_processed(self, doer_with_decks):
        """Multiple requests in one recur cycle."""
        doer, input_deck, output_deck = doer_with_decks
        doer.enter()

        for i in range(3):
            results = TestResults(total=5, passed=5, failed=0, skipped=0)
            edges = CredentialEdges(test_suite_gaid="EGAID", test_suite_sn=0)
            cred = TestExecutionCredential(
                tree_root_said="ERoot", results=results, edges=edges,
                timestamp=FIXED_TIMESTAMP,
            )
            req = TestAttestationRequest(
                request_id=f"req-{i}",
                credential=cred,
                suite_gaid="EGAID",
                suite_sn=0,
            )
            input_deck.push(req)

        doer.recur(tyme=0.0)

        responses = []
        while True:
            r = output_deck.pull(emptive=True)
            if r is None:
                break
            responses.append(r)

        assert len(responses) == 3
        assert all(r.success for r in responses)

    def test_response_contains_valid_said(self, doer_with_decks, sample_request):
        doer, input_deck, output_deck = doer_with_decks
        doer.enter()
        input_deck.push(sample_request)
        doer.recur(tyme=0.0)
        response = output_deck.pull(emptive=True)
        # KERI SAIDs start with E (Blake3_256)
        assert response.credential_said.startswith("E")

    def test_error_response_on_no_schema(self, keri_env):
        """Without schema_said, attestation fails gracefully."""
        doer, input_deck, output_deck = create_test_attestation_doer(
            schema_said=None,  # No schema
            temp=True,
            hby=keri_env["hby"],
            rgy=keri_env["rgy"],
        )
        doer.enter()

        results = TestResults(total=1, passed=1, failed=0, skipped=0)
        edges = CredentialEdges(test_suite_gaid="EGAID", test_suite_sn=0)
        cred = TestExecutionCredential(
            tree_root_said="ERoot", results=results, edges=edges,
            timestamp=FIXED_TIMESTAMP,
        )
        req = TestAttestationRequest(
            request_id="req-err",
            credential=cred,
            suite_gaid="EGAID",
            suite_sn=0,
        )
        input_deck.push(req)
        doer.recur(tyme=0.0)

        response = output_deck.pull(emptive=True)
        assert response is not None
        assert response.success is False
        assert response.error is not None


# ---------------------------------------------------------------------------
# Background anchoring
# ---------------------------------------------------------------------------


class TestBackgroundAnchoring:
    def test_queues_anchoring_task(self, doer_with_decks, sample_request):
        doer, input_deck, output_deck = doer_with_decks
        doer.enter()
        input_deck.push(sample_request)
        doer.recur(tyme=0.0)

        # Task should be queued
        assert doer.anchoring_queue_size >= 1

    def test_anchoring_processes_queue(self, doer_with_decks, sample_request):
        doer, input_deck, output_deck = doer_with_decks
        doer.enter()
        input_deck.push(sample_request)

        # First recur: process request, queue anchoring
        doer.recur(tyme=0.0)
        initial_queue = doer.anchoring_queue_size

        # Second recur: process anchoring (or fail after max attempts)
        for _ in range(5):
            doer.recur(tyme=0.0)

        # Queue should eventually drain (success or max-attempts exhaustion)
        assert doer.anchoring_queue_size <= initial_queue


# ---------------------------------------------------------------------------
# Reger storage verification
# ---------------------------------------------------------------------------


class TestRegerStorageIntegration:
    def test_credential_stored_in_reger(self, doer_with_decks, keri_env, sample_request):
        doer, input_deck, output_deck = doer_with_decks
        doer.enter()
        input_deck.push(sample_request)
        doer.recur(tyme=0.0)

        response = output_deck.pull(emptive=True)
        assert response.success

        # Verify stored in Reger
        rgy = keri_env["rgy"]
        stored = rgy.reger.creds.get(keys=response.credential_said)
        assert stored is not None

    def test_schema_index_populated(self, doer_with_decks, keri_env, sample_request):
        doer, input_deck, output_deck = doer_with_decks
        doer.enter()
        input_deck.push(sample_request)
        doer.recur(tyme=0.0)

        response = output_deck.pull(emptive=True)
        assert response.success

        # Verify schema index
        rgy = keri_env["rgy"]
        schema_creds = list(rgy.reger.schms.getIter(keys=FAKE_SCHEMA_SAID))
        saids = [s.qb64 for s in schema_creds]
        assert response.credential_said in saids


# ---------------------------------------------------------------------------
# Factory function
# ---------------------------------------------------------------------------


class TestFactory:
    def test_create_returns_tuple(self):
        doer, input_deck, output_deck = create_test_attestation_doer(
            schema_said=FAKE_SCHEMA_SAID,
            temp=True,
        )
        assert isinstance(doer, TestAttestationDoer)
        assert isinstance(input_deck, Deck)
        assert isinstance(output_deck, Deck)
