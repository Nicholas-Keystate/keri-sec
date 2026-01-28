# -*- encoding: utf-8 -*-
"""
TestAttestationDoer: HIO Doer for background TEL anchoring of test credentials.

Pattern: replicates TurnAttestationDoer (ai-orchestrator) lifecycle:
- Fast-path: proving.credential() -> store in Reger -> push SAID response
- Background: TEL anchoring via registry.issue() -> hab.interact() -> anchorMsg()

HIO Architecture:
- Extends DoDoer for lifecycle management
- Uses input/output Decks for request/response flow
- Background anchoring queue processed in recur() cycle
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from hio.base import DoDoer
from hio.help import Deck

from keri.app import habbing
from keri.core import coring, eventing
from keri.vc import proving
from keri.vdr import credentialing

from keri_sec.testing.execution_credential import TestExecutionCredential
from keri_sec.testing.reger_storage import store_in_reger
from keri_sec.testing.tel_bridge import (
    TestCredentialIssuer,
    TestRegistryManager,
    anchor_credential,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Request / Response types
# ---------------------------------------------------------------------------


@dataclass
class TestAttestationRequest:
    """Request to attest a test execution."""
    request_id: str
    credential: TestExecutionCredential
    suite_gaid: str
    suite_sn: int


@dataclass
class TestAttestationResponse:
    """Response from test attestation."""
    request_id: str
    success: bool
    credential_said: Optional[str] = None
    tel_anchored: bool = False
    error: Optional[str] = None


@dataclass
class AnchoringTask:
    """Task for background TEL anchoring."""
    credential_said: str
    issuer_aid: str
    dt: str
    attempts: int = 0
    max_attempts: int = 3


# ---------------------------------------------------------------------------
# TestAttestationDoer
# ---------------------------------------------------------------------------


class TestAttestationDoer(DoDoer):
    """Background TEL anchoring for test execution credentials.

    Fast-path flow:
        1. Pull TestAttestationRequest from input_deck
        2. Build ACDC via TestCredentialIssuer
        3. Store in Reger (critical for KGQL)
        4. Push TestAttestationResponse with SAID
        5. Queue AnchoringTask for background

    Background flow (recur cycle):
        1. Pop one AnchoringTask
        2. registry.issue(said, dt) -> hab.interact(seal) -> anchorMsg()
        3. rgy.processEscrows()
    """

    def __init__(
        self,
        input_deck: Deck,
        output_deck: Deck,
        hby: Optional[habbing.Habery] = None,
        rgy: Optional[credentialing.Regery] = None,
        schema_said: Optional[str] = None,
        policy_schema_said: Optional[str] = None,
        temp: bool = False,
        **kwa,
    ):
        super().__init__(doers=[], **kwa)

        self.input_deck = input_deck
        self.output_deck = output_deck
        self._temp = temp

        # Infrastructure (set in enter() or passed directly for testing)
        self._hby = hby
        self._rgy = rgy
        self._schema_said = schema_said
        self._policy_schema_said = policy_schema_said

        # Components (initialized in enter())
        self._issuer: Optional[TestCredentialIssuer] = None
        self._registry_mgr: Optional[TestRegistryManager] = None

        # Background anchoring queue
        self._anchoring_queue: List[AnchoringTask] = []

        # Lifecycle state
        self._entered = False

    def enter(self, **kwa):
        """Initialize resources on Doer start."""
        if self._entered:
            return

        # Create Habery/Regery if not provided (non-test mode)
        if self._hby is None:
            self._hby = habbing.Habery(
                name="test-attestation",
                temp=self._temp,
            )
        if self._rgy is None:
            self._rgy = credentialing.Regery(
                hby=self._hby,
                name="test-attestation",
                temp=self._temp,
            )

        # Initialize components
        if self._schema_said:
            self._issuer = TestCredentialIssuer(
                schema_said=self._schema_said,
                policy_schema_said=self._policy_schema_said,
            )
        self._registry_mgr = TestRegistryManager(self._rgy)

        self._entered = True
        logger.info("TestAttestationDoer initialized")

    def recur(self, tyme):
        """Process attestation requests and background anchoring."""
        if not self._entered:
            self.enter()

        # Fast path: process attestation requests
        requests_processed = 0
        while True:
            req = self.input_deck.pull(emptive=True)
            if req is None:
                break

            if isinstance(req, TestAttestationRequest):
                response = self._attest(req)
                self.output_deck.push(response)
                requests_processed += 1

        # Background: process anchoring queue (one per cycle)
        self._process_anchoring_queue()

        if requests_processed > 0:
            logger.debug(f"Processed {requests_processed} test attestation requests")

        return False  # Not done, continue running

    def exit(self):
        """Clean up on normal exit."""
        # Drain remaining anchoring tasks
        while self._anchoring_queue:
            self._process_anchoring_queue()
        logger.debug("TestAttestationDoer exiting")

    def abort(self, ex):
        """Handle exception."""
        logger.error(f"TestAttestationDoer aborting: {type(ex).__name__}: {ex}")

    # -----------------------------------------------------------------------
    # Fast-path attestation
    # -----------------------------------------------------------------------

    def _attest(self, req: TestAttestationRequest) -> TestAttestationResponse:
        """Attest a test execution with minimal latency.

        Returns SAID immediately, queues TEL anchoring for background.
        """
        try:
            if self._issuer is None:
                raise RuntimeError("TestCredentialIssuer not initialized (no schema_said)")

            # Get or create issuer Hab
            hab = self._get_or_create_hab(req.suite_gaid)

            # Get or create registry
            registry = self._registry_mgr.get_or_create(hab)

            # Build and issue ACDC credential
            creder = self._issuer.issue(hab, registry, req.credential)

            # Store in Reger (critical for KGQL queryability)
            store_in_reger(
                self._rgy,
                creder,
                hab.pre,
                self._schema_said,
            )

            # Queue background TEL anchoring
            dt = req.credential.timestamp
            self._anchoring_queue.append(AnchoringTask(
                credential_said=creder.said,
                issuer_aid=hab.pre,
                dt=dt,
            ))

            return TestAttestationResponse(
                request_id=req.request_id,
                success=True,
                credential_said=creder.said,
            )

        except Exception as e:
            logger.error(f"Test attestation failed: {type(e).__name__}: {e}")
            return TestAttestationResponse(
                request_id=req.request_id,
                success=False,
                error=str(e),
            )

    def _get_or_create_hab(self, name_hint: str) -> habbing.Hab:
        """Get or create a Hab for test attestation issuance."""
        hab_name = f"test-attest-{name_hint[:12]}"
        hab = self._hby.habByName(hab_name)
        if hab is None:
            hab = self._hby.makeHab(name=hab_name, transferable=True)
        return hab

    # -----------------------------------------------------------------------
    # Background anchoring
    # -----------------------------------------------------------------------

    def _process_anchoring_queue(self):
        """Process one background TEL anchoring task per cycle."""
        if not self._anchoring_queue:
            return

        task = self._anchoring_queue[0]
        task.attempts += 1

        try:
            # Get the hab for this AID
            hab = self._hby.habByPre(task.issuer_aid)
            if hab is None:
                raise RuntimeError(f"No Hab found for AID {task.issuer_aid}")

            # Get registry
            registry = self._registry_mgr.get_or_create(hab)

            # Full TEL anchoring pipeline
            anchor_credential(hab, registry, task.credential_said, dt=task.dt)

            # Process escrows
            self._rgy.processEscrows()

            # Success — remove from queue
            self._anchoring_queue.pop(0)
            logger.debug(f"TEL anchored credential {task.credential_said[:16]}...")

        except Exception as e:
            logger.error(
                f"TEL anchoring attempt {task.attempts}/{task.max_attempts} "
                f"for {task.credential_said[:16]}...: {type(e).__name__}: {e}"
            )
            if task.attempts >= task.max_attempts:
                self._anchoring_queue.pop(0)
                logger.error(f"Abandoned TEL anchoring for {task.credential_said[:16]}...")

    # -----------------------------------------------------------------------
    # Properties
    # -----------------------------------------------------------------------

    @property
    def anchoring_queue_size(self) -> int:
        return len(self._anchoring_queue)

    @property
    def entered(self) -> bool:
        return self._entered


# ---------------------------------------------------------------------------
# Factory function
# ---------------------------------------------------------------------------


def create_test_attestation_doer(
    schema_said: Optional[str] = None,
    policy_schema_said: Optional[str] = None,
    temp: bool = False,
    hby: Optional[habbing.Habery] = None,
    rgy: Optional[credentialing.Regery] = None,
):
    """Create a TestAttestationDoer with input/output Decks.

    Returns:
        Tuple of (doer, input_deck, output_deck)
    """
    input_deck = Deck()
    output_deck = Deck()

    doer = TestAttestationDoer(
        input_deck=input_deck,
        output_deck=output_deck,
        hby=hby,
        rgy=rgy,
        schema_said=schema_said,
        policy_schema_said=policy_schema_said,
        temp=temp,
    )

    return doer, input_deck, output_deck
