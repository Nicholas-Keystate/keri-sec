# -*- encoding: utf-8 -*-
"""
TEL Bridge: connects TestExecutionCredential to real keripy ACDC issuance.

Maps application-layer TestExecutionCredential and PolicyCredential
to ACDC attributes/edges blocks, issues via proving.credential(),
and manages dedicated test attestation registries.

Pattern: replicates TurnAttestationDoer (ai-orchestrator) for test credentials.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from keri import kering
from keri.core import coring, eventing, serdering
from keri.core.coring import Diger, MtrDex, Saider, Seqner
from keri.core.eventing import SealEvent
from keri.vc import proving
from keri.vdr import credentialing

from keri_sec.testing.execution_credential import (
    TestExecutionCredential,
)
from keri_sec.testing.policies import PolicyCredential


# ---------------------------------------------------------------------------
# Schema SAIDs (computed after $id SAIDification)
# ---------------------------------------------------------------------------

# These will be set after loading schemas via Schemer.
# For now, placeholder — the Doer (Phase 3) loads these at enter().
TEST_EXECUTION_SCHEMA_SAID: Optional[str] = None
STALENESS_POLICY_SCHEMA_SAID: Optional[str] = None


def load_schema_said(schema_path: str) -> str:
    """Load a JSON schema and compute its SAID."""
    with open(schema_path, "r") as f:
        raw = f.read()
    ser = raw.encode("utf-8")
    return Diger(ser=ser, code=MtrDex.Blake3_256).qb64


# ---------------------------------------------------------------------------
# TestCredentialIssuer
# ---------------------------------------------------------------------------


class TestCredentialIssuer:
    """Builds ACDC attributes/edges and issues via proving.credential().

    Maps TestExecutionCredential (application layer) to ACDC structure
    (KERI layer) and calls proving.credential() with the correct parameters.

    Usage:
        issuer = TestCredentialIssuer(
            schema_said="ESchema...",
            policy_schema_said="EPolicy...",
        )
        attrs = issuer.build_acdc_attrs(cred)
        edges = issuer.build_acdc_edges(cred)
        creder = issuer.issue(hab, registry, cred)
    """

    def __init__(
        self,
        schema_said: str,
        policy_schema_said: Optional[str] = None,
    ):
        self._schema_said = schema_said
        self._policy_schema_said = policy_schema_said

    @property
    def schema_said(self) -> str:
        return self._schema_said

    @property
    def policy_schema_said(self) -> Optional[str]:
        return self._policy_schema_said

    def build_acdc_attrs(self, cred: TestExecutionCredential) -> dict:
        """Map TestExecutionCredential to ACDC attributes block.

        The ``d`` field is left as ``""`` for SAID computation by
        proving.credential().
        """
        attrs: Dict[str, Any] = {
            "d": "",
            "dt": cred.timestamp,
            "treeRootSaid": cred.tree_root_said,
            "results": {
                "total": cred.results.total,
                "passed": cred.results.passed,
                "failed": cred.results.failed,
                "skipped": cred.results.skipped,
            },
        }

        if cred.results.errors:
            attrs["results"]["errors"] = cred.results.errors
        if cred.results.duration_seconds:
            attrs["results"]["durationSeconds"] = cred.results.duration_seconds
        if cred.results.coverage_percent is not None:
            attrs["results"]["coveragePercent"] = cred.results.coverage_percent

        if cred.edges.test_suite_sn is not None:
            attrs["suiteSn"] = cred.edges.test_suite_sn

        if cred.runner_aid:
            attrs["runnerAid"] = cred.runner_aid

        return attrs

    def build_acdc_edges(self, cred: TestExecutionCredential) -> dict:
        """Map TestExecutionCredential to ACDC edges block.

        Each edge has ``n`` (node SAID) and ``s`` (schema SAID).
        The top-level ``d`` is ``""`` for SAID computation.
        """
        edges: Dict[str, Any] = {"d": ""}

        # Suite edge (always present)
        edges["suite"] = {
            "n": cred.edges.test_suite_gaid,
            "s": self._schema_said,
        }

        # Previous run edge (chain)
        if cred.edges.previous_run_said:
            edges["previousRun"] = {
                "n": cred.edges.previous_run_said,
                "s": self._schema_said,
            }

        # Code under test edge
        if cred.edges.code_under_test_said:
            edges["codeUnderTest"] = {
                "n": cred.edges.code_under_test_said,
                "s": self._schema_said,
            }

        # Runtime environment edge
        if cred.edges.runtime_env_said:
            edges["runtimeEnv"] = {
                "n": cred.edges.runtime_env_said,
                "s": self._schema_said,
            }

        return edges

    def issue(
        self,
        hab,
        registry,
        cred: TestExecutionCredential,
    ):
        """Issue a real ACDC credential via proving.credential().

        Args:
            hab: Issuer Hab (keripy habbing.Hab)
            registry: TEL Registry (keripy credentialing.Registry)
            cred: Application-layer credential

        Returns:
            Creder object with real SAID
        """
        attrs = self.build_acdc_attrs(cred)
        edges = self.build_acdc_edges(cred)

        creder = proving.credential(
            schema=self._schema_said,
            issuer=hab.pre,
            recipient=hab.pre,
            data=attrs,
            status=registry.regk,
            source=edges,
        )

        return creder

    def build_policy_attrs(self, policy: PolicyCredential) -> dict:
        """Map PolicyCredential to ACDC attributes block."""
        attrs: Dict[str, Any] = {
            "d": "",
            "dt": policy.timestamp if hasattr(policy, "timestamp") else datetime.now(timezone.utc).isoformat(),
            "policyType": policy.policy_type.value.lower(),
            "subtreePath": policy.subtree_path,
        }

        if hasattr(policy, "parameters") and policy.parameters:
            attrs["parameters"] = policy.parameters
        if hasattr(policy, "priority") and policy.priority is not None:
            attrs["priority"] = policy.priority
        if hasattr(policy, "description") and policy.description:
            attrs["description"] = policy.description

        return attrs

    def build_policy_edges(
        self,
        suite_gaid: str,
        previous_policy_said: Optional[str] = None,
    ) -> dict:
        """Map policy to ACDC edges block."""
        if self._policy_schema_said is None:
            raise ValueError("policy_schema_said required for policy issuance")

        edges: Dict[str, Any] = {"d": ""}

        edges["suite"] = {
            "n": suite_gaid,
            "s": self._policy_schema_said,
        }

        if previous_policy_said:
            edges["previousPolicy"] = {
                "n": previous_policy_said,
                "s": self._policy_schema_said,
            }

        return edges

    def issue_policy(
        self,
        hab,
        registry,
        policy: PolicyCredential,
        suite_gaid: str,
        previous_policy_said: Optional[str] = None,
    ):
        """Issue a real ACDC policy credential.

        Returns:
            Creder object with real SAID
        """
        if self._policy_schema_said is None:
            raise ValueError("policy_schema_said required for policy issuance")

        attrs = self.build_policy_attrs(policy)
        edges = self.build_policy_edges(suite_gaid, previous_policy_said)

        creder = proving.credential(
            schema=self._policy_schema_said,
            issuer=hab.pre,
            recipient=hab.pre,
            data=attrs,
            status=registry.regk,
            source=edges,
        )

        return creder


# ---------------------------------------------------------------------------
# TestRegistryManager
# ---------------------------------------------------------------------------


class TestRegistryManager:
    """Manages dedicated TEL registries for test attestation.

    Creates one registry per issuer AID, named
    ``test-attestation-{aid[:12]}-registry``.

    The registry inception (VCP) is anchored in the issuer's KEL
    via an interaction event.
    """

    def __init__(self, rgy: credentialing.Regery):
        self._rgy = rgy
        self._cache: Dict[str, Any] = {}  # aid_prefix -> registry

    @property
    def rgy(self) -> credentialing.Regery:
        return self._rgy

    def get_or_create(self, issuer_hab) -> Any:
        """Get or create a dedicated test attestation registry.

        Args:
            issuer_hab: Issuer Hab (keripy habbing.Hab)

        Returns:
            Registry object
        """
        aid = issuer_hab.pre
        if aid in self._cache:
            return self._cache[aid]

        registry_name = f"test-attestation-{aid[:12]}-registry"

        registry = self._rgy.makeRegistry(
            name=registry_name,
            prefix=aid,
            noBackers=True,
        )

        # Anchor VCP inception in issuer's KEL
        rseal = SealEvent(registry.regk, "0", registry.regd)
        rseal_dict = dict(i=rseal.i, s=rseal.s, d=rseal.d)
        issuer_hab.interact(data=[rseal_dict])

        # Process escrows to complete VCP lifecycle
        self._rgy.processEscrows()

        self._cache[aid] = registry
        return registry


# ---------------------------------------------------------------------------
# TEL anchoring helpers
# ---------------------------------------------------------------------------


def anchor_credential(hab, registry, creder_said: str, dt: Optional[str] = None):
    """Full TEL anchoring pipeline for a credential.

    Steps:
        1. Create ISS event in TEL
        2. Anchor in issuer's KEL via interaction seal
        3. Extract anchor info (seqner, saider)
        4. Record anchor in registry
        5. Process escrows

    Args:
        hab: Issuer Hab
        registry: TEL Registry
        creder_said: Credential SAID to anchor
        dt: Optional timestamp override

    Returns:
        Tuple of (iss_serder, seqner, saider)
    """
    if dt is None:
        dt = datetime.now(timezone.utc).isoformat()

    # Step 1: Create ISS event
    iss = registry.issue(said=creder_said, dt=dt)

    # Step 2: Anchor in KEL
    seal = SealEvent(iss.pre, "0", iss.said)
    seal_dict = dict(i=seal.i, s=seal.s, d=seal.d)
    hab.interact(data=[seal_dict])

    # Step 3: Extract anchor info
    seqner = Seqner(sn=hab.kever.sner.num)
    saider = Saider(qb64=hab.kever.serder.said)

    # Step 4: Record anchor
    registry.anchorMsg(
        pre=iss.pre,
        regd=iss.said,
        seqner=seqner,
        saider=saider,
    )

    return iss, seqner, saider


def anchor_tel_event(hab, registry, tel_serder):
    """Process a TEL event to populate reger.tevers.

    Used in tests to complete the TEL event lifecycle that
    normally happens via keripy's event processing.

    Args:
        hab: Issuer Hab
        registry: TEL Registry (has .tvy for TEL event processing)
        tel_serder: TEL event serder (VCP, ISS, etc.)

    Returns:
        Anchor KEL event bytes
    """
    rseal = SealEvent(tel_serder.pre, tel_serder.snh, tel_serder.said)
    anc = hab.interact(data=[dict(i=rseal.i, s=rseal.s, d=rseal.d)])

    anc_serder = serdering.SerderKERI(raw=bytes(anc))
    seqner = Seqner(sn=int(anc_serder.ked["s"], 16))
    saider = Saider(qb64=anc_serder.said)

    registry.tvy.processEvent(serder=tel_serder, seqner=seqner, saider=saider)

    return anc
