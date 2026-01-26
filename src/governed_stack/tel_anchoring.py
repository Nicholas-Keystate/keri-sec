# -*- encoding: utf-8 -*-
"""
TEL Anchoring for Governed Stacks.

Provides cryptographic attestation of stack definitions via KERI TEL.
Without TEL anchoring, stack SAIDs are just computed hashes.
With TEL anchoring, they become verifiable credentials.

Requirements:
- Master AID (issuer) with access to a registry
- Registry for TEL events
- Schema SAIDs registered

Usage:
    from governed_stack.tel_anchoring import StackCredentialIssuer

    issuer = StackCredentialIssuer(hab=master_hab, registry=registry)
    cred_said = issuer.issue_stack_credential(stack)
"""

import json
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from keri.core import coring
from keri.core.coring import Saider, MtrDex

logger = logging.getLogger(__name__)

# Schema SAIDs (placeholder - compute actual SAIDs on first use)
STACK_SCHEMA_SAID = "EStack_Cred_Schema________________________"
WORKSPACE_SCHEMA_SAID = "EWorkspace_Schema_________________________"


@dataclass
class CredentialIssuanceResult:
    """Result of issuing a credential."""
    success: bool
    credential_said: Optional[str]
    registry_said: Optional[str]
    error: Optional[str] = None


def compute_schema_said(schema_path: Path) -> str:
    """Compute SAID for a schema file."""
    content = schema_path.read_text()
    schema = json.loads(content)

    # Remove $id to compute SAID of content
    schema_copy = schema.copy()
    schema_copy["$id"] = ""

    ser = json.dumps(schema_copy, sort_keys=True, separators=(",", ":")).encode("utf-8")
    saider = Saider(sad=schema_copy, code=MtrDex.Blake3_256, label="$id")

    return saider.qb64


class StackCredentialIssuer:
    """
    Issues TEL-anchored credentials for governed stacks.

    This connects governed-stack to real KERI infrastructure.
    """

    def __init__(
        self,
        hab: Optional[Any] = None,
        registry: Optional[Any] = None,
        schemas_path: Optional[Path] = None,
    ):
        """
        Initialize issuer.

        Args:
            hab: KERI Habitat (signing identity)
            registry: KERI Registry for TEL
            schemas_path: Path to schema files (default: ./schemas/)
        """
        self.hab = hab
        self.registry = registry
        self.schemas_path = schemas_path or Path(__file__).parent.parent.parent / "schemas"

        # Cache schema SAIDs
        self._schema_saids: Dict[str, str] = {}

    def _get_schema_said(self, schema_name: str) -> str:
        """Get or compute schema SAID."""
        if schema_name not in self._schema_saids:
            schema_file = self.schemas_path / f"{schema_name}.json"
            if schema_file.exists():
                self._schema_saids[schema_name] = compute_schema_said(schema_file)
            else:
                # Use placeholder
                if schema_name == "stack_credential":
                    self._schema_saids[schema_name] = STACK_SCHEMA_SAID
                elif schema_name == "workspace_credential":
                    self._schema_saids[schema_name] = WORKSPACE_SCHEMA_SAID
                else:
                    raise ValueError(f"Unknown schema: {schema_name}")

        return self._schema_saids[schema_name]

    def can_issue(self) -> Tuple[bool, str]:
        """Check if we can issue credentials."""
        if not self.hab:
            return False, "No Habitat (signing identity) configured"
        if not self.registry:
            return False, "No Registry (TEL) configured"
        return True, "Ready to issue"

    def issue_stack_credential(
        self,
        stack_name: str,
        stack_said: str,
        constraints: Dict[str, str],
        rationale: str = "",
        workspace_cred_said: Optional[str] = None,
        previous_cred_said: Optional[str] = None,
    ) -> CredentialIssuanceResult:
        """
        Issue a TEL-anchored credential for a stack.

        Args:
            stack_name: Human-readable stack name
            stack_said: Computed SAID of constraint set
            constraints: Package -> version spec mapping
            rationale: Why these constraints
            workspace_cred_said: Optional edge to workspace credential
            previous_cred_said: Optional edge to previous version

        Returns:
            CredentialIssuanceResult with credential SAID or error
        """
        can, reason = self.can_issue()
        if not can:
            return CredentialIssuanceResult(
                success=False,
                credential_said=None,
                registry_said=None,
                error=reason,
            )

        try:
            # Build attributes
            attrs = {
                "dt": datetime.now(timezone.utc).isoformat(),
                "name": stack_name,
                "stackSaid": stack_said,
                "constraints": constraints,
                "constraintCount": len(constraints),
                "rationale": rationale,
            }

            # Build edges
            edges = {}
            if workspace_cred_said:
                edges["workspace"] = {
                    "d": workspace_cred_said,
                    "s": self._get_schema_said("workspace_credential"),
                }
            if previous_cred_said:
                edges["previousVersion"] = {
                    "d": previous_cred_said,
                    "s": self._get_schema_said("stack_credential"),
                }

            # Issue credential
            schema_said = self._get_schema_said("stack_credential")

            # Use keri.vc.proving.credential() for proper ACDC structure
            from keri.vc import proving

            creder = proving.credential(
                issuer=self.hab.pre,
                schema=schema_said,
                data=attrs,
                status=self.registry.regk,
                source=edges if edges else None,
            )

            # Anchor to TEL
            self.registry.issue(creder=creder)

            logger.info(f"Issued stack credential: {creder.said}")

            return CredentialIssuanceResult(
                success=True,
                credential_said=creder.said,
                registry_said=self.registry.regk,
            )

        except Exception as e:
            logger.error(f"Failed to issue credential: {e}")
            return CredentialIssuanceResult(
                success=False,
                credential_said=None,
                registry_said=None,
                error=str(e),
            )

    def issue_workspace_credential(
        self,
        workspace_name: str,
        workspace_said: str,
        unified_constraints: Dict[str, str],
        project_saids: List[str],
    ) -> CredentialIssuanceResult:
        """
        Issue a TEL-anchored credential for a workspace.

        Args:
            workspace_name: Workspace name
            workspace_said: Computed SAID of unified constraints
            unified_constraints: Unified package -> version spec
            project_saids: SAIDs of individual project stacks

        Returns:
            CredentialIssuanceResult
        """
        can, reason = self.can_issue()
        if not can:
            return CredentialIssuanceResult(
                success=False,
                credential_said=None,
                registry_said=None,
                error=reason,
            )

        try:
            attrs = {
                "dt": datetime.now(timezone.utc).isoformat(),
                "name": workspace_name,
                "workspaceSaid": workspace_said,
                "unifiedConstraints": unified_constraints,
                "projectCount": len(project_saids),
                "projectSaids": project_saids,
            }

            # Build edges to project stacks
            edges = {
                "projects": [
                    {
                        "d": said,
                        "s": self._get_schema_said("stack_credential"),
                    }
                    for said in project_saids
                ]
            }

            schema_said = self._get_schema_said("workspace_credential")

            from keri.vc import proving

            creder = proving.credential(
                issuer=self.hab.pre,
                schema=schema_said,
                data=attrs,
                status=self.registry.regk,
                source=edges,
            )

            self.registry.issue(creder=creder)

            logger.info(f"Issued workspace credential: {creder.said}")

            return CredentialIssuanceResult(
                success=True,
                credential_said=creder.said,
                registry_said=self.registry.regk,
            )

        except Exception as e:
            logger.error(f"Failed to issue workspace credential: {e}")
            return CredentialIssuanceResult(
                success=False,
                credential_said=None,
                registry_said=None,
                error=str(e),
            )


def get_issuer_from_session() -> Optional[StackCredentialIssuer]:
    """
    Try to get an issuer from current KERI session.

    Looks for:
    1. ai-orchestrator's credential service
    2. Session hab from hooks

    Returns None if KERI infrastructure not available.
    """
    try:
        # Try ai-orchestrator's credential service
        import sys
        sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent / "ai-orchestrator"))

        from agents.credential_service import get_credential_service
        service = get_credential_service()

        if service and service.hab and service.registry:
            return StackCredentialIssuer(
                hab=service.hab,
                registry=service.registry,
            )
    except ImportError:
        pass
    except Exception as e:
        logger.debug(f"Could not get issuer from session: {e}")

    return None
