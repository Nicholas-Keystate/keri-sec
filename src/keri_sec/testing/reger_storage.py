# -*- encoding: utf-8 -*-
"""
Reger storage: populates keripy Reger indexes for KGQL queryability.

Without explicit Reger index population, KGQL queries return nothing.
This module stores Creder objects and creates the issuer, subject,
and schema indexes that KGQL uses for credential graph traversal.

Pattern: replicates CredentialService.issue_credential() storage step.
"""

from __future__ import annotations

from typing import Optional

from keri.core.coring import Saider
from keri.vdr import credentialing


def store_in_reger(
    rgy: credentialing.Regery,
    creder,
    issuer_aid: str,
    schema_said: str,
    subject_aid: Optional[str] = None,
) -> str:
    """Store a credential in Reger with full indexing.

    Populates four indexes:
        1. creds: Main credential storage (keyed by SAID)
        2. issus: Issuer index (issuer AID -> credential SAID)
        3. subjs: Subject index (subject AID -> credential SAID)
        4. schms: Schema index (schema SAID -> credential SAID)

    This MUST be called before TEL issuance for the credential
    to be resolvable via KGQL queries.

    Args:
        rgy: Regery instance (has .reger with LMDBer stores)
        creder: Creder object from proving.credential()
        issuer_aid: Issuer AID prefix
        schema_said: Schema SAID
        subject_aid: Subject AID (defaults to issuer_aid for self-issued)

    Returns:
        Credential SAID
    """
    if subject_aid is None:
        subject_aid = issuer_aid

    saider = Saider(qb64=creder.said)

    # Main credential storage
    rgy.reger.creds.put(keys=creder.said, val=creder)

    # Issuer index
    rgy.reger.issus.add(keys=issuer_aid, val=saider)

    # Subject index
    rgy.reger.subjs.add(keys=subject_aid, val=saider)

    # Schema index
    rgy.reger.schms.add(keys=schema_said, val=saider)

    return creder.said
