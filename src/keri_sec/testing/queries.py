# -*- encoding: utf-8 -*-
"""
KGQL query templates for test execution credentials.

Provides parameterized KGQL query strings for querying the credential
graph of test executions, staleness policies, and execution chains.

KGQL translates to keripy Reger index lookups (issus, subjs, schms)
and edge traversals. These templates are the declarative interface
consumed by euler-prototypes and other downstream tools.
"""

from __future__ import annotations

from string import Template


class TestQueryTemplates:
    """Static KGQL query templates for test credential graph traversal.

    All templates use ``string.Template`` syntax (``$var``) for parameter
    substitution. Call ``.substitute(var=value)`` or ``.safe_substitute()``
    to produce executable KGQL strings.

    Template variables:
        $schema_said    - TestExecutionCredential schema SAID
        $suite_gaid     - Test suite GAID
        $tree_root_said - Smith tree root SAID
        $runner_aid     - Test runner AID
        $credential_said - Specific credential SAID
        $subtree_path   - Smith tree subtree path
        $aid            - AID for keystate context
        $seq            - Sequence number for keystate context
        $current_root   - Current tree root SAID (for staleness comparison)
        $policy_schema_said - StalenessPolicyCredential schema SAID
    """

    # ------------------------------------------------------------------
    # Staleness detection
    # ------------------------------------------------------------------

    STALE_EXECUTIONS = Template(
        "MATCH (exec:$schema_said)\n"
        "WHERE exec.a.treeRootSaid != \"$current_root\"\n"
        "  AND exec.e.suite.n = \"$suite_gaid\"\n"
        "RETURN exec.d AS credential_said,\n"
        "       exec.a.treeRootSaid AS attested_root,\n"
        "       exec.a.dt AS execution_time"
    )

    # ------------------------------------------------------------------
    # Execution chain traversal
    # ------------------------------------------------------------------

    EXECUTION_CHAIN = Template(
        "MATCH path = (latest:$schema_said)-[:previousRun*]->(first:$schema_said)\n"
        "WHERE latest.d = \"$credential_said\"\n"
        "RETURN path, length(path) AS chain_depth"
    )

    # ------------------------------------------------------------------
    # Runner queries
    # ------------------------------------------------------------------

    EXECUTIONS_BY_RUNNER = Template(
        "MATCH (exec:$schema_said)\n"
        "WHERE exec.a.runnerAid = \"$runner_aid\"\n"
        "RETURN exec.d AS credential_said,\n"
        "       exec.a.dt AS execution_time,\n"
        "       exec.a.results AS results"
    )

    # ------------------------------------------------------------------
    # Tree root queries
    # ------------------------------------------------------------------

    EXECUTIONS_FOR_ROOT = Template(
        "MATCH (exec:$schema_said)\n"
        "WHERE exec.a.treeRootSaid = \"$tree_root_said\"\n"
        "  AND exec.e.suite.n = \"$suite_gaid\"\n"
        "RETURN exec.d AS credential_said,\n"
        "       exec.a.dt AS execution_time,\n"
        "       exec.a.results AS results"
    )

    # ------------------------------------------------------------------
    # Runner verification
    # ------------------------------------------------------------------

    VERIFY_RUNNER = Template(
        "MATCH (exec:$schema_said)\n"
        "WHERE exec.d = \"$credential_said\"\n"
        "RETURN exec, PROOF(exec) AS verification"
    )

    # ------------------------------------------------------------------
    # Policy queries
    # ------------------------------------------------------------------

    POLICY_BY_SUBTREE = Template(
        "MATCH (policy:$policy_schema_said)\n"
        "WHERE policy.a.subtreePath = \"$subtree_path\"\n"
        "  AND policy.e.suite.n = \"$suite_gaid\"\n"
        "RETURN policy.d AS policy_said,\n"
        "       policy.a.policyType AS policy_type,\n"
        "       policy.a.priority AS priority"
    )

    # ------------------------------------------------------------------
    # Temporal queries (keystate context)
    # ------------------------------------------------------------------

    EXECUTION_AT_KEYSTATE = Template(
        "AT KEYSTATE (aid = \"$aid\", seq = $seq)\n"
        "MATCH (exec:$schema_said)\n"
        "WHERE exec.e.suite.n = \"$suite_gaid\"\n"
        "RETURN exec.d AS credential_said,\n"
        "       exec.a.dt AS execution_time"
    )

    # ------------------------------------------------------------------
    # Suite execution summary
    # ------------------------------------------------------------------

    SUITE_LATEST_EXECUTION = Template(
        "MATCH (exec:$schema_said)\n"
        "WHERE exec.e.suite.n = \"$suite_gaid\"\n"
        "RETURN exec.d AS credential_said,\n"
        "       exec.a.dt AS execution_time,\n"
        "       exec.a.treeRootSaid AS tree_root,\n"
        "       exec.a.results AS results\n"
        "ORDER BY exec.a.dt DESC\n"
        "LIMIT 1"
    )
