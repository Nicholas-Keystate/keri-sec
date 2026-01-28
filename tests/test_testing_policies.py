# -*- encoding: utf-8 -*-
"""Tests for staleness policies and policy algebra."""

import pytest

from keri_sec.testing.policies import (
    PolicyAction,
    PolicyAlgebra,
    PolicyCredential,
    PolicyType,
    PolicyVerdict,
    policy_severity,
)


class TestPolicyType:
    def test_severity_ordering(self):
        assert policy_severity(PolicyType.BLOCK) < policy_severity(PolicyType.CASCADE_REVOKE)
        assert policy_severity(PolicyType.CASCADE_REVOKE) < policy_severity(PolicyType.RE_EXECUTE)
        assert policy_severity(PolicyType.RE_EXECUTE) < policy_severity(PolicyType.SELECTIVE_RETEST)
        assert policy_severity(PolicyType.SELECTIVE_RETEST) < policy_severity(PolicyType.WARN)

    def test_dominance(self):
        assert PolicyAlgebra.dominates(PolicyType.BLOCK, PolicyType.WARN)
        assert PolicyAlgebra.dominates(PolicyType.BLOCK, PolicyType.CASCADE_REVOKE)
        assert PolicyAlgebra.dominates(PolicyType.CASCADE_REVOKE, PolicyType.RE_EXECUTE)
        assert not PolicyAlgebra.dominates(PolicyType.WARN, PolicyType.BLOCK)
        assert not PolicyAlgebra.dominates(PolicyType.WARN, PolicyType.WARN)


class TestPolicyCredential:
    def test_said_is_stable(self):
        p = PolicyCredential(
            policy_type=PolicyType.BLOCK,
            subtree_path="source/keri_sec",
        )
        s1 = p.said
        s2 = p.said
        assert s1 == s2
        assert s1.startswith("E")

    def test_different_policies_different_saids(self):
        p1 = PolicyCredential(
            policy_type=PolicyType.BLOCK,
            subtree_path="source/keri_sec",
        )
        p2 = PolicyCredential(
            policy_type=PolicyType.WARN,
            subtree_path="source/keri_sec",
        )
        assert p1.said != p2.said

    def test_to_dict(self):
        p = PolicyCredential(
            policy_type=PolicyType.SELECTIVE_RETEST,
            subtree_path="tests/integration",
            parameters={"retest_scope": "changed_only"},
            priority=10,
            description="Retest changed integration tests",
        )
        d = p.to_dict()
        assert d["policy_type"] == "selective_retest"
        assert d["subtree_path"] == "tests/integration"
        assert d["parameters"]["retest_scope"] == "changed_only"
        assert d["priority"] == 10

    def test_to_dict_minimal(self):
        p = PolicyCredential(
            policy_type=PolicyType.WARN,
            subtree_path="root",
        )
        d = p.to_dict()
        assert "parameters" not in d
        assert "priority" not in d
        assert "issuer" not in d


class TestPolicyAlgebra:
    def test_block_absorbs_all(self):
        policies = [
            PolicyCredential(PolicyType.BLOCK, "source/keri_sec"),
            PolicyCredential(PolicyType.RE_EXECUTE, "tests"),
            PolicyCredential(PolicyType.WARN, "root"),
        ]
        verdict = PolicyAlgebra.compose(policies, ["source/keri_sec", "tests"])
        assert verdict.blocked
        assert verdict.effective_type == PolicyType.BLOCK
        # Only BLOCK action should be present (absorbing)
        assert len(verdict.actions) == 1
        assert verdict.actions[0].action_type == PolicyType.BLOCK

    def test_cascade_revoke_dominates_re_execute(self):
        policies = [
            PolicyCredential(PolicyType.CASCADE_REVOKE, "source/keri_sec"),
            PolicyCredential(PolicyType.RE_EXECUTE, "tests"),
        ]
        verdict = PolicyAlgebra.compose(policies, ["source/keri_sec", "tests"])
        assert not verdict.blocked
        assert verdict.effective_type == PolicyType.CASCADE_REVOKE
        # CASCADE_REVOKE subsumes RE_EXECUTE
        action_types = [a.action_type for a in verdict.actions]
        assert PolicyType.CASCADE_REVOKE in action_types
        assert PolicyType.RE_EXECUTE not in action_types

    def test_warn_transparent(self):
        policies = [
            PolicyCredential(PolicyType.RE_EXECUTE, "source"),
            PolicyCredential(PolicyType.WARN, "tests", description="Tests may be stale"),
        ]
        verdict = PolicyAlgebra.compose(policies, ["source", "tests"])
        assert not verdict.blocked
        assert verdict.effective_type == PolicyType.RE_EXECUTE
        assert len(verdict.actions) == 1
        assert verdict.actions[0].action_type == PolicyType.RE_EXECUTE
        assert len(verdict.warnings) == 1
        assert "stale" in verdict.warnings[0].lower()

    def test_selective_retest_and_re_execute_both_emitted(self):
        policies = [
            PolicyCredential(PolicyType.RE_EXECUTE, "source/core"),
            PolicyCredential(PolicyType.SELECTIVE_RETEST, "source/utils"),
        ]
        verdict = PolicyAlgebra.compose(policies, ["source/core", "source/utils"])
        action_types = [a.action_type for a in verdict.actions]
        assert PolicyType.RE_EXECUTE in action_types
        assert PolicyType.SELECTIVE_RETEST in action_types

    def test_warn_only(self):
        policies = [
            PolicyCredential(PolicyType.WARN, "root", description="Advisory only"),
        ]
        verdict = PolicyAlgebra.compose(policies, ["root"])
        assert not verdict.blocked
        assert verdict.effective_type == PolicyType.WARN
        assert len(verdict.actions) == 0
        assert len(verdict.warnings) == 1
        assert not verdict.requires_action

    def test_empty_policies(self):
        verdict = PolicyAlgebra.compose([], [])
        assert not verdict.blocked
        assert verdict.effective_type == PolicyType.WARN
        assert len(verdict.actions) == 0

    def test_block_only(self):
        policies = [
            PolicyCredential(PolicyType.BLOCK, "source/keri_sec"),
        ]
        verdict = PolicyAlgebra.compose(policies, ["source/keri_sec"])
        assert verdict.blocked
        assert verdict.requires_action

    def test_duplicate_type_deduplicated(self):
        policies = [
            PolicyCredential(PolicyType.RE_EXECUTE, "source/a"),
            PolicyCredential(PolicyType.RE_EXECUTE, "source/b"),
        ]
        verdict = PolicyAlgebra.compose(policies, ["source/a", "source/b"])
        re_exec_actions = [a for a in verdict.actions if a.action_type == PolicyType.RE_EXECUTE]
        assert len(re_exec_actions) == 1


class TestPolicyVerdict:
    def test_verdict_said_stable(self):
        verdict = PolicyVerdict(
            blocked=True,
            actions=[],
            warnings=[],
            effective_type=PolicyType.BLOCK,
        )
        s1 = verdict.verdict_said
        s2 = verdict.verdict_said
        assert s1 == s2
        assert s1.startswith("E")

    def test_requires_action_for_block(self):
        verdict = PolicyVerdict(
            blocked=True,
            actions=[PolicyAction(
                action_type=PolicyType.BLOCK,
                subtree_path="root",
                source_policy_said="ETest",
            )],
            warnings=[],
            effective_type=PolicyType.BLOCK,
        )
        assert verdict.requires_action

    def test_warn_does_not_require_action(self):
        verdict = PolicyVerdict(
            blocked=False,
            actions=[],
            warnings=["advisory"],
            effective_type=PolicyType.WARN,
        )
        assert not verdict.requires_action
