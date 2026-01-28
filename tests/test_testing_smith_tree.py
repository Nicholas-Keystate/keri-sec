# -*- encoding: utf-8 -*-
"""Tests for TestSmithTree: file-based Smith trees."""

import pytest
from pathlib import Path

from keri_sec.testing.smith_tree import (
    TestSmithTree,
    FileLeaf,
    EnvLeaf,
    SubtreeNode,
    compute_file_said,
    compute_node_said,
)


@pytest.fixture
def sample_project(tmp_path):
    """Create a minimal project structure for testing."""
    src = tmp_path / "src" / "mylib"
    src.mkdir(parents=True)
    (src / "__init__.py").write_text("")
    (src / "core.py").write_text("def hello(): return 'world'")
    (src / "utils.py").write_text("def add(a, b): return a + b")

    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "test_core.py").write_text("def test_hello(): pass")
    (tests / "test_utils.py").write_text("def test_add(): pass")

    return tmp_path


@pytest.fixture
def manifest_said():
    return compute_node_said({"python": "3.12.12", "keripy": "1.3.3"})


class TestSAIDComputation:
    def test_file_said_deterministic(self):
        content = b"def hello(): return 'world'"
        s1 = compute_file_said(content)
        s2 = compute_file_said(content)
        assert s1 == s2
        assert s1.startswith("E")

    def test_file_said_changes_with_content(self):
        s1 = compute_file_said(b"version 1")
        s2 = compute_file_said(b"version 2")
        assert s1 != s2

    def test_node_said_deterministic(self):
        d = {"name": "root", "children_saids": ["Ea", "Eb"]}
        s1 = compute_node_said(d)
        s2 = compute_node_said(d)
        assert s1 == s2

    def test_node_said_order_matters(self):
        s1 = compute_node_said({"children_saids": ["Ea", "Eb"]})
        s2 = compute_node_said({"children_saids": ["Eb", "Ea"]})
        assert s1 != s2


class TestTreeBuilding:
    def test_build_from_project(self, sample_project, manifest_said):
        tree = TestSmithTree.build(
            source_dirs=["src"],
            test_dirs=["tests"],
            manifest_said=manifest_said,
            project_root=str(sample_project),
        )
        assert tree.root_said is not None
        assert tree.root_said.startswith("E")

    def test_deterministic_root(self, sample_project, manifest_said):
        t1 = TestSmithTree.build(
            source_dirs=["src"],
            test_dirs=["tests"],
            manifest_said=manifest_said,
            project_root=str(sample_project),
        )
        t2 = TestSmithTree.build(
            source_dirs=["src"],
            test_dirs=["tests"],
            manifest_said=manifest_said,
            project_root=str(sample_project),
        )
        assert t1.root_said == t2.root_said

    def test_root_changes_on_file_modify(self, sample_project, manifest_said):
        t1 = TestSmithTree.build(
            source_dirs=["src"],
            test_dirs=["tests"],
            manifest_said=manifest_said,
            project_root=str(sample_project),
        )

        # Modify a source file
        (sample_project / "src" / "mylib" / "core.py").write_text(
            "def hello(): return 'changed'"
        )

        t2 = TestSmithTree.build(
            source_dirs=["src"],
            test_dirs=["tests"],
            manifest_said=manifest_said,
            project_root=str(sample_project),
        )
        assert t1.root_said != t2.root_said

    def test_root_changes_on_env_change(self, sample_project):
        m1 = compute_node_said({"python": "3.12.12"})
        m2 = compute_node_said({"python": "3.13.0"})

        t1 = TestSmithTree.build(
            source_dirs=["src"],
            test_dirs=["tests"],
            manifest_said=m1,
            project_root=str(sample_project),
        )
        t2 = TestSmithTree.build(
            source_dirs=["src"],
            test_dirs=["tests"],
            manifest_said=m2,
            project_root=str(sample_project),
        )
        assert t1.root_said != t2.root_said

    def test_leaf_count(self, sample_project, manifest_said):
        tree = TestSmithTree.build(
            source_dirs=["src"],
            test_dirs=["tests"],
            manifest_said=manifest_said,
            project_root=str(sample_project),
        )
        # __init__.py + core.py + utils.py + test_core.py + test_utils.py = 5
        assert tree.leaf_count() == 5

    def test_no_env_leaf(self, sample_project):
        tree = TestSmithTree.build(
            source_dirs=["src"],
            test_dirs=["tests"],
            project_root=str(sample_project),
        )
        assert tree.root_said is not None
        assert tree.leaf_count() == 5

    def test_empty_dirs_skipped(self, tmp_path):
        (tmp_path / "src").mkdir()
        (tmp_path / "tests").mkdir()
        tree = TestSmithTree.build(
            source_dirs=["src"],
            test_dirs=["tests"],
            project_root=str(tmp_path),
        )
        # Root with no children still has a SAID
        assert tree.root_said is not None


class TestTreeDiff:
    def test_no_changes(self, sample_project, manifest_said):
        t1 = TestSmithTree.build(
            source_dirs=["src"],
            test_dirs=["tests"],
            manifest_said=manifest_said,
            project_root=str(sample_project),
        )
        t2 = TestSmithTree.build(
            source_dirs=["src"],
            test_dirs=["tests"],
            manifest_said=manifest_said,
            project_root=str(sample_project),
        )
        diff = t1.diff(t2)
        assert not diff.has_changes

    def test_detects_file_change(self, sample_project, manifest_said):
        t1 = TestSmithTree.build(
            source_dirs=["src"],
            test_dirs=["tests"],
            manifest_said=manifest_said,
            project_root=str(sample_project),
        )
        (sample_project / "src" / "mylib" / "core.py").write_text("modified")
        t2 = TestSmithTree.build(
            source_dirs=["src"],
            test_dirs=["tests"],
            manifest_said=manifest_said,
            project_root=str(sample_project),
        )
        diff = t2.diff(t1)
        assert diff.has_changes
        assert len(diff.changed_subtrees) > 0

    def test_detects_env_change(self, sample_project):
        m1 = compute_node_said({"python": "3.12.12"})
        m2 = compute_node_said({"python": "3.13.0"})

        t1 = TestSmithTree.build(
            source_dirs=["src"],
            test_dirs=["tests"],
            manifest_said=m1,
            project_root=str(sample_project),
        )
        t2 = TestSmithTree.build(
            source_dirs=["src"],
            test_dirs=["tests"],
            manifest_said=m2,
            project_root=str(sample_project),
        )
        diff = t2.diff(t1)
        assert diff.env_changed

    def test_detects_added_file(self, sample_project, manifest_said):
        t1 = TestSmithTree.build(
            source_dirs=["src"],
            test_dirs=["tests"],
            manifest_said=manifest_said,
            project_root=str(sample_project),
        )
        (sample_project / "src" / "mylib" / "new_module.py").write_text("new")
        t2 = TestSmithTree.build(
            source_dirs=["src"],
            test_dirs=["tests"],
            manifest_said=manifest_said,
            project_root=str(sample_project),
        )
        diff = t2.diff(t1)
        assert diff.has_changes
        # The added file shows as a changed subtree (parent SAID changed)
        assert len(diff.changed_subtrees) > 0


class TestSerialization:
    def test_to_dict(self, sample_project, manifest_said):
        tree = TestSmithTree.build(
            source_dirs=["src"],
            test_dirs=["tests"],
            manifest_said=manifest_said,
            project_root=str(sample_project),
        )
        d = tree.to_dict()
        assert d["type"] == "subtree"
        assert d["name"] == "root"
        assert "said" in d
        assert "children" in d
        assert len(d["children"]) == 3  # source, tests, env

    def test_subtree_node_structure(self):
        leaf = FileLeaf(
            path="src/core.py",
            content_said="ETestSAID",
            file_type="source",
            size_bytes=100,
        )
        node = SubtreeNode(name="src", subtree_type="source_module", children=[leaf])
        assert node.children_saids == ["ETestSAID"]
        assert node.said.startswith("E")
