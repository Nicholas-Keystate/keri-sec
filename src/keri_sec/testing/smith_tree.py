# -*- encoding: utf-8 -*-
"""
TestSmithTree: File-based Smith trees for test surface commitment.

Builds a hierarchical SAID-committed tree from source files, test files,
and runtime environment manifests. Each leaf is a file content SAID.
The root SAID is a Merkle commitment to the entire test surface.

When any leaf changes (file modified, env rotated), the root SAID changes,
which constitutes a DAID content rotation (sn:N -> sn:N+1) of the test suite.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from keri.core.coring import Diger, MtrDex


# ---------------------------------------------------------------------------
# SAID computation
# ---------------------------------------------------------------------------


def compute_file_said(content: bytes) -> str:
    """Compute SAID for file content using Blake3_256."""
    # Diger cannot hash empty bytes; use a sentinel for empty files
    if not content:
        content = b"\x00"
    return Diger(ser=content, code=MtrDex.Blake3_256).qb64


def compute_node_said(canonical: dict) -> str:
    """Compute SAID for a tree node from its canonical dict."""
    ser = json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode()
    return Diger(ser=ser, code=MtrDex.Blake3_256).qb64


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass
class FileLeaf:
    """A leaf in the test Smith tree representing a single file."""

    path: str  # Relative path from project root
    content_said: str  # SAID of file content (Blake3)
    file_type: str  # "source", "test", "config", "fixture"
    size_bytes: int

    @property
    def said(self) -> str:
        return self.content_said


@dataclass
class EnvLeaf:
    """A leaf representing the runtime environment manifest."""

    manifest_said: str  # RuntimeManifest.said
    manifest_data: Dict[str, Any]

    @property
    def said(self) -> str:
        return self.manifest_said


@dataclass
class SubtreeNode:
    """Interior node grouping related files."""

    name: str  # e.g., "src/keri_sec/attestation"
    subtree_type: str  # "source_module", "test_module", "env", "root"
    children: List[Union[SubtreeNode, FileLeaf, EnvLeaf]]
    _said: Optional[str] = field(default=None, repr=False)

    @property
    def children_saids(self) -> List[str]:
        return [child.said for child in self.children]

    @property
    def said(self) -> str:
        if self._said is None:
            canonical = {
                "name": self.name,
                "subtree_type": self.subtree_type,
                "children_saids": self.children_saids,
            }
            self._said = compute_node_said(canonical)
        return self._said

    def invalidate(self):
        """Clear cached SAID (call when children change)."""
        self._said = None


# ---------------------------------------------------------------------------
# Diff result
# ---------------------------------------------------------------------------


@dataclass
class ChangedSubtree:
    """A subtree that changed between two tree versions."""

    path: str
    previous_said: str
    current_said: str
    changed_files: List[str]
    subtree_type: str


@dataclass
class TreeDiff:
    """Result of diffing two TestSmithTrees."""

    changed_subtrees: List[ChangedSubtree]
    unchanged_subtree_paths: List[str]
    added_paths: List[str]
    removed_paths: List[str]
    env_changed: bool

    @property
    def has_changes(self) -> bool:
        return bool(
            self.changed_subtrees
            or self.added_paths
            or self.removed_paths
            or self.env_changed
        )


# ---------------------------------------------------------------------------
# TestSmithTree
# ---------------------------------------------------------------------------


class TestSmithTree:
    """
    A Smith tree built from filesystem paths and an environment manifest.

    Structure:
        root (d=root_said)
        +-- source/ (subtree)
        |   +-- module_a/ (subtree)
        |   |   +-- file1.py (leaf, d=SAID of content)
        |   |   +-- file2.py (leaf)
        |   +-- module_b/ (subtree)
        +-- tests/ (subtree)
        |   +-- test_module_a.py (leaf)
        |   +-- conftest.py (leaf)
        +-- env (leaf, d=RuntimeManifest.said)
    """

    def __init__(self, root: SubtreeNode):
        self.root = root

    @property
    def root_said(self) -> str:
        return self.root.said

    @staticmethod
    def build(
        source_dirs: List[str],
        test_dirs: List[str],
        manifest_said: Optional[str] = None,
        manifest_data: Optional[Dict[str, Any]] = None,
        project_root: Optional[str] = None,
        file_extensions: Optional[List[str]] = None,
    ) -> TestSmithTree:
        """
        Build a TestSmithTree from filesystem paths.

        Args:
            source_dirs: Directories containing source code (relative or absolute)
            test_dirs: Directories containing tests (relative or absolute)
            manifest_said: SAID of the RuntimeManifest (env leaf)
            manifest_data: Optional manifest dict for the env leaf
            project_root: Root directory for relative path computation
            file_extensions: File extensions to include (default: [".py"])

        Returns:
            TestSmithTree with computed SAIDs
        """
        extensions = file_extensions or [".py"]
        root_path = Path(project_root) if project_root else Path.cwd()

        children: List[Union[SubtreeNode, EnvLeaf]] = []

        # Build source subtree
        source_children = []
        for src_dir in source_dirs:
            src_path = Path(src_dir)
            if not src_path.is_absolute():
                src_path = root_path / src_path
            if src_path.exists():
                node = _build_dir_subtree(
                    src_path, root_path, "source_module", extensions
                )
                if node is not None:
                    source_children.append(node)

        if source_children:
            children.append(
                SubtreeNode(
                    name="source",
                    subtree_type="source_root",
                    children=source_children,
                )
            )

        # Build test subtree
        test_children = []
        for test_dir in test_dirs:
            test_path = Path(test_dir)
            if not test_path.is_absolute():
                test_path = root_path / test_path
            if test_path.exists():
                node = _build_dir_subtree(
                    test_path, root_path, "test_module", extensions
                )
                if node is not None:
                    test_children.append(node)

        if test_children:
            children.append(
                SubtreeNode(
                    name="tests",
                    subtree_type="test_root",
                    children=test_children,
                )
            )

        # Add env leaf
        if manifest_said is not None:
            children.append(
                EnvLeaf(
                    manifest_said=manifest_said,
                    manifest_data=manifest_data or {},
                )
            )

        root = SubtreeNode(
            name="root",
            subtree_type="root",
            children=children,
        )

        return TestSmithTree(root=root)

    def get_all_leaves(self) -> List[FileLeaf]:
        """Get all file leaves in the tree."""
        return _collect_leaves(self.root)

    def get_subtree(self, path: str) -> Optional[SubtreeNode]:
        """Get a subtree node by path (e.g., 'source/keri_sec/attestation')."""
        return _find_subtree(self.root, path.split("/"), 0)

    def leaf_count(self) -> int:
        """Count total file leaves."""
        return len(self.get_all_leaves())

    def diff(self, other: TestSmithTree) -> TreeDiff:
        """
        Diff this tree against another tree.

        Returns which subtrees changed, which are unchanged,
        and whether the env leaf changed.
        """
        changed = []
        unchanged = []
        added = []
        removed = []

        self_index = _index_subtrees(self.root, "")
        other_index = _index_subtrees(other.root, "")

        for path, node in self_index.items():
            if path in other_index:
                other_node = other_index[path]
                if node.said != other_node.said:
                    changed_files = _diff_leaves(node, other_node)
                    changed.append(
                        ChangedSubtree(
                            path=path,
                            previous_said=other_node.said,
                            current_said=node.said,
                            changed_files=changed_files,
                            subtree_type=node.subtree_type
                            if isinstance(node, SubtreeNode)
                            else "leaf",
                        )
                    )
                else:
                    unchanged.append(path)
            else:
                added.append(path)

        for path in other_index:
            if path not in self_index:
                removed.append(path)

        # Check env leaf
        env_changed = False
        self_env = _find_env_leaf(self.root)
        other_env = _find_env_leaf(other.root)
        if self_env and other_env:
            env_changed = self_env.said != other_env.said
        elif self_env or other_env:
            env_changed = True

        return TreeDiff(
            changed_subtrees=changed,
            unchanged_subtree_paths=unchanged,
            added_paths=added,
            removed_paths=removed,
            env_changed=env_changed,
        )

    def to_dict(self) -> dict:
        """Serialize tree to dict for storage/comparison."""
        return _node_to_dict(self.root)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _build_dir_subtree(
    dir_path: Path,
    project_root: Path,
    subtree_type: str,
    extensions: List[str],
) -> Optional[SubtreeNode]:
    """Recursively build a subtree from a directory."""
    children: List[Union[SubtreeNode, FileLeaf]] = []

    try:
        entries = sorted(dir_path.iterdir(), key=lambda e: e.name)
    except PermissionError:
        return None

    for entry in entries:
        if entry.name.startswith(".") or entry.name == "__pycache__":
            continue

        if entry.is_file() and any(entry.name.endswith(ext) for ext in extensions):
            try:
                content = entry.read_bytes()
                rel_path = str(entry.relative_to(project_root))
                children.append(
                    FileLeaf(
                        path=rel_path,
                        content_said=compute_file_said(content),
                        file_type="test" if entry.name.startswith("test_") else "source",
                        size_bytes=len(content),
                    )
                )
            except (PermissionError, OSError):
                continue

        elif entry.is_dir():
            sub = _build_dir_subtree(entry, project_root, subtree_type, extensions)
            if sub is not None:
                children.append(sub)

    if not children:
        return None

    rel_name = str(dir_path.relative_to(project_root))
    return SubtreeNode(
        name=rel_name,
        subtree_type=subtree_type,
        children=children,
    )


def _collect_leaves(
    node: Union[SubtreeNode, FileLeaf, EnvLeaf],
) -> List[FileLeaf]:
    """Recursively collect all FileLeaf nodes."""
    if isinstance(node, FileLeaf):
        return [node]
    if isinstance(node, EnvLeaf):
        return []
    leaves = []
    for child in node.children:
        leaves.extend(_collect_leaves(child))
    return leaves


def _find_subtree(
    node: Union[SubtreeNode, FileLeaf, EnvLeaf],
    path_parts: List[str],
    depth: int,
) -> Optional[SubtreeNode]:
    """Find a subtree by path parts."""
    if not isinstance(node, SubtreeNode):
        return None
    if depth >= len(path_parts):
        return node
    target = path_parts[depth]
    for child in node.children:
        if isinstance(child, SubtreeNode) and child.name.endswith(target):
            result = _find_subtree(child, path_parts, depth + 1)
            if result is not None:
                return result
    return None


def _index_subtrees(
    node: Union[SubtreeNode, FileLeaf, EnvLeaf],
    prefix: str,
) -> Dict[str, Union[SubtreeNode, FileLeaf]]:
    """Build a flat index of path -> node for diffing."""
    index: Dict[str, Union[SubtreeNode, FileLeaf]] = {}
    if isinstance(node, FileLeaf):
        index[node.path] = node
        return index
    if isinstance(node, EnvLeaf):
        return index
    path = f"{prefix}/{node.name}" if prefix else node.name
    index[path] = node
    for child in node.children:
        index.update(_index_subtrees(child, path))
    return index


def _diff_leaves(
    current: Union[SubtreeNode, FileLeaf],
    previous: Union[SubtreeNode, FileLeaf],
) -> List[str]:
    """Find files that changed between two subtree nodes."""
    if isinstance(current, FileLeaf) and isinstance(previous, FileLeaf):
        if current.content_said != previous.content_said:
            return [current.path]
        return []

    if not isinstance(current, SubtreeNode) or not isinstance(previous, SubtreeNode):
        return []

    current_leaves = {l.path: l for l in _collect_leaves(current)}
    previous_leaves = {l.path: l for l in _collect_leaves(previous)}

    changed = []
    for path, leaf in current_leaves.items():
        if path in previous_leaves:
            if leaf.content_said != previous_leaves[path].content_said:
                changed.append(path)
        else:
            changed.append(path)

    for path in previous_leaves:
        if path not in current_leaves:
            changed.append(path)

    return changed


def _find_env_leaf(
    node: Union[SubtreeNode, FileLeaf, EnvLeaf],
) -> Optional[EnvLeaf]:
    """Find the environment leaf in the tree."""
    if isinstance(node, EnvLeaf):
        return node
    if isinstance(node, SubtreeNode):
        for child in node.children:
            result = _find_env_leaf(child)
            if result is not None:
                return result
    return None


def _node_to_dict(node: Union[SubtreeNode, FileLeaf, EnvLeaf]) -> dict:
    """Serialize a node to dict."""
    if isinstance(node, FileLeaf):
        return {
            "type": "file",
            "path": node.path,
            "said": node.content_said,
            "file_type": node.file_type,
            "size_bytes": node.size_bytes,
        }
    if isinstance(node, EnvLeaf):
        return {
            "type": "env",
            "said": node.manifest_said,
        }
    return {
        "type": "subtree",
        "name": node.name,
        "subtree_type": node.subtree_type,
        "said": node.said,
        "children_saids": node.children_saids,
        "children": [_node_to_dict(c) for c in node.children],
    }
