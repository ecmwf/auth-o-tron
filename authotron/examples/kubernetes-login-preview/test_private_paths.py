"""Private location guards using only synthetic project paths."""

from pathlib import Path
import tempfile
import unittest

import private_paths
import render


class PrivatePathTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.project = self.root / "project"
        self.project.mkdir()

    def checked(self, path):
        return private_paths.checked_private_path(
            path, self.project, render.SOURCE_FILES, render.SOURCE_DIRS
        )

    def test_absent_archive_paths_are_rejected_without_git(self):
        for name in (*render.SOURCE_FILES, *render.SOURCE_DIRS):
            for suffix in ("", "/private.json"):
                path = self.project / (name + suffix)
                with self.subTest(path=path), self.assertRaises(ValueError):
                    self.checked(path)
                self.assertFalse(path.exists())
        self.assertEqual(self.checked(self.root / "private"), self.root / "private")

    def test_git_directory_file_and_dangling_marker_are_rejected(self):
        marker = self.project / ".git"
        for kind in ("directory", "file", "symlink"):
            if kind == "directory":
                marker.mkdir()
            elif kind == "file":
                marker.write_text("gitdir: synthetic-worktree")
            else:
                marker.symlink_to(self.root / "absent")
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                self.checked(self.project / "nested/private.json")
            if kind == "directory":
                marker.rmdir()
            else:
                marker.unlink()

    def test_git_node_and_parent_traversal_are_rejected(self):
        for path in (
            self.project / ".git",
            self.project / ".git/private.json",
            self.root / "absent/../private.json",
        ):
            with self.subTest(path=path), self.assertRaises(ValueError):
                self.checked(path)


if __name__ == "__main__":
    unittest.main()
