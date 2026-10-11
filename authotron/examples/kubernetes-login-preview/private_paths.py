"""Location guards for credentials and secret-bearing example outputs."""

import os
from pathlib import Path


def outside_git(path):
    if ".." in Path(path).parts:
        raise ValueError("private paths must not contain parent traversal")
    path = Path(os.path.abspath(path))
    if any(
        parent.name == ".git"
        or (parent / ".git").exists()
        or (parent / ".git").is_symlink()
        for parent in (path, *path.parents)
    ):
        raise ValueError("private files and output directories must be outside Git")
    return path


def checked_private_path(path, project, source_files, source_dirs):
    """Reject archive inputs even when the project has no Git metadata."""
    path = outside_git(path)
    for name in source_files:
        if path.is_relative_to(Path(os.path.abspath(project / name))):
            raise ValueError("private output collides with an archived source file")
    for name in source_dirs:
        if path.is_relative_to(Path(os.path.abspath(project / name))):
            raise ValueError("private output must not be inside archived source")
    return path
