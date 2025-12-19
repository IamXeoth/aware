"""Scanners for different sources (git, files, etc)."""

from .git_diff import (
    GitDiffScanner,
    get_diff_for_push,
    get_staged_diff,
    get_staged_files,
)

__all__ = [
    "GitDiffScanner",
    "get_diff_for_push",
    "get_staged_diff",
    "get_staged_files",
]