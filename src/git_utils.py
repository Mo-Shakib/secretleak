"""Git integration utilities: reading working tree, diffs, and commit ranges."""

from __future__ import annotations

import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator, Optional

# Extensions we skip entirely (binary, compiled, lock files, etc.)
_SKIP_EXTENSIONS = frozenset(
    {
        ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg", ".webp",
        ".pdf", ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z", ".rar",
        ".exe", ".dll", ".so", ".dylib", ".bin", ".obj", ".o", ".a",
        ".class", ".pyc", ".pyo", ".pyd",
        ".wasm", ".woff", ".woff2", ".ttf", ".otf", ".eot",
        ".mp3", ".mp4", ".wav", ".avi", ".mov",
        ".lock",  # package-lock.json, poetry.lock – high false-positive noise
    }
)

_MAX_FILE_SIZE = 1 * 1024 * 1024  # 1 MB


@dataclass
class ScannableLine:
    """A single line extracted from a file or diff, ready for scanning."""

    file_path: str
    line_number: int
    content: str
    commit_hash: Optional[str] = None
    author: Optional[str] = None


@dataclass
class DiffFile:
    """A file's changed lines from a unified diff."""

    path: str
    lines: list[ScannableLine] = field(default_factory=list)


def _run_git(args: list[str], cwd: Path) -> str:
    """Run a git command and return stdout; raises on non-zero exit."""
    result = subprocess.run(
        ["git", *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if result.returncode != 0:
        raise GitError(f"git {' '.join(args)!r} failed: {result.stderr.strip()}")
    return result.stdout


class GitError(RuntimeError):
    pass


def iter_working_tree(repo_path: Path) -> Iterator[ScannableLine]:
    """Yield scannable lines from every tracked (and untracked) text file."""
    try:
        tracked_raw = _run_git(
            ["ls-files", "--cached", "--others", "--exclude-standard"], repo_path
        )
        tracked = [p.strip() for p in tracked_raw.splitlines() if p.strip()]
    except GitError:
        # Fallback: walk the directory
        tracked = [
            str(p.relative_to(repo_path))
            for p in repo_path.rglob("*")
            if p.is_file()
        ]

    for rel_path in tracked:
        abs_path = repo_path / rel_path
        if not abs_path.is_file():
            continue
        if abs_path.suffix.lower() in _SKIP_EXTENSIONS:
            continue
        if abs_path.stat().st_size > _MAX_FILE_SIZE:
            continue
        try:
            text = abs_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for lineno, line in enumerate(text.splitlines(), start=1):
            yield ScannableLine(
                file_path=rel_path,
                line_number=lineno,
                content=line,
            )


def iter_staged_diff(repo_path: Path) -> Iterator[ScannableLine]:
    """Yield added lines from the staged diff."""
    try:
        diff_text = _run_git(["diff", "--staged", "--unified=0"], repo_path)
    except GitError:
        return
    yield from _parse_diff(diff_text)


def iter_commit_range(repo_path: Path, from_ref: str, to_ref: str) -> Iterator[ScannableLine]:
    """Yield added lines between two refs (commit range)."""
    try:
        diff_text = _run_git(
            ["diff", "--unified=0", from_ref, to_ref], repo_path
        )
    except GitError:
        return
    # Collect commit authors for the range
    author_map = _build_author_map(repo_path, from_ref, to_ref)
    for line in _parse_diff(diff_text):
        # Author attribution is approximate (latest commit that touched the file)
        line.author = author_map.get(line.file_path)
        yield line


def _build_author_map(repo_path: Path, from_ref: str, to_ref: str) -> dict[str, str]:
    """Map file path → most recent author email in the commit range."""
    try:
        log = _run_git(
            ["log", "--format=%ae", "--name-only", f"{from_ref}..{to_ref}"],
            repo_path,
        )
    except GitError:
        return {}
    author_map: dict[str, str] = {}
    current_author = ""
    for line in log.splitlines():
        line = line.strip()
        if not line:
            continue
        if "@" in line or not line.startswith("/"):
            # Heuristic: email lines contain @
            if "@" in line:
                current_author = line
        else:
            if current_author and line not in author_map:
                author_map[line] = current_author
    return author_map


def _parse_diff(diff_text: str) -> Iterator[ScannableLine]:
    """Parse a unified diff and yield only added lines with accurate line numbers."""
    current_file: Optional[str] = None
    current_lineno = 0

    for raw_line in diff_text.splitlines():
        if raw_line.startswith("diff --git "):
            # Extract b/path
            parts = raw_line.split(" b/", 1)
            current_file = parts[1].strip() if len(parts) == 2 else None
            current_lineno = 0
            continue

        if raw_line.startswith("+++ b/"):
            current_file = raw_line[6:].strip()
            continue

        if raw_line.startswith("+++ /dev/null") or raw_line.startswith("--- "):
            continue

        if raw_line.startswith("@@ "):
            # @@ -old_start,old_count +new_start,new_count @@
            try:
                new_part = raw_line.split("+")[1].split("@@")[0].strip()
                current_lineno = int(new_part.split(",")[0]) - 1
            except (IndexError, ValueError):
                current_lineno = 0
            continue

        if raw_line.startswith("+") and not raw_line.startswith("+++"):
            if current_file and current_file.split(".")[-1] not in _SKIP_EXTENSIONS:
                current_lineno += 1
                if Path(current_file).suffix.lower() not in _SKIP_EXTENSIONS:
                    yield ScannableLine(
                        file_path=current_file,
                        line_number=current_lineno,
                        content=raw_line[1:],  # strip leading '+'
                    )
            continue

        if not raw_line.startswith("-"):
            current_lineno += 1


def get_repo_root(path: Path) -> Optional[Path]:
    """Return the git repository root for the given path, or None."""
    try:
        root = _run_git(["rev-parse", "--show-toplevel"], path).strip()
        return Path(root)
    except GitError:
        return None
